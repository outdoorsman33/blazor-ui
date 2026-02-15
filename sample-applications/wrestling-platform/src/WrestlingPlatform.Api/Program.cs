using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure;
using WrestlingPlatform.Infrastructure.Persistence;
using WrestlingPlatform.Infrastructure.Services;
using WrestlingPlatform.Api;
using WrestlingPlatform.Api.Hubs;
using WrestlingPlatform.Api.Services;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "PinPointArena";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "PinPointArenaClients";
var jwtSigningKeyRaw = builder.Configuration["Jwt:SigningKey"] ?? "CHANGE_ME_TO_A_LONG_RANDOM_KEY_32CHARS_MINIMUM_12345";
var jwtAccessTokenMinutes = int.TryParse(builder.Configuration["Jwt:AccessTokenMinutes"], out var configuredMinutes)
    ? configuredMinutes
    : 180;
var jwtRefreshTokenDays = int.TryParse(builder.Configuration["Jwt:RefreshTokenDays"], out var configuredRefreshDays)
    ? configuredRefreshDays
    : 14;
var stripeWebhookToleranceSeconds = int.TryParse(builder.Configuration["Payments:WebhookSignatureToleranceSeconds"], out var configuredToleranceSeconds)
    ? configuredToleranceSeconds
    : 300;
var mfaRequiredRoles = ResolveMfaRequiredRoles(builder.Configuration);

var signingKeyBytes = Encoding.UTF8.GetBytes(jwtSigningKeyRaw);
if (signingKeyBytes.Length < 32)
{
    throw new InvalidOperationException("JWT signing key must be at least 32 bytes.");
}

var jwtSigningKey = new SymmetricSecurityKey(signingKeyBytes);

builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi();
builder.Services.AddSignalR();
builder.Services.Configure<MediaPipelineOptions>(builder.Configuration.GetSection("MediaPipeline"));
builder.Services.Configure<RequestSecurityPolicyOptions>(builder.Configuration.GetSection("Security:RequestPolicy"));
builder.Services.AddHttpClient("media-pipeline").SetHandlerLifetime(TimeSpan.FromMinutes(15));
builder.Services.AddHttpClient("media-ai").SetHandlerLifetime(TimeSpan.FromMinutes(5));
builder.Services.AddSingleton<IMediaObjectStorage, MediaObjectStorage>();
builder.Services.AddSingleton<ILiveMatScoringService, LiveMatScoringService>();
builder.Services.AddSingleton<ITournamentControlService, TournamentControlService>();
builder.Services.AddSingleton<IMediaPipelineService, MediaPipelineService>();
builder.Services.AddSingleton<ISecurityAuditTrailService, SecurityAuditTrailService>();
builder.Services.AddSingleton<IMfaService, MfaService>();
builder.Services.AddHostedService<MediaPipelineWorker>();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("api-default", context =>
    {
        var key = context.User.Identity?.Name
                  ?? context.Connection.RemoteIpAddress?.ToString()
                  ?? "anonymous";

        return RateLimitPartition.GetTokenBucketLimiter(
            key,
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = 120,
                TokensPerPeriod = 120,
                ReplenishmentPeriod = TimeSpan.FromSeconds(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 30,
                AutoReplenishment = true
            });
    });

    options.AddFixedWindowLimiter("auth-strict", limiter =>
    {
        limiter.PermitLimit = 20;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
    });
});

var redisConfiguration = builder.Configuration["Redis:Configuration"];
if (string.IsNullOrWhiteSpace(redisConfiguration))
{
    builder.Services.AddDistributedMemoryCache();
}
else
{
    builder.Services.AddStackExchangeRedisCache(options => { options.Configuration = redisConfiguration; });
}

builder.Services
    .AddOpenTelemetry()
    .ConfigureResource(resource => resource.AddService("WrestlingPlatform.Api"))
    .WithTracing(tracing =>
    {
        tracing.AddAspNetCoreInstrumentation();
        tracing.AddHttpClientInstrumentation();
        tracing.AddEntityFrameworkCoreInstrumentation();

        var otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
        {
            tracing.AddOtlpExporter(options => { options.Endpoint = new Uri(otlpEndpoint); });
        }
    })
    .WithMetrics(metrics =>
    {
        metrics.AddAspNetCoreInstrumentation();
        metrics.AddHttpClientInstrumentation();
        metrics.AddRuntimeInstrumentation();

        var otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
        {
            metrics.AddOtlpExporter(options => { options.Endpoint = new Uri(otlpEndpoint); });
        }
    });

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = jwtSigningKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CoachOrAdmin", policy => policy.RequireRole(
        UserRole.Coach.ToString(),
        UserRole.ClubAdmin.ToString(),
        UserRole.SchoolAdmin.ToString(),
        UserRole.EventAdmin.ToString(),
        UserRole.SystemAdmin.ToString()));

    options.AddPolicy("EventOps", policy => policy.RequireRole(
        UserRole.Coach.ToString(),
        UserRole.ClubAdmin.ToString(),
        UserRole.SchoolAdmin.ToString(),
        UserRole.EventAdmin.ToString(),
        UserRole.SystemAdmin.ToString()));
});

builder.Services.AddWrestlingPlatformInfrastructure(builder.Configuration);

var app = builder.Build();

app.UseExceptionHandler();
app.UseMiddleware<RequestSecurityPolicyMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    await next();

    var auditTrail = context.RequestServices.GetRequiredService<ISecurityAuditTrailService>();
    var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var role = context.User.FindFirstValue(ClaimTypes.Role);

    auditTrail.Record(new SecurityAuditRecord(
        Guid.NewGuid(),
        DateTime.UtcNow,
        context.Request.Method,
        context.Request.Path,
        context.Response.StatusCode,
        userId,
        role,
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        context.Response.StatusCode < 400 ? "Success" : "Failure",
        context.TraceIdentifier));
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

await InitializeDatabaseWithRetryAsync(app.Services, app.Logger, CancellationToken.None);

app.MapGet("/healthz", async (WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    try
    {
        var canConnect = await dbContext.Database.CanConnectAsync(cancellationToken);
        if (!canConnect)
        {
            return Results.Problem(
                title: "Database connectivity check failed.",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        return Results.Ok(new
        {
            Status = "ok",
            Service = "api",
            Utc = DateTime.UtcNow
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(
            title: "Health check failed.",
            detail: ex.Message,
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).AllowAnonymous();

var api = app.MapGroup("/api").RequireRateLimiting("api-default");
app.MapHub<MatchOpsHub>("/hubs/match-ops");

var auth = api.MapGroup("/auth").RequireRateLimiting("auth-strict");

auth.MapPost("/login", async (
    LoginRequest request,
    WrestlingPlatformDbContext dbContext,
    IMfaService mfaService,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest("Email and password are required.");
    }


    var normalizedEmail = request.Email.Trim().ToLowerInvariant();
    var user = await dbContext.UserAccounts.FirstOrDefaultAsync(x => x.Email == normalizedEmail, cancellationToken);

    if (user is null || !user.IsActive || !ApiSecurityHelpers.VerifyPassword(request.Password, user.PasswordHash))
    {
        return Results.Unauthorized();
    }

    if (mfaRequiredRoles.Contains(user.Role))
    {
        if (!mfaService.IsEnabled(user.Id))
        {
            return Results.Problem(
                title: "MFA enrollment required.",
                detail: "This account role requires MFA enrollment before sign-in.",
                statusCode: StatusCodes.Status428PreconditionRequired);
        }

        var verification = mfaService.Verify(new VerifyMfaCodeRequest(user.Id, request.MfaCode ?? string.Empty));
        if (!verification.Verified)
        {
            return Results.Unauthorized();
        }
    }

    var token = await ApiSecurityHelpers.IssueAuthTokenAsync(user, dbContext, jwtSigningKey, jwtIssuer, jwtAudience, jwtAccessTokenMinutes, jwtRefreshTokenDays, cancellationToken);
    return Results.Ok(token);
}).AllowAnonymous();

auth.MapPost("/refresh", async (
    RefreshTokenRequest request,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        return Results.BadRequest("Refresh token is required.");
    }

    var refreshedToken = await ApiSecurityHelpers.TryRefreshAuthTokenAsync(
        request.RefreshToken.Trim(),
        dbContext,
        jwtSigningKey,
        jwtIssuer,
        jwtAudience,
        jwtAccessTokenMinutes,
        jwtRefreshTokenDays,
        cancellationToken);

    return refreshedToken is null ? Results.Unauthorized() : Results.Ok(refreshedToken);
}).AllowAnonymous();

auth.MapPost("/logout", async (
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var userId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await ApiSecurityHelpers.RevokeAllRefreshTokensForUserAsync(dbContext, userId.Value, "logout", cancellationToken);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Ok(new { Revoked = true });
}).RequireAuthorization();

auth.MapGet("/me", (HttpContext httpContext) =>
{
    var userIdRaw = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var email = httpContext.User.FindFirstValue(ClaimTypes.Email);
    var role = httpContext.User.FindFirstValue(ClaimTypes.Role);

    return Results.Ok(new
    {
        UserId = userIdRaw,
        Email = email,
        Role = role
    });
}).RequireAuthorization();

var users = api.MapGroup("/users");
users.MapPost("/register", async (
    RegisterUserRequest request,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest("Email and password are required.");
    }


    if (!ApiSecurityHelpers.IsPublicRegistrationRole(request.Role))
    {
        return Results.BadRequest("Self-registration is limited to Athlete, Coach, Parent, and Fan roles.");
    }
    var normalizedEmail = request.Email.Trim().ToLowerInvariant();
    var exists = await dbContext.UserAccounts.AnyAsync(x => x.Email == normalizedEmail, cancellationToken);
    if (exists)
    {
        return Results.Conflict("A user with this email already exists.");
    }

    var user = new UserAccount
    {
        Email = normalizedEmail,
        PasswordHash = ApiSecurityHelpers.HashPassword(request.Password),
        Role = request.Role,
        PhoneNumber = request.PhoneNumber
    };

    dbContext.UserAccounts.Add(user);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Email, user.Role });
});

users.MapGet("/{userId:guid}", async (Guid userId, HttpContext httpContext, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    if (!ApiSecurityHelpers.CanAccessUserResource(httpContext, userId))
    {
        return Results.Forbid();
    }
    var user = await dbContext.UserAccounts
        .Where(x => x.Id == userId)
        .Select(x => new { x.Id, x.Email, x.Role, x.PhoneNumber, x.IsActive, x.CreatedUtc })
        .FirstOrDefaultAsync(cancellationToken);

    return user is null ? Results.NotFound() : Results.Ok(user);
}).RequireAuthorization();

var profiles = api.MapGroup("/profiles").RequireAuthorization();
profiles.MapPost("/athletes", async (
    CreateAthleteProfileRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (!ApiSecurityHelpers.CanAccessUserResource(httpContext, request.UserAccountId))
    {
        return Results.Forbid();
    }
    var user = await dbContext.UserAccounts.FirstOrDefaultAsync(x => x.Id == request.UserAccountId, cancellationToken);
    if (user is null)
    {
        return Results.BadRequest("User does not exist.");
    }

    var profileExists = await dbContext.AthleteProfiles.AnyAsync(x => x.UserAccountId == request.UserAccountId, cancellationToken);
    if (profileExists)
    {
        return Results.Conflict("Athlete profile already exists for this user.");
    }

    var profile = new AthleteProfile
    {
        UserAccountId = request.UserAccountId,
        FirstName = request.FirstName.Trim(),
        LastName = request.LastName.Trim(),
        DateOfBirthUtc = request.DateOfBirthUtc,
        State = request.State.Trim().ToUpperInvariant(),
        City = request.City.Trim(),
        SchoolOrClubName = request.SchoolOrClubName?.Trim(),
        Grade = request.Grade,
        WeightClass = request.WeightClass,
        Level = request.Level
    };

    dbContext.AthleteProfiles.Add(profile);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/profiles/athletes/{profile.Id}", profile);
});

profiles.MapPost("/coaches", async (
    CreateCoachProfileRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (!ApiSecurityHelpers.CanAccessUserResource(httpContext, request.UserAccountId))
    {
        return Results.Forbid();
    }

    var user = await dbContext.UserAccounts.FirstOrDefaultAsync(x => x.Id == request.UserAccountId, cancellationToken);
    if (user is null)
    {
        return Results.BadRequest("User does not exist.");
    }

    var profileExists = await dbContext.CoachProfiles.AnyAsync(x => x.UserAccountId == request.UserAccountId, cancellationToken);
    if (profileExists)
    {
        return Results.Conflict("Coach profile already exists for this user.");
    }

    var profile = new CoachProfile
    {
        UserAccountId = request.UserAccountId,
        FirstName = request.FirstName.Trim(),
        LastName = request.LastName.Trim(),
        State = request.State.Trim().ToUpperInvariant(),
        City = request.City.Trim(),
        Bio = request.Bio?.Trim()
    };

    dbContext.CoachProfiles.Add(profile);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/profiles/coaches/{profile.Id}", profile);
});

var teams = api.MapGroup("/teams").RequireAuthorization("CoachOrAdmin");
teams.MapPost("", async (CreateTeamRequest request, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Name))
    {
        return Results.BadRequest("Team name is required.");
    }

    var team = new Team
    {
        Name = request.Name.Trim(),
        Type = request.Type,
        State = request.State.Trim().ToUpperInvariant(),
        City = request.City.Trim()
    };

    dbContext.Teams.Add(team);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/teams/{team.Id}", team);
});

var coaches = api.MapGroup("/coaches").RequireAuthorization("CoachOrAdmin");
coaches.MapPost("/{coachProfileId:guid}/associations", async (
    Guid coachProfileId,
    CreateCoachAssociationRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var canManageCoach = await ApiSecurityHelpers.CanManageCoachProfileAsync(dbContext, httpContext.User, coachProfileId, cancellationToken);
    if (!canManageCoach)
    {
        return Results.Forbid();
    }

    var coachExists = await dbContext.CoachProfiles.AnyAsync(x => x.Id == coachProfileId, cancellationToken);
    if (!coachExists)
    {
        return Results.NotFound("Coach profile not found.");
    }

    if (request.AthleteProfileId is not null)
    {
        var athleteExists = await dbContext.AthleteProfiles.AnyAsync(x => x.Id == request.AthleteProfileId, cancellationToken);
        if (!athleteExists)
        {
            return Results.BadRequest("Athlete profile not found.");
        }
    }

    if (request.TeamId is not null)
    {
        var teamExists = await dbContext.Teams.AnyAsync(x => x.Id == request.TeamId, cancellationToken);
        if (!teamExists)
        {
            return Results.BadRequest("Team not found.");
        }
    }

    var association = new CoachAssociation
    {
        CoachProfileId = coachProfileId,
        AthleteProfileId = request.AthleteProfileId,
        TeamId = request.TeamId,
        RoleTitle = request.RoleTitle.Trim(),
        IsPrimary = request.IsPrimary,
        ApprovedUtc = DateTime.UtcNow
    };

    dbContext.CoachAssociations.Add(association);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/coaches/{coachProfileId}/associations/{association.Id}", association);
});

var events = api.MapGroup("/events").RequireAuthorization();
events.MapPost("", async (CreateTournamentEventRequest request, HttpContext httpContext, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    if (request.EndUtc < request.StartUtc)
    {
        return Results.BadRequest("End date must be after start date.");
    }

    var organizerExists = request.OrganizerType switch
    {
        OrganizerType.School or OrganizerType.Club => await dbContext.Teams.AnyAsync(x => x.Id == request.OrganizerId, cancellationToken),
        OrganizerType.Coach => await dbContext.CoachProfiles.AnyAsync(x => x.Id == request.OrganizerId, cancellationToken),
        OrganizerType.Independent => true,
        _ => false
    };

    if (!organizerExists)
    {
        return Results.BadRequest("Organizer was not found for the specified organizer type.");
    }

    if (request.OrganizerType == OrganizerType.Coach)
    {
        var canManageCoach = await ApiSecurityHelpers.CanManageCoachProfileAsync(dbContext, httpContext.User, request.OrganizerId, cancellationToken);
        if (!canManageCoach)
        {
            return Results.Forbid();
        }
    }

    var tournamentEvent = new TournamentEvent
    {
        Name = request.Name.Trim(),
        OrganizerType = request.OrganizerType,
        OrganizerId = request.OrganizerId,
        State = request.State.Trim().ToUpperInvariant(),
        City = request.City.Trim(),
        Venue = request.Venue.Trim(),
        StartUtc = request.StartUtc,
        EndUtc = request.EndUtc,
        EntryFeeCents = request.EntryFeeCents,
        IsPublished = request.IsPublished
    };

    dbContext.TournamentEvents.Add(tournamentEvent);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/events/{tournamentEvent.Id}", tournamentEvent);
}).RequireAuthorization("EventOps");

events.MapPost("/{eventId:guid}/divisions", async (
    Guid eventId,
    CreateTournamentDivisionRequest request,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var division = new TournamentDivision
    {
        TournamentEventId = eventId,
        Name = request.Name.Trim(),
        Level = request.Level,
        WeightClass = request.WeightClass
    };

    dbContext.TournamentDivisions.Add(division);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/events/{eventId}/divisions/{division.Id}", division);
}).RequireAuthorization("EventOps");

events.MapGet("/search", async (
    [FromQuery] string? state,
    [FromQuery] string? city,
    [FromQuery] CompetitionLevel? level,
    [FromQuery] DateTime? startsOnOrAfterUtc,
    [FromQuery] DateTime? startsOnOrBeforeUtc,
    [FromQuery] int? maxEntryFeeCents,
    IDistributedCache cache,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var searchCacheKey = BuildCacheKey(
        "events:search:v1",
        ("state", state?.Trim().ToUpperInvariant()),
        ("city", city?.Trim()),
        ("level", level?.ToString()),
        ("from", startsOnOrAfterUtc?.ToString("O")),
        ("to", startsOnOrBeforeUtc?.ToString("O")),
        ("maxFee", maxEntryFeeCents?.ToString()));

    var cachedSearch = await TryGetCachedResponseAsync(cache, searchCacheKey, cancellationToken);
    if (cachedSearch is not null)
    {
        return Results.Content(cachedSearch, "application/json");
    }

    var query = dbContext.TournamentEvents.AsNoTracking().AsQueryable();

    if (!string.IsNullOrWhiteSpace(state))
    {
        var stateTrimmed = state.Trim().ToUpperInvariant();
        query = query.Where(x => x.State == stateTrimmed);
    }

    if (!string.IsNullOrWhiteSpace(city))
    {
        var cityTrimmed = city.Trim();
        query = query.Where(x => x.City == cityTrimmed);
    }

    if (startsOnOrAfterUtc is not null)
    {
        query = query.Where(x => x.StartUtc >= startsOnOrAfterUtc.Value);
    }

    if (startsOnOrBeforeUtc is not null)
    {
        query = query.Where(x => x.StartUtc <= startsOnOrBeforeUtc.Value);
    }

    if (maxEntryFeeCents is not null)
    {
        query = query.Where(x => x.EntryFeeCents <= maxEntryFeeCents.Value);
    }

    if (level is not null)
    {
        query =
            from tournamentEvent in query
            join division in dbContext.TournamentDivisions on tournamentEvent.Id equals division.TournamentEventId
            where division.Level == level.Value
            select tournamentEvent;
    }

    query = query.Distinct();

    var result = await query
        .OrderBy(x => x.State)
        .ThenBy(x => x.City)
        .ThenBy(x => x.StartUtc)
        .Take(200)
        .ToListAsync(cancellationToken);

    await SetCachedResponseAsync(cache, searchCacheKey, result, TimeSpan.FromSeconds(30), cancellationToken);
    return Results.Ok(result);
}).AllowAnonymous();

events.MapGet("/grouped", async (IDistributedCache cache, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    const string groupedCacheKey = "events:grouped:v1";
    var cachedGrouped = await TryGetCachedResponseAsync(cache, groupedCacheKey, cancellationToken);
    if (cachedGrouped is not null)
    {
        return Results.Content(cachedGrouped, "application/json");
    }

    var allEvents = await dbContext.TournamentEvents
        .AsNoTracking()
        .OrderBy(x => x.State)
        .ThenBy(x => x.City)
        .ThenBy(x => x.StartUtc)
        .ToListAsync(cancellationToken);

    var grouped = allEvents
        .GroupBy(x => new { x.State, x.City })
        .Select(x => new
        {
            x.Key.State,
            x.Key.City,
            Events = x.Select(e => new
            {
                e.Id,
                e.Name,
                e.StartUtc,
                e.EndUtc,
                e.EntryFeeCents,
                e.Venue
            }).ToList()
        })
        .ToList();

    await SetCachedResponseAsync(cache, groupedCacheKey, grouped, TimeSpan.FromSeconds(30), cancellationToken);
    return Results.Ok(grouped);
}).AllowAnonymous();

events.MapGet("/{eventId:guid}/controls", async (
    Guid eventId,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    return Results.Ok(tournamentControlService.GetOrCreate(eventId, registrantCount));
});

events.MapPut("/{eventId:guid}/controls", async (
    Guid eventId,
    UpdateTournamentControlSettingsRequest request,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    try
    {
        var updated = tournamentControlService.Update(eventId, registrantCount, request);
        return Results.Ok(updated);
    }
    catch (ArgumentOutOfRangeException ex)
    {
        return Results.BadRequest(ex.Message);
    }
}).RequireAuthorization("EventOps");

events.MapPost("/{eventId:guid}/controls/release-brackets", async (
    Guid eventId,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    var updated = tournamentControlService.ReleaseBrackets(eventId, registrantCount);
    return Results.Ok(updated);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/directory", async (
    Guid eventId,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var tournamentEvent = await dbContext.TournamentEvents.AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == eventId, cancellationToken);

    if (tournamentEvent is null)
    {
        return Results.NotFound("Event not found.");
    }

    var divisions = await dbContext.TournamentDivisions.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .OrderBy(x => x.Level)
        .ThenBy(x => x.WeightClass)
        .ToListAsync(cancellationToken);

    var registrations = await dbContext.EventRegistrations.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled)
        .ToListAsync(cancellationToken);

    var athletesById = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x => registrations.Select(r => r.AthleteProfileId).Contains(x.Id))
        .ToDictionaryAsync(x => x.Id, cancellationToken);

    var registrantCount = registrations.Count;
    var controls = tournamentControlService.GetOrCreate(eventId, registrantCount);

    var divisionRows = divisions.Select(division =>
    {
        var count = registrations.Count(reg =>
            athletesById.TryGetValue(reg.AthleteProfileId, out var athlete)
            && athlete.Level == division.Level
            && athlete.WeightClass == division.WeightClass);

        return new TournamentDivisionDirectoryRow(
            division.Id,
            division.Name,
            division.Level,
            ResolveAgeGroupLabel(division.Level),
            division.WeightClass,
            count,
            controls.RegistrationCapEnabled ? controls.RegistrationCap : null,
            InferDivisionStyle(division),
            controls.TournamentFormat);
    }).ToList();

    var row = new TournamentDirectoryRow(
        tournamentEvent.Id,
        tournamentEvent.Name,
        tournamentEvent.State,
        tournamentEvent.City,
        tournamentEvent.Venue,
        tournamentEvent.StartUtc,
        tournamentEvent.EndUtc,
        tournamentEvent.EntryFeeCents,
        controls,
        divisionRows);

    return Results.Ok(row);
}).AllowAnonymous();

events.MapGet("/{eventId:guid}/mats", async (
    Guid eventId,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var tournamentEvent = await dbContext.TournamentEvents.AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == eventId, cancellationToken);

    if (tournamentEvent is null)
    {
        return Results.NotFound("Event not found.");
    }

    var brackets = await dbContext.Brackets.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .ToListAsync(cancellationToken);

    var bracketIds = brackets.Select(x => x.Id).ToList();
    if (bracketIds.Count == 0)
    {
        var controlsEmpty = tournamentControlService.GetOrCreate(eventId, 0);
        return Results.Ok(new TableWorkerEventBoard(
            eventId,
            tournamentEvent.Name,
            WrestlingStyle.Folkstyle,
            controlsEmpty,
            []));
    }

    var matches = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .OrderBy(x => x.MatNumber)
        .ThenBy(x => x.Round)
        .ThenBy(x => x.MatchNumber)
        .ToListAsync(cancellationToken);

    var athleteIds = matches
        .SelectMany(x => new[] { x.AthleteAId, x.AthleteBId })
        .Where(x => x is not null)
        .Select(x => x!.Value)
        .Distinct()
        .ToList();

    var athletes = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x => athleteIds.Contains(x.Id))
        .ToDictionaryAsync(x => x.Id, cancellationToken);

    var currentRegistrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    var controls = tournamentControlService.GetOrCreate(eventId, currentRegistrantCount);
    var eventStyle = InferEventStyle(matches, brackets);
    var mats = matches
        .GroupBy(x => string.IsNullOrWhiteSpace(x.MatNumber) ? "Unassigned" : x.MatNumber!.Trim())
        .OrderBy(x => x.Key == "Unassigned" ? 1 : 0)
        .ThenBy(x => x.Key)
        .Select(group =>
        {
            var rows = group.Select(match =>
                new TableWorkerMatchSummary(
                    match.Id,
                    match.Round,
                    match.MatchNumber,
                    match.Status,
                    match.AthleteAId,
                    match.AthleteBId,
                    BuildAthleteLabel(match.AthleteAId, athletes),
                    BuildAthleteLabel(match.AthleteBId, athletes),
                    match.Score,
                    match.ResultMethod,
                    match.ScheduledUtc)).ToList();

            return new TableWorkerMatSummary(
                group.Key,
                rows.Count(x => x.Status == MatchStatus.Scheduled),
                rows.Count(x => x.Status == MatchStatus.InTheHole),
                rows.Count(x => x.Status == MatchStatus.OnMat),
                rows.Count(x => x.Status == MatchStatus.Completed),
                rows);
        })
        .ToList();

    return Results.Ok(new TableWorkerEventBoard(
        eventId,
        tournamentEvent.Name,
        eventStyle,
        controls,
        mats));
}).AllowAnonymous();

events.MapGet("/{eventId:guid}/brackets/visual", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var tournamentEvent = await dbContext.TournamentEvents.AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == eventId, cancellationToken);

    if (tournamentEvent is null)
    {
        return Results.NotFound("Event not found.");
    }

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);
    var controls = tournamentControlService.GetOrCreate(eventId, registrantCount);
    var released = tournamentControlService.AreBracketsReleased(eventId, DateTime.UtcNow);

    if (!released && !ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User))
    {
        return Results.Forbid();
    }

    var bracketRows = await dbContext.Brackets.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .ToListAsync(cancellationToken);

    var bracketIds = bracketRows.Select(x => x.Id).ToList();
    var entryRows = await dbContext.BracketEntries.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .OrderBy(x => x.Seed)
        .ToListAsync(cancellationToken);
    var matchRows = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .OrderBy(x => x.Round)
        .ThenBy(x => x.MatchNumber)
        .ToListAsync(cancellationToken);

    var athleteIds = entryRows.Select(x => x.AthleteProfileId)
        .Concat(matchRows.SelectMany(x => new[] { x.AthleteAId, x.AthleteBId, x.WinnerAthleteId }.Where(id => id is not null).Select(id => id!.Value)))
        .Distinct()
        .ToList();

    var athletesById = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x => athleteIds.Contains(x.Id))
        .ToDictionaryAsync(x => x.Id, cancellationToken);

    var rankings = await dbContext.AthleteRankings.AsNoTracking()
        .Where(x => athleteIds.Contains(x.AthleteProfileId))
        .GroupBy(x => x.AthleteProfileId)
        .Select(group => group.OrderBy(r => r.SnapshotUtc).First())
        .ToDictionaryAsync(x => x.AthleteProfileId, cancellationToken);

    BracketVisualAthlete? ToAthlete(Guid? athleteId, Guid bracketId)
    {
        if (athleteId is null || !athletesById.TryGetValue(athleteId.Value, out var athlete))
        {
            return null;
        }

        var seed = entryRows
            .Where(x => x.BracketId == bracketId && x.AthleteProfileId == athleteId.Value)
            .Select(x => x.Seed)
            .FirstOrDefault();

        var ranking = rankings.GetValueOrDefault(athleteId.Value);
        var rank = ranking?.Rank ?? 999;
        var rating = ranking?.RatingPoints ?? 1200m;

        return new BracketVisualAthlete(
            athlete.Id,
            $"{athlete.FirstName} {athlete.LastName}",
            athlete.Level,
            athlete.WeightClass,
            seed,
            rank,
            rating);
    }

    var visualMatches = matchRows.Select(match =>
    {
        var bracket = bracketRows.First(x => x.Id == match.BracketId);
        var athleteA = ToAthlete(match.AthleteAId, match.BracketId);
        var athleteB = ToAthlete(match.AthleteBId, match.BracketId);
        var winner = ToAthlete(match.WinnerAthleteId, match.BracketId);

        return new BracketVisualMatch(
            match.Id,
            match.Round,
            match.MatchNumber,
            $"{bracket.Level} {bracket.WeightClass:0.##} - Round {match.Round}",
            match.Status,
            athleteA,
            athleteB,
            winner,
            match.Score,
            match.ResultMethod,
            match.MatNumber);
    }).ToList();

    var pools = new List<PoolVisualGroup>();
    if (controls.TournamentFormat == TournamentFormat.MadisonPool)
    {
        foreach (var bracket in bracketRows)
        {
            var bracketEntries = entryRows.Where(x => x.BracketId == bracket.Id).ToList();
            if (bracketEntries.Count == 0)
            {
                continue;
            }

            var bracketMatches = visualMatches
                .Where(x => x.Label.Contains($"Round", StringComparison.OrdinalIgnoreCase) && matchRows.Any(m => m.Id == x.MatchId && m.BracketId == bracket.Id))
                .ToList();

            var standingMap = new Dictionary<Guid, PoolStanding>();
            foreach (var entry in bracketEntries)
            {
                if (!athletesById.TryGetValue(entry.AthleteProfileId, out var athlete))
                {
                    continue;
                }

                standingMap[entry.AthleteProfileId] = new PoolStanding(
                    athlete.Id,
                    $"{athlete.FirstName} {athlete.LastName}",
                    0,
                    0,
                    0,
                    0,
                    0);
            }

            foreach (var match in matchRows.Where(x => x.BracketId == bracket.Id && x.Status == MatchStatus.Completed))
            {
                if (match.AthleteAId is null || match.AthleteBId is null)
                {
                    continue;
                }

                var (aScore, bScore) = ParseScore(match.Score);
                if (standingMap.TryGetValue(match.AthleteAId.Value, out var aStanding))
                {
                    standingMap[match.AthleteAId.Value] = aStanding with
                    {
                        Wins = aStanding.Wins + (match.WinnerAthleteId == match.AthleteAId ? 1 : 0),
                        Losses = aStanding.Losses + (match.WinnerAthleteId == match.AthleteAId ? 0 : 1),
                        PointsFor = aStanding.PointsFor + aScore,
                        PointsAgainst = aStanding.PointsAgainst + bScore,
                        Differential = (aStanding.PointsFor + aScore) - (aStanding.PointsAgainst + bScore)
                    };
                }

                if (standingMap.TryGetValue(match.AthleteBId.Value, out var bStanding))
                {
                    standingMap[match.AthleteBId.Value] = bStanding with
                    {
                        Wins = bStanding.Wins + (match.WinnerAthleteId == match.AthleteBId ? 1 : 0),
                        Losses = bStanding.Losses + (match.WinnerAthleteId == match.AthleteBId ? 0 : 1),
                        PointsFor = bStanding.PointsFor + bScore,
                        PointsAgainst = bStanding.PointsAgainst + aScore,
                        Differential = (bStanding.PointsFor + bScore) - (bStanding.PointsAgainst + aScore)
                    };
                }
            }

            var standings = standingMap.Values
                .OrderByDescending(x => x.Wins)
                .ThenByDescending(x => x.Differential)
                .ThenByDescending(x => x.PointsFor)
                .ThenBy(x => x.AthleteName)
                .ToList();

            pools.Add(new PoolVisualGroup(
                $"Pool {bracket.Level} {bracket.WeightClass:0.##}",
                bracket.Level,
                bracket.WeightClass,
                InferStyleForLevel(bracket.Level),
                bracketMatches,
                standings));
        }
    }

    var bundle = new TournamentBracketVisualBundle(
        eventId,
        tournamentEvent.Name,
        controls.TournamentFormat,
        released,
        visualMatches,
        pools);

    return Results.Ok(bundle);
}).AllowAnonymous();

events.MapPost("/{eventId:guid}/registrations", async (
    Guid eventId,
    RegisterForEventRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    IPaymentGateway paymentGateway,
    CancellationToken cancellationToken) =>
{
    var canManageAthlete = await ApiSecurityHelpers.CanManageAthleteProfileAsync(dbContext, httpContext.User, request.AthleteProfileId, cancellationToken);
    if (!canManageAthlete)
    {
        return Results.Forbid();
    }

    if (request.TeamId is not null && !ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User))
    {
        return Results.Forbid();
    }

    var tournamentEvent = await dbContext.TournamentEvents.FirstOrDefaultAsync(x => x.Id == eventId, cancellationToken);
    if (tournamentEvent is null)
    {
        return Results.NotFound("Event not found.");
    }

    var athleteExists = await dbContext.AthleteProfiles.AnyAsync(x => x.Id == request.AthleteProfileId, cancellationToken);
    if (!athleteExists)
    {
        return Results.BadRequest("Athlete profile not found.");
    }

    if (request.TeamId is not null)
    {
        var teamExists = await dbContext.Teams.AnyAsync(x => x.Id == request.TeamId, cancellationToken);
        if (!teamExists)
        {
            return Results.BadRequest("Team not found.");
        }
    }

    var currentRegistrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    if (!tournamentControlService.CanRegister(eventId, currentRegistrantCount, out var capReason))
    {
        return Results.BadRequest(capReason);
    }

    var alreadyRegistered = await dbContext.EventRegistrations
        .AnyAsync(x => x.TournamentEventId == eventId && x.AthleteProfileId == request.AthleteProfileId, cancellationToken);

    if (alreadyRegistered)
    {
        return Results.Conflict("Athlete is already registered for this event.");
    }

    var registration = new EventRegistration
    {
        TournamentEventId = eventId,
        AthleteProfileId = request.AthleteProfileId,
        TeamId = request.TeamId,
        IsFreeAgent = request.IsFreeAgent,
        Status = RegistrationStatus.Confirmed,
        PaymentStatus = tournamentEvent.EntryFeeCents > 0 ? PaymentStatus.Pending : PaymentStatus.NotRequired,
        PaidAmountCents = 0
    };

    dbContext.EventRegistrations.Add(registration);
    await dbContext.SaveChangesAsync(cancellationToken);

    if (tournamentEvent.EntryFeeCents <= 0)
    {
        return Results.Created($"/api/events/{eventId}/registrations/{registration.Id}", registration);
    }

    var paymentIntent = await paymentGateway.CreatePaymentIntentAsync(registration, tournamentEvent, cancellationToken);
    registration.PaymentReference = paymentIntent.ProviderReference;
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/events/{eventId}/registrations/{registration.Id}", new
    {
        Registration = registration,
        PaymentIntent = paymentIntent
    });
});

events.MapGet("/{eventId:guid}/free-agents", async (Guid eventId, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    var freeAgents = await (
            from registration in dbContext.EventRegistrations
            join athlete in dbContext.AthleteProfiles on registration.AthleteProfileId equals athlete.Id
            where registration.TournamentEventId == eventId && registration.IsFreeAgent
            select new
            {
                registration.Id,
                AthleteId = athlete.Id,
                athlete.FirstName,
                athlete.LastName,
                athlete.Level,
                athlete.WeightClass,
                athlete.State,
                athlete.City,
                registration.Status
            })
        .OrderBy(x => x.Level)
        .ThenBy(x => x.WeightClass)
        .ToListAsync(cancellationToken);

    return Results.Ok(freeAgents);
});

events.MapPost("/{eventId:guid}/free-agents/{registrationId:guid}/invite", async (
    Guid eventId,
    Guid registrationId,
    TeamInviteFreeAgentRequest request,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var registration = await dbContext.EventRegistrations
        .FirstOrDefaultAsync(x => x.Id == registrationId && x.TournamentEventId == eventId, cancellationToken);

    if (registration is null || !registration.IsFreeAgent)
    {
        return Results.NotFound("Free-agent registration not found.");
    }

    var teamExists = await dbContext.Teams.AnyAsync(x => x.Id == request.TeamId, cancellationToken);
    if (!teamExists)
    {
        return Results.BadRequest("Team not found.");
    }

    var invite = new FreeAgentTeamInvite
    {
        EventRegistrationId = registrationId,
        TeamId = request.TeamId,
        Message = request.Message?.Trim(),
        Accepted = false
    };

    dbContext.FreeAgentTeamInvites.Add(invite);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/events/{eventId}/free-agents/{registrationId}/invite/{invite.Id}", invite);
}).RequireAuthorization("CoachOrAdmin");

var registrations = api.MapGroup("/registrations").RequireAuthorization();
registrations.MapPost("/{registrationId:guid}/payments/confirm", async (
    Guid registrationId,
    ConfirmRegistrationPaymentRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (registrationId != request.RegistrationId)
    {
        return Results.BadRequest("Registration id mismatch.");
    }

    var registration = await dbContext.EventRegistrations.FirstOrDefaultAsync(x => x.Id == registrationId, cancellationToken);
    if (registration is null)
    {
        return Results.NotFound("Registration not found.");
    }

    if (!ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User))
    {
        var canManageAthlete = await ApiSecurityHelpers.CanManageAthleteProfileAsync(dbContext, httpContext.User, registration.AthleteProfileId, cancellationToken);
        if (!canManageAthlete)
        {
            return Results.Forbid();
        }
    }

    registration.PaymentStatus = PaymentStatus.Paid;
    registration.PaidAmountCents = await dbContext.TournamentEvents
        .Where(x => x.Id == registration.TournamentEventId)
        .Select(x => x.EntryFeeCents)
        .FirstOrDefaultAsync(cancellationToken);
    registration.PaymentReference = request.ProviderReference;

    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Ok(registration);
});

events.MapPost("/{eventId:guid}/brackets/generate", async (
    Guid eventId,
    GenerateBracketRequest request,
    ITournamentControlService tournamentControlService,
    IBracketService bracketService,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var mode = request.Mode == BracketGenerationMode.Manual
        ? tournamentControlService.ResolveGenerationMode(eventId, request.Mode)
        : request.Mode;

    var result = await bracketService.GenerateAsync(
        new BracketGenerationInput(eventId, request.Level, request.WeightClass, mode, request.DivisionId),
        cancellationToken);

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);
    tournamentControlService.GetOrCreate(eventId, registrantCount);

    return Results.Ok(result);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/brackets", async (
    Guid eventId,
    HttpContext httpContext,
    IDistributedCache cache,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var bracketsCacheKey = BuildCacheKey("events:brackets:v1", ("eventId", eventId.ToString("N")));
    var cachedBrackets = await TryGetCachedResponseAsync(cache, bracketsCacheKey, cancellationToken);
    if (cachedBrackets is not null)
    {
        return Results.Content(cachedBrackets, "application/json");
    }

    var bracketRows = await dbContext.Brackets
        .AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .OrderBy(x => x.Level)
        .ThenBy(x => x.WeightClass)
        .ToListAsync(cancellationToken);

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    var controls = tournamentControlService.GetOrCreate(eventId, registrantCount);
    if (!tournamentControlService.AreBracketsReleased(eventId, DateTime.UtcNow)
        && !ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User))
    {
        return Results.Ok(Array.Empty<object>());
    }

    var bracketIds = bracketRows.Select(x => x.Id).ToList();

    var entryRows = await dbContext.BracketEntries
        .AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .OrderBy(x => x.Seed)
        .ToListAsync(cancellationToken);

    var matchRows = await dbContext.Matches
        .AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .OrderBy(x => x.Round)
        .ThenBy(x => x.MatchNumber)
        .ToListAsync(cancellationToken);

    var result = bracketRows.Select(bracket => new
    {
        Bracket = bracket,
        Entrants = entryRows.Where(x => x.BracketId == bracket.Id).ToList(),
        Matches = matchRows.Where(x => x.BracketId == bracket.Id).ToList(),
        Controls = controls
    });

    await SetCachedResponseAsync(cache, bracketsCacheKey, result, TimeSpan.FromSeconds(20), cancellationToken);
    return Results.Ok(result);
}).AllowAnonymous();

api.MapGet("/table-worker/events", async (
    [FromQuery] string? state,
    [FromQuery] int? daysAhead,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var safeDaysAhead = daysAhead is null or < 1 or > 365 ? 30 : daysAhead.Value;
    var windowStart = DateTime.UtcNow.Date.AddDays(-1);
    var windowEnd = DateTime.UtcNow.Date.AddDays(safeDaysAhead);

    var query = dbContext.TournamentEvents.AsNoTracking()
        .Where(x => x.StartUtc >= windowStart && x.StartUtc <= windowEnd);

    if (!string.IsNullOrWhiteSpace(state))
    {
        var normalizedState = state.Trim().ToUpperInvariant();
        query = query.Where(x => x.State == normalizedState);
    }

    var eventsInWindow = await query
        .OrderBy(x => x.StartUtc)
        .Take(200)
        .ToListAsync(cancellationToken);

    var eventIds = eventsInWindow.Select(x => x.Id).ToList();
    var brackets = await dbContext.Brackets.AsNoTracking()
        .Where(x => eventIds.Contains(x.TournamentEventId))
        .ToListAsync(cancellationToken);
    var bracketIds = brackets.Select(x => x.Id).ToList();
    var matches = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .ToListAsync(cancellationToken);

    var output = new List<TableWorkerEventSummary>();
    foreach (var evt in eventsInWindow)
    {
        var eventBrackets = brackets.Where(x => x.TournamentEventId == evt.Id).ToList();
        var eventBracketIds = eventBrackets.Select(x => x.Id).ToHashSet();
        var eventMatches = matches.Where(x => eventBracketIds.Contains(x.BracketId)).ToList();
        var registrantCount = await dbContext.EventRegistrations
            .CountAsync(x => x.TournamentEventId == evt.Id && x.Status != RegistrationStatus.Cancelled, cancellationToken);
        tournamentControlService.GetOrCreate(evt.Id, registrantCount);

        output.Add(new TableWorkerEventSummary(
            evt.Id,
            evt.Name,
            evt.State,
            evt.City,
            evt.Venue,
            evt.StartUtc,
            InferEventStyle(eventMatches, eventBrackets),
            eventMatches.Select(x => string.IsNullOrWhiteSpace(x.MatNumber) ? "Unassigned" : x.MatNumber!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            eventMatches.Count(x => x.Status is MatchStatus.InTheHole or MatchStatus.OnMat or MatchStatus.Scheduled)));
    }

    return Results.Ok(output);
}).AllowAnonymous();

var matches = api.MapGroup("/matches").RequireAuthorization("EventOps");
matches.MapPost("/{matchId:guid}/assign-mat", async (
    Guid matchId,
    AssignMatRequest request,
    WrestlingPlatformDbContext dbContext,
    INotificationDispatcher notificationDispatcher,
    IHubContext<MatchOpsHub> hubContext,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    var tournamentEventId = await dbContext.Brackets
        .Where(x => x.Id == match.BracketId)
        .Select(x => x.TournamentEventId)
        .FirstOrDefaultAsync(cancellationToken);

    match.MatNumber = request.MatNumber.Trim();
    match.ScheduledUtc = request.ScheduledUtc;
    match.Status = request.MarkInTheHole ? MatchStatus.InTheHole : MatchStatus.Scheduled;

    await dbContext.SaveChangesAsync(cancellationToken);

    var athleteIds = new[] { match.AthleteAId, match.AthleteBId }
        .Where(x => x is not null)
        .Select(x => x!.Value)
        .ToArray();

    var eventType = request.MarkInTheHole ? NotificationEventType.InTheHole : NotificationEventType.MatAssignment;
    var message = request.MarkInTheHole
        ? $"You are in-the-hole on mat {match.MatNumber}."
        : $"Your match was assigned to mat {match.MatNumber}.";

    foreach (var athleteId in athleteIds)
    {
        await notificationDispatcher.DispatchAsync(
            new NotificationDispatchRequest(tournamentEventId, match.Id, athleteId, eventType, message),
            cancellationToken);
    }

    if (tournamentEventId != Guid.Empty)
    {
        var liveUpdate = new
        {
            MatchId = match.Id,
            EventId = tournamentEventId,
            match.Status,
            match.MatNumber,
            match.ScheduledUtc,
            Message = message,
            UpdatedUtc = DateTime.UtcNow
        };

        await hubContext.Clients.Group(MatchOpsHubGroups.ForEvent(tournamentEventId))
            .SendAsync("matchStatusUpdated", liveUpdate, cancellationToken);
        await hubContext.Clients.Group(MatchOpsHubGroups.ForMatch(match.Id))
            .SendAsync("matchStatusUpdated", liveUpdate, cancellationToken);
    }

    return Results.Ok(match);
});

matches.MapPost("/{matchId:guid}/result", async (
    Guid matchId,
    RecordMatchResultRequest request,
    WrestlingPlatformDbContext dbContext,
    IRankingService rankingService,
    INotificationDispatcher notificationDispatcher,
    IHubContext<MatchOpsHub> hubContext,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    if (match.AthleteAId != request.WinnerAthleteId && match.AthleteBId != request.WinnerAthleteId)
    {
        return Results.BadRequest("Winner must be one of the athletes in the match.");
    }

    var tournamentEventId = await dbContext.Brackets
        .Where(x => x.Id == match.BracketId)
        .Select(x => x.TournamentEventId)
        .FirstOrDefaultAsync(cancellationToken);

    match.WinnerAthleteId = request.WinnerAthleteId;
    match.Score = request.Score.Trim();
    match.ResultMethod = request.ResultMethod.Trim();
    match.Status = MatchStatus.Completed;
    match.CompletedUtc = DateTime.UtcNow;

    await rankingService.ApplyMatchResultAsync(
        match,
        request.WinnerAthleteId,
        request.PointsForWinner,
        request.PointsForLoser,
        cancellationToken);

    await AdvanceBracketProgressionAsync(dbContext, match.BracketId, cancellationToken);
    await dbContext.SaveChangesAsync(cancellationToken);

    var outcomeMessage = $"Match {match.MatchNumber} final: {request.Score} via {request.ResultMethod}.";
    foreach (var athleteId in new[] { match.AthleteAId, match.AthleteBId }.Where(x => x is not null).Select(x => x!.Value))
    {
        await notificationDispatcher.DispatchAsync(
            new NotificationDispatchRequest(tournamentEventId, match.Id, athleteId, NotificationEventType.MatchResult, outcomeMessage),
            cancellationToken);
    }

    if (tournamentEventId != Guid.Empty)
    {
        var liveUpdate = new
        {
            MatchId = match.Id,
            EventId = tournamentEventId,
            match.Status,
            match.Score,
            match.ResultMethod,
            match.WinnerAthleteId,
            Message = outcomeMessage,
            UpdatedUtc = DateTime.UtcNow
        };

        await hubContext.Clients.Group(MatchOpsHubGroups.ForEvent(tournamentEventId))
            .SendAsync("matchStatusUpdated", liveUpdate, cancellationToken);
        await hubContext.Clients.Group(MatchOpsHubGroups.ForMatch(match.Id))
            .SendAsync("matchStatusUpdated", liveUpdate, cancellationToken);
    }

    return Results.Ok(match);
});
matches.MapGet("/{matchId:guid}/scoreboard", async (
    Guid matchId,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.AsNoTracking().FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    return Results.Ok(liveMatScoringService.GetOrCreate(match));
}).AllowAnonymous();

matches.MapGet("/{matchId:guid}/scoreboard/rules", async (
    Guid matchId,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.AsNoTracking().FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    var bracket = await dbContext.Brackets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == match.BracketId, cancellationToken);
    if (bracket is not null)
    {
        liveMatScoringService.Configure(
            match,
            new ConfigureMatchScoringRequest(
                InferStyleForLevel(bracket.Level),
                bracket.Level,
                AutoEndEnabled: true,
                TechFallPointGap: null,
                RegulationPeriods: 3));
    }

    return Results.Ok(liveMatScoringService.GetRules(match));
}).AllowAnonymous();

matches.MapPost("/{matchId:guid}/scoreboard/rules", async (
    Guid matchId,
    ConfigureMatchScoringRequest request,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.AsNoTracking().FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    try
    {
        var rules = liveMatScoringService.Configure(match, request);
        return Results.Ok(rules);
    }
    catch (ArgumentOutOfRangeException ex)
    {
        return Results.BadRequest(ex.Message);
    }
}).RequireAuthorization("EventOps");

api.MapGet("/scoring/rules", (
    [FromQuery] WrestlingStyle? style,
    [FromQuery] CompetitionLevel? level,
    ILiveMatScoringService liveMatScoringService) =>
{
    var selectedStyle = style ?? WrestlingStyle.Folkstyle;
    var selectedLevel = level ?? CompetitionLevel.HighSchool;
    var fallbackMatch = new Match
    {
        Id = Guid.Empty,
        Status = MatchStatus.Scheduled
    };

    var rules = liveMatScoringService.Configure(
        fallbackMatch,
        new ConfigureMatchScoringRequest(selectedStyle, selectedLevel, true, null, 3));

    return Results.Ok(rules with { MatchId = Guid.Empty });
}).AllowAnonymous();

matches.MapPost("/{matchId:guid}/scoreboard/events", async (
    Guid matchId,
    AddMatScoreEventRequest request,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    IRankingService rankingService,
    INotificationDispatcher notificationDispatcher,
    IHubContext<MatchOpsHub> hubContext,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    var bracket = await dbContext.Brackets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == match.BracketId, cancellationToken);
    var tournamentEventId = bracket?.TournamentEventId ?? Guid.Empty;
    if (bracket is not null)
    {
        liveMatScoringService.Configure(
            match,
            new ConfigureMatchScoringRequest(
                InferStyleForLevel(bracket.Level),
                bracket.Level,
                AutoEndEnabled: true,
                TechFallPointGap: null,
                RegulationPeriods: 3));
    }

    MatScoreboardSnapshot scoreboard;
    try
    {
        scoreboard = liveMatScoringService.AddScoreEvent(match, request);
    }
    catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidOperationException)
    {
        return Results.BadRequest(ex.Message);
    }

    if (scoreboard.Status == MatchStatus.OnMat && match.Status != MatchStatus.OnMat)
    {
        match.Status = MatchStatus.OnMat;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    if (scoreboard.IsFinal && scoreboard.WinnerAthleteId is not null && match.Status != MatchStatus.Completed)
    {
        match.WinnerAthleteId = scoreboard.WinnerAthleteId;
        match.Score = $"{scoreboard.AthleteAScore}-{scoreboard.AthleteBScore}";
        match.ResultMethod = scoreboard.OutcomeReason ?? "Decision";
        match.Status = MatchStatus.Completed;
        match.CompletedUtc = DateTime.UtcNow;

        var winnerPoints = Math.Max(scoreboard.AthleteAScore, scoreboard.AthleteBScore);
        var loserPoints = Math.Min(scoreboard.AthleteAScore, scoreboard.AthleteBScore);

        await rankingService.ApplyMatchResultAsync(match, scoreboard.WinnerAthleteId.Value, winnerPoints, loserPoints, cancellationToken);
        await AdvanceBracketProgressionAsync(dbContext, match.BracketId, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        var outcomeMessage = $"Match {match.MatchNumber} final: {match.Score} via {match.ResultMethod}.";
        foreach (var athleteId in new[] { match.AthleteAId, match.AthleteBId }.Where(x => x is not null).Select(x => x!.Value))
        {
            await notificationDispatcher.DispatchAsync(
                new NotificationDispatchRequest(tournamentEventId, match.Id, athleteId, NotificationEventType.MatchResult, outcomeMessage),
                cancellationToken);
        }

        var finalUpdate = new
        {
            MatchId = match.Id,
            EventId = tournamentEventId,
            match.Status,
            match.Score,
            match.ResultMethod,
            match.WinnerAthleteId,
            Message = outcomeMessage,
            UpdatedUtc = DateTime.UtcNow
        };

        if (tournamentEventId != Guid.Empty)
        {
            await hubContext.Clients.Group(MatchOpsHubGroups.ForEvent(tournamentEventId))
                .SendAsync("matchStatusUpdated", finalUpdate, cancellationToken);
        }

        await hubContext.Clients.Group(MatchOpsHubGroups.ForMatch(match.Id))
            .SendAsync("matchStatusUpdated", finalUpdate, cancellationToken);
    }

    await hubContext.Clients.Group(MatchOpsHubGroups.ForMatch(matchId))
        .SendAsync("scoreboardUpdated", scoreboard, cancellationToken);
    if (tournamentEventId != Guid.Empty)
    {
        await hubContext.Clients.Group(MatchOpsHubGroups.ForEvent(tournamentEventId))
            .SendAsync("scoreboardUpdated", scoreboard, cancellationToken);
    }

    return Results.Ok(scoreboard);
}).RequireAuthorization("EventOps");

matches.MapPost("/{matchId:guid}/scoreboard/reset", async (
    Guid matchId,
    ResetMatScoreboardRequest request,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    IHubContext<MatchOpsHub> hubContext,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    var tournamentEventId = await dbContext.Brackets
        .Where(x => x.Id == match.BracketId)
        .Select(x => x.TournamentEventId)
        .FirstOrDefaultAsync(cancellationToken);

    var scoreboard = liveMatScoringService.Reset(match, request.Reason);
    match.Status = MatchStatus.OnMat;
    match.WinnerAthleteId = null;
    match.Score = null;
    match.ResultMethod = null;
    match.CompletedUtc = null;
    await dbContext.SaveChangesAsync(cancellationToken);

    await hubContext.Clients.Group(MatchOpsHubGroups.ForMatch(matchId))
        .SendAsync("scoreboardUpdated", scoreboard, cancellationToken);
    if (tournamentEventId != Guid.Empty)
    {
        await hubContext.Clients.Group(MatchOpsHubGroups.ForEvent(tournamentEventId))
            .SendAsync("scoreboardUpdated", scoreboard, cancellationToken);
    }

    return Results.Ok(scoreboard);
}).RequireAuthorization("EventOps");

var athletes = api.MapGroup("/athletes").RequireAuthorization();
athletes.MapGet("/{athleteId:guid}/stats/history", async (Guid athleteId, HttpContext httpContext, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    var canManageAthlete = await ApiSecurityHelpers.CanManageAthleteProfileAsync(dbContext, httpContext.User, athleteId, cancellationToken);
    if (!canManageAthlete)
    {
        return Results.Forbid();
    }

    var snapshots = await dbContext.AthleteStatsSnapshots
        .AsNoTracking()
        .Where(x => x.AthleteProfileId == athleteId)
        .OrderByDescending(x => x.SnapshotUtc)
        .ToListAsync(cancellationToken);

    return Results.Ok(snapshots);
});

athletes.MapGet("/{athleteId:guid}/highlights", async (
    Guid athleteId,
    IMediaPipelineService mediaPipelineService,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var athlete = await dbContext.AthleteProfiles.AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == athleteId, cancellationToken);

    if (athlete is null)
    {
        return Results.NotFound("Athlete not found.");
    }

    var completedMatches = await dbContext.Matches.AsNoTracking()
        .Where(x => (x.AthleteAId == athleteId || x.AthleteBId == athleteId) && x.Status == MatchStatus.Completed)
        .OrderByDescending(x => x.CompletedUtc)
        .Take(24)
        .ToListAsync(cancellationToken);

    var matchIds = completedMatches.Select(x => x.Id).ToHashSet();
    var streams = await dbContext.StreamSessions.AsNoTracking()
        .Where(x => x.MatchId != null && matchIds.Contains(x.MatchId.Value))
        .ToListAsync(cancellationToken);

    var highlights = new List<AthleteHighlightClip>();
    foreach (var match in completedMatches)
    {
        var stream = streams.FirstOrDefault(x => x.MatchId == match.Id);
        var wonMatch = match.WinnerAthleteId == athleteId;
        var impactScore = wonMatch ? 84 : 64;

        if (string.Equals(match.ResultMethod, "Pin", StringComparison.OrdinalIgnoreCase))
        {
            impactScore += 8;
        }
        else if (string.Equals(match.ResultMethod, "Major Decision", StringComparison.OrdinalIgnoreCase))
        {
            impactScore += 4;
        }

        highlights.Add(new AthleteHighlightClip(
            Guid.NewGuid(),
            athleteId,
            match.Id,
            stream?.Id,
            wonMatch ? "Signature Win" : "Tough Battle",
            $"Auto-generated from {match.ResultMethod ?? "match result"} ({match.Score ?? "N/A"}).",
            stream?.PlaybackUrl ?? $"https://stream.local/highlights/{match.Id:N}.m3u8",
            match.ScheduledUtc ?? DateTime.UtcNow.AddMinutes(-8),
            match.CompletedUtc ?? DateTime.UtcNow,
            Math.Min(99, impactScore),
            AiGenerated: true));
    }

    var pipelineVideos = mediaPipelineService.GetAthleteVideos(athleteId);
    foreach (var video in pipelineVideos.Where(x => x.State == VideoPipelineState.Ready).Take(18))
    {
        highlights.Add(new AthleteHighlightClip(
            video.VideoId,
            athleteId,
            video.MatchId,
            video.StreamId,
            "Pipeline Clip",
            "Processed via media storage + transcode pipeline.",
            video.PlaybackUrl,
            video.CreatedUtc,
            video.ReadyUtc ?? DateTime.UtcNow,
            72,
            AiGenerated: false));
    }

    var generated = mediaPipelineService.GetGeneratedHighlights(athleteId);
    foreach (var clip in generated)
    {
        highlights.Add(clip);
    }

    var deduped = highlights
        .GroupBy(x => x.ClipId)
        .Select(group => group.First())
        .OrderByDescending(x => x.ImpactScore)
        .ThenByDescending(x => x.ClipEndUtc)
        .Take(200)
        .ToList();

    return Results.Ok(deduped);
}).AllowAnonymous();

athletes.MapGet("/{athleteId:guid}/nil-profile", async (
    Guid athleteId,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var athlete = await dbContext.AthleteProfiles.AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == athleteId, cancellationToken);

    if (athlete is null)
    {
        return Results.NotFound("Athlete not found.");
    }

    var latestStats = await dbContext.AthleteStatsSnapshots.AsNoTracking()
        .Where(x => x.AthleteProfileId == athleteId)
        .OrderByDescending(x => x.SnapshotUtc)
        .FirstOrDefaultAsync(cancellationToken);

    var ranking = await dbContext.AthleteRankings.AsNoTracking()
        .Where(x => x.AthleteProfileId == athleteId)
        .OrderBy(x => x.Rank)
        .FirstOrDefaultAsync(cancellationToken);

    var wins = latestStats?.Wins ?? 0;
    var losses = latestStats?.Losses ?? 0;
    var ratingPoints = ranking?.RatingPoints ?? 0m;
    var followers = (int)Math.Clamp(500 + (wins * 24) + Math.Round(ratingPoints * 0.6m), 500, 175_000);
    var marketabilityScore = Math.Round(Math.Clamp((wins * 1.7m) + (ratingPoints * 0.35m), 40m, 99m), 1);

    var tags = new List<string>
    {
        athlete.Level.ToString(),
        $"{athlete.WeightClass:0.#} lbs",
        $"#{athlete.State}",
        ranking is null ? "Unranked watchlist" : $"Ranked #{ranking.Rank}"
    };

    var profile = new AthleteNilProfile(
        athlete.Id,
        $"{athlete.FirstName} {athlete.LastName}",
        athlete.Level,
        athlete.State,
        athlete.City,
        athlete.WeightClass,
        followers,
        wins,
        losses,
        ratingPoints,
        marketabilityScore,
        tags);

    return Results.Ok(profile);
}).AllowAnonymous();

athletes.MapGet("/{athleteId:guid}/videos", (Guid athleteId, IMediaPipelineService mediaPipelineService) =>
{
    var videos = mediaPipelineService.GetAthleteVideos(athleteId);
    return Results.Ok(videos);
}).AllowAnonymous();

var media = api.MapGroup("/media").RequireAuthorization();
media.MapPost("/videos", (
    CreateVideoAssetRequest request,
    IMediaPipelineService mediaPipelineService) =>
{
    try
    {
        var video = mediaPipelineService.CreateVideoAsset(request);
        return Results.Created($"/api/media/videos/{video.VideoId}", video);
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(ex.Message);
    }
});

media.MapGet("/videos/{videoId:guid}", (Guid videoId, IMediaPipelineService mediaPipelineService) =>
{
    var video = mediaPipelineService.GetVideo(videoId);
    return video is null ? Results.NotFound("Video not found.") : Results.Ok(video);
}).AllowAnonymous();

media.MapPost("/highlights/queue", (
    QueueAiHighlightsRequest request,
    IMediaPipelineService mediaPipelineService) =>
{
    try
    {
        var job = mediaPipelineService.QueueAiHighlights(request);
        return Results.Accepted($"/api/media/highlights/jobs/{request.AthleteProfileId}", job);
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(ex.Message);
    }
});

media.MapGet("/highlights/jobs/{athleteId:guid}", (Guid athleteId, IMediaPipelineService mediaPipelineService) =>
{
    var jobs = mediaPipelineService.GetAiJobs(athleteId);
    return Results.Ok(jobs);
}).AllowAnonymous();

var recruiting = api.MapGroup("/recruiting");
recruiting.MapGet("/athletes", async (
    [FromQuery] CompetitionLevel? level,
    [FromQuery] string? state,
    [FromQuery] int? minWins,
    [FromQuery] int? take,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var safeTake = take is null or <= 0 or > 120 ? 50 : take.Value;
    var safeMinWins = minWins is null or < 0 ? 0 : minWins.Value;

    var rankingQuery = dbContext.AthleteRankings.AsNoTracking().AsQueryable();
    if (level is not null)
    {
        rankingQuery = rankingQuery.Where(x => x.Level == level.Value);
    }

    if (!string.IsNullOrWhiteSpace(state))
    {
        var normalizedState = state.Trim().ToUpperInvariant();
        rankingQuery = rankingQuery.Where(x => x.State == normalizedState);
    }

    var rankings = await rankingQuery
        .OrderBy(x => x.Level)
        .ThenBy(x => x.State)
        .ThenBy(x => x.Rank)
        .Take(safeTake * 2)
        .ToListAsync(cancellationToken);

    var athleteIds = rankings.Select(x => x.AthleteProfileId).ToHashSet();
    var athletesMap = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x => athleteIds.Contains(x.Id))
        .ToDictionaryAsync(x => x.Id, cancellationToken);

    var latestStats = await dbContext.AthleteStatsSnapshots.AsNoTracking()
        .Where(x => athleteIds.Contains(x.AthleteProfileId))
        .GroupBy(x => x.AthleteProfileId)
        .Select(group => group.OrderByDescending(x => x.SnapshotUtc).First())
        .ToListAsync(cancellationToken);

    var statsByAthleteId = latestStats.ToDictionary(x => x.AthleteProfileId);

    var result = new List<RecruitingAthleteCard>();
    foreach (var ranking in rankings)
    {
        if (!athletesMap.TryGetValue(ranking.AthleteProfileId, out var athlete))
        {
            continue;
        }

        var stats = statsByAthleteId.GetValueOrDefault(athlete.Id);
        var wins = stats?.Wins ?? 0;
        if (wins < safeMinWins)
        {
            continue;
        }

        result.Add(new RecruitingAthleteCard(
            athlete.Id,
            athlete.FirstName,
            athlete.LastName,
            athlete.Level,
            athlete.State,
            athlete.City,
            athlete.WeightClass,
            ranking.Rank,
            ranking.RatingPoints,
            wins,
            stats?.Losses ?? 0,
            OpenToRecruitment: true));

        if (result.Count >= safeTake)
        {
            break;
        }
    }

    return Results.Ok(result);
}).AllowAnonymous();

api.MapGet("/rankings", async (
    [FromQuery] CompetitionLevel? level,
    [FromQuery] string? state,
    [FromQuery] int take,
    IDistributedCache cache,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (take <= 0 || take > 200)
    {
        take = 50;
    }

    var rankingsCacheKey = BuildCacheKey(
        "rankings:v1",
        ("level", level?.ToString()),
        ("state", state?.Trim().ToUpperInvariant()),
        ("take", take.ToString()));

    var cachedRankings = await TryGetCachedResponseAsync(cache, rankingsCacheKey, cancellationToken);
    if (cachedRankings is not null)
    {
        return Results.Content(cachedRankings, "application/json");
    }

    var query = dbContext.AthleteRankings.AsNoTracking().AsQueryable();

    if (level is not null)
    {
        query = query.Where(x => x.Level == level.Value);
    }

    if (!string.IsNullOrWhiteSpace(state))
    {
        var normalizedState = state.Trim().ToUpperInvariant();
        query = query.Where(x => x.State == normalizedState);
    }

    var rankings = await query
        .OrderBy(x => x.Level)
        .ThenBy(x => x.State)
        .ThenBy(x => x.Rank)
        .Take(take)
        .ToListAsync(cancellationToken);

    await SetCachedResponseAsync(cache, rankingsCacheKey, rankings, TimeSpan.FromSeconds(45), cancellationToken);
    return Results.Ok(rankings);
});

var notifications = api.MapGroup("/notifications").RequireAuthorization();
notifications.MapPost("/subscriptions", async (
    SubscribeNotificationRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (!ApiSecurityHelpers.CanAccessUserResource(httpContext, request.UserAccountId))
    {
        return Results.Forbid();
    }

    var userExists = await dbContext.UserAccounts.AnyAsync(x => x.Id == request.UserAccountId, cancellationToken);
    if (!userExists)
    {
        return Results.BadRequest("User not found.");
    }

    var subscription = new NotificationSubscription
    {
        UserAccountId = request.UserAccountId,
        TournamentEventId = request.TournamentEventId,
        AthleteProfileId = request.AthleteProfileId,
        EventType = request.EventType,
        Channel = request.Channel,
        Destination = request.Destination.Trim()
    };

    dbContext.NotificationSubscriptions.Add(subscription);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/notifications/subscriptions/{subscription.Id}", subscription);
});

notifications.MapGet("/subscriptions/{userId:guid}", async (Guid userId, HttpContext httpContext, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    if (!ApiSecurityHelpers.CanAccessUserResource(httpContext, userId))
    {
        return Results.Forbid();
    }

    var subscriptions = await dbContext.NotificationSubscriptions
        .AsNoTracking()
        .Where(x => x.UserAccountId == userId)
        .OrderBy(x => x.EventType)
        .ThenBy(x => x.Channel)
        .ToListAsync(cancellationToken);

    return Results.Ok(subscriptions);
});

notifications.MapGet("/messages/{userId:guid}", async (Guid userId, HttpContext httpContext, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    if (!ApiSecurityHelpers.CanAccessUserResource(httpContext, userId))
    {
        return Results.Forbid();
    }

    var messages = await (
            from message in dbContext.NotificationMessages
            join subscription in dbContext.NotificationSubscriptions on message.NotificationSubscriptionId equals subscription.Id
            where subscription.UserAccountId == userId
            orderby message.CreatedUtc descending
            select message)
        .Take(200)
        .ToListAsync(cancellationToken);

    return Results.Ok(messages);
});

var security = api.MapGroup("/security").RequireAuthorization();
security.MapGet("/audit", ([FromQuery] int? take, ISecurityAuditTrailService auditTrail) =>
{
    var safeTake = take is null or <= 0 ? 100 : take.Value;
    return Results.Ok(auditTrail.GetRecent(safeTake));
}).RequireAuthorization("EventOps");

security.MapPost("/mfa/enroll/{userId:guid}", async (
    Guid userId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    IMfaService mfaService,
    CancellationToken cancellationToken) =>
{
    var canAccess = ApiSecurityHelpers.CanAccessUserResource(httpContext, userId) || ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User);
    if (!canAccess)
    {
        return Results.Forbid();
    }

    var user = await dbContext.UserAccounts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == userId, cancellationToken);
    if (user is null)
    {
        return Results.NotFound("User not found.");
    }

    var enrolled = mfaService.Enroll(userId, user.Email);
    return Results.Ok(enrolled);
});

security.MapPost("/mfa/verify", (
    VerifyMfaCodeRequest request,
    HttpContext httpContext,
    IMfaService mfaService) =>
{
    var canAccess = ApiSecurityHelpers.CanAccessUserResource(httpContext, request.UserId) || ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User);
    if (!canAccess)
    {
        return Results.Forbid();
    }

    var verified = mfaService.Verify(request);
    return verified.Verified ? Results.Ok(verified) : Results.BadRequest("Invalid MFA code.");
});

security.MapGet("/mfa/enabled/{userId:guid}", (Guid userId, HttpContext httpContext, IMfaService mfaService) =>
{
    var canAccess = ApiSecurityHelpers.CanAccessUserResource(httpContext, userId) || ApiSecurityHelpers.IsEventOperatorPrincipal(httpContext.User);
    if (!canAccess)
    {
        return Results.Forbid();
    }

    return Results.Ok(new
    {
        UserId = userId,
        Enabled = mfaService.IsEnabled(userId)
    });
});

var streams = api.MapGroup("/streams").RequireAuthorization("EventOps");
events.MapPost("/{eventId:guid}/streams", async (
    Guid eventId,
    CreateStreamSessionRequest request,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    if (request.MatchId is not null)
    {
        var matchExists = await dbContext.Matches.AnyAsync(x => x.Id == request.MatchId, cancellationToken);
        if (!matchExists)
        {
            return Results.BadRequest("Match not found.");
        }
    }

    var normalizedDeviceName = string.IsNullOrWhiteSpace(request.DeviceName)
        ? "Mat Stream Device"
        : request.DeviceName.Trim();

    var normalizedProtocol = string.IsNullOrWhiteSpace(request.IngestProtocol)
        ? "RTMP"
        : request.IngestProtocol.Trim().ToUpperInvariant();

    var generatedPlaybackUrl = $"https://stream.local/{eventId:N}/{Guid.NewGuid():N}.m3u8";
    var playbackUrl = string.IsNullOrWhiteSpace(request.SourceUrl)
        ? generatedPlaybackUrl
        : request.SourceUrl.Trim();

    var stream = new StreamSession
    {
        TournamentEventId = eventId,
        MatchId = request.MatchId,
        DeviceName = $"{normalizedDeviceName} [{normalizedProtocol}]",
        IngestKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace("/", "_").Replace("+", "-"),
        PlaybackUrl = playbackUrl,
        Status = StreamStatus.Provisioned
    };

    dbContext.StreamSessions.Add(stream);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/streams/{stream.Id}", stream);
}).RequireAuthorization("EventOps");

streams.MapPost("/{streamId:guid}/status", async (
    Guid streamId,
    UpdateStreamStatusRequest request,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var stream = await dbContext.StreamSessions.FirstOrDefaultAsync(x => x.Id == streamId, cancellationToken);
    if (stream is null)
    {
        return Results.NotFound("Stream not found.");
    }

    stream.Status = request.Status;
    stream.StartedUtc = request.Status == StreamStatus.Live ? DateTime.UtcNow : stream.StartedUtc;
    stream.EndedUtc = request.Status == StreamStatus.Ended ? DateTime.UtcNow : stream.EndedUtc;

    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Ok(stream);
});

events.MapGet("/{eventId:guid}/streams/active", async (Guid eventId, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    var streamsForEvent = await dbContext.StreamSessions
        .AsNoTracking()
        .Where(x => x.TournamentEventId == eventId && x.Status == StreamStatus.Live)
        .OrderBy(x => x.CreatedUtc)
        .ToListAsync(cancellationToken);

    return Results.Ok(streamsForEvent);
}).AllowAnonymous();

var payments = api.MapGroup("/payments").RequireAuthorization("EventOps");
payments.MapPost("/reconciliation/process", async (
    [FromQuery] int? batchSize,
    IPaymentWebhookReconciliationService reconciliationService,
    CancellationToken cancellationToken) =>
{
    var safeBatchSize = batchSize is null or <= 0 or > 250 ? 50 : batchSize.Value;
    var processed = await reconciliationService.ProcessPendingAsync(safeBatchSize, cancellationToken);

    return Results.Ok(new
    {
        Processed = processed,
        BatchSize = safeBatchSize
    });
});

async Task<IResult> HandleStripeWebhookAsync(
    HttpRequest httpRequest,
    IConfiguration configuration,
    IPaymentWebhookReconciliationService reconciliationService,
    CancellationToken cancellationToken)
{
    var payload = await new StreamReader(httpRequest.Body, Encoding.UTF8).ReadToEndAsync(cancellationToken);
    if (string.IsNullOrWhiteSpace(payload))
    {
        return Results.BadRequest("Webhook body is required.");
    }

    var expectedSecret = configuration["Payments:StripeWebhookSecret"];
    var tolerance = TimeSpan.FromSeconds(Math.Clamp(stripeWebhookToleranceSeconds, 30, 1_800));

    if (!StripeWebhookHelpers.VerifyStripeWebhookSignature(httpRequest, payload, expectedSecret, tolerance))
    {
        return Results.Unauthorized();
    }

    if (!StripeWebhookHelpers.TryParseStripeWebhookIngress(payload, out var ingress, out var parseError))
    {
        return Results.BadRequest(parseError);
    }

    var enqueueResult = await reconciliationService.EnqueueAsync(ingress, cancellationToken);

    return Results.Accepted(value: new
    {
        enqueueResult.EventRecordId,
        enqueueResult.Status,
        enqueueResult.IsDuplicate
    });
}

var webhooks = api.MapGroup("/webhooks");
webhooks.MapPost("/stripe", HandleStripeWebhookAsync).AllowAnonymous();
webhooks.MapPost("/stripe/payment-confirmed", HandleStripeWebhookAsync).AllowAnonymous();

app.Run();

static string BuildCacheKey(string prefix, params (string Name, string? Value)[] parts)
{
    var nonEmptyParts = parts
        .Where(x => !string.IsNullOrWhiteSpace(x.Value))
        .Select(x => $"{x.Name}:{x.Value}")
        .ToArray();

    return nonEmptyParts.Length == 0
        ? prefix
        : $"{prefix}|{string.Join("|", nonEmptyParts)}";
}

static async Task<string?> TryGetCachedResponseAsync(IDistributedCache cache, string key, CancellationToken cancellationToken)
{
    return await cache.GetStringAsync(key, cancellationToken);
}

static async Task SetCachedResponseAsync<T>(
    IDistributedCache cache,
    string key,
    T payload,
    TimeSpan ttl,
    CancellationToken cancellationToken)
{
    var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
    jsonOptions.Converters.Add(new JsonStringEnumConverter());
    var serialized = JsonSerializer.Serialize(payload, jsonOptions);
    var options = new DistributedCacheEntryOptions
    {
        AbsoluteExpirationRelativeToNow = ttl
    };

    await cache.SetStringAsync(key, serialized, options, cancellationToken);
}

static async Task InitializeDatabaseWithRetryAsync(
    IServiceProvider services,
    ILogger logger,
    CancellationToken cancellationToken)
{
    const int maxAttempts = 12;
    var delay = TimeSpan.FromSeconds(2);
    Exception? lastException = null;

    for (var attempt = 1; attempt <= maxAttempts; attempt++)
    {
        try
        {
            await services.InitializeDatabaseAsync(cancellationToken);
            return;
        }
        catch (Exception ex) when (attempt < maxAttempts)
        {
            lastException = ex;
            logger.LogWarning(
                ex,
                "Database initialization attempt {Attempt}/{MaxAttempts} failed. Retrying in {DelaySeconds}s.",
                attempt,
                maxAttempts,
                delay.TotalSeconds);

            await Task.Delay(delay, cancellationToken);
            delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 1.5d, 20d));
        }
        catch (Exception ex)
        {
            lastException = ex;
            break;
        }
    }

    throw new InvalidOperationException("Database initialization failed after multiple attempts.", lastException);
}
static async Task AdvanceBracketProgressionAsync(
    WrestlingPlatformDbContext dbContext,
    Guid bracketId,
    CancellationToken cancellationToken)
{
    var bracketMatches = await dbContext.Matches
        .Where(x => x.BracketId == bracketId)
        .OrderBy(x => x.Round)
        .ThenBy(x => x.MatchNumber)
        .ToListAsync(cancellationToken);

    BracketProgressionEngine.Resolve(bracketMatches);
}

static string ResolveAgeGroupLabel(CompetitionLevel level)
{
    return level switch
    {
        CompetitionLevel.ElementaryK6 => "Elementary (K-6)",
        CompetitionLevel.MiddleSchool => "Middle School (7-8)",
        CompetitionLevel.HighSchool => "High School (9-12)",
        CompetitionLevel.College => "College",
        _ => level.ToString()
    };
}

static WrestlingStyle InferStyleForLevel(CompetitionLevel level)
{
    return level switch
    {
        CompetitionLevel.College => WrestlingStyle.Folkstyle,
        CompetitionLevel.HighSchool => WrestlingStyle.Folkstyle,
        CompetitionLevel.MiddleSchool => WrestlingStyle.Folkstyle,
        CompetitionLevel.ElementaryK6 => WrestlingStyle.Folkstyle,
        _ => WrestlingStyle.Folkstyle
    };
}

static WrestlingStyle InferDivisionStyle(TournamentDivision division)
{
    if (division.Name.Contains("greco", StringComparison.OrdinalIgnoreCase))
    {
        return WrestlingStyle.GrecoRoman;
    }

    if (division.Name.Contains("freestyle", StringComparison.OrdinalIgnoreCase))
    {
        return WrestlingStyle.Freestyle;
    }

    return InferStyleForLevel(division.Level);
}

static WrestlingStyle InferEventStyle(IReadOnlyCollection<Match> matches, IReadOnlyCollection<Bracket> brackets)
{
    if (matches.Any(x => string.Equals(x.ResultMethod, "Greco", StringComparison.OrdinalIgnoreCase)))
    {
        return WrestlingStyle.GrecoRoman;
    }

    if (matches.Any(x => string.Equals(x.ResultMethod, "Freestyle", StringComparison.OrdinalIgnoreCase)))
    {
        return WrestlingStyle.Freestyle;
    }

    var firstBracket = brackets.OrderBy(x => x.Level).FirstOrDefault();
    return firstBracket is null ? WrestlingStyle.Folkstyle : InferStyleForLevel(firstBracket.Level);
}

static string BuildAthleteLabel(Guid? athleteId, IReadOnlyDictionary<Guid, AthleteProfile> athletesById)
{
    if (athleteId is null)
    {
        return "TBD";
    }

    if (!athletesById.TryGetValue(athleteId.Value, out var athlete))
    {
        return athleteId.Value.ToString("N")[..8];
    }

    return $"{athlete.FirstName} {athlete.LastName}";
}

static (int AthleteAScore, int AthleteBScore) ParseScore(string? score)
{
    if (string.IsNullOrWhiteSpace(score))
    {
        return (0, 0);
    }

    var normalized = score.Trim();
    var dashIndex = normalized.IndexOf('-');
    if (dashIndex <= 0 || dashIndex >= normalized.Length - 1)
    {
        return (0, 0);
    }

    var left = normalized[..dashIndex];
    var right = normalized[(dashIndex + 1)..];
    return int.TryParse(left, out var aScore) && int.TryParse(right, out var bScore)
        ? (Math.Max(0, aScore), Math.Max(0, bScore))
        : (0, 0);
}

static HashSet<UserRole> ResolveMfaRequiredRoles(IConfiguration configuration)
{
    var configuredRoles = configuration.GetSection("Security:Mfa:RequiredRoles").Get<string[]>();
    if (configuredRoles is null || configuredRoles.Length == 0)
    {
        return
        [
            UserRole.SchoolAdmin,
            UserRole.ClubAdmin,
            UserRole.EventAdmin,
            UserRole.SystemAdmin
        ];
    }

    var resolved = new HashSet<UserRole>();
    foreach (var roleRaw in configuredRoles)
    {
        if (Enum.TryParse<UserRole>(roleRaw, ignoreCase: true, out var role))
        {
            resolved.Add(role);
        }
    }

    return resolved.Count == 0
        ?
        [
            UserRole.SchoolAdmin,
            UserRole.ClubAdmin,
            UserRole.EventAdmin,
            UserRole.SystemAdmin
        ]
        : resolved;
}


