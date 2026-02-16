using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Concurrent;
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
var demoDataResetToken = builder.Configuration["DemoData:ResetToken"]?.Trim();
var mfaRequiredRoles = ResolveMfaRequiredRoles(builder.Configuration);
var samplePlaybackUrls = ResolveSamplePlaybackUrls(builder.Configuration);
var nilOverridesByAthlete = new ConcurrentDictionary<Guid, UpdateAthleteNilProfileRequest>();

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
builder.Services.AddSingleton<IEventOpsChecklistService, EventOpsChecklistService>();
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
        UserRole.TournamentDirector.ToString(),
        UserRole.ClubAdmin.ToString(),
        UserRole.SchoolAdmin.ToString(),
        UserRole.EventAdmin.ToString(),
        UserRole.SystemAdmin.ToString()));

    options.AddPolicy("EventOps", policy => policy.RequireRole(
        UserRole.TournamentDirector.ToString(),
        UserRole.EventAdmin.ToString(),
        UserRole.ClubAdmin.ToString(),
        UserRole.SchoolAdmin.ToString(),
        UserRole.SystemAdmin.ToString()));

    options.AddPolicy("MatScoring", policy => policy.RequireRole(
        UserRole.MatWorker.ToString(),
        UserRole.Coach.ToString(),
        UserRole.TournamentDirector.ToString(),
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
await InitializeDemoRuntimeStateAsync(app.Services, app.Logger, samplePlaybackUrls, CancellationToken.None);

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

var demo = api.MapGroup("/demo");
demo.MapPost("/reset-data", async (HttpRequest request, IServiceProvider services, CancellationToken cancellationToken) =>
{
    var token = request.Headers["X-Demo-Reset-Token"].FirstOrDefault()
                ?? request.Query["token"].FirstOrDefault();

    var allowWithoutToken = app.Environment.IsDevelopment() && string.IsNullOrWhiteSpace(demoDataResetToken);
    var tokenValid = !string.IsNullOrWhiteSpace(demoDataResetToken)
                     && string.Equals(token, demoDataResetToken, StringComparison.Ordinal);

    if (!allowWithoutToken && !tokenValid)
    {
        return Results.Unauthorized();
    }

    await services.ResetDemoDataAsync(cancellationToken);
    return Results.Ok(new
    {
        Status = "demo-data-reset",
        Utc = DateTime.UtcNow
    });
});

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

    var requestedRole = ApiSecurityHelpers.NormalizeRole(request.Role);
    if (!ApiSecurityHelpers.IsPublicRegistrationRole(requestedRole))
    {
        return Results.BadRequest("Self-registration is limited to Athlete, Parent/Guardian, Coach, Fan, Mat Worker, and Tournament Director roles.");
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
        Role = requestedRole,
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
    var currentUserId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    if (currentUserId is null)
    {
        return Results.Unauthorized();
    }

    var isDirector = ApiSecurityHelpers.IsTournamentDirectorPrincipal(httpContext.User);
    var isAdmin = ApiSecurityHelpers.IsAdminPrincipal(httpContext.User);
    if (!isDirector && !isAdmin)
    {
        return Results.Forbid();
    }

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
        CreatedByUserAccountId = currentUserId.Value,
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
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
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

events.MapGet("/explorer", async (
    [FromQuery] int? daysBack,
    [FromQuery] int? daysAhead,
    [FromQuery] string? state,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var nowUtc = DateTime.UtcNow;
    var safeDaysBack = Math.Clamp(daysBack ?? 180, 7, 730);
    var safeDaysAhead = Math.Clamp(daysAhead ?? 180, 7, 730);
    var fromUtc = nowUtc.AddDays(-safeDaysBack);
    var toUtc = nowUtc.AddDays(safeDaysAhead);

    var eventQuery = dbContext.TournamentEvents
        .AsNoTracking()
        .Where(x => x.EndUtc >= fromUtc && x.StartUtc <= toUtc);

    if (!string.IsNullOrWhiteSpace(state))
    {
        var normalizedState = state.Trim().ToUpperInvariant();
        eventQuery = eventQuery.Where(x => x.State == normalizedState);
    }

    var eventRows = await eventQuery
        .OrderBy(x => x.StartUtc)
        .ThenBy(x => x.Name)
        .ToListAsync(cancellationToken);

    var eventIds = eventRows.Select(x => x.Id).ToList();
    if (eventIds.Count == 0)
    {
        return Results.Ok(new TournamentExplorerResponse(nowUtc, [], [], []));
    }

    var registrationCounts = await dbContext.EventRegistrations.AsNoTracking()
        .Where(x => eventIds.Contains(x.TournamentEventId) && x.Status != RegistrationStatus.Cancelled)
        .GroupBy(x => x.TournamentEventId)
        .Select(group => new { EventId = group.Key, Count = group.Count() })
        .ToListAsync(cancellationToken);
    var registrationCountByEvent = registrationCounts.ToDictionary(x => x.EventId, x => x.Count);

    var liveStreamCounts = await dbContext.StreamSessions.AsNoTracking()
        .Where(x => eventIds.Contains(x.TournamentEventId) && x.Status == StreamStatus.Live)
        .GroupBy(x => x.TournamentEventId)
        .Select(group => new { EventId = group.Key, Count = group.Count() })
        .ToListAsync(cancellationToken);
    var liveStreamCountByEvent = liveStreamCounts.ToDictionary(x => x.EventId, x => x.Count);

    var divisions = await dbContext.TournamentDivisions.AsNoTracking()
        .Where(x => eventIds.Contains(x.TournamentEventId))
        .ToListAsync(cancellationToken);
    var styleByEvent = divisions
        .GroupBy(x => x.TournamentEventId)
        .ToDictionary(
            group => group.Key,
            group =>
            {
                var firstDivision = group
                    .OrderBy(x => x.Level)
                    .ThenBy(x => x.WeightClass)
                    .First();
                return InferDivisionStyle(firstDivision);
            });

    var brackets = await dbContext.Brackets.AsNoTracking()
        .Where(x => eventIds.Contains(x.TournamentEventId))
        .Select(x => new { x.Id, x.TournamentEventId })
        .ToListAsync(cancellationToken);
    var bracketIds = brackets.Select(x => x.Id).ToList();
    var eventIdByBracketId = brackets.ToDictionary(x => x.Id, x => x.TournamentEventId);

    var activeMatSetByEvent = new Dictionary<Guid, HashSet<string>>();
    var completedMatchCountByEvent = new Dictionary<Guid, int>();

    if (bracketIds.Count > 0)
    {
        var matchRows = await dbContext.Matches.AsNoTracking()
            .Where(x => bracketIds.Contains(x.BracketId))
            .Select(x => new { x.BracketId, x.Status, x.MatNumber })
            .ToListAsync(cancellationToken);

        foreach (var match in matchRows)
        {
            if (!eventIdByBracketId.TryGetValue(match.BracketId, out var eventId))
            {
                continue;
            }

            if (match.Status == MatchStatus.Completed)
            {
                completedMatchCountByEvent[eventId] = completedMatchCountByEvent.TryGetValue(eventId, out var currentCompleted)
                    ? currentCompleted + 1
                    : 1;
            }

            if (match.Status is MatchStatus.OnMat or MatchStatus.InTheHole)
            {
                var matLabel = string.IsNullOrWhiteSpace(match.MatNumber) ? "Unassigned" : match.MatNumber.Trim();
                if (!activeMatSetByEvent.TryGetValue(eventId, out var matSet))
                {
                    matSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    activeMatSetByEvent[eventId] = matSet;
                }

                matSet.Add(matLabel);
            }
        }
    }

    var cards = eventRows.Select(tournamentEvent =>
    {
        var registeredAthletes = registrationCountByEvent.GetValueOrDefault(tournamentEvent.Id);
        var activeMats = activeMatSetByEvent.TryGetValue(tournamentEvent.Id, out var mats) ? mats.Count : 0;
        var completedMatches = completedMatchCountByEvent.GetValueOrDefault(tournamentEvent.Id);
        var liveStreams = liveStreamCountByEvent.GetValueOrDefault(tournamentEvent.Id);
        var style = styleByEvent.GetValueOrDefault(tournamentEvent.Id, WrestlingStyle.Folkstyle);
        var isWithinEventWindow = tournamentEvent.StartUtc <= nowUtc && tournamentEvent.EndUtc >= nowUtc;
        var isNearWindowWithLiveStreams = liveStreams > 0
                                          && tournamentEvent.StartUtc <= nowUtc.AddHours(2)
                                          && tournamentEvent.EndUtc >= nowUtc.AddHours(-2);
        var isLive = isWithinEventWindow || activeMats > 0 || isNearWindowWithLiveStreams;

        return new TournamentExplorerCard(
            tournamentEvent.Id,
            tournamentEvent.Name,
            tournamentEvent.State,
            tournamentEvent.City,
            tournamentEvent.Venue,
            tournamentEvent.StartUtc,
            tournamentEvent.EndUtc,
            tournamentEvent.EntryFeeCents,
            style,
            registeredAthletes,
            activeMats,
            completedMatches,
            liveStreams,
            isLive);
    }).ToList();

    var live = cards
        .Where(x => x.IsLive)
        .OrderBy(x => x.StartUtc)
        .ThenBy(x => x.Name)
        .ToList();

    var upcoming = cards
        .Where(x => !x.IsLive && x.StartUtc > nowUtc)
        .OrderBy(x => x.StartUtc)
        .ThenBy(x => x.Name)
        .ToList();

    var past = cards
        .Where(x => !x.IsLive && x.EndUtc < nowUtc)
        .OrderByDescending(x => x.EndUtc)
        .ThenBy(x => x.Name)
        .ToList();

    return Results.Ok(new TournamentExplorerResponse(nowUtc, live, upcoming, past));
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
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
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
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);

    await AssignBoutNumbersAsync(eventId, dbContext, cancellationToken);
    var updated = tournamentControlService.ReleaseBrackets(eventId, registrantCount);
    return Results.Ok(updated);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops-checklist", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    IEventOpsChecklistService eventOpsChecklistService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    return Results.Ok(eventOpsChecklistService.GetOrCreate(eventId));
}).RequireAuthorization("EventOps");

events.MapPut("/{eventId:guid}/ops-checklist", async (
    Guid eventId,
    UpdateEventOpsChecklistRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    IEventOpsChecklistService eventOpsChecklistService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var updated = eventOpsChecklistService.Update(eventId, request);
    return Results.Ok(updated);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops-checklist/artifacts", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    IEventOpsChecklistService eventOpsChecklistService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    eventOpsChecklistService.GetOrCreate(eventId);
    var baseUrl = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}";
    var links = new EventOpsArtifactLinks(
        eventId,
        $"{baseUrl}/search?q={Uri.EscapeDataString(eventId.ToString())}",
        $"{baseUrl}/table-worker?eventId={eventId:D}",
        $"{baseUrl}/admin?eventId={eventId:D}",
        $"{baseUrl}/api/events/{eventId:D}/directory",
        $"{baseUrl}/api/events/{eventId:D}/directory",
        DateTime.UtcNow);

    return Results.Ok(links);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops-checklist/recovery", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    IEventOpsChecklistService eventOpsChecklistService,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    eventOpsChecklistService.GetOrCreate(eventId);
    var bracketIds = await dbContext.Brackets.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .Select(x => x.Id)
        .ToListAsync(cancellationToken);

    if (bracketIds.Count == 0)
    {
        return Results.Ok(Array.Empty<EventOpsRecoverySnapshot>());
    }

    var matchesForEvent = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .OrderByDescending(x => x.Status == MatchStatus.OnMat)
        .ThenByDescending(x => x.Status == MatchStatus.InTheHole)
        .ThenBy(x => x.MatNumber)
        .ThenBy(x => x.Round)
        .ThenBy(x => x.MatchNumber)
        .ToListAsync(cancellationToken);

    var baseUrl = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}";
    var recoveryRows = matchesForEvent
        .Select(match =>
        {
            var board = liveMatScoringService.GetOrCreate(match);
            return new EventOpsRecoverySnapshot(
                match.Id,
                match.Status,
                match.MatNumber,
                match.Score,
                board.CurrentPeriod,
                board.ClockSecondsRemaining,
                board.ClockRunning,
                match.WinnerAthleteId,
                $"{baseUrl}/mat-scoring?matchId={match.Id:D}",
                board.UpdatedUtc);
        })
        .ToList();

    return Results.Ok(recoveryRows);
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
                    match.BoutNumber,
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

events.MapPost("/{eventId:guid}/ops/staff-assignments", async (
    Guid eventId,
    AssignTournamentStaffRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var userExists = await dbContext.UserAccounts.AnyAsync(x => x.Id == request.UserAccountId, cancellationToken);
    if (!userExists)
    {
        return Results.BadRequest("User not found.");
    }

    var normalizedRole = ApiSecurityHelpers.NormalizeRole(request.Role);
    if (normalizedRole is not (UserRole.MatWorker or UserRole.Coach or UserRole.TournamentDirector))
    {
        return Results.BadRequest("Staff assignment role must be MatWorker, Coach, or TournamentDirector.");
    }

    var assignment = await dbContext.TournamentStaffAssignments
        .FirstOrDefaultAsync(
            x => x.TournamentEventId == eventId
                 && x.UserAccountId == request.UserAccountId,
            cancellationToken);

    if (assignment is null)
    {
        assignment = new TournamentStaffAssignment
        {
            TournamentEventId = eventId,
            UserAccountId = request.UserAccountId
        };

        dbContext.TournamentStaffAssignments.Add(assignment);
    }

    assignment.Role = normalizedRole;
    assignment.CanScoreMatches = request.CanScoreMatches;
    assignment.CanManageMatches = request.CanManageMatches;
    assignment.CanManageStreams = request.CanManageStreams;

    await dbContext.SaveChangesAsync(cancellationToken);
    return Results.Ok(assignment);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops/staff-assignments", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var assignments = await dbContext.TournamentStaffAssignments
        .AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .OrderByDescending(x => x.CanScoreMatches)
        .ThenBy(x => x.Role)
        .ThenBy(x => x.UserAccountId)
        .ToListAsync(cancellationToken);

    return Results.Ok(assignments);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops/leaderboard", async (
    Guid eventId,
    [FromQuery] CompetitionLevel? level,
    [FromQuery] decimal? weightClass,
    [FromQuery] string? sortBy,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var registrations = await dbContext.EventRegistrations.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled)
        .ToListAsync(cancellationToken);

    var athleteIds = registrations.Select(x => x.AthleteProfileId).Distinct().ToList();
    if (athleteIds.Count == 0)
    {
        return Results.Ok(Array.Empty<object>());
    }

    var athletes = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x => athleteIds.Contains(x.Id))
        .ToListAsync(cancellationToken);

    var latestStats = await dbContext.AthleteStatsSnapshots.AsNoTracking()
        .Where(x => athleteIds.Contains(x.AthleteProfileId))
        .GroupBy(x => x.AthleteProfileId)
        .Select(group => group.OrderByDescending(x => x.SnapshotUtc).First())
        .ToListAsync(cancellationToken);
    var statsByAthleteId = latestStats.ToDictionary(x => x.AthleteProfileId);

    var rows = athletes
        .Where(x => level is null || x.Level == level.Value)
        .Where(x => weightClass is null || x.WeightClass == weightClass.Value)
        .Select(athlete =>
        {
            var stats = statsByAthleteId.GetValueOrDefault(athlete.Id);
            return new
            {
                AthleteId = athlete.Id,
                Name = $"{athlete.FirstName} {athlete.LastName}",
                athlete.Level,
                athlete.WeightClass,
                Wins = stats?.Wins ?? 0,
                Losses = stats?.Losses ?? 0,
                Pins = stats?.Pins ?? 0,
                TechFalls = stats?.TechFalls ?? 0,
                MajorDecisions = stats?.MajorDecisions ?? 0
            };
        })
        .ToList();

    var ordered = (sortBy ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        "techfalls" => rows.OrderByDescending(x => x.TechFalls).ThenByDescending(x => x.Wins).ThenBy(x => x.Name),
        "majordecisions" => rows.OrderByDescending(x => x.MajorDecisions).ThenByDescending(x => x.Wins).ThenBy(x => x.Name),
        "wins" => rows.OrderByDescending(x => x.Wins).ThenByDescending(x => x.Pins).ThenBy(x => x.Name),
        _ => rows.OrderByDescending(x => x.Pins).ThenByDescending(x => x.TechFalls).ThenByDescending(x => x.Wins).ThenBy(x => x.Name)
    };

    return Results.Ok(ordered.ToList());
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops/live-bouts", async (
    Guid eventId,
    [FromQuery] CompetitionLevel? level,
    [FromQuery] decimal? weightClass,
    [FromQuery] string? mat,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var brackets = await dbContext.Brackets.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .ToListAsync(cancellationToken);
    var bracketIds = brackets.Select(x => x.Id).ToHashSet();

    var matches = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .Where(x =>
            x.Status == MatchStatus.OnMat
            || x.Status == MatchStatus.InTheHole
            || x.Status == MatchStatus.Scheduled)
        .ToListAsync(cancellationToken);

    var bracketById = brackets.ToDictionary(x => x.Id);
    matches = matches
        .Where(x => level is null || bracketById.GetValueOrDefault(x.BracketId)?.Level == level.Value)
        .Where(x => weightClass is null || bracketById.GetValueOrDefault(x.BracketId)?.WeightClass == weightClass.Value)
        .Where(x => string.IsNullOrWhiteSpace(mat) || string.Equals((x.MatNumber ?? "Unassigned").Trim(), mat.Trim(), StringComparison.OrdinalIgnoreCase))
        .ToList();

    var athleteIds = matches
        .SelectMany(x => new[] { x.AthleteAId, x.AthleteBId })
        .Where(x => x is not null)
        .Select(x => x!.Value)
        .Distinct()
        .ToList();
    var athletesById = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x => athleteIds.Contains(x.Id))
        .ToDictionaryAsync(x => x.Id, cancellationToken);

    var rows = matches
        .OrderByDescending(x => x.Status == MatchStatus.OnMat)
        .ThenByDescending(x => x.Status == MatchStatus.InTheHole)
        .ThenBy(x => string.IsNullOrWhiteSpace(x.MatNumber))
        .ThenBy(x => x.MatNumber)
        .ThenBy(x => x.BoutNumber ?? x.MatchNumber)
        .Select(match =>
        {
            var bracket = bracketById.GetValueOrDefault(match.BracketId);
            return new
            {
                match.Id,
                BoutNumber = match.BoutNumber ?? match.MatchNumber,
                match.Round,
                match.Status,
                MatNumber = string.IsNullOrWhiteSpace(match.MatNumber) ? "Unassigned" : match.MatNumber,
                DivisionLevel = bracket?.Level,
                DivisionWeight = bracket?.WeightClass,
                AthleteA = BuildAthleteLabel(match.AthleteAId, athletesById),
                AthleteB = BuildAthleteLabel(match.AthleteBId, athletesById),
                match.Score,
                match.ResultMethod
            };
        })
        .ToList();

    return Results.Ok(rows);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/ops/brackets/completed", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var brackets = await dbContext.Brackets.AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .OrderBy(x => x.Level)
        .ThenBy(x => x.WeightClass)
        .ToListAsync(cancellationToken);
    var bracketIds = brackets.Select(x => x.Id).ToHashSet();

    var completedMatches = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .Where(x => x.Status == MatchStatus.Completed)
        .OrderBy(x => x.Round)
        .ThenBy(x => x.BoutNumber ?? x.MatchNumber)
        .ToListAsync(cancellationToken);

    var rows = brackets.Select(bracket =>
    {
        var matchesForBracket = completedMatches.Where(x => x.BracketId == bracket.Id).ToList();
        return new
        {
            BracketId = bracket.Id,
            bracket.Level,
            bracket.WeightClass,
            CompletedBoutCount = matchesForBracket.Count,
            Matches = matchesForBracket.Select(match => new
            {
                match.Id,
                BoutNumber = match.BoutNumber ?? match.MatchNumber,
                match.Round,
                match.Score,
                match.ResultMethod
            }).ToList()
        };
    }).Where(x => x.CompletedBoutCount > 0).ToList();

    return Results.Ok(rows);
}).RequireAuthorization("EventOps");

events.MapDelete("/{eventId:guid}", async (
    Guid eventId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var tournamentEvent = await dbContext.TournamentEvents.FirstOrDefaultAsync(x => x.Id == eventId, cancellationToken);
    if (tournamentEvent is null)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    var paidRegistrationExists = await dbContext.EventRegistrations.AnyAsync(
        x => x.TournamentEventId == eventId
             && x.Status != RegistrationStatus.Cancelled
             && x.PaymentStatus == PaymentStatus.Paid,
        cancellationToken);

    if (paidRegistrationExists)
    {
        return Results.Conflict("Event cannot be cancelled because paid registrations exist.");
    }

    var registrations = await dbContext.EventRegistrations
        .Where(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled)
        .ToListAsync(cancellationToken);
    foreach (var registration in registrations)
    {
        registration.Status = RegistrationStatus.Cancelled;
    }

    tournamentEvent.IsPublished = false;
    if (tournamentEvent.EndUtc > DateTime.UtcNow)
    {
        tournamentEvent.EndUtc = DateTime.UtcNow;
    }

    await dbContext.SaveChangesAsync(cancellationToken);
    return Results.Ok(new
    {
        EventId = eventId,
        Cancelled = true,
        CancelledRegistrations = registrations.Count
    });
}).RequireAuthorization("EventOps");

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

    if (!released)
    {
        var canViewUnreleased = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken)
                                || await ApiSecurityHelpers.CanScoreEventAsync(dbContext, httpContext.User, eventId, cancellationToken);
        if (!canViewUnreleased)
        {
            return Results.Forbid();
        }
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
            match.BoutNumber,
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

events.MapGet("/{eventId:guid}/live-hub", async (
    Guid eventId,
    [FromQuery] CompetitionLevel? level,
    [FromQuery] decimal? weightClass,
    [FromQuery] string? mat,
    [FromQuery] string? sortBy,
    WrestlingPlatformDbContext dbContext,
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
    var bracketIds = brackets.Select(x => x.Id).ToHashSet();
    var bracketById = brackets.ToDictionary(x => x.Id);

    var matches = await dbContext.Matches.AsNoTracking()
        .Where(x => bracketIds.Contains(x.BracketId))
        .ToListAsync(cancellationToken);

    matches = matches
        .Where(x => level is null || bracketById.GetValueOrDefault(x.BracketId)?.Level == level.Value)
        .Where(x => weightClass is null || bracketById.GetValueOrDefault(x.BracketId)?.WeightClass == weightClass.Value)
        .Where(x => string.IsNullOrWhiteSpace(mat) || string.Equals((x.MatNumber ?? "Unassigned").Trim(), mat.Trim(), StringComparison.OrdinalIgnoreCase))
        .ToList();

    var ordered = (sortBy ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        "status" => matches.OrderByDescending(x => x.Status == MatchStatus.OnMat)
            .ThenByDescending(x => x.Status == MatchStatus.InTheHole)
            .ThenBy(x => x.BoutNumber ?? x.MatchNumber)
            .ToList(),
        "round" => matches.OrderBy(x => x.Round).ThenBy(x => x.BoutNumber ?? x.MatchNumber).ToList(),
        _ => matches.OrderBy(x => x.BoutNumber ?? x.MatchNumber).ThenBy(x => x.Round).ToList()
    };

    var mats = ordered
        .GroupBy(x => string.IsNullOrWhiteSpace(x.MatNumber) ? "Unassigned" : x.MatNumber!.Trim())
        .OrderBy(x => x.Key == "Unassigned" ? 1 : 0)
        .ThenBy(x => x.Key)
        .Select(group => new
        {
            Mat = group.Key,
            OnMat = group.Count(x => x.Status == MatchStatus.OnMat),
            InTheHole = group.Count(x => x.Status == MatchStatus.InTheHole),
            Scheduled = group.Count(x => x.Status == MatchStatus.Scheduled),
            Bouts = group.Select(x => new
            {
                x.Id,
                BoutNumber = x.BoutNumber ?? x.MatchNumber,
                x.Round,
                x.Status,
                x.Score,
                x.ResultMethod
            }).ToList()
        })
        .ToList();

    return Results.Ok(new
    {
        Event = new { tournamentEvent.Id, tournamentEvent.Name, tournamentEvent.StartUtc, tournamentEvent.EndUtc },
        Filters = new { level, weightClass, Mat = mat, SortBy = sortBy },
        AvailableLevels = brackets.Select(x => x.Level).Distinct().OrderBy(x => x).ToList(),
        AvailableWeights = brackets.Select(x => x.WeightClass).Distinct().OrderBy(x => x).ToList(),
        Mats = mats,
        TotalBouts = ordered.Count,
        OnMat = ordered.Count(x => x.Status == MatchStatus.OnMat)
    });
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
    HttpContext httpContext,
    ITournamentControlService tournamentControlService,
    IEventOpsChecklistService eventOpsChecklistService,
    IBracketService bracketService,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManageOps)
    {
        return Results.Forbid();
    }

    if (!eventOpsChecklistService.CanGenerateBrackets(eventId, out var checklistReason))
    {
        return Results.BadRequest(checklistReason);
    }

    var mode = request.Mode == BracketGenerationMode.Manual
        ? tournamentControlService.ResolveGenerationMode(eventId, request.Mode)
        : request.Mode;

    var result = await bracketService.GenerateAsync(
        new BracketGenerationInput(eventId, request.Level, request.WeightClass, mode, request.DivisionId),
        cancellationToken);

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(x => x.TournamentEventId == eventId && x.Status != RegistrationStatus.Cancelled, cancellationToken);
    tournamentControlService.GetOrCreate(eventId, registrantCount);
    eventOpsChecklistService.MarkBracketsGenerated(eventId);
    await AssignBoutNumbersAsync(eventId, dbContext, cancellationToken);

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
    if (!tournamentControlService.AreBracketsReleased(eventId, DateTime.UtcNow))
    {
        var canViewUnreleased = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken)
                                || await ApiSecurityHelpers.CanScoreEventAsync(dbContext, httpContext.User, eventId, cancellationToken);
        if (!canViewUnreleased)
        {
            return Results.Ok(Array.Empty<object>());
        }
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

api.MapGet("/search/global", async (
    [FromQuery] string? q,
    [FromQuery] int? take,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var queryText = q?.Trim() ?? string.Empty;
    if (queryText.Length < 2)
    {
        return Results.Ok(new GlobalSearchResponse(queryText, 0, []));
    }

    var safeTake = take is null or < 1 or > 60 ? 24 : take.Value;
    var queryLower = queryText.ToLowerInvariant();
    var athletePoolSize = safeTake * 2;
    var results = new List<GlobalSearchResultItem>(safeTake * 2);

    var athleteRows = await dbContext.AthleteProfiles.AsNoTracking()
        .Where(x =>
            (x.FirstName + " " + x.LastName).ToLower().Contains(queryLower)
            || x.City.ToLower().Contains(queryLower)
            || x.State.ToLower().Contains(queryLower)
            || (x.SchoolOrClubName ?? string.Empty).ToLower().Contains(queryLower))
        .OrderBy(x => x.LastName)
        .ThenBy(x => x.FirstName)
        .Take(athletePoolSize)
        .ToListAsync(cancellationToken);

    results.AddRange(athleteRows.Select(athlete => new GlobalSearchResultItem(
        GlobalSearchEntityType.Athlete,
        athlete.Id,
        $"{athlete.FirstName} {athlete.LastName}",
        $"{athlete.Level} | {athlete.WeightClass:0.#} lbs | {athlete.City}, {athlete.State}",
        "/athlete",
        State: athlete.State,
        City: athlete.City,
        Badge: "Athlete")));

    var coachRows = await dbContext.CoachProfiles.AsNoTracking()
        .Where(x =>
            (x.FirstName + " " + x.LastName).ToLower().Contains(queryLower)
            || x.City.ToLower().Contains(queryLower)
            || x.State.ToLower().Contains(queryLower)
            || (x.Bio ?? string.Empty).ToLower().Contains(queryLower))
        .OrderBy(x => x.LastName)
        .ThenBy(x => x.FirstName)
        .Take(Math.Max(8, safeTake / 2))
        .ToListAsync(cancellationToken);

    results.AddRange(coachRows.Select(coach => new GlobalSearchResultItem(
        GlobalSearchEntityType.Coach,
        coach.Id,
        $"{coach.FirstName} {coach.LastName}",
        $"Coach | {coach.City}, {coach.State}",
        "/coach",
        State: coach.State,
        City: coach.City,
        Badge: "Coach")));

    var teamRows = await dbContext.Teams.AsNoTracking()
        .Where(x =>
            x.Name.ToLower().Contains(queryLower)
            || x.City.ToLower().Contains(queryLower)
            || x.State.ToLower().Contains(queryLower))
        .OrderBy(x => x.Name)
        .Take(Math.Max(10, safeTake))
        .ToListAsync(cancellationToken);

    results.AddRange(teamRows.Select(team => new GlobalSearchResultItem(
        GlobalSearchEntityType.Team,
        team.Id,
        team.Name,
        $"{team.Type} | {team.City}, {team.State}",
        "/coach",
        State: team.State,
        City: team.City,
        Badge: team.Type.ToString())));

    var eventRows = await dbContext.TournamentEvents.AsNoTracking()
        .Where(x =>
            x.Name.ToLower().Contains(queryLower)
            || x.City.ToLower().Contains(queryLower)
            || x.State.ToLower().Contains(queryLower)
            || x.Venue.ToLower().Contains(queryLower))
        .OrderBy(x => x.StartUtc)
        .Take(Math.Max(12, safeTake))
        .ToListAsync(cancellationToken);

    results.AddRange(eventRows.Select(tournamentEvent => new GlobalSearchResultItem(
        GlobalSearchEntityType.Tournament,
        tournamentEvent.Id,
        tournamentEvent.Name,
        $"{tournamentEvent.City}, {tournamentEvent.State} | {tournamentEvent.StartUtc.ToLocalTime():MMM dd, yyyy}",
        "/tournaments",
        tournamentEvent.StartUtc,
        tournamentEvent.State,
        tournamentEvent.City,
        Badge: "Tournament")));

    var streamRows = await dbContext.StreamSessions.AsNoTracking()
        .Where(x =>
            x.DeviceName.ToLower().Contains(queryLower)
            || x.PlaybackUrl.ToLower().Contains(queryLower))
        .OrderByDescending(x => x.StartedUtc)
        .Take(Math.Max(8, safeTake / 2))
        .ToListAsync(cancellationToken);

    results.AddRange(streamRows.Select(stream => new GlobalSearchResultItem(
        GlobalSearchEntityType.Stream,
        stream.Id,
        stream.DeviceName,
        $"Stream {stream.Status} | Event {stream.TournamentEventId.ToString()[..8]}",
        "/live",
        stream.StartedUtc,
        Badge: "Live Stream")));

    var matchRows = await dbContext.Matches.AsNoTracking()
        .Where(x =>
            (x.MatNumber ?? string.Empty).ToLower().Contains(queryLower)
            || (x.ResultMethod ?? string.Empty).ToLower().Contains(queryLower)
            || (x.Score ?? string.Empty).ToLower().Contains(queryLower))
        .OrderByDescending(x => x.CompletedUtc)
        .Take(Math.Max(8, safeTake / 2))
        .ToListAsync(cancellationToken);

    results.AddRange(matchRows.Select(match => new GlobalSearchResultItem(
        GlobalSearchEntityType.Match,
        match.Id,
        $"Bout {(match.BoutNumber ?? match.MatchNumber)} - Round {match.Round}",
        $"{match.Status} | Mat {(string.IsNullOrWhiteSpace(match.MatNumber) ? "Unassigned" : match.MatNumber)} | Score {match.Score ?? "N/A"}",
        "/mat-scoring",
        match.CompletedUtc ?? match.ScheduledUtc,
        Badge: "Match")));

    var ordered = results
        .OrderByDescending(item => ScoreSearchHit(item.Title, queryLower))
        .ThenByDescending(item => ScoreSearchHit(item.Subtitle, queryLower))
        .ThenByDescending(item => item.DateUtc)
        .ThenBy(item => item.Title)
        .Take(safeTake)
        .ToList();

    return Results.Ok(new GlobalSearchResponse(queryText, ordered.Count, ordered));
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
}).RequireAuthorization("MatScoring");

var matches = api.MapGroup("/matches").RequireAuthorization();
matches.MapPost("/{matchId:guid}/assign-mat", async (
    Guid matchId,
    AssignMatRequest request,
    HttpContext httpContext,
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

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, tournamentEventId, cancellationToken);
    var currentUserId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    var canManageMatchOps = currentUserId is not null && await dbContext.TournamentStaffAssignments.AsNoTracking()
        .AnyAsync(
            x => x.TournamentEventId == tournamentEventId
                 && x.UserAccountId == currentUserId.Value
                 && (x.CanManageMatches || x.CanScoreMatches),
            cancellationToken);
    if (!canManageOps && !canManageMatchOps)
    {
        return Results.Forbid();
    }

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
    HttpContext httpContext,
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

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, tournamentEventId, cancellationToken);
    var currentUserId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    var canManageMatchOps = currentUserId is not null && await dbContext.TournamentStaffAssignments.AsNoTracking()
        .AnyAsync(
            x => x.TournamentEventId == tournamentEventId
                 && x.UserAccountId == currentUserId.Value
                 && (x.CanManageMatches || x.CanScoreMatches),
            cancellationToken);
    if (!canManageOps && !canManageMatchOps)
    {
        return Results.Forbid();
    }

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

    var outcomeMessage = $"Bout {(match.BoutNumber ?? match.MatchNumber)} final: {request.Score} via {request.ResultMethod}.";
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
    ITournamentControlService tournamentControlService,
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
        var controls = tournamentControlService.GetOrCreate(bracket.TournamentEventId, 0);
        var configuredRules = BuildScoringRequestFromPreset(bracket, controls);
        liveMatScoringService.Configure(
            match,
            configuredRules);
    }

    return Results.Ok(liveMatScoringService.GetRules(match));
}).AllowAnonymous();

matches.MapPost("/{matchId:guid}/scoreboard/rules", async (
    Guid matchId,
    ConfigureMatchScoringRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ILiveMatScoringService liveMatScoringService,
    CancellationToken cancellationToken) =>
{
    var match = await dbContext.Matches.AsNoTracking().FirstOrDefaultAsync(x => x.Id == matchId, cancellationToken);
    if (match is null)
    {
        return Results.NotFound("Match not found.");
    }

    var canScoreMatch = await ApiSecurityHelpers.CanScoreMatchAsync(dbContext, httpContext.User, matchId, cancellationToken);
    if (!canScoreMatch)
    {
        return Results.Forbid();
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
}).RequireAuthorization("MatScoring");

matches.MapPost("/{matchId:guid}/scoreboard/clock", async (
    Guid matchId,
    ControlMatchClockRequest request,
    HttpContext httpContext,
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

    var canScoreMatch = await ApiSecurityHelpers.CanScoreMatchAsync(dbContext, httpContext.User, matchId, cancellationToken);
    if (!canScoreMatch)
    {
        return Results.Forbid();
    }

    var tournamentEventId = await dbContext.Brackets
        .Where(x => x.Id == match.BracketId)
        .Select(x => x.TournamentEventId)
        .FirstOrDefaultAsync(cancellationToken);

    MatScoreboardSnapshot scoreboard;
    try
    {
        scoreboard = liveMatScoringService.ControlClock(match, request);
    }
    catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidOperationException)
    {
        return Results.BadRequest(ex.Message);
    }

    var shouldSave = false;
    if (scoreboard.Status == MatchStatus.OnMat && match.Status != MatchStatus.OnMat)
    {
        match.Status = MatchStatus.OnMat;
        shouldSave = true;
    }

    if (scoreboard.IsFinal && scoreboard.WinnerAthleteId is not null && match.Status != MatchStatus.Completed)
    {
        match.WinnerAthleteId = scoreboard.WinnerAthleteId;
        match.Score = $"{scoreboard.AthleteAScore}-{scoreboard.AthleteBScore}";
        match.ResultMethod = scoreboard.OutcomeReason ?? "Decision";
        match.Status = MatchStatus.Completed;
        match.CompletedUtc = DateTime.UtcNow;
        shouldSave = true;
    }

    if (shouldSave)
    {
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    await hubContext.Clients.Group(MatchOpsHubGroups.ForMatch(matchId))
        .SendAsync("scoreboardUpdated", scoreboard, cancellationToken);
    if (tournamentEventId != Guid.Empty)
    {
        await hubContext.Clients.Group(MatchOpsHubGroups.ForEvent(tournamentEventId))
            .SendAsync("scoreboardUpdated", scoreboard, cancellationToken);
    }

    return Results.Ok(scoreboard);
}).RequireAuthorization("MatScoring");

api.MapGet("/scoring/rules", (
    [FromQuery] WrestlingStyle? style,
    [FromQuery] CompetitionLevel? level,
    [FromQuery] ScoringPreset? preset,
    ILiveMatScoringService liveMatScoringService) =>
{
    var selectedStyle = style ?? WrestlingStyle.Folkstyle;
    var selectedLevel = level ?? CompetitionLevel.HighSchool;
    var selectedPreset = preset ?? ScoringPreset.NfhsHighSchool;
    var fallbackMatch = new Match
    {
        Id = Guid.Empty,
        Status = MatchStatus.Scheduled
    };

    var seededRequest = BuildPresetScoringRequest(
        selectedPreset,
        selectedStyle,
        selectedLevel,
        strictEnforcement: true);
    var rules = liveMatScoringService.Configure(
        fallbackMatch,
        seededRequest);

    return Results.Ok(rules with { MatchId = Guid.Empty });
}).AllowAnonymous();

matches.MapPost("/{matchId:guid}/scoreboard/events", async (
    Guid matchId,
    AddMatScoreEventRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    ITournamentControlService tournamentControlService,
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

    var canScoreMatch = await ApiSecurityHelpers.CanScoreMatchAsync(dbContext, httpContext.User, matchId, cancellationToken);
    if (!canScoreMatch)
    {
        return Results.Forbid();
    }

    var bracket = await dbContext.Brackets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == match.BracketId, cancellationToken);
    var tournamentEventId = bracket?.TournamentEventId ?? Guid.Empty;
    if (bracket is not null)
    {
        var controls = tournamentControlService.GetOrCreate(bracket.TournamentEventId, 0);
        var configuredRules = BuildScoringRequestFromPreset(bracket, controls);
        liveMatScoringService.Configure(
            match,
            configuredRules);
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

        var outcomeMessage = $"Bout {(match.BoutNumber ?? match.MatchNumber)} final: {match.Score} via {match.ResultMethod}.";
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
}).RequireAuthorization("MatScoring");

matches.MapPost("/{matchId:guid}/scoreboard/reset", async (
    Guid matchId,
    ResetMatScoreboardRequest request,
    HttpContext httpContext,
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

    var canScoreMatch = await ApiSecurityHelpers.CanScoreMatchAsync(dbContext, httpContext.User, matchId, cancellationToken);
    if (!canScoreMatch)
    {
        return Results.Forbid();
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
}).RequireAuthorization("MatScoring");

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
            NormalizePlaybackUrlForClient(stream?.PlaybackUrl, match.Id, stream?.Id ?? match.Id, samplePlaybackUrls),
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
    var profile = await BuildAthleteNilProfileAsync(athleteId, dbContext, nilOverridesByAthlete, cancellationToken);
    return profile is null ? Results.NotFound("Athlete not found.") : Results.Ok(profile);
}).AllowAnonymous();

athletes.MapPut("/{athleteId:guid}/nil-profile", async (
    Guid athleteId,
    UpdateAthleteNilProfileRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var canManageAthlete = await ApiSecurityHelpers.CanManageAthleteProfileAsync(dbContext, httpContext.User, athleteId, cancellationToken);
    if (!canManageAthlete)
    {
        return Results.Forbid();
    }

    var athleteExists = await dbContext.AthleteProfiles
        .AsNoTracking()
        .AnyAsync(x => x.Id == athleteId, cancellationToken);
    if (!athleteExists)
    {
        return Results.NotFound("Athlete not found.");
    }

    nilOverridesByAthlete[athleteId] = NormalizeNilProfileUpdate(request);
    var profile = await BuildAthleteNilProfileAsync(athleteId, dbContext, nilOverridesByAthlete, cancellationToken);
    return Results.Ok(profile);
}).RequireAuthorization();

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

var nil = api.MapGroup("/nil");
nil.MapGet("/policy", () =>
{
    return Results.Ok(BuildNilPolicyResponse());
}).AllowAnonymous();

var help = api.MapGroup("/help");
help.MapGet("/faqs", ([FromQuery] string? q) =>
{
    var query = q?.Trim();
    var faqs = GetHelpFaqItems();

    if (!string.IsNullOrWhiteSpace(query))
    {
        var normalized = query.ToLowerInvariant();
        faqs = faqs
            .Where(item =>
                item.Question.Contains(query, StringComparison.OrdinalIgnoreCase)
                || item.Answer.Contains(query, StringComparison.OrdinalIgnoreCase)
                || item.Category.Contains(query, StringComparison.OrdinalIgnoreCase)
                || item.SearchTags.Any(tag => tag.Contains(normalized, StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    return Results.Ok(faqs);
}).AllowAnonymous();

help.MapGet("/guide", () =>
{
    return Results.Ok(GetSupportGuideSteps());
}).AllowAnonymous();

help.MapPost("/chat", (HelpChatRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Message))
    {
        return Results.BadRequest("Message is required.");
    }

    var response = BuildHelpChatResponse(request.Message, request.Context);
    return Results.Ok(response);
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

    if (request.TournamentEventId is not null)
    {
        var eventExists = await dbContext.TournamentEvents.AsNoTracking()
            .AnyAsync(x => x.Id == request.TournamentEventId.Value, cancellationToken);
        if (!eventExists)
        {
            return Results.BadRequest("Tournament event not found.");
        }
    }

    if (request.AthleteProfileId is not null)
    {
        var athleteExists = await dbContext.AthleteProfiles.AsNoTracking()
            .AnyAsync(x => x.Id == request.AthleteProfileId.Value, cancellationToken);
        if (!athleteExists)
        {
            return Results.BadRequest("Athlete profile not found.");
        }
    }

    if (request.TournamentEventId is not null && request.AthleteProfileId is not null)
    {
        var athleteRegisteredForEvent = await dbContext.EventRegistrations.AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == request.TournamentEventId.Value
                     && x.AthleteProfileId == request.AthleteProfileId.Value
                     && x.Status != RegistrationStatus.Cancelled,
                cancellationToken);
        if (!athleteRegisteredForEvent)
        {
            return Results.BadRequest("Athlete is not currently registered in that tournament.");
        }
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

var streams = api.MapGroup("/streams").RequireAuthorization();
streams.MapGet("/samples", () =>
{
    var samples = samplePlaybackUrls
        .Select((url, index) => new
        {
            Name = $"Sample Playback {index + 1}",
            Url = url
        })
        .ToList();

    return Results.Ok(samples);
}).AllowAnonymous();

events.MapPut("/{eventId:guid}/streaming/permissions", async (
    Guid eventId,
    SetAthleteStreamingPermissionRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var athleteInEvent = await dbContext.EventRegistrations.AsNoTracking()
        .AnyAsync(
            x => x.TournamentEventId == eventId
                 && x.AthleteProfileId == request.AthleteProfileId
                 && x.Status != RegistrationStatus.Cancelled,
            cancellationToken);
    if (!athleteInEvent)
    {
        return Results.BadRequest("Athlete must be registered for the selected tournament.");
    }

    var canManage = await ApiSecurityHelpers.CanManageStreamingDelegationAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManage)
    {
        return Results.Forbid();
    }

    var currentUserId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    if (currentUserId is null)
    {
        return Results.Unauthorized();
    }

    var isParentGuardian = ApiSecurityHelpers.IsInRole(httpContext.User, UserRole.ParentGuardian, UserRole.Parent);
    if (isParentGuardian
        && request.ParentGuardianUserAccountId is not null
        && request.ParentGuardianUserAccountId.Value != currentUserId.Value)
    {
        return Results.Forbid();
    }

    var parentUserId = request.ParentGuardianUserAccountId ?? currentUserId.Value;
    var parentExists = await dbContext.UserAccounts.AnyAsync(x => x.Id == parentUserId, cancellationToken);
    if (!parentExists)
    {
        return Results.BadRequest("Parent/guardian user was not found.");
    }

    var delegateExists = await dbContext.UserAccounts.AnyAsync(x => x.Id == request.DelegateUserAccountId, cancellationToken);
    if (!delegateExists)
    {
        return Results.BadRequest("Delegate user was not found.");
    }

    var permission = await dbContext.AthleteStreamingPermissions
        .FirstOrDefaultAsync(
            x => x.AthleteProfileId == request.AthleteProfileId
                 && x.DelegateUserAccountId == request.DelegateUserAccountId,
            cancellationToken);

    if (permission is null)
    {
        permission = new AthleteStreamingPermission
        {
            AthleteProfileId = request.AthleteProfileId,
            ParentGuardianUserAccountId = parentUserId,
            DelegateUserAccountId = request.DelegateUserAccountId,
            IsActive = request.IsActive
        };

        dbContext.AthleteStreamingPermissions.Add(permission);
    }
    else
    {
        permission.ParentGuardianUserAccountId = parentUserId;
        permission.IsActive = request.IsActive;
    }

    await dbContext.SaveChangesAsync(cancellationToken);
    return Results.Ok(permission);
}).RequireAuthorization();

events.MapGet("/{eventId:guid}/streaming/permissions/{athleteId:guid}", async (
    Guid eventId,
    Guid athleteId,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var canManage = await ApiSecurityHelpers.CanManageStreamingDelegationAsync(dbContext, httpContext.User, eventId, cancellationToken);
    if (!canManage)
    {
        return Results.Forbid();
    }

    var permissions = await dbContext.AthleteStreamingPermissions.AsNoTracking()
        .Where(x => x.AthleteProfileId == athleteId && x.IsActive)
        .OrderBy(x => x.ParentGuardianUserAccountId)
        .ThenBy(x => x.DelegateUserAccountId)
        .ToListAsync(cancellationToken);

    return Results.Ok(permissions);
}).RequireAuthorization();

events.MapPost("/{eventId:guid}/streams", async (
    Guid eventId,
    CreateStreamSessionRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    var eventExists = await dbContext.TournamentEvents.AnyAsync(x => x.Id == eventId, cancellationToken);
    if (!eventExists)
    {
        return Results.NotFound("Event not found.");
    }

    var currentUserId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    if (currentUserId is null)
    {
        return Results.Unauthorized();
    }

    if (request.IsPersonalStream)
    {
        if (request.AthleteProfileId is null)
        {
            return Results.BadRequest("AthleteProfileId is required for personal streaming.");
        }

        var athleteInEvent = await dbContext.EventRegistrations.AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == eventId
                     && x.AthleteProfileId == request.AthleteProfileId.Value
                     && x.Status != RegistrationStatus.Cancelled,
                cancellationToken);
        if (!athleteInEvent)
        {
            return Results.BadRequest("Athlete must be registered for this tournament.");
        }

        var isParentGuardian = ApiSecurityHelpers.IsInRole(httpContext.User, UserRole.ParentGuardian, UserRole.Parent);
        if (!isParentGuardian)
        {
            var delegated = await dbContext.AthleteStreamingPermissions.AsNoTracking()
                .AnyAsync(
                    x => x.AthleteProfileId == request.AthleteProfileId.Value
                         && x.DelegateUserAccountId == currentUserId.Value
                         && x.IsActive
                         && (request.DelegatedByUserAccountId == null || x.ParentGuardianUserAccountId == request.DelegatedByUserAccountId.Value),
                    cancellationToken);
            if (!delegated)
            {
                return Results.Forbid();
            }
        }

        var hasActivePersonalStream = await dbContext.StreamSessions.AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == eventId
                     && x.AthleteProfileId == request.AthleteProfileId.Value
                     && x.IsPersonalStream
                     && x.Status == StreamStatus.Live,
                cancellationToken);
        if (hasActivePersonalStream)
        {
            return Results.Conflict("Only one personal stream can be live for this athlete at a time.");
        }
    }
    else
    {
        var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, eventId, cancellationToken);
        var canManageStreams = await dbContext.TournamentStaffAssignments.AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == eventId
                     && x.UserAccountId == currentUserId.Value
                     && x.CanManageStreams,
                cancellationToken);

        if (!canManageOps && !canManageStreams)
        {
            return Results.Forbid();
        }
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

    var streamId = Guid.NewGuid();
    var playbackUrl = NormalizePlaybackUrlForClient(request.SourceUrl, eventId, streamId, samplePlaybackUrls);

    var stream = new StreamSession
    {
        Id = streamId,
        TournamentEventId = eventId,
        MatchId = request.MatchId,
        AthleteProfileId = request.AthleteProfileId,
        RequestedByUserAccountId = currentUserId,
        DelegatedByUserAccountId = request.DelegatedByUserAccountId,
        IsPersonalStream = request.IsPersonalStream,
        SaveToAthleteProfile = request.SaveToAthleteProfile,
        IsPrivate = request.IsPrivate,
        DeviceName = $"{normalizedDeviceName} [{normalizedProtocol}]",
        IngestKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace("/", "_").Replace("+", "-"),
        PlaybackUrl = playbackUrl,
        Status = StreamStatus.Provisioned
    };

    dbContext.StreamSessions.Add(stream);
    await dbContext.SaveChangesAsync(cancellationToken);

    return Results.Created($"/api/streams/{stream.Id}", stream);
}).RequireAuthorization();

streams.MapPost("/{streamId:guid}/status", async (
    Guid streamId,
    UpdateStreamStatusRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
    IMediaPipelineService mediaPipelineService,
    CancellationToken cancellationToken) =>
{
    var stream = await dbContext.StreamSessions.FirstOrDefaultAsync(x => x.Id == streamId, cancellationToken);
    if (stream is null)
    {
        return Results.NotFound("Stream not found.");
    }

    var currentUserId = ApiSecurityHelpers.GetAuthenticatedUserId(httpContext.User);
    if (currentUserId is null)
    {
        return Results.Unauthorized();
    }

    var canManageOps = await ApiSecurityHelpers.CanManageTournamentOpsAsync(dbContext, httpContext.User, stream.TournamentEventId, cancellationToken);
    if (stream.IsPersonalStream)
    {
        var canControlPersonalStream = canManageOps
                                       || stream.RequestedByUserAccountId == currentUserId.Value
                                       || stream.DelegatedByUserAccountId == currentUserId.Value;
        if (!canControlPersonalStream)
        {
            return Results.Forbid();
        }
    }
    else
    {
        var canManageStreams = await dbContext.TournamentStaffAssignments.AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == stream.TournamentEventId
                     && x.UserAccountId == currentUserId.Value
                     && x.CanManageStreams,
                cancellationToken);
        if (!canManageOps && !canManageStreams)
        {
            return Results.Forbid();
        }
    }

    stream.Status = request.Status;
    stream.StartedUtc = request.Status == StreamStatus.Live ? DateTime.UtcNow : stream.StartedUtc;
    stream.EndedUtc = request.Status == StreamStatus.Ended ? DateTime.UtcNow : stream.EndedUtc;

    await dbContext.SaveChangesAsync(cancellationToken);

    if (request.Status == StreamStatus.Ended
        && stream.IsPersonalStream
        && stream.SaveToAthleteProfile
        && stream.AthleteProfileId is not null
        && stream.MatchId is not null)
    {
        mediaPipelineService.CreateVideoAsset(new CreateVideoAssetRequest(
            stream.AthleteProfileId.Value,
            stream.MatchId.Value,
            stream.Id,
            stream.PlaybackUrl,
            QueueTranscode: true));
    }

    stream.PlaybackUrl = NormalizePlaybackUrlForClient(stream.PlaybackUrl, stream.TournamentEventId, stream.Id, samplePlaybackUrls);
    return Results.Ok(stream);
});

events.MapGet("/{eventId:guid}/streams/active", async (Guid eventId, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    var streamsForEvent = await dbContext.StreamSessions
        .AsNoTracking()
        .Where(x => x.TournamentEventId == eventId && x.Status == StreamStatus.Live)
        .OrderBy(x => x.CreatedUtc)
        .ToListAsync(cancellationToken);

    foreach (var stream in streamsForEvent)
    {
        stream.PlaybackUrl = NormalizePlaybackUrlForClient(stream.PlaybackUrl, eventId, stream.Id, samplePlaybackUrls);
    }

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

await PrimeDemoTournamentControlStateAsync(app.Services);

app.Run();

static async Task PrimeDemoTournamentControlStateAsync(IServiceProvider services)
{
    using var scope = services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
    var controlService = scope.ServiceProvider.GetRequiredService<ITournamentControlService>();

    var youthPoolEvent = await dbContext.TournamentEvents
        .AsNoTracking()
        .Where(evt => evt.Name == "Ohio Youth State Preview")
        .Select(evt => new { evt.Id })
        .FirstOrDefaultAsync();

    if (youthPoolEvent is null)
    {
        return;
    }

    var registrantCount = await dbContext.EventRegistrations
        .CountAsync(registration =>
            registration.TournamentEventId == youthPoolEvent.Id
            && registration.Status != RegistrationStatus.Cancelled);

    controlService.Update(
        youthPoolEvent.Id,
        registrantCount,
        new UpdateTournamentControlSettingsRequest(
            TournamentFormat.MadisonPool,
            BracketReleaseMode.Immediate,
            BracketReleaseUtc: null,
            BracketCreationMode.Seeded,
            RegistrationCapEnabled: false,
            RegistrationCap: null));

    controlService.ReleaseBrackets(youthPoolEvent.Id, registrantCount);
    await AssignBoutNumbersAsync(youthPoolEvent.Id, dbContext, CancellationToken.None);
}

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

static async Task InitializeDemoRuntimeStateAsync(
    IServiceProvider services,
    ILogger logger,
    IReadOnlyList<string> samplePlaybackUrls,
    CancellationToken cancellationToken)
{
    try
    {
        await using var scope = services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
        var controlsService = scope.ServiceProvider.GetRequiredService<ITournamentControlService>();
        var mediaPipelineService = scope.ServiceProvider.GetRequiredService<IMediaPipelineService>();

        var events = await dbContext.TournamentEvents
            .AsNoTracking()
            .ToListAsync(cancellationToken);
        if (events.Count == 0)
        {
            return;
        }

        var eventIds = events.Select(x => x.Id).ToList();
        var registrantCounts = await dbContext.EventRegistrations.AsNoTracking()
            .Where(x => eventIds.Contains(x.TournamentEventId) && x.Status != RegistrationStatus.Cancelled)
            .GroupBy(x => x.TournamentEventId)
            .Select(group => new { EventId = group.Key, Count = group.Count() })
            .ToDictionaryAsync(x => x.EventId, x => x.Count, cancellationToken);

        foreach (var tournamentEvent in events)
        {
            var registrantCount = registrantCounts.GetValueOrDefault(tournamentEvent.Id);
            var name = tournamentEvent.Name;

            if (name.Contains("Youth State Preview", StringComparison.OrdinalIgnoreCase))
            {
                controlsService.Update(
                    tournamentEvent.Id,
                    registrantCount,
                    new UpdateTournamentControlSettingsRequest(
                        TournamentFormat.MadisonPool,
                        BracketReleaseMode.Immediate,
                        BracketReleaseUtc: null,
                        BracketCreationMode.Seeded,
                        RegistrationCapEnabled: true,
                        RegistrationCap: 128,
                        ScoringPreset: ScoringPreset.NfhsHighSchool,
                        StrictScoringEnforcement: true,
                        OvertimeFormat: OvertimeFormat.FolkstyleStandard,
                        MaxOvertimePeriods: 3,
                        EndOnFirstOvertimeScore: false));
                continue;
            }

            if (name.Contains("Freestyle", StringComparison.OrdinalIgnoreCase))
            {
                controlsService.Update(
                    tournamentEvent.Id,
                    registrantCount,
                    new UpdateTournamentControlSettingsRequest(
                        TournamentFormat.EliminationBracket,
                        BracketReleaseMode.Immediate,
                        BracketReleaseUtc: null,
                        BracketCreationMode.AiSeeded,
                        RegistrationCapEnabled: true,
                        RegistrationCap: 64,
                        ScoringPreset: ScoringPreset.UwwFreestyle,
                        StrictScoringEnforcement: true,
                        OvertimeFormat: OvertimeFormat.FreestyleCriteria,
                        MaxOvertimePeriods: 0,
                        EndOnFirstOvertimeScore: false));
                continue;
            }

            if (name.Contains("Greco", StringComparison.OrdinalIgnoreCase))
            {
                controlsService.Update(
                    tournamentEvent.Id,
                    registrantCount,
                    new UpdateTournamentControlSettingsRequest(
                        TournamentFormat.EliminationBracket,
                        BracketReleaseMode.Immediate,
                        BracketReleaseUtc: null,
                        BracketCreationMode.Manual,
                        RegistrationCapEnabled: true,
                        RegistrationCap: 64,
                        ScoringPreset: ScoringPreset.UwwGrecoRoman,
                        StrictScoringEnforcement: true,
                        OvertimeFormat: OvertimeFormat.GrecoCriteria,
                        MaxOvertimePeriods: 0,
                        EndOnFirstOvertimeScore: false));
            }
        }

        foreach (var tournamentEvent in events)
        {
            await AssignBoutNumbersAsync(tournamentEvent.Id, dbContext, cancellationToken);
        }

        var bracketEventById = await dbContext.Brackets.AsNoTracking()
            .ToDictionaryAsync(x => x.Id, x => x.TournamentEventId, cancellationToken);

        var completedMatches = await dbContext.Matches.AsNoTracking()
            .Where(x => x.Status == MatchStatus.Completed || x.Status == MatchStatus.Forfeit)
            .OrderByDescending(x => x.CompletedUtc)
            .Take(40)
            .ToListAsync(cancellationToken);

        if (completedMatches.Count == 0)
        {
            return;
        }

        var matchIds = completedMatches.Select(x => x.Id).ToList();
        var streamsByMatchId = await dbContext.StreamSessions.AsNoTracking()
            .Where(x => x.MatchId != null && matchIds.Contains(x.MatchId.Value))
            .GroupBy(x => x.MatchId!.Value)
            .ToDictionaryAsync(
                group => group.Key,
                group => group.OrderByDescending(x => x.CreatedUtc).First(),
                cancellationToken);

        const int targetVideosPerAthlete = 6;
        var completedMatchesByAthleteId = new Dictionary<Guid, List<Match>>();
        var perAthleteSeededCount = new Dictionary<Guid, int>();
        foreach (var match in completedMatches)
        {
            var athleteIdsForMatch = new[] { match.AthleteAId, match.AthleteBId }
                .Where(x => x is not null)
                .Select(x => x!.Value)
                .Distinct()
                .ToList();

            if (athleteIdsForMatch.Count == 0)
            {
                continue;
            }

            foreach (var athleteId in athleteIdsForMatch)
            {
                if (!completedMatchesByAthleteId.TryGetValue(athleteId, out var athleteMatches))
                {
                    athleteMatches = [];
                    completedMatchesByAthleteId[athleteId] = athleteMatches;
                }

                athleteMatches.Add(match);
            }

            var stream = streamsByMatchId.GetValueOrDefault(match.Id);
            var streamId = stream?.Id;
            var eventId = bracketEventById.GetValueOrDefault(match.BracketId, Guid.Empty);
            if (eventId == Guid.Empty)
            {
                continue;
            }

            var normalizedPlayback = NormalizePlaybackUrlForClient(
                stream?.PlaybackUrl,
                eventId,
                streamId ?? match.Id,
                samplePlaybackUrls);

            if (stream?.IsPersonalStream == true
                && stream.AthleteProfileId is Guid personalAthleteId
                && athleteIdsForMatch.Contains(personalAthleteId))
            {
                athleteIdsForMatch = [personalAthleteId];
            }

            foreach (var athleteId in athleteIdsForMatch)
            {
                var existing = mediaPipelineService.GetAthleteVideos(athleteId);
                if (existing.Count >= targetVideosPerAthlete)
                {
                    continue;
                }

                if (perAthleteSeededCount.GetValueOrDefault(athleteId) >= targetVideosPerAthlete)
                {
                    continue;
                }

                if (existing.Any(x => x.MatchId == match.Id && x.StreamId == streamId))
                {
                    continue;
                }

                mediaPipelineService.CreateVideoAsset(new CreateVideoAssetRequest(
                    athleteId,
                    match.Id,
                    streamId,
                    normalizedPlayback,
                    QueueTranscode: false));

                perAthleteSeededCount[athleteId] = perAthleteSeededCount.GetValueOrDefault(athleteId) + 1;
            }
        }

        foreach (var (athleteId, athleteMatches) in completedMatchesByAthleteId)
        {
            var existingCount = mediaPipelineService.GetAthleteVideos(athleteId).Count;
            if (existingCount >= targetVideosPerAthlete || athleteMatches.Count == 0)
            {
                continue;
            }

            var orderedAthleteMatches = athleteMatches
                .OrderByDescending(x => x.CompletedUtc)
                .ThenBy(x => x.Id)
                .ToList();

            var supplementIndex = 0;
            while (existingCount < targetVideosPerAthlete && supplementIndex < targetVideosPerAthlete * 4)
            {
                var sourceMatch = orderedAthleteMatches[supplementIndex % orderedAthleteMatches.Count];
                var eventId = bracketEventById.GetValueOrDefault(sourceMatch.BracketId, Guid.Empty);
                if (eventId == Guid.Empty)
                {
                    supplementIndex++;
                    continue;
                }

                var sourceStream = streamsByMatchId.GetValueOrDefault(sourceMatch.Id);
                var sourceIndex = samplePlaybackUrls.Count == 0
                    ? 0
                    : (int)(unchecked((uint)HashCode.Combine(athleteId, supplementIndex)) % (uint)samplePlaybackUrls.Count);
                var sourceUrl = samplePlaybackUrls.Count == 0
                    ? "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
                    : samplePlaybackUrls[sourceIndex];

                var normalizedPlayback = NormalizePlaybackUrlForClient(
                    sourceStream?.PlaybackUrl ?? sourceUrl,
                    eventId,
                    sourceStream?.Id ?? sourceMatch.Id,
                    samplePlaybackUrls);

                mediaPipelineService.CreateVideoAsset(new CreateVideoAssetRequest(
                    athleteId,
                    sourceMatch.Id,
                    sourceStream?.Id,
                    normalizedPlayback,
                    QueueTranscode: false));

                existingCount++;
                supplementIndex++;
            }
        }

        var athleteIds = completedMatchesByAthleteId.Keys
            .Where(athleteId => mediaPipelineService.GetAthleteVideos(athleteId).Count > 0)
            .Take(16)
            .ToList();

        foreach (var athleteId in athleteIds)
        {
            if (mediaPipelineService.GetAiJobs(athleteId).Count > 0)
            {
                continue;
            }

            mediaPipelineService.QueueAiHighlights(new QueueAiHighlightsRequest(
                athleteId,
                EventId: null,
                MaxMatches: 12));
        }

        for (var tick = 0; tick < 40; tick++)
        {
            await mediaPipelineService.ProcessTickAsync(cancellationToken);
        }
    }
    catch (Exception ex)
    {
        logger.LogWarning(ex, "Demo runtime state initialization failed. Continuing startup.");
    }
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

static async Task AssignBoutNumbersAsync(
    Guid eventId,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken)
{
    var bracketRows = await dbContext.Brackets
        .AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .Select(x => new { x.Id, x.Level, x.WeightClass })
        .ToListAsync(cancellationToken);

    if (bracketRows.Count == 0)
    {
        return;
    }

    var bracketIds = bracketRows.Select(x => x.Id).ToHashSet();
    var bracketById = bracketRows.ToDictionary(x => x.Id);

    var matches = await dbContext.Matches
        .Where(x => bracketIds.Contains(x.BracketId))
        .ToListAsync(cancellationToken);

    var ordered = matches
        .OrderBy(x => bracketById[x.BracketId].Level)
        .ThenBy(x => bracketById[x.BracketId].WeightClass)
        .ThenBy(x => x.Round)
        .ThenBy(x => x.MatchNumber)
        .ThenBy(x => x.Id)
        .ToList();

    var nextBoutNumber = 1;
    var hasChanges = false;
    foreach (var match in ordered)
    {
        if (match.BoutNumber == nextBoutNumber)
        {
            nextBoutNumber++;
            continue;
        }

        match.BoutNumber = nextBoutNumber;
        hasChanges = true;
        nextBoutNumber++;
    }

    if (hasChanges)
    {
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}

static ConfigureMatchScoringRequest BuildScoringRequestFromPreset(Bracket bracket, TournamentControlSettings controls)
{
    var inferredStyle = InferStyleForLevel(bracket.Level);
    return BuildPresetScoringRequest(
        controls.ScoringPreset,
        inferredStyle,
        bracket.Level,
        controls.StrictScoringEnforcement,
        controls.OvertimeFormat,
        controls.MaxOvertimePeriods,
        controls.EndOnFirstOvertimeScore);
}

static ConfigureMatchScoringRequest BuildPresetScoringRequest(
    ScoringPreset preset,
    WrestlingStyle style,
    CompetitionLevel level,
    bool strictEnforcement,
    OvertimeFormat? overtimeFormatOverride = null,
    int? maxOvertimePeriodsOverride = null,
    bool? endOnFirstOvertimeScoreOverride = null)
{
    return preset switch
    {
        ScoringPreset.NcaaFolkstyle => new ConfigureMatchScoringRequest(
            Style: WrestlingStyle.Folkstyle,
            Level: level,
            AutoEndEnabled: true,
            TechFallPointGap: 15,
            RegulationPeriods: 3,
            OvertimeFormat: OvertimeFormat.FolkstyleStandard,
            MaxOvertimePeriods: 5,
            EndOnFirstOvertimeScore: false,
            StrictRuleEnforcement: strictEnforcement),
        ScoringPreset.UwwFreestyle => new ConfigureMatchScoringRequest(
            Style: WrestlingStyle.Freestyle,
            Level: level,
            AutoEndEnabled: true,
            TechFallPointGap: 10,
            RegulationPeriods: 2,
            OvertimeFormat: OvertimeFormat.FreestyleCriteria,
            MaxOvertimePeriods: 0,
            EndOnFirstOvertimeScore: false,
            StrictRuleEnforcement: strictEnforcement),
        ScoringPreset.UwwGrecoRoman => new ConfigureMatchScoringRequest(
            Style: WrestlingStyle.GrecoRoman,
            Level: level,
            AutoEndEnabled: true,
            TechFallPointGap: 8,
            RegulationPeriods: 2,
            OvertimeFormat: OvertimeFormat.GrecoCriteria,
            MaxOvertimePeriods: 0,
            EndOnFirstOvertimeScore: false,
            StrictRuleEnforcement: strictEnforcement),
        ScoringPreset.Custom => new ConfigureMatchScoringRequest(
            Style: style,
            Level: level,
            AutoEndEnabled: true,
            TechFallPointGap: null,
            RegulationPeriods: style == WrestlingStyle.Folkstyle ? 3 : 2,
            OvertimeFormat: overtimeFormatOverride ?? (style == WrestlingStyle.Folkstyle ? OvertimeFormat.FolkstyleStandard : OvertimeFormat.None),
            MaxOvertimePeriods: Math.Max(0, maxOvertimePeriodsOverride ?? (style == WrestlingStyle.Folkstyle ? 3 : 0)),
            EndOnFirstOvertimeScore: endOnFirstOvertimeScoreOverride ?? false,
            StrictRuleEnforcement: strictEnforcement),
        _ => new ConfigureMatchScoringRequest(
            Style: WrestlingStyle.Folkstyle,
            Level: level,
            AutoEndEnabled: true,
            TechFallPointGap: 15,
            RegulationPeriods: 3,
            OvertimeFormat: OvertimeFormat.FolkstyleStandard,
            MaxOvertimePeriods: 3,
            EndOnFirstOvertimeScore: false,
            StrictRuleEnforcement: strictEnforcement)
    };
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

static List<string> ResolveSamplePlaybackUrls(IConfiguration configuration)
{
    var configured = configuration.GetSection("Streams:SamplePlaybackUrls").Get<string[]>();
    var cleaned = (configured ?? Array.Empty<string>())
        .Select(x => x?.Trim())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x!)
        .Where(x =>
            Uri.TryCreate(x, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (cleaned.Count > 0)
    {
        return cleaned;
    }

    return
    [
        "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4",
        "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4",
        "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4",
        "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"
    ];
}

static string NormalizePlaybackUrlForClient(
    string? playbackUrl,
    Guid eventId,
    Guid streamId,
    IReadOnlyList<string> samplePlaybackUrls)
{
    var fallback = SelectSamplePlaybackUrl(eventId, streamId, samplePlaybackUrls);
    if (string.IsNullOrWhiteSpace(playbackUrl))
    {
        return fallback;
    }

    var trimmed = playbackUrl.Trim();
    if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
    {
        return fallback;
    }

    if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
        && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
    {
        return fallback;
    }

    var host = uri.Host.Trim();
    if (host.Equals("stream.local", StringComparison.OrdinalIgnoreCase)
        || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
    {
        return fallback;
    }

    return trimmed;
}

static string SelectSamplePlaybackUrl(Guid eventId, Guid streamId, IReadOnlyList<string> samplePlaybackUrls)
{
    if (samplePlaybackUrls.Count == 0)
    {
        return "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4";
    }

    var index = Math.Abs(HashCode.Combine(eventId, streamId)) % samplePlaybackUrls.Count;
    return samplePlaybackUrls[index];
}

static int ScoreSearchHit(string text, string queryLower)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return 0;
    }

    var normalized = text.Trim().ToLowerInvariant();
    if (normalized == queryLower)
    {
        return 120;
    }

    if (normalized.StartsWith(queryLower, StringComparison.Ordinal))
    {
        return 100;
    }

    if (normalized.Contains($" {queryLower}", StringComparison.Ordinal))
    {
        return 80;
    }

    return normalized.Contains(queryLower, StringComparison.Ordinal) ? 60 : 0;
}

static async Task<AthleteNilProfile?> BuildAthleteNilProfileAsync(
    Guid athleteId,
    WrestlingPlatformDbContext dbContext,
    ConcurrentDictionary<Guid, UpdateAthleteNilProfileRequest> nilOverridesByAthlete,
    CancellationToken cancellationToken)
{
    var athlete = await dbContext.AthleteProfiles.AsNoTracking()
        .FirstOrDefaultAsync(x => x.Id == athleteId, cancellationToken);

    if (athlete is null)
    {
        return null;
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
        ranking is null ? "Unranked watchlist" : $"Ranked #{ranking.Rank}",
        wins >= 30 ? "High-volume season" : "Building season volume"
    };

    var suggestedHandle = $"{athlete.FirstName}.{athlete.LastName}".Replace(" ", string.Empty).ToLowerInvariant();
    var defaultOverride = new UpdateAthleteNilProfileRequest(
        XHandle: suggestedHandle,
        InstagramHandle: suggestedHandle,
        TwitterHandle: suggestedHandle,
        ContactEmail: $"{athlete.FirstName}.{athlete.LastName}@pinpointarena.local".ToLowerInvariant(),
        OpenToBrandDeals: true,
        OpenToCampsClinics: true,
        OpenToCollectives: athlete.Level == CompetitionLevel.College,
        Bio: $"{athlete.FirstName} is a {ResolveAgeGroupLabel(athlete.Level)} wrestler from {athlete.City}, {athlete.State}.");

    var nilOverride = nilOverridesByAthlete.GetValueOrDefault(athleteId, defaultOverride);

    return new AthleteNilProfile(
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
        tags,
        nilOverride.XHandle,
        nilOverride.InstagramHandle,
        nilOverride.TwitterHandle,
        nilOverride.ContactEmail,
        nilOverride.OpenToBrandDeals,
        nilOverride.OpenToCampsClinics,
        nilOverride.OpenToCollectives,
        nilOverride.Bio);
}

static UpdateAthleteNilProfileRequest NormalizeNilProfileUpdate(UpdateAthleteNilProfileRequest request)
{
    return new UpdateAthleteNilProfileRequest(
        NormalizeSocialHandle(request.XHandle),
        NormalizeSocialHandle(request.InstagramHandle),
        NormalizeSocialHandle(request.TwitterHandle),
        NormalizeEmail(request.ContactEmail),
        request.OpenToBrandDeals,
        request.OpenToCampsClinics,
        request.OpenToCollectives,
        string.IsNullOrWhiteSpace(request.Bio) ? null : request.Bio.Trim());
}

static string? NormalizeSocialHandle(string? raw)
{
    if (string.IsNullOrWhiteSpace(raw))
    {
        return null;
    }

    var trimmed = raw.Trim();
    if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            trimmed = uri.Segments.LastOrDefault()?.Trim('/') ?? trimmed;
        }
    }

    trimmed = trimmed.Trim().TrimStart('@');
    if (trimmed.Length > 32)
    {
        trimmed = trimmed[..32];
    }

    return string.IsNullOrWhiteSpace(trimmed) ? null : $"@{trimmed}";
}

static string? NormalizeEmail(string? raw)
{
    if (string.IsNullOrWhiteSpace(raw))
    {
        return null;
    }

    var trimmed = raw.Trim();
    return trimmed.Contains('@', StringComparison.Ordinal) ? trimmed : null;
}

static NilPolicyResponse BuildNilPolicyResponse()
{
    return new NilPolicyResponse(
        DateTime.UtcNow,
        "NIL policies vary by state law, school policy, sanctioning body rules, and event policy. This is product guidance, not legal advice.",
        [
            new NilComplianceRule(
                "College athletes",
                "United States",
                "NCAA schools may permit NIL activity, but athletes must still comply with school/conference policy and disclosure requirements.",
                "NCAA NIL Resource Hub",
                "https://www.ncaa.org/sports/2021/2/10/name-image-likeness.aspx",
                "Check institution policy each season."),
            new NilComplianceRule(
                "High school athletes",
                "United States (state-by-state)",
                "High school NIL eligibility and allowed activities vary by state association and district policy; verification is required before activation.",
                "NFHS NIL Guidance",
                "https://www.nfhs.org/articles/nfhs-offers-name-image-and-likeness-resources-and-guidance-for-high-school-student-athletes/",
                "Rules differ significantly across states."),
            new NilComplianceRule(
                "K-8 athletes",
                "United States",
                "Youth athletes generally require parent/guardian consent and stricter identity, safety, and publicity controls.",
                "Platform Safety Policy",
                "https://support.pinpointarena.local/nil-youth",
                "Always require verified guardian approval.")
        ],
        [
            "Require athlete + guardian disclosure workflow for minors.",
            "Capture sponsor category and conflict checks before publishing campaigns.",
            "Store immutable audit trails for NIL offer acceptance and disclosures.",
            "Enable school/club compliance review queues before public profile changes.",
            "Enforce clear separation between recruiting communications and paid endorsements."
        ],
        [
            "Do not post misleading endorsements or unverifiable claims.",
            "Do not accept deals that conflict with school, conference, or state restrictions.",
            "Do not publish minor athlete contact details publicly without guardian controls.",
            "Do not use copyrighted logos/media without permission."
        ]);
}

static List<HelpFaqItem> GetHelpFaqItems()
{
    return
    [
        new HelpFaqItem(
            "faq-registration-01",
            "Registration",
            "How do I register an athlete for a tournament?",
            "Open Tournaments, choose the event, then open Register for Event. Enter athlete ID, choose team or free-agent, and submit registration.",
            ["registration", "athlete", "event", "entry", "free-agent"]),
        new HelpFaqItem(
            "faq-role-access-01",
            "Role Access",
            "What are the platform roles and how is access enforced?",
            "Roles are Athlete, Parent/Guardian, Coach, Fan, Mat Worker, and Tournament Director. Sign-in is required; tournament ops are limited to the creating director, while mat scoring is restricted to event-assigned scoring users.",
            ["roles", "access", "permissions", "tournament director", "mat worker"]),
        new HelpFaqItem(
            "faq-brackets-01",
            "Brackets",
            "How are brackets released?",
            "Event directors set release mode in registration controls: Immediate, Scheduled, or Manual release. Once released, brackets appear in Bracket Center.",
            ["brackets", "release", "director", "manual", "scheduled"]),
        new HelpFaqItem(
            "faq-brackets-02",
            "Brackets",
            "How do I use the Bracket Builder wizard?",
            "Open Bracket Builder, select your event, choose division/weight, apply controls, then generate and preview before publishing.",
            ["bracket builder", "wizard", "generate", "division", "weight"]),
        new HelpFaqItem(
            "faq-brackets-03",
            "Brackets",
            "Can I run Madison pool style brackets?",
            "Yes. Set tournament format to MadisonPool in controls or Bracket Builder. The Bracket Center will render pool lanes with standings.",
            ["pool", "madison", "round robin", "standings", "lanes"]),
        new HelpFaqItem(
            "faq-scoring-01",
            "Mat Scoring",
            "How do table workers score in real time?",
            "Open Table Worker, select event/mat/match, then use Mat Scoring to push scoring actions and live updates to dashboards.",
            ["mat", "scoring", "table worker", "real-time", "signalr"]),
        new HelpFaqItem(
            "faq-scoring-02",
            "Mat Scoring",
            "How do I run the match clock with pause/resume/seek?",
            "In Mat Scoring use Start, Pause, Resume, Seek, Advance Period, and Reset Period Clock. The timer syncs in real time and keeps period context.",
            ["clock", "timer", "pause", "resume", "seek", "period"]),
        new HelpFaqItem(
            "faq-scoring-03",
            "Mat Scoring",
            "What happens if services go down during a live tournament?",
            "Open Table Worker for the event, select the impacted mat, and reopen the active match. Saved clock, period, and scoring state allow fast resume with minimal disruption.",
            ["recovery", "outage", "resume", "live event", "table worker"]),
        new HelpFaqItem(
            "faq-nil-01",
            "NIL",
            "Can athletes add social accounts for NIL?",
            "Yes. In Athlete Portal NIL section, update X, Instagram, and Twitter handles and configure NIL availability settings.",
            ["nil", "social", "x", "instagram", "twitter"]),
        new HelpFaqItem(
            "faq-nil-02",
            "NIL",
            "Is NIL functionality legal for college and high school athletes?",
            "Policy differs by NCAA/school policy and by state high-school association. Use /api/nil/policy and verify local compliance before activating deals.",
            ["nil policy", "compliance", "college", "high school", "legal"]),
        new HelpFaqItem(
            "faq-stream-01",
            "Live Streaming",
            "How do I start a live stream from mat-side?",
            "Open Live Hub, choose event, create stream session, set source URL or sample URL, then set stream status to Live. Personal streams require parent/guardian role or active delegated permission.",
            ["stream", "live", "video", "mat cam", "playback"]),
        new HelpFaqItem(
            "faq-stream-02",
            "Live Streaming",
            "How does personal streaming permission work?",
            "Only parent/guardian accounts (or users delegated by them) can start personal athlete streams. The system enforces one active personal stream per athlete at a time and supports private archive visibility.",
            ["personal stream", "parent", "guardian", "delegate", "private"]),
        new HelpFaqItem(
            "faq-ops-01",
            "Event Ops",
            "When should brackets be generated relative to weigh-ins?",
            "Complete weigh-ins first, freeze scratch list, then generate brackets and bout numbers in Bracket Builder. Do not reseed after live scoring begins unless you republish brackets.",
            ["weigh-ins", "scratch", "generate", "event workflow", "bracket builder"]),
        new HelpFaqItem(
            "faq-ops-02",
            "Event Ops",
            "How do I publish final results after event completion?",
            "In Bracket Center and Event Admin, verify all finals are complete, export placings and team points, then publish finals and award sheets.",
            ["final results", "placings", "team points", "awards", "publish"]),
        new HelpFaqItem(
            "faq-ops-03",
            "Event Ops",
            "What is the full live-event operations checklist?",
            "Before event: lock divisions/weights, format, scoring preset, OT policy, and registration deadline; set seeding mode and print contingency sheets. Weigh-ins: run weigh-ins, freeze scratch list, then generate brackets and bout numbers. During: run head table assignments and mat table scorer/timer coverage, and post QR/live links for results. After: lock finals, export placings/team points, print awards, and publish final brackets.",
            ["event workflow", "before event", "weigh-ins", "head table", "qr", "after event"]),
        new HelpFaqItem(
            "faq-ops-04",
            "Event Ops",
            "When can a tournament director cancel an event?",
            "A director can cancel only when there are no paid registrations. If any paid entries exist, cancellation is blocked and the event must be resolved through refund/compliance workflow first.",
            ["cancel", "paid registrations", "director", "refund"]),
        new HelpFaqItem(
            "faq-live-01",
            "Live Matches",
            "How do I filter live tournament bouts on one page?",
            "Open the tournament live hub and filter by age group, weight class, and mat. You can sort by bout number, status, or round while viewing all active mats and brackets in one workflow.",
            ["live", "filters", "age group", "weight class", "mat", "bout"]),
        new HelpFaqItem(
            "faq-search-01",
            "Search",
            "What can I search from the top search bar?",
            "You can search athletes, coaches, teams, tournaments, streams, and match identifiers from any page.",
            ["search", "athlete", "tournament", "team", "match"])
    ];
}

static List<SupportGuideStep> GetSupportGuideSteps()
{
    return
    [
        new SupportGuideStep(1, "Sign In", "Use demo credentials or your account to unlock role-based workflows.", "/", "Open Command Center"),
        new SupportGuideStep(2, "Configure Event Rules", "Set age/weight divisions, bout format (RR/DE/Madison), bout length, and scoring policy.", "/tournaments", "Open Events"),
        new SupportGuideStep(3, "Set Registration Window", "Publish registration and enforce hard deadline, entry caps, and free-agent options.", "/registration", "Open Registration"),
        new SupportGuideStep(4, "Choose Seeding + Contingency", "Confirm random vs coach seeding and prep print contingency sheets before start.", "/bracket-builder", "Open Bracket Builder"),
        new SupportGuideStep(5, "Run Weigh-ins + Scratch", "Complete weigh-ins and freeze scratch list before bracket generation.", "/registration", "Open Event Registration"),
        new SupportGuideStep(6, "Build Brackets + Bout Numbers", "Use Bracket Builder wizard and generate divisions after scratch freeze.", "/bracket-builder", "Open Bracket Builder"),
        new SupportGuideStep(7, "Run Head Table + Mat Tables", "Assign mats, manage bout numbers, and maintain scorer/timer coverage on each table.", "/table-worker", "Open Table Worker"),
        new SupportGuideStep(8, "Score Live Match", "Control period clock (start/pause/resume/seek) and apply scoring actions live.", "/mat-scoring", "Open Mat Scoring"),
        new SupportGuideStep(9, "Publish Live Links", "Post QR links for live results, mat schedules, and bracket views for families.", "/live", "Open Live Hub"),
        new SupportGuideStep(10, "Recover Fast", "Use Table Worker and Mat Scoring restore flow to resume live matches from saved period/clock context.", "/table-worker", "Open Recovery Flow"),
        new SupportGuideStep(11, "Stream + Archive", "Provision stream sessions, publish live playback, and feed athlete video archives.", "/live", "Open Live Hub"),
        new SupportGuideStep(12, "Publish Finals", "Lock results, export placings/team points, print awards, and publish final brackets.", "/brackets", "Open Bracket Center"),
        new SupportGuideStep(13, "Build Athlete Brand", "Update NIL profile, social links, highlights, and recruiting cards.", "/athlete", "Open Athlete Portal")
    ];
}

static HelpChatResponse BuildHelpChatResponse(string message, string? context)
{
    var normalized = message.Trim().ToLowerInvariant();
    var suggestions = new List<string>();
    var faqSuggestions = new List<string>();
    string reply;

    if (normalized.Contains("register", StringComparison.Ordinal)
        || normalized.Contains("entry", StringComparison.Ordinal))
    {
        reply = "Use the Registration page: search event, select it, add athlete id, choose team/free-agent, then submit.";
        suggestions.Add("Open /registration");
        suggestions.Add("Open /tournaments");
        faqSuggestions.Add("faq-registration-01");
    }
    else if (normalized.Contains("role", StringComparison.Ordinal)
             || normalized.Contains("permission", StringComparison.Ordinal)
             || normalized.Contains("access", StringComparison.Ordinal))
    {
        reply = "Sign in first, then verify your active role. Tournament Director owns event ops, Mat Worker/assigned staff handle scoring, and Parent/Guardian controls personal streaming permissions.";
        suggestions.Add("Open /support");
        suggestions.Add("Open /tournaments");
        faqSuggestions.Add("faq-role-access-01");
    }
    else if (normalized.Contains("score", StringComparison.Ordinal)
             || normalized.Contains("mat", StringComparison.Ordinal)
             || normalized.Contains("overtime", StringComparison.Ordinal))
    {
        reply = "For live scoring, open Table Worker to pick the match, then score on Mat Scoring. Configure style + overtime rules before match start.";
        suggestions.Add("Open /table-worker");
        suggestions.Add("Open /mat-scoring");
        faqSuggestions.Add("faq-scoring-01");
        faqSuggestions.Add("faq-scoring-02");
    }
    else if (normalized.Contains("nil", StringComparison.Ordinal)
             || normalized.Contains("instagram", StringComparison.Ordinal)
             || normalized.Contains("twitter", StringComparison.Ordinal)
             || normalized.Contains("x ", StringComparison.Ordinal))
    {
        reply = "NIL social links are managed in Athlete Portal. Add handles, contact email, and deal preferences. Verify school/state eligibility first.";
        suggestions.Add("Open /athlete");
        suggestions.Add("View /api/nil/policy");
        faqSuggestions.Add("faq-nil-01");
    }
    else if (normalized.Contains("stream", StringComparison.Ordinal)
             || normalized.Contains("video", StringComparison.Ordinal)
             || normalized.Contains("playback", StringComparison.Ordinal))
    {
        reply = "Live Hub handles stream session creation, live status changes, and playback links. Use sample URLs if you are testing locally.";
        suggestions.Add("Open /live");
        suggestions.Add("Open /athlete");
        faqSuggestions.Add("faq-stream-01");
        faqSuggestions.Add("faq-stream-02");
    }
    else if (normalized.Contains("recovery", StringComparison.Ordinal)
             || normalized.Contains("outage", StringComparison.Ordinal)
             || normalized.Contains("down", StringComparison.Ordinal)
             || normalized.Contains("scratch", StringComparison.Ordinal)
             || normalized.Contains("checklist", StringComparison.Ordinal))
    {
        reply = "Use event workflow controls and Table Worker recovery: freeze scratch list before bracket generation, then reopen impacted mats and resume from saved period/clock state.";
        suggestions.Add("Open /table-worker");
        suggestions.Add("Open /bracket-builder");
        faqSuggestions.Add("faq-scoring-03");
        faqSuggestions.Add("faq-ops-01");
        faqSuggestions.Add("faq-ops-02");
        faqSuggestions.Add("faq-ops-03");
        faqSuggestions.Add("faq-ops-04");
    }
    else if (normalized.Contains("search", StringComparison.Ordinal)
             || normalized.Contains("find", StringComparison.Ordinal))
    {
        reply = "Use the top search bar to find athletes, teams, tournaments, matches, and streams from any page.";
        suggestions.Add("Open /search");
        faqSuggestions.Add("faq-search-01");
    }
    else
    {
        reply = "I can help with registration, brackets, mat scoring, streaming, NIL setup, and recruiting workflows. Ask in plain language and I'll route you.";
        suggestions.Add("Open /support");
        suggestions.Add("Open /tournaments");
    }

    if (!string.IsNullOrWhiteSpace(context))
    {
        suggestions.Add($"Context: {context.Trim()}");
    }

    return new HelpChatResponse(reply, suggestions.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), faqSuggestions);
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
        if (Enum.TryParse<UserRole>(roleRaw, ignoreCase: true, out var configuredRole))
        {
            resolved.Add(configuredRole);
            continue;
        }

        var normalizedRole = ApiSecurityHelpers.ParseRole(roleRaw);
        if (normalizedRole is not null)
        {
            resolved.Add(normalizedRole.Value);
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


