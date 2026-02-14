using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure;
using WrestlingPlatform.Infrastructure.Persistence;
using WrestlingPlatform.Infrastructure.Services;
using WrestlingPlatform.Api;

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
app.UseAuthentication();
app.UseAuthorization();

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

var api = app.MapGroup("/api");

var auth = api.MapGroup("/auth");

auth.MapPost("/login", async (
    LoginRequest request,
    WrestlingPlatformDbContext dbContext,
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
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
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

    return Results.Ok(result);
}).AllowAnonymous();

events.MapGet("/grouped", async (WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
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

    return Results.Ok(grouped);
}).AllowAnonymous();

events.MapPost("/{eventId:guid}/registrations", async (
    Guid eventId,
    RegisterForEventRequest request,
    HttpContext httpContext,
    WrestlingPlatformDbContext dbContext,
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
    IBracketService bracketService,
    CancellationToken cancellationToken) =>
{
    var result = await bracketService.GenerateAsync(
        new BracketGenerationInput(eventId, request.Level, request.WeightClass, request.Mode, request.DivisionId),
        cancellationToken);

    return Results.Ok(result);
}).RequireAuthorization("EventOps");

events.MapGet("/{eventId:guid}/brackets", async (Guid eventId, WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken) =>
{
    var bracketRows = await dbContext.Brackets
        .AsNoTracking()
        .Where(x => x.TournamentEventId == eventId)
        .OrderBy(x => x.Level)
        .ThenBy(x => x.WeightClass)
        .ToListAsync(cancellationToken);

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
        Matches = matchRows.Where(x => x.BracketId == bracket.Id).ToList()
    });

    return Results.Ok(result);
}).AllowAnonymous();

var matches = api.MapGroup("/matches").RequireAuthorization("EventOps");
matches.MapPost("/{matchId:guid}/assign-mat", async (
    Guid matchId,
    AssignMatRequest request,
    WrestlingPlatformDbContext dbContext,
    INotificationDispatcher notificationDispatcher,
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

    return Results.Ok(match);
});

matches.MapPost("/{matchId:guid}/result", async (
    Guid matchId,
    RecordMatchResultRequest request,
    WrestlingPlatformDbContext dbContext,
    IRankingService rankingService,
    INotificationDispatcher notificationDispatcher,
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

    return Results.Ok(match);
});

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

api.MapGet("/rankings", async (
    [FromQuery] CompetitionLevel? level,
    [FromQuery] string? state,
    [FromQuery] int take,
    WrestlingPlatformDbContext dbContext,
    CancellationToken cancellationToken) =>
{
    if (take <= 0 || take > 200)
    {
        take = 50;
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

    var stream = new StreamSession
    {
        TournamentEventId = eventId,
        MatchId = request.MatchId,
        DeviceName = request.DeviceName.Trim(),
        IngestKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace("/", "_").Replace("+", "-"),
        PlaybackUrl = $"https://stream.local/{eventId:N}/{Guid.NewGuid():N}.m3u8",
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


