using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;
using WrestlingPlatform.Infrastructure.Services;

namespace WrestlingPlatform.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddWrestlingPlatformInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var configuredConnectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=wrestling-platform.db";
        var usePostgres = IsPostgresConfigured(configuredConnectionString, configuration["Database:Provider"]);
        var connectionString = usePostgres
            ? NormalizePostgresConnectionString(configuredConnectionString)
            : configuredConnectionString;

        services.AddDbContext<WrestlingPlatformDbContext>(options =>
        {
            if (usePostgres)
            {
                options.UseNpgsql(connectionString, npgsql =>
                {
                    // Render + managed Postgres can briefly fail over during maintenance.
                    npgsql.EnableRetryOnFailure(maxRetryCount: 5, maxRetryDelay: TimeSpan.FromSeconds(10), errorCodesToAdd: null);
                });
                return;
            }

            options.UseSqlite(connectionString);
        });

        var paymentOptions = new PaymentGatewayOptions
        {
            ProviderMode = configuration["Payments:ProviderMode"] ?? "Mock",
            BaseCheckoutUrl = configuration["Payments:BaseCheckoutUrl"] ?? "https://payments.local",
            StripeSecretKey = configuration["Payments:StripeSecretKey"] ?? string.Empty,
            StripeSuccessUrl = configuration["Payments:StripeSuccessUrl"] ?? "https://platform.local/payments/success",
            StripeCancelUrl = configuration["Payments:StripeCancelUrl"] ?? "https://platform.local/payments/cancel",
            StripeWebhookSecret = configuration["Payments:StripeWebhookSecret"] ?? string.Empty
        };

        var paymentWebhookProcessingOptions = new PaymentWebhookProcessingOptions
        {
            PollIntervalSeconds = int.TryParse(configuration["Payments:WebhookProcessing:PollIntervalSeconds"], out var pollIntervalSeconds)
                ? pollIntervalSeconds
                : 10,
            BatchSize = int.TryParse(configuration["Payments:WebhookProcessing:BatchSize"], out var batchSize)
                ? batchSize
                : 50,
            MaxAttempts = int.TryParse(configuration["Payments:WebhookProcessing:MaxAttempts"], out var maxAttempts)
                ? maxAttempts
                : 20,
            RetryWindowMinutes = int.TryParse(configuration["Payments:WebhookProcessing:RetryWindowMinutes"], out var retryWindowMinutes)
                ? retryWindowMinutes
                : 90
        };

        var notificationOptions = new NotificationProviderOptions
        {
            ProviderMode = configuration["Notifications:ProviderMode"] ?? "Mock",
            TwilioAccountSid = configuration["Notifications:Twilio:AccountSid"] ?? string.Empty,
            TwilioAuthToken = configuration["Notifications:Twilio:AuthToken"] ?? string.Empty,
            TwilioFromNumber = configuration["Notifications:Twilio:FromNumber"] ?? string.Empty,
            SendGridApiKey = configuration["Notifications:SendGrid:ApiKey"] ?? string.Empty,
            SendGridFromEmail = configuration["Notifications:SendGrid:FromEmail"] ?? string.Empty,
            SendGridFromName = configuration["Notifications:SendGrid:FromName"] ?? "PinPoint Arena"
        };

        services.AddSingleton(Options.Create(paymentOptions));
        services.AddSingleton(Options.Create(paymentWebhookProcessingOptions));
        services.AddSingleton(Options.Create(notificationOptions));

        services.AddScoped<IBracketService, BracketService>();
        services.AddScoped<IRankingService, RankingService>();
        services.AddScoped<IOutboundNotificationSender, OutboundNotificationSender>();
        services.AddScoped<INotificationDispatcher, NotificationDispatcher>();
        services.AddScoped<IPaymentGateway, ConfigurablePaymentGateway>();
        services.AddScoped<IPaymentWebhookReconciliationService, PaymentWebhookReconciliationService>();

        services.AddHostedService<PaymentWebhookReconciliationWorker>();

        return services;
    }

    public static async Task InitializeDatabaseAsync(this IServiceProvider serviceProvider, CancellationToken cancellationToken = default)
    {
        using var scope = serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

        await dbContext.Database.EnsureCreatedAsync(cancellationToken);
        await SeedDemoDataAsync(dbContext, cancellationToken);
    }

    private static async Task SeedDemoDataAsync(WrestlingPlatformDbContext dbContext, CancellationToken cancellationToken)
    {
        var athleteSeeds = new[]
        {
            new AthleteSeed("demo.athlete@pinpointarena.local", "+16145550002", "Eli", "Turner", 16, "OH", "Columbus", "PinPoint Wrestling Club", 10, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("noah.miller@pinpointarena.local", "+16145550003", "Noah", "Miller", 17, "OH", "Dublin", "River Valley Wrestling", 11, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("jayden.clark@pinpointarena.local", "+16145550004", "Jayden", "Clark", 18, "OH", "Toledo", "River Valley Wrestling", 12, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("logan.price@pinpointarena.local", "+16145550005", "Logan", "Price", 16, "OH", "Cincinnati", "Buckeye Elite", 10, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("cameron.lee@pinpointarena.local", "+16145550006", "Cameron", "Lee", 17, "PA", "Pittsburgh", "Steel City Wrestling", 11, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("tyler.nguyen@pinpointarena.local", "+16145550007", "Tyler", "Nguyen", 17, "MI", "Detroit", "Motor City Wrestling", 11, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("ethan.brooks@pinpointarena.local", "+16145550008", "Ethan", "Brooks", 15, "OH", "Columbus", "PinPoint Wrestling Club", 9, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("ayden.foster@pinpointarena.local", "+16145550009", "Ayden", "Foster", 16, "PA", "Erie", "Steel City Wrestling", 10, 132m, CompetitionLevel.HighSchool),
            new AthleteSeed("luca.brown@pinpointarena.local", "+16145550010", "Luca", "Brown", 11, "OH", "Columbus", "PinPoint Youth Academy", 5, 75m, CompetitionLevel.ElementaryK6),
            new AthleteSeed("owen.hill@pinpointarena.local", "+16145550011", "Owen", "Hill", 12, "OH", "Dayton", "Dayton Youth Wrestling", 6, 78m, CompetitionLevel.ElementaryK6),
            new AthleteSeed("gabe.soto@pinpointarena.local", "+16145550012", "Gabe", "Soto", 14, "OH", "Columbus", "Capital Middle School", 8, 98m, CompetitionLevel.MiddleSchool),
            new AthleteSeed("isaac.wells@pinpointarena.local", "+16145550013", "Isaac", "Wells", 13, "PA", "Pittsburgh", "Keystone Middle School", 7, 95m, CompetitionLevel.MiddleSchool),
            new AthleteSeed("cooper.james@pinpointarena.local", "+16145550014", "Cooper", "James", 20, "IA", "Ames", "Heartland University", 12, 157m, CompetitionLevel.College),
            new AthleteSeed("riley.mitchell@pinpointarena.local", "+16145550015", "Riley", "Mitchell", 21, "OK", "Tulsa", "Tulsa State University", 12, 165m, CompetitionLevel.College)
        };

        var athleteUsersByEmail = new Dictionary<string, UserAccount>(StringComparer.OrdinalIgnoreCase);
        var athleteProfilesByEmail = new Dictionary<string, AthleteProfile>(StringComparer.OrdinalIgnoreCase);

        foreach (var seed in athleteSeeds)
        {
            var athleteUser = await EnsureUserAsync(
                dbContext,
                seed.Email,
                UserRole.Athlete,
                seed.PhoneNumber,
                "DemoPass!123",
                cancellationToken);

            var athleteProfile = await EnsureAthleteProfileAsync(
                dbContext,
                athleteUser.Id,
                seed.FirstName,
                seed.LastName,
                DateTime.UtcNow.Date.AddYears(-seed.AgeYears),
                seed.State,
                seed.City,
                seed.SchoolOrClubName,
                seed.Grade,
                seed.WeightClass,
                seed.Level,
                cancellationToken);

            athleteUsersByEmail[seed.Email] = athleteUser;
            athleteProfilesByEmail[seed.Email] = athleteProfile;
        }

        var coachUser = await EnsureUserAsync(
            dbContext,
            "demo.coach@pinpointarena.local",
            UserRole.Coach,
            "+16145550001",
            "DemoPass!123",
            cancellationToken);

        var coachProfile = await EnsureCoachProfileAsync(
            dbContext,
            coachUser.Id,
            "Mason",
            "Reed",
            "OH",
            "Columbus",
            "Lead coach for the local demo circuit.",
            cancellationToken);

        var primaryTeam = await EnsureTeamAsync(
            dbContext,
            "PinPoint Wrestling Club",
            TeamType.Club,
            "OH",
            "Columbus",
            cancellationToken);

        var secondaryTeam = await EnsureTeamAsync(
            dbContext,
            "River Valley Wrestling",
            TeamType.School,
            "OH",
            "Dublin",
            cancellationToken);

        var scoutingTeam = await EnsureTeamAsync(
            dbContext,
            "Steel City Wrestling",
            TeamType.Club,
            "PA",
            "Pittsburgh",
            cancellationToken);

        await EnsureCoachAssociationAsync(
            dbContext,
            coachProfile.Id,
            athleteProfileId: null,
            teamId: primaryTeam.Id,
            roleTitle: "Head Coach",
            isPrimary: true,
            cancellationToken);

        foreach (var athleteProfile in athleteProfilesByEmail.Values.Where(x => x.Level == CompetitionLevel.HighSchool).Take(6))
        {
            await EnsureCoachAssociationAsync(
                dbContext,
                coachProfile.Id,
                athleteProfile.Id,
                primaryTeam.Id,
                "Head Coach",
                true,
                cancellationToken);
        }

        var todayUtc = DateTime.UtcNow.Date;
        var showcaseEvent = await EnsureEventAsync(
            dbContext,
            "PinPoint Local Showcase",
            OrganizerType.Club,
            primaryTeam.Id,
            "OH",
            "Columbus",
            "Metro Sports Complex",
            todayUtc.AddDays(7).AddHours(14),
            todayUtc.AddDays(8).AddHours(2),
            3500,
            true,
            cancellationToken);

        var youthPreviewEvent = await EnsureEventAsync(
            dbContext,
            "Ohio Youth State Preview",
            OrganizerType.School,
            secondaryTeam.Id,
            "OH",
            "Columbus",
            "Capital Youth Fieldhouse",
            todayUtc.AddDays(14).AddHours(13),
            todayUtc.AddDays(15).AddHours(2),
            2200,
            true,
            cancellationToken);

        var middleOpenEvent = await EnsureEventAsync(
            dbContext,
            "Keystone Middle School Open",
            OrganizerType.Club,
            scoutingTeam.Id,
            "PA",
            "Pittsburgh",
            "Keystone Event Center",
            todayUtc.AddDays(21).AddHours(13),
            todayUtc.AddDays(22).AddHours(2),
            1900,
            true,
            cancellationToken);

        var collegeDualEvent = await EnsureEventAsync(
            dbContext,
            "Heartland College Duals",
            OrganizerType.Club,
            primaryTeam.Id,
            "IA",
            "Des Moines",
            "Heartland Arena",
            todayUtc.AddDays(28).AddHours(15),
            todayUtc.AddDays(29).AddHours(4),
            4200,
            true,
            cancellationToken);

        var tulsaEvent = await EnsureEventAsync(
            dbContext,
            "Tulsa Winter Folkstyle",
            OrganizerType.Club,
            scoutingTeam.Id,
            "OK",
            "Tulsa",
            "Sooner Athletic Hall",
            todayUtc.AddDays(35).AddHours(14),
            todayUtc.AddDays(36).AddHours(3),
            3000,
            true,
            cancellationToken);

        var motorCityEvent = await EnsureEventAsync(
            dbContext,
            "Motor City Elementary Festival",
            OrganizerType.School,
            secondaryTeam.Id,
            "MI",
            "Detroit",
            "Detroit Youth Sports Center",
            todayUtc.AddDays(42).AddHours(13),
            todayUtc.AddDays(43).AddHours(1),
            1500,
            true,
            cancellationToken);

        var showcaseDivision = await EnsureDivisionAsync(
            dbContext,
            showcaseEvent.Id,
            "High School 132",
            CompetitionLevel.HighSchool,
            132m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            showcaseEvent.Id,
            "Middle School 98",
            CompetitionLevel.MiddleSchool,
            98m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            youthPreviewEvent.Id,
            "Elementary 75",
            CompetitionLevel.ElementaryK6,
            75m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            youthPreviewEvent.Id,
            "Middle School 98",
            CompetitionLevel.MiddleSchool,
            98m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            middleOpenEvent.Id,
            "Middle School 95",
            CompetitionLevel.MiddleSchool,
            95m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            collegeDualEvent.Id,
            "College 157",
            CompetitionLevel.College,
            157m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            tulsaEvent.Id,
            "High School 132",
            CompetitionLevel.HighSchool,
            132m,
            cancellationToken);

        await EnsureDivisionAsync(
            dbContext,
            motorCityEvent.Id,
            "Elementary 78",
            CompetitionLevel.ElementaryK6,
            78m,
            cancellationToken);

        var showcaseAthletes = new[]
        {
            athleteProfilesByEmail["demo.athlete@pinpointarena.local"],
            athleteProfilesByEmail["noah.miller@pinpointarena.local"],
            athleteProfilesByEmail["jayden.clark@pinpointarena.local"],
            athleteProfilesByEmail["logan.price@pinpointarena.local"],
            athleteProfilesByEmail["cameron.lee@pinpointarena.local"],
            athleteProfilesByEmail["tyler.nguyen@pinpointarena.local"],
            athleteProfilesByEmail["ethan.brooks@pinpointarena.local"],
            athleteProfilesByEmail["ayden.foster@pinpointarena.local"]
        };

        var freeAgentRegistrations = new List<EventRegistration>();
        for (var index = 0; index < showcaseAthletes.Length; index++)
        {
            var teamId = index < 4 ? primaryTeam.Id : (Guid?)null;
            var isFreeAgent = teamId is null;

            var registration = await EnsureRegistrationAsync(
                dbContext,
                showcaseEvent.Id,
                showcaseAthletes[index].Id,
                teamId,
                isFreeAgent,
                RegistrationStatus.Confirmed,
                PaymentStatus.Paid,
                showcaseEvent.EntryFeeCents,
                cancellationToken);

            if (isFreeAgent)
            {
                freeAgentRegistrations.Add(registration);
            }
        }

        await EnsureRegistrationAsync(
            dbContext,
            youthPreviewEvent.Id,
            athleteProfilesByEmail["luca.brown@pinpointarena.local"].Id,
            null,
            true,
            RegistrationStatus.Confirmed,
            PaymentStatus.Paid,
            youthPreviewEvent.EntryFeeCents,
            cancellationToken);

        await EnsureRegistrationAsync(
            dbContext,
            youthPreviewEvent.Id,
            athleteProfilesByEmail["owen.hill@pinpointarena.local"].Id,
            secondaryTeam.Id,
            false,
            RegistrationStatus.Confirmed,
            PaymentStatus.Paid,
            youthPreviewEvent.EntryFeeCents,
            cancellationToken);

        await EnsureRegistrationAsync(
            dbContext,
            middleOpenEvent.Id,
            athleteProfilesByEmail["gabe.soto@pinpointarena.local"].Id,
            secondaryTeam.Id,
            false,
            RegistrationStatus.Confirmed,
            PaymentStatus.Paid,
            middleOpenEvent.EntryFeeCents,
            cancellationToken);

        await EnsureRegistrationAsync(
            dbContext,
            middleOpenEvent.Id,
            athleteProfilesByEmail["isaac.wells@pinpointarena.local"].Id,
            null,
            true,
            RegistrationStatus.Confirmed,
            PaymentStatus.Paid,
            middleOpenEvent.EntryFeeCents,
            cancellationToken);

        await EnsureRegistrationAsync(
            dbContext,
            collegeDualEvent.Id,
            athleteProfilesByEmail["cooper.james@pinpointarena.local"].Id,
            primaryTeam.Id,
            false,
            RegistrationStatus.Confirmed,
            PaymentStatus.Paid,
            collegeDualEvent.EntryFeeCents,
            cancellationToken);

        await EnsureRegistrationAsync(
            dbContext,
            collegeDualEvent.Id,
            athleteProfilesByEmail["riley.mitchell@pinpointarena.local"].Id,
            null,
            true,
            RegistrationStatus.Confirmed,
            PaymentStatus.Paid,
            collegeDualEvent.EntryFeeCents,
            cancellationToken);

        if (freeAgentRegistrations.Count > 0)
        {
            await EnsureFreeAgentInviteAsync(
                dbContext,
                freeAgentRegistrations[0].Id,
                primaryTeam.Id,
                "Join PinPoint Wrestling Club for this event.",
                false,
                cancellationToken);
        }

        if (freeAgentRegistrations.Count > 1)
        {
            await EnsureFreeAgentInviteAsync(
                dbContext,
                freeAgentRegistrations[1].Id,
                scoutingTeam.Id,
                "Steel City would like you on this card.",
                false,
                cancellationToken);
        }

        var showcaseBracket = await EnsureBracketAsync(
            dbContext,
            showcaseEvent.Id,
            showcaseDivision.Id,
            CompetitionLevel.HighSchool,
            132m,
            BracketGenerationMode.Seeded,
            cancellationToken);

        for (var seed = 0; seed < showcaseAthletes.Length; seed++)
        {
            await EnsureBracketEntryAsync(
                dbContext,
                showcaseBracket.Id,
                showcaseAthletes[seed].Id,
                seed + 1,
                cancellationToken);
        }

        var matchStartUtc = showcaseEvent.StartUtc.Date.AddHours(14);
        var quarterFinal1 = await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            1,
            1,
            showcaseAthletes[0].Id,
            showcaseAthletes[7].Id,
            showcaseAthletes[0].Id,
            "10-2",
            "Decision",
            "Mat 1",
            MatchStatus.Completed,
            matchStartUtc.AddMinutes(0),
            matchStartUtc.AddMinutes(18),
            cancellationToken);

        var quarterFinal2 = await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            1,
            2,
            showcaseAthletes[3].Id,
            showcaseAthletes[4].Id,
            showcaseAthletes[4].Id,
            "6-4",
            "Decision",
            "Mat 1",
            MatchStatus.Completed,
            matchStartUtc.AddMinutes(22),
            matchStartUtc.AddMinutes(40),
            cancellationToken);

        var quarterFinal3 = await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            1,
            3,
            showcaseAthletes[1].Id,
            showcaseAthletes[6].Id,
            showcaseAthletes[1].Id,
            "Fall 1:42",
            "Pin",
            "Mat 2",
            MatchStatus.Completed,
            matchStartUtc.AddMinutes(45),
            matchStartUtc.AddMinutes(53),
            cancellationToken);

        var quarterFinal4 = await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            1,
            4,
            showcaseAthletes[2].Id,
            showcaseAthletes[5].Id,
            showcaseAthletes[2].Id,
            "11-3",
            "Major Decision",
            "Mat 2",
            MatchStatus.Completed,
            matchStartUtc.AddMinutes(58),
            matchStartUtc.AddMinutes(76),
            cancellationToken);

        var semiFinal1 = await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            2,
            5,
            quarterFinal1.WinnerAthleteId,
            quarterFinal2.WinnerAthleteId,
            winnerAthleteId: null,
            score: null,
            resultMethod: null,
            matNumber: "Mat 1",
            status: MatchStatus.InTheHole,
            scheduledUtc: matchStartUtc.AddHours(2),
            completedUtc: null,
            cancellationToken);

        await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            2,
            6,
            quarterFinal3.WinnerAthleteId,
            quarterFinal4.WinnerAthleteId,
            winnerAthleteId: null,
            score: null,
            resultMethod: null,
            matNumber: "Mat 2",
            status: MatchStatus.Scheduled,
            scheduledUtc: matchStartUtc.AddHours(2).AddMinutes(20),
            completedUtc: null,
            cancellationToken);

        await EnsureMatchAsync(
            dbContext,
            showcaseBracket.Id,
            3,
            7,
            athleteAId: null,
            athleteBId: null,
            winnerAthleteId: null,
            score: null,
            resultMethod: null,
            matNumber: "Mat 1",
            status: MatchStatus.Scheduled,
            scheduledUtc: matchStartUtc.AddHours(4),
            completedUtc: null,
            cancellationToken);

        await EnsureStreamSessionAsync(
            dbContext,
            showcaseEvent.Id,
            quarterFinal1.Id,
            "Mat 1 iPhone 14",
            StreamStatus.Live,
            "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4",
            matchStartUtc.AddMinutes(2),
            endedUtc: null,
            cancellationToken);

        await EnsureStreamSessionAsync(
            dbContext,
            showcaseEvent.Id,
            quarterFinal3.Id,
            "Mat 2 PTZ Cam",
            StreamStatus.Live,
            "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4",
            matchStartUtc.AddMinutes(46),
            endedUtc: null,
            cancellationToken);

        await EnsureStreamSessionAsync(
            dbContext,
            showcaseEvent.Id,
            semiFinal1.Id,
            "Table Cam Backup",
            StreamStatus.Provisioned,
            "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4",
            startedUtc: null,
            endedUtc: null,
            cancellationToken);

        await EnsureDemoBracketAndStreamCoverageAsync(dbContext, athleteProfilesByEmail, cancellationToken);

        var demoAthleteUser = athleteUsersByEmail["demo.athlete@pinpointarena.local"];
        var demoAthleteProfile = athleteProfilesByEmail["demo.athlete@pinpointarena.local"];

        var matAssignmentSubscription = await EnsureNotificationSubscriptionAsync(
            dbContext,
            demoAthleteUser.Id,
            showcaseEvent.Id,
            demoAthleteProfile.Id,
            NotificationEventType.MatAssignment,
            NotificationChannel.Email,
            "family+demo@pinpointarena.local",
            cancellationToken);

        var inTheHoleSubscription = await EnsureNotificationSubscriptionAsync(
            dbContext,
            demoAthleteUser.Id,
            showcaseEvent.Id,
            demoAthleteProfile.Id,
            NotificationEventType.InTheHole,
            NotificationChannel.Sms,
            "+16145550002",
            cancellationToken);

        var matchResultSubscription = await EnsureNotificationSubscriptionAsync(
            dbContext,
            demoAthleteUser.Id,
            showcaseEvent.Id,
            demoAthleteProfile.Id,
            NotificationEventType.MatchResult,
            NotificationChannel.Email,
            "family+demo@pinpointarena.local",
            cancellationToken);

        await EnsureNotificationMessageAsync(
            dbContext,
            matAssignmentSubscription.Id,
            showcaseEvent.Id,
            quarterFinal1.Id,
            NotificationEventType.MatAssignment,
            NotificationChannel.Email,
            "family+demo@pinpointarena.local",
            "Your match has been assigned to Mat 1.",
            DateTime.UtcNow.AddMinutes(-90),
            cancellationToken);

        await EnsureNotificationMessageAsync(
            dbContext,
            inTheHoleSubscription.Id,
            showcaseEvent.Id,
            semiFinal1.Id,
            NotificationEventType.InTheHole,
            NotificationChannel.Sms,
            "+16145550002",
            "You are in-the-hole on Mat 1. Warm up now.",
            DateTime.UtcNow.AddMinutes(-40),
            cancellationToken);

        await EnsureNotificationMessageAsync(
            dbContext,
            matchResultSubscription.Id,
            showcaseEvent.Id,
            quarterFinal1.Id,
            NotificationEventType.MatchResult,
            NotificationChannel.Email,
            "family+demo@pinpointarena.local",
            "Match result posted: 10-2 Decision.",
            DateTime.UtcNow.AddMinutes(-25),
            cancellationToken);

        var seededAthleteIds = athleteProfilesByEmail.Values.Select(x => x.Id).ToHashSet();

        var existingStats = await dbContext.AthleteStatsSnapshots
            .Where(x => seededAthleteIds.Contains(x.AthleteProfileId))
            .ToListAsync(cancellationToken);

        if (existingStats.Count > 0)
        {
            dbContext.AthleteStatsSnapshots.RemoveRange(existingStats);
        }

        var existingRankings = await dbContext.AthleteRankings
            .Where(x => seededAthleteIds.Contains(x.AthleteProfileId))
            .ToListAsync(cancellationToken);

        if (existingRankings.Count > 0)
        {
            dbContext.AthleteRankings.RemoveRange(existingRankings);
        }

        var athleteProfileRows = athleteProfilesByEmail.Values
            .OrderBy(x => x.Level)
            .ThenBy(x => x.LastName)
            .ThenBy(x => x.FirstName)
            .ToList();

        for (var index = 0; index < athleteProfileRows.Count; index++)
        {
            var athlete = athleteProfileRows[index];
            var baseWins = athlete.Level switch
            {
                CompetitionLevel.ElementaryK6 => 9,
                CompetitionLevel.MiddleSchool => 14,
                CompetitionLevel.HighSchool => 21,
                CompetitionLevel.College => 28,
                _ => 12
            } + index;

            var baseLosses = athlete.Level switch
            {
                CompetitionLevel.ElementaryK6 => 2,
                CompetitionLevel.MiddleSchool => 4,
                CompetitionLevel.HighSchool => 5,
                CompetitionLevel.College => 6,
                _ => 3
            } + (index % 3);

            dbContext.AthleteStatsSnapshots.Add(new AthleteStatsSnapshot
            {
                AthleteProfileId = athlete.Id,
                Level = athlete.Level,
                SnapshotUtc = todayUtc.AddDays(-45),
                Wins = baseWins,
                Losses = baseLosses,
                Pins = Math.Max(1, baseWins / 2),
                TechFalls = Math.Max(0, baseWins / 5),
                MajorDecisions = Math.Max(0, baseWins / 6),
                MatchPointsFor = (baseWins * 8) + 10,
                MatchPointsAgainst = (baseLosses * 4) + 8
            });

            dbContext.AthleteStatsSnapshots.Add(new AthleteStatsSnapshot
            {
                AthleteProfileId = athlete.Id,
                Level = athlete.Level,
                SnapshotUtc = todayUtc.AddDays(-2),
                Wins = baseWins + 2,
                Losses = baseLosses + (index % 2),
                Pins = Math.Max(1, (baseWins + 2) / 2),
                TechFalls = Math.Max(0, (baseWins + 2) / 5),
                MajorDecisions = Math.Max(0, (baseWins + 2) / 6),
                MatchPointsFor = ((baseWins + 2) * 8) + 16,
                MatchPointsAgainst = ((baseLosses + (index % 2)) * 4) + 11
            });
        }

        AthleteRanking BuildRanking(string athleteEmail, string state, decimal rating, int rank)
        {
            var athlete = athleteProfilesByEmail[athleteEmail];
            return new AthleteRanking
            {
                AthleteProfileId = athlete.Id,
                Level = athlete.Level,
                State = state.ToUpperInvariant(),
                RatingPoints = rating,
                Rank = rank,
                SnapshotUtc = todayUtc.AddDays(-1)
            };
        }

        dbContext.AthleteRankings.AddRange(
            BuildRanking("demo.athlete@pinpointarena.local", "OH", 1585m, 1),
            BuildRanking("noah.miller@pinpointarena.local", "OH", 1564m, 2),
            BuildRanking("jayden.clark@pinpointarena.local", "OH", 1542m, 3),
            BuildRanking("logan.price@pinpointarena.local", "OH", 1520m, 4),
            BuildRanking("ethan.brooks@pinpointarena.local", "OH", 1498m, 5),
            BuildRanking("cameron.lee@pinpointarena.local", "PA", 1570m, 1),
            BuildRanking("ayden.foster@pinpointarena.local", "PA", 1510m, 2),
            BuildRanking("tyler.nguyen@pinpointarena.local", "MI", 1505m, 1),
            BuildRanking("gabe.soto@pinpointarena.local", "OH", 1412m, 1),
            BuildRanking("isaac.wells@pinpointarena.local", "PA", 1398m, 1),
            BuildRanking("luca.brown@pinpointarena.local", "OH", 1320m, 1),
            BuildRanking("owen.hill@pinpointarena.local", "OH", 1294m, 2),
            BuildRanking("cooper.james@pinpointarena.local", "IA", 1706m, 1),
            BuildRanking("riley.mitchell@pinpointarena.local", "OK", 1682m, 1));

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private static async Task<UserAccount> EnsureUserAsync(
        WrestlingPlatformDbContext dbContext,
        string email,
        UserRole role,
        string? phoneNumber,
        string password,
        CancellationToken cancellationToken)
    {
        var normalizedEmail = email.Trim().ToLowerInvariant();
        var user = await dbContext.UserAccounts
            .FirstOrDefaultAsync(x => x.Email == normalizedEmail, cancellationToken);

        if (user is null)
        {
            user = new UserAccount
            {
                Email = normalizedEmail,
                Role = role,
                PhoneNumber = phoneNumber,
                IsActive = true
            };

            dbContext.UserAccounts.Add(user);
        }

        user.Role = role;
        user.PhoneNumber = phoneNumber;
        user.IsActive = true;
        user.PasswordHash = HashPassword(password);
        return user;
    }

    private static async Task<AthleteProfile> EnsureAthleteProfileAsync(
        WrestlingPlatformDbContext dbContext,
        Guid userAccountId,
        string firstName,
        string lastName,
        DateTime dateOfBirthUtc,
        string state,
        string city,
        string schoolOrClubName,
        int grade,
        decimal weightClass,
        CompetitionLevel level,
        CancellationToken cancellationToken)
    {
        var profile = await dbContext.AthleteProfiles
            .FirstOrDefaultAsync(x => x.UserAccountId == userAccountId, cancellationToken);

        if (profile is null)
        {
            profile = new AthleteProfile
            {
                UserAccountId = userAccountId
            };

            dbContext.AthleteProfiles.Add(profile);
        }

        profile.FirstName = firstName.Trim();
        profile.LastName = lastName.Trim();
        profile.DateOfBirthUtc = DateTime.SpecifyKind(dateOfBirthUtc, DateTimeKind.Utc);
        profile.State = state.Trim().ToUpperInvariant();
        profile.City = city.Trim();
        profile.SchoolOrClubName = schoolOrClubName.Trim();
        profile.Grade = grade;
        profile.WeightClass = weightClass;
        profile.Level = level;
        return profile;
    }

    private static async Task<CoachProfile> EnsureCoachProfileAsync(
        WrestlingPlatformDbContext dbContext,
        Guid userAccountId,
        string firstName,
        string lastName,
        string state,
        string city,
        string bio,
        CancellationToken cancellationToken)
    {
        var profile = await dbContext.CoachProfiles
            .FirstOrDefaultAsync(x => x.UserAccountId == userAccountId, cancellationToken);

        if (profile is null)
        {
            profile = new CoachProfile
            {
                UserAccountId = userAccountId
            };

            dbContext.CoachProfiles.Add(profile);
        }

        profile.FirstName = firstName.Trim();
        profile.LastName = lastName.Trim();
        profile.State = state.Trim().ToUpperInvariant();
        profile.City = city.Trim();
        profile.Bio = bio.Trim();
        return profile;
    }

    private static async Task<Team> EnsureTeamAsync(
        WrestlingPlatformDbContext dbContext,
        string name,
        TeamType teamType,
        string state,
        string city,
        CancellationToken cancellationToken)
    {
        var normalizedName = name.Trim();
        var team = await dbContext.Teams
            .FirstOrDefaultAsync(x => x.Name == normalizedName, cancellationToken);

        if (team is null)
        {
            team = new Team
            {
                Name = normalizedName
            };

            dbContext.Teams.Add(team);
        }

        team.Type = teamType;
        team.State = state.Trim().ToUpperInvariant();
        team.City = city.Trim();
        return team;
    }

    private static async Task<CoachAssociation> EnsureCoachAssociationAsync(
        WrestlingPlatformDbContext dbContext,
        Guid coachProfileId,
        Guid? athleteProfileId,
        Guid? teamId,
        string roleTitle,
        bool isPrimary,
        CancellationToken cancellationToken)
    {
        var association = await dbContext.CoachAssociations.FirstOrDefaultAsync(
            x => x.CoachProfileId == coachProfileId
                 && x.AthleteProfileId == athleteProfileId
                 && x.TeamId == teamId
                 && x.RoleTitle == roleTitle,
            cancellationToken);

        if (association is null)
        {
            association = new CoachAssociation
            {
                CoachProfileId = coachProfileId,
                AthleteProfileId = athleteProfileId,
                TeamId = teamId,
                RoleTitle = roleTitle.Trim()
            };

            dbContext.CoachAssociations.Add(association);
        }

        association.IsPrimary = isPrimary;
        association.ApprovedUtc = association.ApprovedUtc ?? DateTime.UtcNow;
        return association;
    }

    private static async Task<TournamentEvent> EnsureEventAsync(
        WrestlingPlatformDbContext dbContext,
        string name,
        OrganizerType organizerType,
        Guid organizerId,
        string state,
        string city,
        string venue,
        DateTime startUtc,
        DateTime endUtc,
        int entryFeeCents,
        bool isPublished,
        CancellationToken cancellationToken)
    {
        var normalizedName = name.Trim();
        var tournamentEvent = await dbContext.TournamentEvents
            .FirstOrDefaultAsync(x => x.Name == normalizedName, cancellationToken);

        if (tournamentEvent is null)
        {
            tournamentEvent = new TournamentEvent
            {
                Name = normalizedName
            };

            dbContext.TournamentEvents.Add(tournamentEvent);
        }

        tournamentEvent.OrganizerType = organizerType;
        tournamentEvent.OrganizerId = organizerId;
        tournamentEvent.State = state.Trim().ToUpperInvariant();
        tournamentEvent.City = city.Trim();
        tournamentEvent.Venue = venue.Trim();
        tournamentEvent.StartUtc = DateTime.SpecifyKind(startUtc, DateTimeKind.Utc);
        tournamentEvent.EndUtc = DateTime.SpecifyKind(endUtc, DateTimeKind.Utc);
        tournamentEvent.EntryFeeCents = entryFeeCents;
        tournamentEvent.Currency = "USD";
        tournamentEvent.IsPublished = isPublished;

        return tournamentEvent;
    }

    private static async Task<TournamentDivision> EnsureDivisionAsync(
        WrestlingPlatformDbContext dbContext,
        Guid eventId,
        string name,
        CompetitionLevel level,
        decimal weightClass,
        CancellationToken cancellationToken)
    {
        var normalizedName = name.Trim();
        var division = await dbContext.TournamentDivisions
            .FirstOrDefaultAsync(x => x.TournamentEventId == eventId && x.Name == normalizedName, cancellationToken);

        if (division is null)
        {
            division = new TournamentDivision
            {
                TournamentEventId = eventId,
                Name = normalizedName
            };

            dbContext.TournamentDivisions.Add(division);
        }

        division.Level = level;
        division.WeightClass = weightClass;
        return division;
    }

    private static async Task<EventRegistration> EnsureRegistrationAsync(
        WrestlingPlatformDbContext dbContext,
        Guid eventId,
        Guid athleteProfileId,
        Guid? teamId,
        bool isFreeAgent,
        RegistrationStatus status,
        PaymentStatus paymentStatus,
        int paidAmountCents,
        CancellationToken cancellationToken)
    {
        var registration = await dbContext.EventRegistrations
            .FirstOrDefaultAsync(x => x.TournamentEventId == eventId && x.AthleteProfileId == athleteProfileId, cancellationToken);

        if (registration is null)
        {
            registration = new EventRegistration
            {
                TournamentEventId = eventId,
                AthleteProfileId = athleteProfileId
            };

            dbContext.EventRegistrations.Add(registration);
        }

        registration.TeamId = teamId;
        registration.IsFreeAgent = isFreeAgent;
        registration.Status = status;
        registration.PaymentStatus = paymentStatus;
        registration.PaidAmountCents = paidAmountCents;
        registration.PaymentReference = paymentStatus == PaymentStatus.Paid
            ? $"seed-{eventId:N}-{athleteProfileId:N}".Substring(0, 24)
            : null;

        return registration;
    }

    private static async Task<FreeAgentTeamInvite> EnsureFreeAgentInviteAsync(
        WrestlingPlatformDbContext dbContext,
        Guid registrationId,
        Guid teamId,
        string message,
        bool accepted,
        CancellationToken cancellationToken)
    {
        var invite = await dbContext.FreeAgentTeamInvites
            .FirstOrDefaultAsync(x => x.EventRegistrationId == registrationId && x.TeamId == teamId, cancellationToken);

        if (invite is null)
        {
            invite = new FreeAgentTeamInvite
            {
                EventRegistrationId = registrationId,
                TeamId = teamId
            };

            dbContext.FreeAgentTeamInvites.Add(invite);
        }

        invite.Message = message.Trim();
        invite.Accepted = accepted;
        return invite;
    }

    private static async Task<Bracket> EnsureBracketAsync(
        WrestlingPlatformDbContext dbContext,
        Guid eventId,
        Guid? divisionId,
        CompetitionLevel level,
        decimal weightClass,
        BracketGenerationMode mode,
        CancellationToken cancellationToken)
    {
        var bracket = await dbContext.Brackets
            .FirstOrDefaultAsync(
                x => x.TournamentEventId == eventId
                     && x.TournamentDivisionId == divisionId
                     && x.Level == level
                     && x.WeightClass == weightClass,
                cancellationToken);

        if (bracket is null)
        {
            bracket = new Bracket
            {
                TournamentEventId = eventId,
                TournamentDivisionId = divisionId,
                Level = level,
                WeightClass = weightClass,
                Mode = mode
            };

            dbContext.Brackets.Add(bracket);
        }

        bracket.Mode = mode;
        return bracket;
    }

    private static async Task<BracketEntry> EnsureBracketEntryAsync(
        WrestlingPlatformDbContext dbContext,
        Guid bracketId,
        Guid athleteProfileId,
        int seed,
        CancellationToken cancellationToken)
    {
        var entry = await dbContext.BracketEntries
            .FirstOrDefaultAsync(x => x.BracketId == bracketId && x.AthleteProfileId == athleteProfileId, cancellationToken);

        if (entry is null)
        {
            entry = new BracketEntry
            {
                BracketId = bracketId,
                AthleteProfileId = athleteProfileId
            };

            dbContext.BracketEntries.Add(entry);
        }

        entry.Seed = seed;
        return entry;
    }

    private static async Task<Match> EnsureMatchAsync(
        WrestlingPlatformDbContext dbContext,
        Guid bracketId,
        int round,
        int matchNumber,
        Guid? athleteAId,
        Guid? athleteBId,
        Guid? winnerAthleteId,
        string? score,
        string? resultMethod,
        string? matNumber,
        MatchStatus status,
        DateTime? scheduledUtc,
        DateTime? completedUtc,
        CancellationToken cancellationToken)
    {
        var match = await dbContext.Matches
            .FirstOrDefaultAsync(
                x => x.BracketId == bracketId
                     && x.Round == round
                     && x.MatchNumber == matchNumber,
                cancellationToken);

        if (match is null)
        {
            match = new Match
            {
                BracketId = bracketId,
                Round = round,
                MatchNumber = matchNumber
            };

            dbContext.Matches.Add(match);
        }

        match.AthleteAId = athleteAId;
        match.AthleteBId = athleteBId;
        match.WinnerAthleteId = winnerAthleteId;
        match.Score = score;
        match.ResultMethod = resultMethod;
        match.MatNumber = matNumber;
        match.Status = status;
        match.ScheduledUtc = scheduledUtc;
        match.CompletedUtc = completedUtc;
        return match;
    }

    private static async Task<NotificationSubscription> EnsureNotificationSubscriptionAsync(
        WrestlingPlatformDbContext dbContext,
        Guid userId,
        Guid? tournamentEventId,
        Guid? athleteProfileId,
        NotificationEventType eventType,
        NotificationChannel channel,
        string destination,
        CancellationToken cancellationToken)
    {
        var normalizedDestination = destination.Trim();
        var subscription = await dbContext.NotificationSubscriptions
            .FirstOrDefaultAsync(
                x => x.UserAccountId == userId
                     && x.TournamentEventId == tournamentEventId
                     && x.AthleteProfileId == athleteProfileId
                     && x.EventType == eventType
                     && x.Channel == channel
                     && x.Destination == normalizedDestination,
                cancellationToken);

        if (subscription is null)
        {
            subscription = new NotificationSubscription
            {
                UserAccountId = userId,
                TournamentEventId = tournamentEventId,
                AthleteProfileId = athleteProfileId,
                EventType = eventType,
                Channel = channel,
                Destination = normalizedDestination
            };

            dbContext.NotificationSubscriptions.Add(subscription);
        }

        return subscription;
    }

    private static async Task<NotificationMessage> EnsureNotificationMessageAsync(
        WrestlingPlatformDbContext dbContext,
        Guid subscriptionId,
        Guid? eventId,
        Guid? matchId,
        NotificationEventType eventType,
        NotificationChannel channel,
        string destination,
        string body,
        DateTime sentUtc,
        CancellationToken cancellationToken)
    {
        var normalizedDestination = destination.Trim();
        var normalizedBody = body.Trim();

        var message = await dbContext.NotificationMessages
            .FirstOrDefaultAsync(
                x => x.NotificationSubscriptionId == subscriptionId
                     && x.MatchId == matchId
                     && x.EventType == eventType
                     && x.Channel == channel
                     && x.Destination == normalizedDestination
                     && x.Body == normalizedBody,
                cancellationToken);

        if (message is null)
        {
            message = new NotificationMessage
            {
                NotificationSubscriptionId = subscriptionId,
                TournamentEventId = eventId,
                MatchId = matchId,
                EventType = eventType,
                Channel = channel,
                Destination = normalizedDestination,
                Body = normalizedBody
            };

            dbContext.NotificationMessages.Add(message);
        }

        message.SentUtc = sentUtc;
        return message;
    }

    private static async Task<StreamSession> EnsureStreamSessionAsync(
        WrestlingPlatformDbContext dbContext,
        Guid eventId,
        Guid? matchId,
        string deviceName,
        StreamStatus status,
        string playbackUrl,
        DateTime? startedUtc,
        DateTime? endedUtc,
        CancellationToken cancellationToken)
    {
        var normalizedDeviceName = deviceName.Trim();
        var stream = await dbContext.StreamSessions
            .FirstOrDefaultAsync(x => x.TournamentEventId == eventId && x.DeviceName == normalizedDeviceName, cancellationToken);

        if (stream is null)
        {
            stream = new StreamSession
            {
                TournamentEventId = eventId,
                DeviceName = normalizedDeviceName,
                IngestKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
                    .Replace('/', '_')
                    .Replace('+', '-')
            };

            dbContext.StreamSessions.Add(stream);
        }

        stream.MatchId = matchId;
        stream.Status = status;
        stream.PlaybackUrl = playbackUrl.Trim();
        stream.StartedUtc = startedUtc;
        stream.EndedUtc = endedUtc;
        return stream;
    }

    private static async Task EnsureDemoBracketAndStreamCoverageAsync(
        WrestlingPlatformDbContext dbContext,
        IReadOnlyDictionary<string, AthleteProfile> athleteProfilesByEmail,
        CancellationToken cancellationToken)
    {
        var athletesByLevel = athleteProfilesByEmail.Values
            .GroupBy(x => x.Level)
            .ToDictionary(
                x => x.Key,
                x => x
                    .OrderBy(profile => profile.LastName)
                    .ThenBy(profile => profile.FirstName)
                    .ToList());

        var allEvents = await dbContext.TournamentEvents
            .AsNoTracking()
            .OrderBy(x => x.StartUtc)
            .ToListAsync(cancellationToken);

        foreach (var tournamentEvent in allEvents)
        {
            var divisions = await dbContext.TournamentDivisions
                .Where(x => x.TournamentEventId == tournamentEvent.Id)
                .OrderBy(x => x.Level)
                .ThenBy(x => x.WeightClass)
                .ToListAsync(cancellationToken);

            if (divisions.Count == 0)
            {
                var fallbackDivision = await EnsureDivisionAsync(
                    dbContext,
                    tournamentEvent.Id,
                    "High School 132",
                    CompetitionLevel.HighSchool,
                    132m,
                    cancellationToken);

                divisions.Add(fallbackDivision);
            }

            var targetDivision = divisions[0];
            var candidates = athletesByLevel.TryGetValue(targetDivision.Level, out var matchingLevelAthletes)
                ? matchingLevelAthletes
                : [];

            if (candidates.Count < 2)
            {
                candidates = athleteProfilesByEmail.Values
                    .OrderBy(x => x.Level)
                    .ThenBy(x => x.LastName)
                    .ThenBy(x => x.FirstName)
                    .ToList();
            }

            if (candidates.Count < 2)
            {
                continue;
            }

            var athleteA = candidates[0];
            var athleteB = candidates[1];

            var bracket = await EnsureBracketAsync(
                dbContext,
                tournamentEvent.Id,
                targetDivision.Id,
                targetDivision.Level,
                targetDivision.WeightClass,
                BracketGenerationMode.Seeded,
                cancellationToken);

            await EnsureBracketEntryAsync(dbContext, bracket.Id, athleteA.Id, 1, cancellationToken);
            await EnsureBracketEntryAsync(dbContext, bracket.Id, athleteB.Id, 2, cancellationToken);

            var firstMatch = await dbContext.Matches
                .Where(x => x.BracketId == bracket.Id)
                .OrderBy(x => x.Round)
                .ThenBy(x => x.MatchNumber)
                .FirstOrDefaultAsync(cancellationToken);

            var matNumber = firstMatch?.MatNumber;
            if (string.IsNullOrWhiteSpace(matNumber))
            {
                matNumber = "Mat 1";
            }

            firstMatch = await EnsureMatchAsync(
                dbContext,
                bracket.Id,
                firstMatch?.Round ?? 1,
                firstMatch?.MatchNumber ?? 1,
                firstMatch?.AthleteAId ?? athleteA.Id,
                firstMatch?.AthleteBId ?? athleteB.Id,
                firstMatch?.WinnerAthleteId,
                firstMatch?.Score,
                firstMatch?.ResultMethod,
                matNumber,
                firstMatch?.Status ?? MatchStatus.Scheduled,
                firstMatch?.ScheduledUtc ?? tournamentEvent.StartUtc.AddMinutes(15),
                firstMatch?.CompletedUtc,
                cancellationToken);

            var hasLiveStream = await dbContext.StreamSessions
                .AnyAsync(
                    x => x.TournamentEventId == tournamentEvent.Id
                         && x.Status == StreamStatus.Live,
                    cancellationToken);

            if (hasLiveStream)
            {
                continue;
            }

            await EnsureStreamSessionAsync(
                dbContext,
                tournamentEvent.Id,
                firstMatch.Id,
                $"Mat Cam - {tournamentEvent.City}",
                StreamStatus.Live,
                ResolveSamplePlaybackUrl(tournamentEvent.Id),
                tournamentEvent.StartUtc.AddMinutes(15),
                endedUtc: null,
                cancellationToken);
        }
    }

    private static string ResolveSamplePlaybackUrl(Guid seed)
    {
        var samples = new[]
        {
            "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4",
            "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4",
            "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4",
            "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"
        };

        var index = Math.Abs(seed.GetHashCode()) % samples.Length;
        return samples[index];
    }

    private static string HashPassword(string password)
    {
        const int passwordIterations = 120_000;
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, passwordIterations, HashAlgorithmName.SHA256, 32);

        return $"PBKDF2${passwordIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    private static bool IsPostgresConfigured(string connectionString, string? provider)
    {
        var normalizedProvider = provider?.Trim().ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(normalizedProvider))
        {
            return normalizedProvider is "postgres" or "postgresql" or "npgsql";
        }

        return connectionString.StartsWith("Host=", StringComparison.OrdinalIgnoreCase)
               || connectionString.StartsWith("Server=", StringComparison.OrdinalIgnoreCase)
               || connectionString.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase)
               || connectionString.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase)
               || connectionString.Contains("Host=", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePostgresConnectionString(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return connectionString;
        }

        var trimmed = connectionString.Trim();
        if (!trimmed.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase)
            && !trimmed.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            return trimmed;
        }

        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = uri.Host,
            Port = uri.Port > 0 ? uri.Port : 5432
        };

        var databaseName = uri.AbsolutePath.Trim('/');
        if (!string.IsNullOrWhiteSpace(databaseName))
        {
            builder.Database = databaseName;
        }

        if (!string.IsNullOrWhiteSpace(uri.UserInfo))
        {
            var userInfoParts = uri.UserInfo.Split(':', 2);
            if (userInfoParts.Length > 0)
            {
                builder.Username = Uri.UnescapeDataString(userInfoParts[0]);
            }

            if (userInfoParts.Length > 1)
            {
                builder.Password = Uri.UnescapeDataString(userInfoParts[1]);
            }
        }

        foreach (var (key, value) in ParseUriQuery(uri.Query))
        {
            ApplyPostgresOption(builder, key, value);
        }

        return builder.ConnectionString;
    }

    private static IEnumerable<(string Key, string Value)> ParseUriQuery(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            yield break;
        }

        var rawQuery = query.TrimStart('?');
        if (string.IsNullOrWhiteSpace(rawQuery))
        {
            yield break;
        }

        var pairs = rawQuery.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var pair in pairs)
        {
            var separatorIndex = pair.IndexOf('=');
            if (separatorIndex < 0)
            {
                var keyOnly = Uri.UnescapeDataString(pair).Trim();
                if (!string.IsNullOrWhiteSpace(keyOnly))
                {
                    yield return (keyOnly, "true");
                }

                continue;
            }

            var key = Uri.UnescapeDataString(pair[..separatorIndex]).Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var value = Uri.UnescapeDataString(pair[(separatorIndex + 1)..]);
            yield return (key, value);
        }
    }

    private static void ApplyPostgresOption(NpgsqlConnectionStringBuilder builder, string key, string value)
    {
        var normalizedKey = key.Trim().ToLowerInvariant();
        switch (normalizedKey)
        {
            case "sslmode":
                if (Enum.TryParse<SslMode>(value, ignoreCase: true, out var sslMode))
                {
                    builder.SslMode = sslMode;
                }

                return;
            default:
                try
                {
                    builder[key] = value;
                }
                catch (ArgumentException)
                {
                    // Ignore unknown query options; known keys above are applied explicitly.
                }

                return;
        }
    }

    private sealed record AthleteSeed(
        string Email,
        string PhoneNumber,
        string FirstName,
        string LastName,
        int AgeYears,
        string State,
        string City,
        string SchoolOrClubName,
        int Grade,
        decimal WeightClass,
        CompetitionLevel Level);
}


