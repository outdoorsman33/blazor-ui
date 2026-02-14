using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;
using WrestlingPlatform.Infrastructure.Services;

namespace WrestlingPlatform.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddWrestlingPlatformInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=wrestling-platform.db";
        var usePostgres = IsPostgresConfigured(connectionString, configuration["Database:Provider"]);

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

        if (await dbContext.TournamentEvents.AnyAsync(cancellationToken))
        {
            return;
        }

        var seedTeam = new Team
        {
            Name = "Sample Wrestling Club",
            Type = TeamType.Club,
            State = "OH",
            City = "Columbus"
        };

        var seedEvent = new TournamentEvent
        {
            Name = "Ohio Open Early Season",
            OrganizerType = OrganizerType.Club,
            OrganizerId = seedTeam.Id,
            State = "OH",
            City = "Columbus",
            Venue = "Metro Sports Complex",
            StartUtc = DateTime.UtcNow.Date.AddDays(21),
            EndUtc = DateTime.UtcNow.Date.AddDays(22),
            EntryFeeCents = 3500,
            IsPublished = true
        };

        var seedDivision = new TournamentDivision
        {
            TournamentEventId = seedEvent.Id,
            Name = "High School 132",
            Level = CompetitionLevel.HighSchool,
            WeightClass = 132m
        };

        dbContext.Teams.Add(seedTeam);
        dbContext.TournamentEvents.Add(seedEvent);
        dbContext.TournamentDivisions.Add(seedDivision);
        await dbContext.SaveChangesAsync(cancellationToken);
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
}
