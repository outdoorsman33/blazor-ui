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
}

