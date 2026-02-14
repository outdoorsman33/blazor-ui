using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WrestlingPlatform.Infrastructure;
using WrestlingPlatform.Infrastructure.Persistence;
using WrestlingPlatform.Infrastructure.Services;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class WrestlingPlatformApiFactory : WebApplicationFactory<Program>
{
    private readonly IReadOnlyDictionary<string, string?> _configurationOverrides;
    private SqliteConnection? _connection;

    public WrestlingPlatformApiFactory()
        : this(configurationOverrides: null)
    {
    }

    internal WrestlingPlatformApiFactory(IReadOnlyDictionary<string, string?>? configurationOverrides)
    {
        _configurationOverrides = configurationOverrides ?? new Dictionary<string, string?>();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("IntegrationTest");

        builder.ConfigureAppConfiguration((_, configurationBuilder) =>
        {
            var configuration = new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = "Data Source=wrestling-platform.integration.db",
                ["Payments:StripeWebhookSecret"] = string.Empty,
                ["Payments:WebhookProcessing:PollIntervalSeconds"] = "600",
                ["Payments:WebhookProcessing:BatchSize"] = "50",
                ["Payments:WebhookProcessing:MaxAttempts"] = "5",
                ["Payments:WebhookProcessing:RetryWindowMinutes"] = "120"
            };

            foreach (var entry in _configurationOverrides)
            {
                configuration[entry.Key] = entry.Value;
            }

            configurationBuilder.AddInMemoryCollection(configuration);
        });

        builder.ConfigureServices(services =>
        {
            var dbContextOptionsDescriptor = services.SingleOrDefault(
                descriptor => descriptor.ServiceType == typeof(DbContextOptions<WrestlingPlatformDbContext>));
            if (dbContextOptionsDescriptor is not null)
            {
                services.Remove(dbContextOptionsDescriptor);
            }

            var dbContextDescriptor = services.SingleOrDefault(
                descriptor => descriptor.ServiceType == typeof(WrestlingPlatformDbContext));
            if (dbContextDescriptor is not null)
            {
                services.Remove(dbContextDescriptor);
            }

            var workerDescriptors = services
                .Where(descriptor =>
                    descriptor.ServiceType == typeof(IHostedService)
                    && descriptor.ImplementationType == typeof(PaymentWebhookReconciliationWorker))
                .ToList();

            foreach (var workerDescriptor in workerDescriptors)
            {
                services.Remove(workerDescriptor);
            }

            _connection = new SqliteConnection("Data Source=:memory:");
            _connection.Open();

            services.AddSingleton(_connection);
            services.AddDbContext<WrestlingPlatformDbContext>((serviceProvider, options) =>
            {
                options.UseSqlite(serviceProvider.GetRequiredService<SqliteConnection>());
            });
        });
    }

    public async Task ResetDatabaseAsync()
    {
        await using var scope = Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

        await dbContext.Database.EnsureDeletedAsync();
        await dbContext.Database.EnsureCreatedAsync();
        await Services.InitializeDatabaseAsync();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing || _connection is null)
        {
            return;
        }

        _connection.Dispose();
        _connection = null;
    }
}
