using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Infrastructure.Services;

public sealed class PaymentWebhookProcessingOptions
{
    public int PollIntervalSeconds { get; set; } = 10;
    public int BatchSize { get; set; } = 50;
    public int MaxAttempts { get; set; } = 20;
    public int RetryWindowMinutes { get; set; } = 90;
}

public sealed class PaymentWebhookReconciliationService(
    WrestlingPlatformDbContext dbContext,
    IOptions<PaymentWebhookProcessingOptions> options,
    ILogger<PaymentWebhookReconciliationService> logger) : IPaymentWebhookReconciliationService
{
    public async Task<PaymentWebhookEnqueueResult> EnqueueAsync(PaymentWebhookIngress ingress, CancellationToken cancellationToken = default)
    {
        var provider = string.IsNullOrWhiteSpace(ingress.Provider) ? "Stripe" : ingress.Provider.Trim();
        var providerEventId = string.IsNullOrWhiteSpace(ingress.ProviderEventId)
            ? $"{provider.ToLowerInvariant()}-{Guid.NewGuid():N}"
            : ingress.ProviderEventId.Trim();

        var duplicate = await dbContext.PaymentWebhookEvents
            .AsNoTracking()
            .AnyAsync(
                x => x.Provider == provider && x.ProviderEventId == providerEventId,
                cancellationToken);

        if (duplicate)
        {
            var existingId = await dbContext.PaymentWebhookEvents
                .AsNoTracking()
                .Where(x => x.Provider == provider && x.ProviderEventId == providerEventId)
                .Select(x => x.Id)
                .FirstAsync(cancellationToken);

            return new PaymentWebhookEnqueueResult(
                Accepted: true,
                IsDuplicate: true,
                EventRecordId: existingId,
                Status: "duplicate");
        }

        var row = new PaymentWebhookEvent
        {
            Provider = provider,
            ProviderEventId = providerEventId,
            EventType = ingress.EventType.Trim(),
            RegistrationId = ingress.RegistrationId,
            ProviderReference = string.IsNullOrWhiteSpace(ingress.ProviderReference) ? null : ingress.ProviderReference.Trim(),
            AmountCents = ingress.AmountCents,
            Currency = string.IsNullOrWhiteSpace(ingress.Currency) ? null : ingress.Currency.Trim().ToLowerInvariant(),
            IsPaymentConfirmed = ingress.IsPaymentConfirmed,
            Payload = ingress.Payload,
            ProcessingStatus = WebhookProcessingStatus.Pending,
            ProcessAttemptCount = 0,
            LastError = null,
            ProcessedUtc = null
        };

        dbContext.PaymentWebhookEvents.Add(row);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            var existingId = await dbContext.PaymentWebhookEvents
                .AsNoTracking()
                .Where(x => x.Provider == provider && x.ProviderEventId == providerEventId)
                .Select(x => x.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (existingId == Guid.Empty)
            {
                throw;
            }

            return new PaymentWebhookEnqueueResult(
                Accepted: true,
                IsDuplicate: true,
                EventRecordId: existingId,
                Status: "duplicate");
        }

        return new PaymentWebhookEnqueueResult(
            Accepted: true,
            IsDuplicate: false,
            EventRecordId: row.Id,
            Status: "queued");
    }

    public async Task<int> ProcessPendingAsync(int maxBatchSize, CancellationToken cancellationToken = default)
    {
        var safeBatchSize = Math.Clamp(maxBatchSize, 1, 250);
        var safeMaxAttempts = Math.Clamp(options.Value.MaxAttempts, 1, 100);
        var retryWindow = TimeSpan.FromMinutes(Math.Clamp(options.Value.RetryWindowMinutes, 1, 1_440));
        var retryCutoffUtc = DateTime.UtcNow.Subtract(retryWindow);

        var pending = await dbContext.PaymentWebhookEvents
            .Where(x => x.ProcessingStatus == WebhookProcessingStatus.Pending)
            .OrderBy(x => x.CreatedUtc)
            .Take(safeBatchSize)
            .ToListAsync(cancellationToken);

        if (pending.Count == 0)
        {
            return 0;
        }

        var processed = 0;

        foreach (var webhook in pending)
        {
            webhook.ProcessAttemptCount += 1;

            if (!webhook.IsPaymentConfirmed)
            {
                webhook.ProcessingStatus = WebhookProcessingStatus.Ignored;
                webhook.ProcessedUtc = DateTime.UtcNow;
                webhook.LastError = "Event does not indicate a successful payment.";
                processed += 1;
                continue;
            }

            if (webhook.RegistrationId is null)
            {
                webhook.ProcessingStatus = WebhookProcessingStatus.Failed;
                webhook.ProcessedUtc = DateTime.UtcNow;
                webhook.LastError = "Missing registration id metadata.";
                processed += 1;
                continue;
            }

            var registration = await dbContext.EventRegistrations
                .FirstOrDefaultAsync(x => x.Id == webhook.RegistrationId.Value, cancellationToken);

            if (registration is null)
            {
                if (webhook.ProcessAttemptCount >= safeMaxAttempts || webhook.CreatedUtc < retryCutoffUtc)
                {
                    webhook.ProcessingStatus = WebhookProcessingStatus.Failed;
                    webhook.ProcessedUtc = DateTime.UtcNow;
                    webhook.LastError = "Registration was not found before retry policy expired.";
                    processed += 1;
                }
                else
                {
                    webhook.LastError = "Registration not found yet; pending retry.";
                }

                continue;
            }

            registration.PaymentStatus = PaymentStatus.Paid;
            registration.PaymentReference = string.IsNullOrWhiteSpace(webhook.ProviderReference)
                ? registration.PaymentReference
                : webhook.ProviderReference;

            if (webhook.AmountCents is > 0)
            {
                registration.PaidAmountCents = webhook.AmountCents.Value;
            }
            else
            {
                registration.PaidAmountCents = await dbContext.TournamentEvents
                    .Where(x => x.Id == registration.TournamentEventId)
                    .Select(x => x.EntryFeeCents)
                    .FirstOrDefaultAsync(cancellationToken);
            }

            webhook.ProcessingStatus = WebhookProcessingStatus.Processed;
            webhook.ProcessedUtc = DateTime.UtcNow;
            webhook.LastError = null;
            processed += 1;
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Processed {ProcessedCount} pending webhook events out of {BatchCount} fetched.",
            processed,
            pending.Count);

        return processed;
    }
}

public sealed class PaymentWebhookReconciliationWorker(
    IServiceProvider serviceProvider,
    IOptions<PaymentWebhookProcessingOptions> options,
    ILogger<PaymentWebhookReconciliationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Clamp(options.Value.PollIntervalSeconds, 2, 300));
        var batchSize = Math.Clamp(options.Value.BatchSize, 1, 250);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = serviceProvider.CreateScope();
                var reconciliationService = scope.ServiceProvider.GetRequiredService<IPaymentWebhookReconciliationService>();
                await reconciliationService.ProcessPendingAsync(batchSize, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Payment webhook reconciliation cycle failed.");
            }

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}