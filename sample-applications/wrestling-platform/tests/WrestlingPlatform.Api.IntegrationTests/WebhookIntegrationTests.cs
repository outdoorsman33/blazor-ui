using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class WebhookIntegrationTests(WrestlingPlatformApiFactory factory) : IClassFixture<WrestlingPlatformApiFactory>
{
    [Fact]
    public async Task StripeWebhook_DuplicateEventId_IsIdempotent()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();

        var eventId = $"evt_idempotent_{Guid.NewGuid():N}";
        var providerReference = $"cs_{Guid.NewGuid():N}";
        var registrationId = Guid.NewGuid();

        var payload = TestApiHelpers.BuildStripeCheckoutCompletedPayload(eventId, providerReference, registrationId, 4200);

        using var firstResponse = await client.PostAsync("/api/webhooks/stripe", TestApiHelpers.JsonPayloadContent(payload));
        Assert.Equal(HttpStatusCode.Accepted, firstResponse.StatusCode);
        var firstBody = await TestApiHelpers.ReadJsonAsync<WebhookEnqueueResponse>(firstResponse);
        Assert.False(firstBody.IsDuplicate);
        Assert.Equal("queued", firstBody.Status);

        using var secondResponse = await client.PostAsync("/api/webhooks/stripe", TestApiHelpers.JsonPayloadContent(payload));
        Assert.Equal(HttpStatusCode.Accepted, secondResponse.StatusCode);
        var secondBody = await TestApiHelpers.ReadJsonAsync<WebhookEnqueueResponse>(secondResponse);
        Assert.True(secondBody.IsDuplicate);
        Assert.Equal("duplicate", secondBody.Status);
        Assert.Equal(firstBody.EventRecordId, secondBody.EventRecordId);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

        var storedEvents = await dbContext.PaymentWebhookEvents
            .Where(x => x.Provider == "Stripe" && x.ProviderEventId == eventId)
            .ToListAsync();

        Assert.Single(storedEvents);
        Assert.Equal(WebhookProcessingStatus.Pending, storedEvents[0].ProcessingStatus);
    }

    [Fact]
    public async Task Reconciliation_RetriesPendingWebhook_AndProcessesAfterRegistrationExists()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var directorEmail = $"director-{Guid.NewGuid():N}@example.com";
        await TestApiHelpers.RegisterUserAsync(client, directorEmail, password, UserRole.TournamentDirector);

        var directorLogin = await TestApiHelpers.LoginAsync(client, directorEmail, password);
        TestApiHelpers.SetBearerToken(client, directorLogin.AccessToken);

        var eventId = $"evt_retry_{Guid.NewGuid():N}";
        var providerReference = $"cs_{Guid.NewGuid():N}";
        var registrationId = Guid.NewGuid();

        var payload = TestApiHelpers.BuildStripeCheckoutCompletedPayload(eventId, providerReference, registrationId, 4700);

        using var webhookResponse = await client.PostAsync("/api/webhooks/stripe", TestApiHelpers.JsonPayloadContent(payload));
        Assert.Equal(HttpStatusCode.Accepted, webhookResponse.StatusCode);

        using var firstProcessResponse = await client.PostAsync("/api/payments/reconciliation/process?batchSize=10", content: null);
        Assert.Equal(HttpStatusCode.OK, firstProcessResponse.StatusCode);
        var firstProcessBody = await TestApiHelpers.ReadJsonAsync<ReconciliationProcessResponse>(firstProcessResponse);
        Assert.Equal(0, firstProcessBody.Processed);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

            var queuedEvent = await dbContext.PaymentWebhookEvents.SingleAsync(x => x.ProviderEventId == eventId);
            Assert.Equal(WebhookProcessingStatus.Pending, queuedEvent.ProcessingStatus);
            Assert.Equal(1, queuedEvent.ProcessAttemptCount);
            Assert.Equal("Registration not found yet; pending retry.", queuedEvent.LastError);

            dbContext.EventRegistrations.Add(new EventRegistration
            {
                Id = registrationId,
                TournamentEventId = Guid.NewGuid(),
                AthleteProfileId = Guid.NewGuid(),
                Status = RegistrationStatus.Confirmed,
                PaymentStatus = PaymentStatus.Pending
            });

            await dbContext.SaveChangesAsync();
        }

        using var secondProcessResponse = await client.PostAsync("/api/payments/reconciliation/process?batchSize=10", content: null);
        Assert.Equal(HttpStatusCode.OK, secondProcessResponse.StatusCode);
        var secondProcessBody = await TestApiHelpers.ReadJsonAsync<ReconciliationProcessResponse>(secondProcessResponse);
        Assert.Equal(1, secondProcessBody.Processed);

        await using (var verificationScope = factory.Services.CreateAsyncScope())
        {
            var dbContext = verificationScope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

            var processedEvent = await dbContext.PaymentWebhookEvents.SingleAsync(x => x.ProviderEventId == eventId);
            var registration = await dbContext.EventRegistrations.SingleAsync(x => x.Id == registrationId);

            Assert.Equal(WebhookProcessingStatus.Processed, processedEvent.ProcessingStatus);
            Assert.Equal(2, processedEvent.ProcessAttemptCount);
            Assert.Null(processedEvent.LastError);

            Assert.Equal(PaymentStatus.Paid, registration.PaymentStatus);
            Assert.Equal(providerReference, registration.PaymentReference);
            Assert.Equal(4700, registration.PaidAmountCents);
        }
    }
}
