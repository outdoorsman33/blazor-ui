using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class SignedWebhookIntegrationTests
{
    private const string SigningSecret = "whsec_integration_test_secret";

    [Fact]
    public async Task StripeWebhook_WithValidStripeSignature_IsAccepted()
    {
        using var factory = new WrestlingPlatformApiFactory(new Dictionary<string, string?>
        {
            ["Payments:StripeWebhookSecret"] = SigningSecret
        });

        await factory.ResetDatabaseAsync();
        using var client = factory.CreateClient();

        var eventId = $"evt_signed_{Guid.NewGuid():N}";
        var providerReference = $"cs_{Guid.NewGuid():N}";
        var registrationId = Guid.NewGuid();
        var payload = TestApiHelpers.BuildStripeCheckoutCompletedPayload(eventId, providerReference, registrationId, 5300);

        using var request = TestApiHelpers.CreateStripeSignedRequest(
            "/api/webhooks/stripe",
            payload,
            SigningSecret);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await TestApiHelpers.ReadJsonAsync<WebhookEnqueueResponse>(response);
        Assert.False(body.IsDuplicate);
        Assert.Equal("queued", body.Status);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
        var storedEvent = await dbContext.PaymentWebhookEvents.SingleAsync(x => x.ProviderEventId == eventId);

        Assert.Equal(WebhookProcessingStatus.Pending, storedEvent.ProcessingStatus);
    }

    [Fact]
    public async Task StripeWebhook_WithMissingSignature_IsUnauthorizedWhenSecretEnabled()
    {
        using var factory = new WrestlingPlatformApiFactory(new Dictionary<string, string?>
        {
            ["Payments:StripeWebhookSecret"] = SigningSecret
        });

        await factory.ResetDatabaseAsync();
        using var client = factory.CreateClient();

        var payload = TestApiHelpers.BuildStripeCheckoutCompletedPayload(
            eventId: $"evt_missing_sig_{Guid.NewGuid():N}",
            providerReference: $"cs_{Guid.NewGuid():N}",
            registrationId: Guid.NewGuid(),
            amountCents: 2000);

        using var response = await client.PostAsync("/api/webhooks/stripe", TestApiHelpers.JsonPayloadContent(payload));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task StripeWebhook_WithInvalidSignature_IsUnauthorizedWhenSecretEnabled()
    {
        using var factory = new WrestlingPlatformApiFactory(new Dictionary<string, string?>
        {
            ["Payments:StripeWebhookSecret"] = SigningSecret
        });

        await factory.ResetDatabaseAsync();
        using var client = factory.CreateClient();

        var eventId = $"evt_bad_sig_{Guid.NewGuid():N}";
        var payload = TestApiHelpers.BuildStripeCheckoutCompletedPayload(
            eventId,
            providerReference: $"cs_{Guid.NewGuid():N}",
            registrationId: Guid.NewGuid(),
            amountCents: 3400);

        using var request = TestApiHelpers.CreateStripeSignedRequest(
            "/api/webhooks/stripe",
            payload,
            SigningSecret,
            signatureOverride: "abc123");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
        var rowCount = await dbContext.PaymentWebhookEvents.CountAsync(x => x.ProviderEventId == eventId);

        Assert.Equal(0, rowCount);
    }
}
