using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Infrastructure.Services;

public sealed class PaymentGatewayOptions
{
    public string ProviderMode { get; set; } = "Mock";
    public string BaseCheckoutUrl { get; set; } = "https://payments.local";
    public string StripeSecretKey { get; set; } = string.Empty;
    public string StripeSuccessUrl { get; set; } = "https://platform.local/payments/success";
    public string StripeCancelUrl { get; set; } = "https://platform.local/payments/cancel";
    public string StripeWebhookSecret { get; set; } = string.Empty;
}

public sealed class ConfigurablePaymentGateway(IOptions<PaymentGatewayOptions> options) : IPaymentGateway
{
    public async Task<PaymentIntentResult> CreatePaymentIntentAsync(
        EventRegistration registration,
        TournamentEvent tournamentEvent,
        CancellationToken cancellationToken = default)
    {
        if (string.Equals(options.Value.ProviderMode, "Stripe", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(options.Value.StripeSecretKey))
        {
            var stripeResult = await TryCreateStripeCheckoutAsync(registration, tournamentEvent, cancellationToken);
            if (stripeResult is not null)
            {
                return stripeResult;
            }
        }

        return CreateMockIntent(registration);
    }

    private async Task<PaymentIntentResult?> TryCreateStripeCheckoutAsync(
        EventRegistration registration,
        TournamentEvent tournamentEvent,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new HttpClient
            {
                BaseAddress = new Uri("https://api.stripe.com")
            };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", options.Value.StripeSecretKey);

            var form = new Dictionary<string, string>
            {
                ["mode"] = "payment",
                ["success_url"] = options.Value.StripeSuccessUrl,
                ["cancel_url"] = options.Value.StripeCancelUrl,
                ["metadata[registration_id]"] = registration.Id.ToString(),
                ["metadata[event_id]"] = registration.TournamentEventId.ToString(),
                ["line_items[0][price_data][currency]"] = tournamentEvent.Currency.ToLowerInvariant(),
                ["line_items[0][price_data][product_data][name]"] = tournamentEvent.Name,
                ["line_items[0][price_data][unit_amount]"] = tournamentEvent.EntryFeeCents.ToString(),
                ["line_items[0][quantity]"] = "1"
            };

            using var content = new FormUrlEncodedContent(form);
            using var response = await client.PostAsync("/v1/checkout/sessions", content, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

            var root = doc.RootElement;
            if (!root.TryGetProperty("id", out var idElement)
                || !root.TryGetProperty("url", out var urlElement))
            {
                return null;
            }

            return new PaymentIntentResult(
                Provider: "Stripe",
                ProviderReference: idElement.GetString() ?? string.Empty,
                CheckoutUrl: urlElement.GetString() ?? string.Empty,
                ExpiresUtc: DateTime.UtcNow.AddMinutes(30));
        }
        catch
        {
            return null;
        }
    }

    private PaymentIntentResult CreateMockIntent(EventRegistration registration)
    {
        var providerReference = $"evt_{registration.TournamentEventId:N}_reg_{registration.Id:N}_{Guid.NewGuid():N}";
        var checkoutUrl = $"{options.Value.BaseCheckoutUrl.TrimEnd('/')}/checkout/{registration.Id:N}?ref={providerReference}";

        return new PaymentIntentResult(
            Provider: "MockStripeCompatible",
            ProviderReference: providerReference,
            CheckoutUrl: checkoutUrl,
            ExpiresUtc: DateTime.UtcNow.AddMinutes(30));
    }
}
