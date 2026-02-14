using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api;

internal static class StripeWebhookHelpers
{
    internal static bool VerifyStripeWebhookSignature(
        HttpRequest httpRequest,
        string payload,
        string? expectedSecret,
        TimeSpan tolerance)
    {
        if (string.IsNullOrWhiteSpace(expectedSecret))
        {
            return true;
        }

        if (httpRequest.Headers.TryGetValue("Stripe-Signature", out var stripeSignatureHeader))
        {
            if (!TryParseStripeSignatureHeader(stripeSignatureHeader.ToString(), out var timestamp, out var signatures))
            {
                return false;
            }

            var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(nowUnix - timestamp) > tolerance.TotalSeconds)
            {
                return false;
            }

            var signedPayload = $"{timestamp}.{payload}";
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(expectedSecret));
            var expectedSignature = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(signedPayload)));

            foreach (var candidate in signatures)
            {
                if (HexEquals(candidate, expectedSignature))
                {
                    return true;
                }
            }

            return false;
        }

        if (httpRequest.Headers.TryGetValue("X-Webhook-Secret", out var legacyHeader))
        {
            return string.Equals(legacyHeader.ToString(), expectedSecret, StringComparison.Ordinal);
        }

        return false;
    }

    internal static bool TryParseStripeWebhookIngress(
        string payload,
        out PaymentWebhookIngress ingress,
        out string parseError)
    {
        ingress = default!;
        parseError = string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(payload);
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                parseError = "Webhook payload must be a JSON object.";
                return false;
            }

            if (root.TryGetProperty("registrationId", out var legacyRegistrationIdElement)
                && root.TryGetProperty("providerReference", out var legacyProviderReferenceElement))
            {
                if (!Guid.TryParse(legacyRegistrationIdElement.GetString(), out var legacyRegistrationId))
                {
                    parseError = "Legacy webhook payload is missing a valid registration id.";
                    return false;
                }

                var legacyProviderReference = legacyProviderReferenceElement.GetString();
                if (string.IsNullOrWhiteSpace(legacyProviderReference))
                {
                    parseError = "Legacy webhook payload is missing provider reference.";
                    return false;
                }

                ingress = new PaymentWebhookIngress(
                    Provider: "Stripe",
                    ProviderEventId: $"legacy-{legacyRegistrationId:N}-{legacyProviderReference.Trim()}",
                    EventType: "legacy.payment-confirmed",
                    RegistrationId: legacyRegistrationId,
                    ProviderReference: legacyProviderReference.Trim(),
                    AmountCents: null,
                    Currency: "usd",
                    IsPaymentConfirmed: true,
                    Payload: payload);

                return true;
            }

            var eventId = root.TryGetProperty("id", out var eventIdElement) ? eventIdElement.GetString() : null;
            var eventType = root.TryGetProperty("type", out var eventTypeElement) ? eventTypeElement.GetString() : null;

            if (!root.TryGetProperty("data", out var dataElement)
                || dataElement.ValueKind != JsonValueKind.Object
                || !dataElement.TryGetProperty("object", out var objectElement)
                || objectElement.ValueKind != JsonValueKind.Object)
            {
                parseError = "Stripe webhook payload is missing data.object.";
                return false;
            }

            var providerReference = objectElement.TryGetProperty("id", out var objectIdElement)
                ? objectIdElement.GetString()
                : null;

            if (string.IsNullOrWhiteSpace(providerReference)
                && objectElement.TryGetProperty("payment_intent", out var paymentIntentElement)
                && paymentIntentElement.ValueKind == JsonValueKind.String)
            {
                providerReference = paymentIntentElement.GetString();
            }

            int? amountCents = null;
            if (objectElement.TryGetProperty("amount_total", out var amountTotalElement)
                && amountTotalElement.ValueKind == JsonValueKind.Number
                && amountTotalElement.TryGetInt32(out var amountTotal))
            {
                amountCents = amountTotal;
            }
            else if (objectElement.TryGetProperty("amount_received", out var amountReceivedElement)
                     && amountReceivedElement.ValueKind == JsonValueKind.Number
                     && amountReceivedElement.TryGetInt32(out var amountReceived))
            {
                amountCents = amountReceived;
            }

            var currency = objectElement.TryGetProperty("currency", out var currencyElement)
                           && currencyElement.ValueKind == JsonValueKind.String
                ? currencyElement.GetString()
                : "usd";

            Guid? registrationId = null;
            if (objectElement.TryGetProperty("metadata", out var metadataElement)
                && metadataElement.ValueKind == JsonValueKind.Object)
            {
                if (metadataElement.TryGetProperty("registration_id", out var registrationIdElement)
                    && registrationIdElement.ValueKind == JsonValueKind.String
                    && Guid.TryParse(registrationIdElement.GetString(), out var parsedRegistrationId))
                {
                    registrationId = parsedRegistrationId;
                }
                else if (metadataElement.TryGetProperty("registrationId", out var registrationIdCamelElement)
                         && registrationIdCamelElement.ValueKind == JsonValueKind.String
                         && Guid.TryParse(registrationIdCamelElement.GetString(), out var parsedCamelRegistrationId))
                {
                    registrationId = parsedCamelRegistrationId;
                }
            }

            var paymentStatus = objectElement.TryGetProperty("payment_status", out var paymentStatusElement)
                ? paymentStatusElement.GetString()
                : null;

            var isPaymentConfirmed =
                string.Equals(paymentStatus, "paid", StringComparison.OrdinalIgnoreCase)
                || string.Equals(eventType, "checkout.session.completed", StringComparison.OrdinalIgnoreCase)
                || string.Equals(eventType, "checkout.session.async_payment_succeeded", StringComparison.OrdinalIgnoreCase)
                || string.Equals(eventType, "payment_intent.succeeded", StringComparison.OrdinalIgnoreCase);

            var effectiveEventType = string.IsNullOrWhiteSpace(eventType) ? "unknown" : eventType.Trim();
            var effectiveEventId = string.IsNullOrWhiteSpace(eventId) ? CreateDeterministicWebhookEventId(payload) : eventId.Trim();

            ingress = new PaymentWebhookIngress(
                Provider: "Stripe",
                ProviderEventId: effectiveEventId,
                EventType: effectiveEventType,
                RegistrationId: registrationId,
                ProviderReference: providerReference,
                AmountCents: amountCents,
                Currency: currency,
                IsPaymentConfirmed: isPaymentConfirmed,
                Payload: payload);

            return true;
        }
        catch (JsonException jsonException)
        {
            parseError = $"Webhook payload is invalid JSON: {jsonException.Message}";
            return false;
        }
        catch (Exception ex)
        {
            parseError = $"Webhook payload parsing failed: {ex.Message}";
            return false;
        }
    }

    private static bool TryParseStripeSignatureHeader(string headerValue, out long timestamp, out List<string> signatures)
    {
        timestamp = 0;
        signatures = [];

        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        var parts = headerValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var keyValue = part.Split('=', 2, StringSplitOptions.TrimEntries);
            if (keyValue.Length != 2)
            {
                continue;
            }

            if (string.Equals(keyValue[0], "t", StringComparison.OrdinalIgnoreCase)
                && long.TryParse(keyValue[1], out var parsedTimestamp))
            {
                timestamp = parsedTimestamp;
                continue;
            }

            if (string.Equals(keyValue[0], "v1", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(keyValue[1]))
            {
                signatures.Add(keyValue[1]);
            }
        }

        return timestamp > 0 && signatures.Count > 0;
    }

    private static bool HexEquals(string leftHex, string rightHex)
    {
        try
        {
            var leftBytes = Convert.FromHexString(leftHex);
            var rightBytes = Convert.FromHexString(rightHex);
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        catch
        {
            return false;
        }
    }

    private static string CreateDeterministicWebhookEventId(string payload)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        var hashHex = Convert.ToHexString(hashBytes).ToLowerInvariant();
        return $"evt_{hashHex[..24]}";
    }
}