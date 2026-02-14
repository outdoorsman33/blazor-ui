using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Api.IntegrationTests;

internal static class TestApiHelpers
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    internal static StringContent JsonContent(object payload)
    {
        return new StringContent(
            JsonSerializer.Serialize(payload, JsonOptions),
            Encoding.UTF8,
            "application/json");
    }

    internal static StringContent JsonPayloadContent(string payload)
    {
        return new StringContent(payload, Encoding.UTF8, "application/json");
    }

    internal static async Task<T> ReadJsonAsync<T>(HttpResponseMessage response)
    {
        var payload = await response.Content.ReadAsStringAsync();
        var parsed = JsonSerializer.Deserialize<T>(payload, JsonOptions);

        return parsed
            ?? throw new InvalidOperationException($"Unable to deserialize response into {typeof(T).Name}. Payload: {payload}");
    }

    internal static async Task<RegisteredUserResponse> RegisterUserAsync(
        HttpClient client,
        string email,
        string password,
        UserRole role,
        string? phoneNumber = null)
    {
        using var response = await client.PostAsync(
            "/api/users/register",
            JsonContent(new RegisterUserRequest(email, password, role, phoneNumber)));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadJsonAsync<RegisteredUserResponse>(response);
    }

    internal static async Task<AuthTokenResponse> LoginAsync(HttpClient client, string email, string password)
    {
        using var response = await client.PostAsync(
            "/api/auth/login",
            JsonContent(new LoginRequest(email, password)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadJsonAsync<AuthTokenResponse>(response);
    }

    internal static Task<HttpResponseMessage> RefreshAsync(HttpClient client, string refreshToken)
    {
        return client.PostAsync("/api/auth/refresh", JsonContent(new RefreshTokenRequest(refreshToken)));
    }

    internal static void SetBearerToken(HttpClient client, string accessToken)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    }

    internal static HttpRequestMessage CreateStripeSignedRequest(
        string path,
        string payload,
        string signingSecret,
        long? timestampUnixSeconds = null,
        string? signatureOverride = null)
    {
        var timestamp = timestampUnixSeconds ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signature = signatureOverride ?? CreateStripeSignature(payload, signingSecret, timestamp);

        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonPayloadContent(payload)
        };

        request.Headers.TryAddWithoutValidation("Stripe-Signature", $"t={timestamp},v1={signature}");
        return request;
    }

    internal static string CreateStripeSignature(string payload, string signingSecret, long timestampUnixSeconds)
    {
        var signedPayload = $"{timestampUnixSeconds}.{payload}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(signingSecret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(signedPayload))).ToLowerInvariant();
    }

    internal static string BuildStripeCheckoutCompletedPayload(
        string eventId,
        string providerReference,
        Guid registrationId,
        int amountCents)
    {
        var payload = new
        {
            id = eventId,
            type = "checkout.session.completed",
            data = new
            {
                @object = new
                {
                    id = providerReference,
                    amount_total = amountCents,
                    currency = "usd",
                    payment_status = "paid",
                    metadata = new
                    {
                        registration_id = registrationId.ToString()
                    }
                }
            }
        };

        return JsonSerializer.Serialize(payload, JsonOptions);
    }
}

internal sealed record RegisteredUserResponse(Guid Id, string Email, UserRole Role);

internal sealed record WebhookEnqueueResponse(Guid EventRecordId, string Status, bool IsDuplicate);

internal sealed record ReconciliationProcessResponse(int Processed, int BatchSize);
