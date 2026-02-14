using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Web.Services;

public sealed class PlatformApiClient(HttpClient httpClient, AuthSession authSession)
{
    private readonly JsonSerializerOptions _jsonOptions = CreateJsonOptions();
    private readonly SemaphoreSlim _sessionLock = new(1, 1);

    public async Task<ApiResult<AuthTokenResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("/api/auth/login", request, _jsonOptions, cancellationToken);
        var result = await ReadResponseAsync<AuthTokenResponse>(response, cancellationToken);

        if (result.Success && result.Data is not null)
        {
            authSession.Set(result.Data);
            ApplyAuthorizationHeader();
        }

        return result;
    }

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        if (authSession.IsAuthenticated)
        {
            try
            {
                ApplyAuthorizationHeader();
                await httpClient.PostAsync("/api/auth/logout", content: null, cancellationToken);
            }
            catch
            {
                // Best-effort token revocation; local session is always cleared.
            }
        }

        authSession.Clear();
        httpClient.DefaultRequestHeaders.Authorization = null;
    }

    public async Task<ApiResult<UserSummary>> RegisterUserAsync(RegisterUserRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/users/register", request, cancellationToken);
        return await ReadResponseAsync<UserSummary>(response, cancellationToken);
    }

    public async Task<ApiResult<AthleteProfile>> CreateAthleteProfileAsync(CreateAthleteProfileRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/profiles/athletes", request, cancellationToken);
        return await ReadResponseAsync<AthleteProfile>(response, cancellationToken);
    }

    public async Task<ApiResult<CoachProfile>> CreateCoachProfileAsync(CreateCoachProfileRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/profiles/coaches", request, cancellationToken);
        return await ReadResponseAsync<CoachProfile>(response, cancellationToken);
    }

    public async Task<ApiResult<Team>> CreateTeamAsync(CreateTeamRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/teams", request, cancellationToken);
        return await ReadResponseAsync<Team>(response, cancellationToken);
    }

    public async Task<ApiResult<CoachAssociation>> CreateCoachAssociationAsync(
        Guid coachProfileId,
        CreateCoachAssociationRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/coaches/{coachProfileId}/associations", request, cancellationToken);
        return await ReadResponseAsync<CoachAssociation>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentEvent>> CreateEventAsync(CreateTournamentEventRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/events", request, cancellationToken);
        return await ReadResponseAsync<TournamentEvent>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentDivision>> CreateDivisionAsync(
        Guid eventId,
        CreateTournamentDivisionRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/events/{eventId}/divisions", request, cancellationToken);
        return await ReadResponseAsync<TournamentDivision>(response, cancellationToken);
    }

    public async Task<ApiResult<List<TournamentEvent>>> SearchEventsAsync(SearchEventsQuery query, CancellationToken cancellationToken = default)
    {
        var queryParams = new Dictionary<string, string?>
        {
            ["state"] = query.State,
            ["city"] = query.City,
            ["level"] = query.Level?.ToString(),
            ["startsOnOrAfterUtc"] = query.StartsOnOrAfterUtc?.ToString("O"),
            ["startsOnOrBeforeUtc"] = query.StartsOnOrBeforeUtc?.ToString("O"),
            ["maxEntryFeeCents"] = query.MaxEntryFeeCents?.ToString()
        };

        var url = BuildUrlWithQuery("/api/events/search", queryParams);
        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<List<TournamentEvent>>(response, cancellationToken);
    }

    public async Task<ApiResult<List<GroupedEventsResponse>>> GetGroupedEventsAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync("/api/events/grouped", cancellationToken);
        return await ReadResponseAsync<List<GroupedEventsResponse>>(response, cancellationToken);
    }

    public async Task<ApiResult<RegistrationSubmissionResponse>> RegisterAthleteForEventAsync(
        Guid eventId,
        RegisterForEventRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/events/{eventId}/registrations", request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return ApiResult<RegistrationSubmissionResponse>.Fail(response.StatusCode, await ReadErrorMessageAsync(response, cancellationToken));
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var jsonDocument = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

        var root = jsonDocument.RootElement;
        var result = new RegistrationSubmissionResponse();

        if (root.TryGetProperty("registration", out var registrationElement))
        {
            result.Registration = registrationElement.Deserialize<EventRegistration>(_jsonOptions);
            if (root.TryGetProperty("paymentIntent", out var paymentIntentElement))
            {
                result.PaymentIntent = paymentIntentElement.Deserialize<PaymentIntentResult>(_jsonOptions);
            }
        }
        else
        {
            result.Registration = root.Deserialize<EventRegistration>(_jsonOptions);
        }

        return ApiResult<RegistrationSubmissionResponse>.Ok(result, "Registration submitted.");
    }

    public async Task<ApiResult<EventRegistration>> ConfirmPaymentAsync(
        ConfirmRegistrationPaymentRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/registrations/{request.RegistrationId}/payments/confirm", request, cancellationToken);
        return await ReadResponseAsync<EventRegistration>(response, cancellationToken);
    }

    public async Task<ApiResult<List<FreeAgentRegistrationView>>> GetFreeAgentsAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/free-agents", cancellationToken);
        return await ReadResponseAsync<List<FreeAgentRegistrationView>>(response, cancellationToken);
    }

    public async Task<ApiResult<FreeAgentTeamInvite>> InviteFreeAgentAsync(
        Guid eventId,
        Guid registrationId,
        TeamInviteFreeAgentRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/events/{eventId}/free-agents/{registrationId}/invite", request, cancellationToken);
        return await ReadResponseAsync<FreeAgentTeamInvite>(response, cancellationToken);
    }

    public async Task<ApiResult<BracketGenerationResult>> GenerateBracketAsync(
        Guid eventId,
        GenerateBracketRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/events/{eventId}/brackets/generate", request, cancellationToken);
        return await ReadResponseAsync<BracketGenerationResult>(response, cancellationToken);
    }

    public async Task<ApiResult<List<BracketBundle>>> GetBracketsAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/brackets", cancellationToken);
        return await ReadResponseAsync<List<BracketBundle>>(response, cancellationToken);
    }

    public async Task<ApiResult<Match>> AssignMatAsync(Guid matchId, AssignMatRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/matches/{matchId}/assign-mat", request, cancellationToken);
        return await ReadResponseAsync<Match>(response, cancellationToken);
    }

    public async Task<ApiResult<Match>> RecordMatchResultAsync(
        Guid matchId,
        RecordMatchResultRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/matches/{matchId}/result", request, cancellationToken);
        return await ReadResponseAsync<Match>(response, cancellationToken);
    }

    public async Task<ApiResult<List<AthleteStatsSnapshot>>> GetAthleteStatsHistoryAsync(Guid athleteId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/athletes/{athleteId}/stats/history", cancellationToken);
        return await ReadResponseAsync<List<AthleteStatsSnapshot>>(response, cancellationToken);
    }

    public async Task<ApiResult<List<AthleteRanking>>> GetRankingsAsync(
        CompetitionLevel? level,
        string? state,
        int take = 50,
        CancellationToken cancellationToken = default)
    {
        var queryParams = new Dictionary<string, string?>
        {
            ["level"] = level?.ToString(),
            ["state"] = state,
            ["take"] = take.ToString()
        };

        var url = BuildUrlWithQuery("/api/rankings", queryParams);
        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<List<AthleteRanking>>(response, cancellationToken);
    }

    public async Task<ApiResult<NotificationSubscription>> SubscribeAsync(
        SubscribeNotificationRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/notifications/subscriptions", request, cancellationToken);
        return await ReadResponseAsync<NotificationSubscription>(response, cancellationToken);
    }

    public async Task<ApiResult<List<NotificationMessage>>> GetNotificationMessagesAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/notifications/messages/{userId}", cancellationToken);
        return await ReadResponseAsync<List<NotificationMessage>>(response, cancellationToken);
    }

    public async Task<ApiResult<StreamSession>> CreateStreamSessionAsync(
        Guid eventId,
        CreateStreamSessionRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/events/{eventId}/streams", request, cancellationToken);
        return await ReadResponseAsync<StreamSession>(response, cancellationToken);
    }

    public async Task<ApiResult<StreamSession>> UpdateStreamStatusAsync(
        Guid streamId,
        UpdateStreamStatusRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/streams/{streamId}/status", request, cancellationToken);
        return await ReadResponseAsync<StreamSession>(response, cancellationToken);
    }

    public async Task<ApiResult<List<StreamSession>>> GetActiveStreamsAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/streams/active", cancellationToken);
        return await ReadResponseAsync<List<StreamSession>>(response, cancellationToken);
    }

    private async Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken)
    {
        await EnsureAccessTokenAsync(cancellationToken);
        return await httpClient.GetAsync(requestUri, cancellationToken);
    }

    private async Task<HttpResponseMessage> PostAsJsonAsync<T>(string requestUri, T payload, CancellationToken cancellationToken)
    {
        await EnsureAccessTokenAsync(cancellationToken);
        return await httpClient.PostAsJsonAsync(requestUri, payload, _jsonOptions, cancellationToken);
    }

    private async Task EnsureAccessTokenAsync(CancellationToken cancellationToken)
    {
        if (authSession.IsAuthenticated && !authSession.IsAccessTokenExpiringSoon(TimeSpan.FromMinutes(2)))
        {
            ApplyAuthorizationHeader();
            return;
        }

        await _sessionLock.WaitAsync(cancellationToken);
        try
        {
            if (authSession.IsAuthenticated && !authSession.IsAccessTokenExpiringSoon(TimeSpan.FromMinutes(2)))
            {
                ApplyAuthorizationHeader();
                return;
            }

            if (authSession.CanRefresh)
            {
                var refreshed = await TryRefreshSessionAsync(cancellationToken);
                if (!refreshed)
                {
                    authSession.Clear();
                }
            }

            ApplyAuthorizationHeader();
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    private async Task<bool> TryRefreshSessionAsync(CancellationToken cancellationToken)
    {
        if (!authSession.CanRefresh || string.IsNullOrWhiteSpace(authSession.RefreshToken))
        {
            return false;
        }

        var previousAuthHeader = httpClient.DefaultRequestHeaders.Authorization;
        httpClient.DefaultRequestHeaders.Authorization = null;

        try
        {
            var response = await httpClient.PostAsJsonAsync(
                "/api/auth/refresh",
                new RefreshTokenRequest(authSession.RefreshToken),
                _jsonOptions,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var token = await response.Content.ReadFromJsonAsync<AuthTokenResponse>(_jsonOptions, cancellationToken);
            if (token is null)
            {
                return false;
            }

            authSession.Set(token);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            httpClient.DefaultRequestHeaders.Authorization = previousAuthHeader;
        }
    }

    private void ApplyAuthorizationHeader()
    {
        if (!authSession.IsAuthenticated || string.IsNullOrWhiteSpace(authSession.AccessToken))
        {
            httpClient.DefaultRequestHeaders.Authorization = null;
            return;
        }

        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authSession.AccessToken);
    }

    private async Task<ApiResult<T>> ReadResponseAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            return ApiResult<T>.Fail(response.StatusCode, await ReadErrorMessageAsync(response, cancellationToken));
        }

        var data = await response.Content.ReadFromJsonAsync<T>(_jsonOptions, cancellationToken);
        return ApiResult<T>.Ok(data);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true
        };

        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private static string BuildUrlWithQuery(string path, IDictionary<string, string?> queryParams)
    {
        var builder = new StringBuilder(path);
        var first = true;

        foreach (var (key, value) in queryParams)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            builder.Append(first ? '?' : '&');
            builder.Append(Uri.EscapeDataString(key));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
            first = false;
        }

        return builder.ToString();
    }

    private static async Task<string> ReadErrorMessageAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var raw = await response.Content.ReadAsStringAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return $"Request failed with status code {(int)response.StatusCode}.";
        }

        return raw;
    }
}