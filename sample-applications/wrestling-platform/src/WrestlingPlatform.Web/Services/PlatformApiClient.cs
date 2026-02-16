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
    public Uri BaseAddress => httpClient.BaseAddress ?? new Uri("http://127.0.0.1:5099");

    public async Task<ApiResult<AuthTokenResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/auth/login", request, cancellationToken);
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

    public async Task<ApiResult<object>> ResetDemoDataAsync(string? token = null, CancellationToken cancellationToken = default)
    {
        var url = BuildUrlWithQuery("/api/demo/reset-data", new Dictionary<string, string?>
        {
            ["token"] = token
        });

        var response = await PostAsJsonAsync<object>(url, new { }, cancellationToken);
        return await ReadResponseAsync<object>(response, cancellationToken);
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

    public async Task<ApiResult<GlobalSearchResponse>> SearchGlobalAsync(
        string query,
        int take = 24,
        CancellationToken cancellationToken = default)
    {
        var url = BuildUrlWithQuery("/api/search/global", new Dictionary<string, string?>
        {
            ["q"] = query,
            ["take"] = take.ToString()
        });

        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<GlobalSearchResponse>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentExplorerResponse>> GetTournamentExplorerAsync(
        int? daysBack = null,
        int? daysAhead = null,
        string? state = null,
        CancellationToken cancellationToken = default)
    {
        var url = BuildUrlWithQuery("/api/events/explorer", new Dictionary<string, string?>
        {
            ["daysBack"] = daysBack?.ToString(),
            ["daysAhead"] = daysAhead?.ToString(),
            ["state"] = state
        });

        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<TournamentExplorerResponse>(response, cancellationToken);
    }

    public async Task<ApiResult<List<GroupedEventsResponse>>> GetGroupedEventsAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync("/api/events/grouped", cancellationToken);
        return await ReadResponseAsync<List<GroupedEventsResponse>>(response, cancellationToken);
    }

    public async Task<ApiResult<List<TableWorkerEventSummary>>> GetTableWorkerEventsAsync(
        string? state = null,
        int? daysAhead = null,
        CancellationToken cancellationToken = default)
    {
        var queryParams = new Dictionary<string, string?>
        {
            ["state"] = state,
            ["daysAhead"] = daysAhead?.ToString()
        };

        var url = BuildUrlWithQuery("/api/table-worker/events", queryParams);
        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<List<TableWorkerEventSummary>>(response, cancellationToken);
    }

    public async Task<ApiResult<TableWorkerEventBoard>> GetTableWorkerBoardAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/mats", cancellationToken);
        return await ReadResponseAsync<TableWorkerEventBoard>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentDirectoryRow>> GetTournamentDirectoryAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/directory", cancellationToken);
        return await ReadResponseAsync<TournamentDirectoryRow>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentControlSettings>> GetTournamentControlsAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/controls", cancellationToken);
        return await ReadResponseAsync<TournamentControlSettings>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentControlSettings>> UpdateTournamentControlsAsync(
        Guid eventId,
        UpdateTournamentControlSettingsRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PutAsJsonAsync($"/api/events/{eventId}/controls", request, cancellationToken);
        return await ReadResponseAsync<TournamentControlSettings>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentControlSettings>> ReleaseBracketsAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync<object>($"/api/events/{eventId}/controls/release-brackets", new { }, cancellationToken);
        return await ReadResponseAsync<TournamentControlSettings>(response, cancellationToken);
    }

    public async Task<ApiResult<EventOpsChecklistState>> GetEventOpsChecklistAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/ops-checklist", cancellationToken);
        return await ReadResponseAsync<EventOpsChecklistState>(response, cancellationToken);
    }

    public async Task<ApiResult<EventOpsChecklistState>> UpdateEventOpsChecklistAsync(
        Guid eventId,
        UpdateEventOpsChecklistRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PutAsJsonAsync($"/api/events/{eventId}/ops-checklist", request, cancellationToken);
        return await ReadResponseAsync<EventOpsChecklistState>(response, cancellationToken);
    }

    public async Task<ApiResult<EventOpsArtifactLinks>> GetEventOpsArtifactsAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/ops-checklist/artifacts", cancellationToken);
        return await ReadResponseAsync<EventOpsArtifactLinks>(response, cancellationToken);
    }

    public async Task<ApiResult<List<EventOpsRecoverySnapshot>>> GetEventOpsRecoveryAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/ops-checklist/recovery", cancellationToken);
        return await ReadResponseAsync<List<EventOpsRecoverySnapshot>>(response, cancellationToken);
    }

    public async Task<ApiResult<TournamentBracketVisualBundle>> GetBracketVisualAsync(Guid eventId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/events/{eventId}/brackets/visual", cancellationToken);
        return await ReadResponseAsync<TournamentBracketVisualBundle>(response, cancellationToken);
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

    public async Task<ApiResult<MatScoreboardSnapshot>> GetMatScoreboardAsync(Guid matchId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/matches/{matchId}/scoreboard", cancellationToken);
        return await ReadResponseAsync<MatScoreboardSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<MatchScoringRulesSnapshot>> GetMatScoringRulesAsync(Guid matchId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/matches/{matchId}/scoreboard/rules", cancellationToken);
        return await ReadResponseAsync<MatchScoringRulesSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<MatchScoringRulesSnapshot>> ConfigureMatScoringRulesAsync(
        Guid matchId,
        ConfigureMatchScoringRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/matches/{matchId}/scoreboard/rules", request, cancellationToken);
        return await ReadResponseAsync<MatchScoringRulesSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<MatScoreboardSnapshot>> AddMatScoreEventAsync(
        Guid matchId,
        AddMatScoreEventRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/matches/{matchId}/scoreboard/events", request, cancellationToken);
        return await ReadResponseAsync<MatScoreboardSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<MatScoreboardSnapshot>> ControlMatchClockAsync(
        Guid matchId,
        ControlMatchClockRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/matches/{matchId}/scoreboard/clock", request, cancellationToken);
        return await ReadResponseAsync<MatScoreboardSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<MatScoreboardSnapshot>> ResetMatScoreboardAsync(
        Guid matchId,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync($"/api/matches/{matchId}/scoreboard/reset", new ResetMatScoreboardRequest(reason), cancellationToken);
        return await ReadResponseAsync<MatScoreboardSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<List<AthleteHighlightClip>>> GetAthleteHighlightsAsync(Guid athleteId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/athletes/{athleteId}/highlights", cancellationToken);
        return await ReadResponseAsync<List<AthleteHighlightClip>>(response, cancellationToken);
    }

    public async Task<ApiResult<List<VideoAssetRecord>>> GetAthleteVideosAsync(Guid athleteId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/athletes/{athleteId}/videos", cancellationToken);
        return await ReadResponseAsync<List<VideoAssetRecord>>(response, cancellationToken);
    }

    public async Task<ApiResult<VideoAssetRecord>> CreateVideoAssetAsync(
        CreateVideoAssetRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/media/videos", request, cancellationToken);
        return await ReadResponseAsync<VideoAssetRecord>(response, cancellationToken);
    }

    public async Task<ApiResult<AiHighlightJobSnapshot>> QueueAiHighlightsAsync(
        QueueAiHighlightsRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/media/highlights/queue", request, cancellationToken);
        return await ReadResponseAsync<AiHighlightJobSnapshot>(response, cancellationToken);
    }

    public async Task<ApiResult<List<AiHighlightJobSnapshot>>> GetAiHighlightJobsAsync(
        Guid athleteId,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/media/highlights/jobs/{athleteId}", cancellationToken);
        return await ReadResponseAsync<List<AiHighlightJobSnapshot>>(response, cancellationToken);
    }

    public async Task<ApiResult<AthleteNilProfile>> GetAthleteNilProfileAsync(Guid athleteId, CancellationToken cancellationToken = default)
    {
        var response = await GetAsync($"/api/athletes/{athleteId}/nil-profile", cancellationToken);
        return await ReadResponseAsync<AthleteNilProfile>(response, cancellationToken);
    }

    public async Task<ApiResult<AthleteNilProfile>> UpdateAthleteNilProfileAsync(
        Guid athleteId,
        UpdateAthleteNilProfileRequest request,
        CancellationToken cancellationToken = default)
    {
        var response = await PutAsJsonAsync($"/api/athletes/{athleteId}/nil-profile", request, cancellationToken);
        return await ReadResponseAsync<AthleteNilProfile>(response, cancellationToken);
    }

    public async Task<ApiResult<NilPolicyResponse>> GetNilPolicyAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync("/api/nil/policy", cancellationToken);
        return await ReadResponseAsync<NilPolicyResponse>(response, cancellationToken);
    }

    public async Task<ApiResult<List<HelpFaqItem>>> GetHelpFaqsAsync(string? query = null, CancellationToken cancellationToken = default)
    {
        var url = BuildUrlWithQuery("/api/help/faqs", new Dictionary<string, string?>
        {
            ["q"] = query
        });

        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<List<HelpFaqItem>>(response, cancellationToken);
    }

    public async Task<ApiResult<List<SupportGuideStep>>> GetSupportGuideAsync(CancellationToken cancellationToken = default)
    {
        var response = await GetAsync("/api/help/guide", cancellationToken);
        return await ReadResponseAsync<List<SupportGuideStep>>(response, cancellationToken);
    }

    public async Task<ApiResult<HelpChatResponse>> AskHelpAssistantAsync(HelpChatRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/help/chat", request, cancellationToken);
        return await ReadResponseAsync<HelpChatResponse>(response, cancellationToken);
    }

    public async Task<ApiResult<List<RecruitingAthleteCard>>> GetRecruitingAthletesAsync(
        CompetitionLevel? level,
        string? state,
        int? minWins = null,
        int take = 50,
        CancellationToken cancellationToken = default)
    {
        var queryParams = new Dictionary<string, string?>
        {
            ["level"] = level?.ToString(),
            ["state"] = state,
            ["minWins"] = minWins?.ToString(),
            ["take"] = take.ToString()
        };

        var url = BuildUrlWithQuery("/api/recruiting/athletes", queryParams);
        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<List<RecruitingAthleteCard>>(response, cancellationToken);
    }

    public async Task<ApiResult<MfaEnrollmentResponse>> EnrollMfaAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync<object>($"/api/security/mfa/enroll/{userId}", new { }, cancellationToken);
        return await ReadResponseAsync<MfaEnrollmentResponse>(response, cancellationToken);
    }

    public async Task<ApiResult<MfaVerifyResponse>> VerifyMfaAsync(VerifyMfaCodeRequest request, CancellationToken cancellationToken = default)
    {
        var response = await PostAsJsonAsync("/api/security/mfa/verify", request, cancellationToken);
        return await ReadResponseAsync<MfaVerifyResponse>(response, cancellationToken);
    }

    public async Task<ApiResult<List<SecurityAuditRecord>>> GetSecurityAuditAsync(int take = 100, CancellationToken cancellationToken = default)
    {
        var url = BuildUrlWithQuery("/api/security/audit", new Dictionary<string, string?> { ["take"] = take.ToString() });
        var response = await GetAsync(url, cancellationToken);
        return await ReadResponseAsync<List<SecurityAuditRecord>>(response, cancellationToken);
    }

    private async Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken)
    {
        await EnsureAccessTokenAsync(cancellationToken);

        try
        {
            return await httpClient.GetAsync(requestUri, cancellationToken);
        }
        catch (Exception ex) when (IsTransportException(ex))
        {
            return CreateTransportErrorResponse(ex);
        }
    }

    private async Task<HttpResponseMessage> PostAsJsonAsync<T>(string requestUri, T payload, CancellationToken cancellationToken)
    {
        await EnsureAccessTokenAsync(cancellationToken);

        try
        {
            return await httpClient.PostAsJsonAsync(requestUri, payload, _jsonOptions, cancellationToken);
        }
        catch (Exception ex) when (IsTransportException(ex))
        {
            return CreateTransportErrorResponse(ex);
        }
    }

    private async Task<HttpResponseMessage> PutAsJsonAsync<T>(string requestUri, T payload, CancellationToken cancellationToken)
    {
        await EnsureAccessTokenAsync(cancellationToken);

        try
        {
            return await httpClient.PutAsJsonAsync(requestUri, payload, _jsonOptions, cancellationToken);
        }
        catch (Exception ex) when (IsTransportException(ex))
        {
            return CreateTransportErrorResponse(ex);
        }
    }

    private static bool IsTransportException(Exception ex)
    {
        return ex is HttpRequestException or TaskCanceledException or InvalidOperationException;
    }

    private static HttpResponseMessage CreateTransportErrorResponse(Exception ex)
    {
        var message = ex switch
        {
            TaskCanceledException => "The API request timed out. Please retry in a moment.",
            HttpRequestException => "The API service is temporarily unreachable. Please retry in about 60 seconds.",
            InvalidOperationException => "The platform is warming up. Please retry in about 60 seconds.",
            _ => "Unexpected API connectivity issue. Please retry in a moment."
        };

        return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        {
            Content = new StringContent(message, Encoding.UTF8, "text/plain")
        };
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

        try
        {
            var data = await response.Content.ReadFromJsonAsync<T>(_jsonOptions, cancellationToken);
            return ApiResult<T>.Ok(data);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return ApiResult<T>.Fail(
                HttpStatusCode.ServiceUnavailable,
                "The API returned an unexpected response. Please retry in about 60 seconds.");
        }
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
            return BuildStatusMessage(response.StatusCode);
        }

        if (TryGetJsonErrorMessage(raw, out var jsonMessage))
        {
            return TruncateForDisplay(jsonMessage);
        }

        if (LooksLikeHtmlPayload(raw))
        {
            return response.StatusCode is HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout
                ? "The API is temporarily unavailable or waking up. Please retry in about 60 seconds."
                : BuildStatusMessage(response.StatusCode);
        }

        return TruncateForDisplay(CollapseWhitespace(raw));
    }

    private static bool TryGetJsonErrorMessage(string raw, out string message)
    {
        message = string.Empty;

        try
        {
            using var document = JsonDocument.Parse(raw);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (TryReadStringProperty(document.RootElement, "detail", out message)
                || TryReadStringProperty(document.RootElement, "title", out message)
                || TryReadStringProperty(document.RootElement, "message", out message))
            {
                return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    private static bool TryReadStringProperty(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;

        if (!root.TryGetProperty(propertyName, out var property))
        {
            return false;
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var parsed = property.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(parsed))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    private static bool LooksLikeHtmlPayload(string raw)
    {
        var trimmed = raw.TrimStart();
        return trimmed.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
               || trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase)
               || trimmed.Contains("<body", StringComparison.OrdinalIgnoreCase)
               || trimmed.Contains("</html>", StringComparison.OrdinalIgnoreCase);
    }

    private static string CollapseWhitespace(string value)
    {
        var input = value.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var output = new StringBuilder(input.Length);
        var previousWasWhitespace = false;

        foreach (var character in input)
        {
            if (char.IsWhiteSpace(character))
            {
                if (!previousWasWhitespace)
                {
                    output.Append(' ');
                    previousWasWhitespace = true;
                }

                continue;
            }

            output.Append(character);
            previousWasWhitespace = false;
        }

        return output.ToString();
    }

    private static string TruncateForDisplay(string value)
    {
        const int maxLength = 280;
        var input = value.Trim();
        if (input.Length <= maxLength)
        {
            return input;
        }

        return $"{input[..maxLength]}...";
    }

    private static string BuildStatusMessage(HttpStatusCode statusCode)
    {
        return statusCode switch
        {
            HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout
                => "The API is temporarily unavailable or waking up. Please retry in about 60 seconds.",
            HttpStatusCode.Unauthorized => "Authentication is required. Please sign in again.",
            HttpStatusCode.Forbidden => "You do not have access to this action.",
            HttpStatusCode.NotFound => "The requested resource was not found.",
            _ => $"Request failed with status code {(int)statusCode}."
        };
    }
}


