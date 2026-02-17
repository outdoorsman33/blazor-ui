using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Application.Contracts;

public sealed record RegisterUserRequest(string Email, string Password, UserRole Role, string? PhoneNumber);

public sealed record LoginRequest(string Email, string Password, string? MfaCode = null);

public sealed record RefreshTokenRequest(string RefreshToken);

public sealed record AuthTokenResponse(
    string AccessToken,
    DateTime ExpiresUtc,
    string RefreshToken,
    DateTime RefreshTokenExpiresUtc,
    Guid UserId,
    string Email,
    UserRole Role);

public sealed record CreateAthleteProfileRequest(
    Guid UserAccountId,
    string FirstName,
    string LastName,
    DateTime DateOfBirthUtc,
    string State,
    string City,
    string? SchoolOrClubName,
    int Grade,
    decimal WeightClass,
    CompetitionLevel Level);

public sealed record CreateCoachProfileRequest(
    Guid UserAccountId,
    string FirstName,
    string LastName,
    string State,
    string City,
    string? Bio);

public sealed record CreateTeamRequest(string Name, TeamType Type, string State, string City);

public sealed record CreateCoachAssociationRequest(Guid? AthleteProfileId, Guid? TeamId, string RoleTitle, bool IsPrimary);

public sealed record CreateTournamentEventRequest(
    string Name,
    OrganizerType OrganizerType,
    Guid OrganizerId,
    string State,
    string City,
    string Venue,
    DateTime StartUtc,
    DateTime EndUtc,
    int EntryFeeCents,
    bool IsPublished);

public sealed record CreateTournamentDivisionRequest(CompetitionLevel Level, decimal WeightClass, string Name);

public sealed record SearchEventsQuery(
    string? State,
    string? City,
    CompetitionLevel? Level,
    DateTime? StartsOnOrAfterUtc,
    DateTime? StartsOnOrBeforeUtc,
    int? MaxEntryFeeCents);

public sealed record RegisterForEventRequest(Guid AthleteProfileId, Guid? TeamId, bool IsFreeAgent);

public sealed record TeamInviteFreeAgentRequest(Guid TeamId, string? Message);

public sealed record GenerateBracketRequest(CompetitionLevel Level, decimal WeightClass, BracketGenerationMode Mode, Guid? DivisionId);

public sealed record AssignMatRequest(string MatNumber, DateTime? ScheduledUtc, bool MarkInTheHole);

public sealed record RecordMatchResultRequest(Guid WinnerAthleteId, string Score, string ResultMethod, int PointsForWinner, int PointsForLoser);

public sealed record SubscribeNotificationRequest(
    Guid UserAccountId,
    Guid? TournamentEventId,
    Guid? AthleteProfileId,
    NotificationEventType EventType,
    NotificationChannel Channel,
    string Destination);

public sealed record CreateStreamSessionRequest(
    Guid? MatchId,
    string DeviceName,
    string IngestProtocol = "RTMP",
    string? SourceUrl = null,
    Guid? AthleteProfileId = null,
    bool IsPersonalStream = false,
    bool SaveToAthleteProfile = false,
    bool IsPrivate = false,
    Guid? DelegatedByUserAccountId = null);

public sealed record AssignTournamentStaffRequest(
    Guid UserAccountId,
    UserRole Role,
    bool CanScoreMatches = true,
    bool CanManageMatches = false,
    bool CanManageStreams = false);

public sealed record SetAthleteStreamingPermissionRequest(
    Guid AthleteProfileId,
    Guid DelegateUserAccountId,
    Guid? ParentGuardianUserAccountId = null,
    bool IsActive = true);

public sealed record ConfirmRegistrationPaymentRequest(Guid RegistrationId, string ProviderReference);

public sealed record BracketGenerationInput(
    Guid EventId,
    CompetitionLevel Level,
    decimal WeightClass,
    BracketGenerationMode Mode,
    Guid? DivisionId);

public sealed record BracketGenerationResult(Guid BracketId, int EntrantCount, int MatchCount);

public sealed record PaymentIntentResult(string Provider, string ProviderReference, string CheckoutUrl, DateTime ExpiresUtc);

public sealed record PaymentWebhookIngress(
    string Provider,
    string ProviderEventId,
    string EventType,
    Guid? RegistrationId,
    string? ProviderReference,
    int? AmountCents,
    string? Currency,
    bool IsPaymentConfirmed,
    string Payload);

public sealed record PaymentWebhookEnqueueResult(bool Accepted, bool IsDuplicate, Guid EventRecordId, string Status);

public sealed record NotificationDispatchRequest(
    Guid? TournamentEventId,
    Guid? MatchId,
    Guid? AthleteProfileId,
    NotificationEventType EventType,
    string Body);

public sealed record UpdateStreamStatusRequest(StreamStatus Status);

public sealed record StartDirectAthleteChatRequest(Guid TargetAthleteProfileId);

public sealed record StartGroupAthleteChatRequest(string Name, List<Guid> AthleteProfileIds);

public sealed record SendAthleteChatMessageRequest(string Body);

public sealed record ReportAthleteChatMessageRequest(string Reason);

public sealed record MuteAthleteChatThreadRequest(int Minutes);

public sealed record ToggleAthleteChatReactionRequest(string Emoji);

public sealed record AthleteChatParticipantSummary(
    Guid UserAccountId,
    Guid AthleteProfileId,
    string DisplayName,
    CompetitionLevel Level,
    string State,
    string City);

public sealed record AthleteChatReactionSummary(
    string Emoji,
    int Count,
    bool IsMine);

public sealed record AthleteChatThreadSummary(
    Guid ThreadId,
    string Name,
    AthleteChatThreadKind Kind,
    DateTime? LastMessageUtc,
    int UnreadCount,
    bool IsMuted,
    string? LastMessagePreview,
    List<AthleteChatParticipantSummary> Participants,
    bool IsPostingLocked,
    DateTime? PostingLockedUntilUtc,
    string? PostingLockReason);

public sealed record AthleteChatMessageView(
    Guid MessageId,
    Guid ThreadId,
    Guid UserAccountId,
    Guid AthleteProfileId,
    string DisplayName,
    string Body,
    AthleteChatMessageModerationStatus ModerationStatus,
    DateTime CreatedUtc,
    bool IsMine,
    List<AthleteChatReactionSummary> Reactions);

public sealed record AthleteChatDirectoryEntry(
    Guid UserAccountId,
    Guid AthleteProfileId,
    string DisplayName,
    CompetitionLevel Level,
    string State,
    string City,
    string? SchoolOrClubName);

public sealed record UpsertAthleteChatAthleteLockRequest(int Minutes, string Reason);

public sealed record AthleteChatAthleteLockView(
    Guid LockId,
    Guid AthleteProfileId,
    Guid UserAccountId,
    string AthleteName,
    string AthleteState,
    string AthleteCity,
    DateTime LockedUntilUtc,
    bool IsActive,
    string Reason,
    Guid LockedByUserAccountId,
    string LockedByEmail,
    DateTime CreatedUtc,
    DateTime? ReleasedUtc);

public sealed record AthleteChatAdminThreadRow(
    Guid ThreadId,
    string Name,
    AthleteChatThreadKind Kind,
    bool IsArchived,
    int ParticipantCount,
    int MessageCount,
    int ReportedMessageCount,
    DateTime? LastMessageUtc,
    string? LastMessagePreview,
    List<AthleteChatParticipantSummary> Participants);

public sealed record AthleteChatAdminAthleteRow(
    Guid UserAccountId,
    Guid AthleteProfileId,
    string DisplayName,
    CompetitionLevel Level,
    string State,
    string City,
    bool IsLocked,
    DateTime? LockedUntilUtc,
    string? LockReason);

public sealed record UpdateTournamentControlSettingsRequest(
    TournamentFormat TournamentFormat,
    BracketReleaseMode BracketReleaseMode,
    DateTime? BracketReleaseUtc,
    BracketCreationMode BracketCreationMode,
    bool RegistrationCapEnabled,
    int? RegistrationCap,
    ScoringPreset ScoringPreset = ScoringPreset.NfhsHighSchool,
    bool StrictScoringEnforcement = true,
    OvertimeFormat OvertimeFormat = OvertimeFormat.FolkstyleStandard,
    int MaxOvertimePeriods = 3,
    bool EndOnFirstOvertimeScore = false);

public sealed record TournamentControlSettings(
    Guid EventId,
    TournamentFormat TournamentFormat,
    BracketReleaseMode BracketReleaseMode,
    DateTime? BracketReleaseUtc,
    BracketCreationMode BracketCreationMode,
    bool RegistrationCapEnabled,
    int? RegistrationCap,
    int CurrentRegistrantCount,
    int RemainingSlots,
    ScoringPreset ScoringPreset = ScoringPreset.NfhsHighSchool,
    bool StrictScoringEnforcement = true,
    OvertimeFormat OvertimeFormat = OvertimeFormat.FolkstyleStandard,
    int MaxOvertimePeriods = 3,
    bool EndOnFirstOvertimeScore = false);

public enum ScoringPreset
{
    NfhsHighSchool,
    NcaaFolkstyle,
    UwwFreestyle,
    UwwGrecoRoman,
    Custom
}

public enum ScoreCompetitor
{
    AthleteA,
    AthleteB
}

public enum ScoringActionCode
{
    Custom,
    Takedown,
    Escape,
    Reversal,
    NearFall2,
    NearFall3,
    NearFall4,
    Exposure,
    PushOut,
    Passivity,
    Penalty,
    CautionAndOne,
    CautionAndTwo,
    TakedownHighAmplitude,
    ThrowHighAmplitude,
    Fall,
    TechnicalFall,
    InjuryDefault,
    Disqualification
}

public enum OvertimeFormat
{
    None,
    FolkstyleStandard,
    FolkstyleSuddenVictoryOnly,
    FreestyleCriteria,
    GrecoCriteria,
    TournamentCustom
}

public sealed record AddMatScoreEventRequest(
    ScoreCompetitor Competitor,
    int? Points,
    string ActionType,
    int Period,
    int? MatchClockSeconds,
    Guid? AthleteId,
    ScoringActionCode ActionCode = ScoringActionCode.Custom,
    bool EndMatch = false);

public sealed record ConfigureMatchScoringRequest(
    WrestlingStyle Style,
    CompetitionLevel Level,
    bool AutoEndEnabled = true,
    int? TechFallPointGap = null,
    int RegulationPeriods = 3,
    OvertimeFormat OvertimeFormat = OvertimeFormat.FolkstyleStandard,
    int MaxOvertimePeriods = 3,
    bool EndOnFirstOvertimeScore = false,
    bool StrictRuleEnforcement = true);

public sealed record ScoringActionDefinition(
    ScoringActionCode ActionCode,
    string Label,
    int DefaultPoints,
    bool EndsMatch,
    string Notes);

public sealed record MatchScoringRulesSnapshot(
    Guid MatchId,
    WrestlingStyle Style,
    CompetitionLevel Level,
    bool AutoEndEnabled,
    int TechFallPointGap,
    int RegulationPeriods,
    List<ScoringActionDefinition> Actions,
    int RegulationPeriodSeconds = 120,
    int OvertimePeriodSeconds = 60,
    OvertimeFormat OvertimeFormat = OvertimeFormat.FolkstyleStandard,
    int MaxOvertimePeriods = 3,
    bool EndOnFirstOvertimeScore = false,
    bool StrictRuleEnforcement = true);

public sealed record ResetMatScoreboardRequest(string? Reason);

public enum MatchClockCommand
{
    Start,
    Pause,
    Resume,
    Seek,
    AdvancePeriod,
    ResetToPeriodDefault
}

public sealed record ControlMatchClockRequest(
    MatchClockCommand Command,
    int? ClockSeconds = null,
    bool ResumeAfterSeek = false);

public sealed record MatScoreEventSnapshot(
    Guid EventId,
    DateTime TimestampUtc,
    ScoreCompetitor Competitor,
    int Points,
    string ActionType,
    int Period,
    int? MatchClockSeconds,
    Guid? AthleteId,
    int AthleteAScore,
    int AthleteBScore);

public sealed record MatScoreboardSnapshot(
    Guid MatchId,
    Guid? AthleteAId,
    Guid? AthleteBId,
    int AthleteAScore,
    int AthleteBScore,
    int CurrentPeriod,
    MatchStatus Status,
    DateTime UpdatedUtc,
    List<MatScoreEventSnapshot> Events,
    WrestlingStyle Style = WrestlingStyle.Folkstyle,
    CompetitionLevel Level = CompetitionLevel.HighSchool,
    Guid? WinnerAthleteId = null,
    Guid? LoserAthleteId = null,
    string? OutcomeReason = null,
    bool IsFinal = false,
    int ClockSecondsRemaining = 0,
    bool ClockRunning = false,
    DateTime? ClockLastStartedUtc = null,
    int RegulationPeriodSeconds = 120,
    int OvertimePeriodSeconds = 60);

public sealed record TableWorkerEventSummary(
    Guid EventId,
    string EventName,
    string State,
    string City,
    string Venue,
    DateTime StartUtc,
    WrestlingStyle Style,
    int MatCount,
    int ActiveMatches);

public sealed record TableWorkerMatchSummary(
    Guid MatchId,
    int Round,
    int MatchNumber,
    int? BoutNumber,
    MatchStatus Status,
    Guid? AthleteAId,
    Guid? AthleteBId,
    string AthleteALabel,
    string AthleteBLabel,
    string? Score,
    string? ResultMethod,
    DateTime? ScheduledUtc);

public sealed record TableWorkerMatSummary(
    string MatNumber,
    int ScheduledCount,
    int InTheHoleCount,
    int OnMatCount,
    int CompletedCount,
    List<TableWorkerMatchSummary> Matches);

public sealed record TableWorkerEventBoard(
    Guid EventId,
    string EventName,
    WrestlingStyle Style,
    TournamentControlSettings Controls,
    List<TableWorkerMatSummary> Mats);

public sealed record TournamentDivisionDirectoryRow(
    Guid DivisionId,
    string Name,
    CompetitionLevel Level,
    string AgeGroup,
    decimal WeightClass,
    int RegistrantCount,
    int? RegistrantCap,
    WrestlingStyle Style,
    TournamentFormat TournamentFormat);

public sealed record TournamentDirectoryRow(
    Guid EventId,
    string EventName,
    string State,
    string City,
    string Venue,
    DateTime StartUtc,
    DateTime EndUtc,
    int EntryFeeCents,
    TournamentControlSettings Controls,
    List<TournamentDivisionDirectoryRow> Divisions);

public sealed record BracketVisualAthlete(
    Guid AthleteId,
    string Name,
    CompetitionLevel Level,
    decimal WeightClass,
    int Seed,
    int Rank,
    decimal RatingPoints);

public sealed record BracketVisualMatch(
    Guid MatchId,
    int Round,
    int MatchNumber,
    int? BoutNumber,
    string Label,
    MatchStatus Status,
    BracketVisualAthlete? AthleteA,
    BracketVisualAthlete? AthleteB,
    BracketVisualAthlete? Winner,
    string? Score,
    string? ResultMethod,
    string? MatNumber);

public sealed record PoolStanding(
    Guid AthleteId,
    string AthleteName,
    int Wins,
    int Losses,
    int PointsFor,
    int PointsAgainst,
    int Differential);

public sealed record PoolVisualGroup(
    string PoolName,
    CompetitionLevel Level,
    decimal WeightClass,
    WrestlingStyle Style,
    List<BracketVisualMatch> Matches,
    List<PoolStanding> Standings);

public sealed record TournamentBracketVisualBundle(
    Guid EventId,
    string EventName,
    TournamentFormat TournamentFormat,
    bool BracketsReleased,
    List<BracketVisualMatch> BracketMatches,
    List<PoolVisualGroup> Pools);

public enum VideoPipelineState
{
    PendingUpload,
    QueuedForTranscode,
    Processing,
    Ready,
    Failed
}

public sealed record VideoAssetRecord(
    Guid VideoId,
    Guid AthleteProfileId,
    Guid MatchId,
    Guid? StreamId,
    string SourceUrl,
    string PlaybackUrl,
    VideoPipelineState State,
    DateTime CreatedUtc,
    DateTime? ReadyUtc,
    string? FailureReason);

public sealed record CreateVideoAssetRequest(
    Guid AthleteProfileId,
    Guid MatchId,
    Guid? StreamId,
    string SourceUrl,
    bool QueueTranscode = true);

public sealed record QueueAiHighlightsRequest(
    Guid AthleteProfileId,
    Guid? EventId,
    int MaxMatches = 12);

public sealed record AiHighlightJobSnapshot(
    Guid JobId,
    Guid AthleteProfileId,
    Guid? EventId,
    DateTime QueuedUtc,
    DateTime? StartedUtc,
    DateTime? CompletedUtc,
    string Status,
    int ClipsProduced,
    string? Details);

public sealed record SecurityAuditRecord(
    Guid AuditId,
    DateTime TimestampUtc,
    string Method,
    string Path,
    int StatusCode,
    string? UserId,
    string? UserRole,
    string SourceIp,
    string Outcome,
    string TraceId);

public sealed record MfaEnrollmentResponse(
    Guid UserId,
    string SharedSecret,
    string ProvisioningUri,
    bool Enabled);

public sealed record VerifyMfaCodeRequest(Guid UserId, string Code);

public sealed record MfaVerifyResponse(
    Guid UserId,
    bool Verified,
    DateTime VerifiedUtc);

public sealed record AthleteHighlightClip(
    Guid ClipId,
    Guid AthleteProfileId,
    Guid MatchId,
    Guid? StreamId,
    string Title,
    string Summary,
    string PlaybackUrl,
    DateTime ClipStartUtc,
    DateTime ClipEndUtc,
    int ImpactScore,
    bool AiGenerated);

public sealed record AthleteNilProfile(
    Guid AthleteProfileId,
    string DisplayName,
    CompetitionLevel Level,
    string State,
    string City,
    decimal WeightClass,
    int Followers,
    int CareerWins,
    int CareerLosses,
    decimal RatingPoints,
    decimal MarketabilityScore,
    List<string> RecruitingTags,
    string? XHandle = null,
    string? InstagramHandle = null,
    string? TwitterHandle = null,
    string? ContactEmail = null,
    bool OpenToBrandDeals = true,
    bool OpenToCampsClinics = true,
    bool OpenToCollectives = true,
    string? Bio = null);

public sealed record UpdateAthleteNilProfileRequest(
    string? XHandle,
    string? InstagramHandle,
    string? TwitterHandle,
    string? ContactEmail,
    bool OpenToBrandDeals = true,
    bool OpenToCampsClinics = true,
    bool OpenToCollectives = true,
    string? Bio = null);

public sealed record NilComplianceRule(
    string Audience,
    string Jurisdiction,
    string Summary,
    string SourceName,
    string SourceUrl,
    string EffectiveDateNote);

public sealed record NilPolicyResponse(
    DateTime GeneratedUtc,
    string LegalNotice,
    List<NilComplianceRule> Rules,
    List<string> BestPractices,
    List<string> ProhibitedExamples);

public enum GlobalSearchEntityType
{
    Athlete,
    Coach,
    Team,
    Tournament,
    Match,
    Stream
}

public sealed record GlobalSearchResultItem(
    GlobalSearchEntityType Type,
    Guid Id,
    string Title,
    string Subtitle,
    string Route,
    DateTime? DateUtc = null,
    string? State = null,
    string? City = null,
    string? Badge = null);

public sealed record GlobalSearchResponse(
    string Query,
    int Total,
    List<GlobalSearchResultItem> Results);

public sealed record TournamentExplorerCard(
    Guid EventId,
    string Name,
    string State,
    string City,
    string Venue,
    DateTime StartUtc,
    DateTime EndUtc,
    int EntryFeeCents,
    WrestlingStyle Style,
    int RegisteredAthletes,
    int ActiveMats,
    int CompletedMatches,
    int LiveStreams,
    bool IsLive);

public sealed record TournamentExplorerResponse(
    DateTime GeneratedUtc,
    List<TournamentExplorerCard> Live,
    List<TournamentExplorerCard> Upcoming,
    List<TournamentExplorerCard> Past);

public sealed record HelpFaqItem(
    string Id,
    string Category,
    string Question,
    string Answer,
    List<string> SearchTags);

public sealed record SupportGuideStep(
    int StepNumber,
    string Title,
    string Description,
    string Route,
    string ActionLabel);

public sealed record HelpChatRequest(string Message, string? Context = null);

public sealed record HelpChatResponse(
    string Reply,
    List<string> SuggestedActions,
    List<string> SuggestedFaqIds);

public sealed record RecruitingAthleteCard(
    Guid AthleteProfileId,
    string FirstName,
    string LastName,
    CompetitionLevel Level,
    string State,
    string City,
    decimal WeightClass,
    int Rank,
    decimal RatingPoints,
    int Wins,
    int Losses,
    bool OpenToRecruitment);

public enum EventOpsSeedingStrategy
{
    RandomDraw,
    CoachSeeding,
    RankingsSeeded,
    HybridAiCoachReview
}

public sealed record EventOpsChecklistState(
    Guid EventId,
    bool DivisionsLocked,
    bool FormatAndRulesLocked,
    bool RegistrationDeadlineSet,
    DateTime? RegistrationDeadlineUtc,
    EventOpsSeedingStrategy SeedingStrategy,
    bool ContingencyPrintReady,
    bool WeighInsCompleted,
    bool ScratchListFrozen,
    bool BracketsGeneratedAfterScratchFreeze,
    bool HeadTableReady,
    bool MatTablesReady,
    bool QrPostedForLiveResults,
    bool FinalResultsLocked,
    bool PlacingsExported,
    bool TeamPointsExported,
    bool AwardSheetsPrinted,
    bool FinalBracketsPublished,
    bool RequireScratchFreezeForBracketGeneration,
    DateTime UpdatedUtc,
    string? Notes = null);

public sealed record UpdateEventOpsChecklistRequest(
    bool? DivisionsLocked = null,
    bool? FormatAndRulesLocked = null,
    bool? RegistrationDeadlineSet = null,
    DateTime? RegistrationDeadlineUtc = null,
    EventOpsSeedingStrategy? SeedingStrategy = null,
    bool? ContingencyPrintReady = null,
    bool? WeighInsCompleted = null,
    bool? ScratchListFrozen = null,
    bool? HeadTableReady = null,
    bool? MatTablesReady = null,
    bool? QrPostedForLiveResults = null,
    bool? FinalResultsLocked = null,
    bool? PlacingsExported = null,
    bool? TeamPointsExported = null,
    bool? AwardSheetsPrinted = null,
    bool? FinalBracketsPublished = null,
    bool? RequireScratchFreezeForBracketGeneration = null,
    string? Notes = null);

public sealed record EventOpsArtifactLinks(
    Guid EventId,
    string LiveResultsUrl,
    string MatScheduleUrl,
    string AwardsSheetUrl,
    string PlacingsExportUrl,
    string TeamPointsExportUrl,
    DateTime GeneratedUtc);

public sealed record EventOpsRecoverySnapshot(
    Guid MatchId,
    MatchStatus Status,
    string? MatNumber,
    string? Score,
    int CurrentPeriod,
    int ClockSecondsRemaining,
    bool ClockRunning,
    Guid? WinnerAthleteId,
    string ResumeScoringUrl,
    DateTime UpdatedUtc);
