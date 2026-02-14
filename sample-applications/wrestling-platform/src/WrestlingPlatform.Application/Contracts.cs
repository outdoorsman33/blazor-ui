using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Application.Contracts;

public sealed record RegisterUserRequest(string Email, string Password, UserRole Role, string? PhoneNumber);

public sealed record LoginRequest(string Email, string Password);

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

public sealed record CreateStreamSessionRequest(Guid? MatchId, string DeviceName);

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