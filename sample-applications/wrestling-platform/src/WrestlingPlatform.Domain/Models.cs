namespace WrestlingPlatform.Domain.Models;

public enum UserRole
{
    Athlete,
    Coach,
    Parent,
    Fan,
    SchoolAdmin,
    ClubAdmin,
    EventAdmin,
    SystemAdmin,
    ParentGuardian,
    MatWorker,
    TournamentDirector
}

public enum CompetitionLevel
{
    ElementaryK6,
    MiddleSchool,
    HighSchool,
    College
}

public enum TeamType
{
    School,
    Club
}

public enum OrganizerType
{
    School,
    Club,
    Coach,
    Independent
}

public enum RegistrationStatus
{
    Pending,
    Confirmed,
    Waitlisted,
    Cancelled
}

public enum PaymentStatus
{
    NotRequired,
    Pending,
    Paid,
    Failed,
    Refunded
}

public enum BracketGenerationMode
{
    Manual,
    Random,
    Seeded
}

public enum WrestlingStyle
{
    Folkstyle,
    Freestyle,
    GrecoRoman
}

public enum TournamentFormat
{
    EliminationBracket,
    MadisonPool
}

public enum BracketReleaseMode
{
    Manual,
    Scheduled,
    Immediate
}

public enum BracketCreationMode
{
    Manual,
    Random,
    Seeded,
    AiSeeded
}

public enum MatchStatus
{
    Scheduled,
    InTheHole,
    OnMat,
    Completed,
    Forfeit,
    Cancelled
}

public enum NotificationChannel
{
    Email,
    Sms
}

public enum NotificationEventType
{
    MatAssignment,
    InTheHole,
    MatchResult
}

public enum StreamStatus
{
    Provisioned,
    Live,
    Ended
}

public enum WebhookProcessingStatus
{
    Pending,
    Processed,
    Failed,
    Ignored
}

public abstract class Entity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class UserAccount : Entity
{
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? PhoneNumber { get; set; }
    public UserRole Role { get; set; }
    public bool IsActive { get; set; } = true;
}

public sealed class UserRefreshToken : Entity
{
    public Guid UserAccountId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public DateTime ExpiresUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
    public string? RevocationReason { get; set; }
    public string? ReplacedByTokenHash { get; set; }
}

public sealed class AthleteProfile : Entity
{
    public Guid UserAccountId { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime DateOfBirthUtc { get; set; }
    public string State { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string? SchoolOrClubName { get; set; }
    public int Grade { get; set; }
    public decimal WeightClass { get; set; }
    public CompetitionLevel Level { get; set; }
}

public sealed class CoachProfile : Entity
{
    public Guid UserAccountId { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string? Bio { get; set; }
}

public sealed class Team : Entity
{
    public string Name { get; set; } = string.Empty;
    public TeamType Type { get; set; }
    public string State { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
}

public sealed class CoachAssociation : Entity
{
    public Guid CoachProfileId { get; set; }
    public Guid? AthleteProfileId { get; set; }
    public Guid? TeamId { get; set; }
    public string RoleTitle { get; set; } = string.Empty;
    public bool IsPrimary { get; set; }
    public DateTime? ApprovedUtc { get; set; }
}

public sealed class TournamentEvent : Entity
{
    public string Name { get; set; } = string.Empty;
    public OrganizerType OrganizerType { get; set; }
    public Guid OrganizerId { get; set; }
    public Guid? CreatedByUserAccountId { get; set; }
    public string State { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Venue { get; set; } = string.Empty;
    public DateTime StartUtc { get; set; }
    public DateTime EndUtc { get; set; }
    public int EntryFeeCents { get; set; }
    public string Currency { get; set; } = "USD";
    public bool IsPublished { get; set; }
}

public sealed class TournamentDivision : Entity
{
    public Guid TournamentEventId { get; set; }
    public CompetitionLevel Level { get; set; }
    public decimal WeightClass { get; set; }
    public string Name { get; set; } = string.Empty;
}

public sealed class EventRegistration : Entity
{
    public Guid TournamentEventId { get; set; }
    public Guid AthleteProfileId { get; set; }
    public Guid? TeamId { get; set; }
    public bool IsFreeAgent { get; set; }
    public RegistrationStatus Status { get; set; } = RegistrationStatus.Pending;
    public PaymentStatus PaymentStatus { get; set; } = PaymentStatus.NotRequired;
    public int PaidAmountCents { get; set; }
    public string? PaymentReference { get; set; }
}

public sealed class FreeAgentTeamInvite : Entity
{
    public Guid EventRegistrationId { get; set; }
    public Guid TeamId { get; set; }
    public string? Message { get; set; }
    public bool Accepted { get; set; }
}

public sealed class Bracket : Entity
{
    public Guid TournamentEventId { get; set; }
    public Guid? TournamentDivisionId { get; set; }
    public CompetitionLevel Level { get; set; }
    public decimal WeightClass { get; set; }
    public BracketGenerationMode Mode { get; set; }
}

public sealed class BracketEntry : Entity
{
    public Guid BracketId { get; set; }
    public Guid AthleteProfileId { get; set; }
    public int Seed { get; set; }
}

public sealed class Match : Entity
{
    public Guid BracketId { get; set; }
    public int Round { get; set; }
    public int MatchNumber { get; set; }
    public int? BoutNumber { get; set; }
    public Guid? AthleteAId { get; set; }
    public Guid? AthleteBId { get; set; }
    public Guid? WinnerAthleteId { get; set; }
    public string? Score { get; set; }
    public string? ResultMethod { get; set; }
    public string? MatNumber { get; set; }
    public MatchStatus Status { get; set; } = MatchStatus.Scheduled;
    public DateTime? ScheduledUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
}

public sealed class AthleteStatsSnapshot : Entity
{
    public Guid AthleteProfileId { get; set; }
    public CompetitionLevel Level { get; set; }
    public DateTime SnapshotUtc { get; set; }
    public int Wins { get; set; }
    public int Losses { get; set; }
    public int Pins { get; set; }
    public int TechFalls { get; set; }
    public int MajorDecisions { get; set; }
    public int MatchPointsFor { get; set; }
    public int MatchPointsAgainst { get; set; }
}

public sealed class AthleteRanking : Entity
{
    public Guid AthleteProfileId { get; set; }
    public CompetitionLevel Level { get; set; }
    public string State { get; set; } = string.Empty;
    public decimal RatingPoints { get; set; }
    public int Rank { get; set; }
    public DateTime SnapshotUtc { get; set; }
}

public sealed class NotificationSubscription : Entity
{
    public Guid UserAccountId { get; set; }
    public Guid? TournamentEventId { get; set; }
    public Guid? AthleteProfileId { get; set; }
    public NotificationEventType EventType { get; set; }
    public NotificationChannel Channel { get; set; }
    public string Destination { get; set; } = string.Empty;
}

public sealed class NotificationMessage : Entity
{
    public Guid NotificationSubscriptionId { get; set; }
    public Guid? TournamentEventId { get; set; }
    public Guid? MatchId { get; set; }
    public NotificationEventType EventType { get; set; }
    public NotificationChannel Channel { get; set; }
    public string Destination { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public DateTime? SentUtc { get; set; }
}

public sealed class StreamSession : Entity
{
    public Guid TournamentEventId { get; set; }
    public Guid? MatchId { get; set; }
    public Guid? AthleteProfileId { get; set; }
    public Guid? RequestedByUserAccountId { get; set; }
    public Guid? DelegatedByUserAccountId { get; set; }
    public bool IsPersonalStream { get; set; }
    public bool SaveToAthleteProfile { get; set; }
    public bool IsPrivate { get; set; }
    public string DeviceName { get; set; } = string.Empty;
    public string IngestKey { get; set; } = string.Empty;
    public string PlaybackUrl { get; set; } = string.Empty;
    public StreamStatus Status { get; set; } = StreamStatus.Provisioned;
    public DateTime? StartedUtc { get; set; }
    public DateTime? EndedUtc { get; set; }
}

public sealed class TournamentStaffAssignment : Entity
{
    public Guid TournamentEventId { get; set; }
    public Guid UserAccountId { get; set; }
    public UserRole Role { get; set; } = UserRole.MatWorker;
    public bool CanScoreMatches { get; set; } = true;
    public bool CanManageMatches { get; set; }
    public bool CanManageStreams { get; set; }
}

public sealed class AthleteStreamingPermission : Entity
{
    public Guid AthleteProfileId { get; set; }
    public Guid ParentGuardianUserAccountId { get; set; }
    public Guid DelegateUserAccountId { get; set; }
    public bool IsActive { get; set; } = true;
}

public sealed class PaymentWebhookEvent : Entity
{
    public string Provider { get; set; } = "Stripe";
    public string ProviderEventId { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public Guid? RegistrationId { get; set; }
    public string? ProviderReference { get; set; }
    public int? AmountCents { get; set; }
    public string? Currency { get; set; }
    public bool IsPaymentConfirmed { get; set; }
    public string Payload { get; set; } = string.Empty;
    public WebhookProcessingStatus ProcessingStatus { get; set; } = WebhookProcessingStatus.Pending;
    public int ProcessAttemptCount { get; set; }
    public DateTime? ProcessedUtc { get; set; }
    public string? LastError { get; set; }
}
