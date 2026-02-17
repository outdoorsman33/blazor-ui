using Microsoft.EntityFrameworkCore;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Infrastructure.Persistence;

public sealed class WrestlingPlatformDbContext(DbContextOptions<WrestlingPlatformDbContext> options) : DbContext(options)
{
    public DbSet<UserAccount> UserAccounts => Set<UserAccount>();
    public DbSet<UserRefreshToken> UserRefreshTokens => Set<UserRefreshToken>();
    public DbSet<AthleteProfile> AthleteProfiles => Set<AthleteProfile>();
    public DbSet<CoachProfile> CoachProfiles => Set<CoachProfile>();
    public DbSet<Team> Teams => Set<Team>();
    public DbSet<CoachAssociation> CoachAssociations => Set<CoachAssociation>();
    public DbSet<TournamentEvent> TournamentEvents => Set<TournamentEvent>();
    public DbSet<TournamentDivision> TournamentDivisions => Set<TournamentDivision>();
    public DbSet<EventRegistration> EventRegistrations => Set<EventRegistration>();
    public DbSet<FreeAgentTeamInvite> FreeAgentTeamInvites => Set<FreeAgentTeamInvite>();
    public DbSet<Bracket> Brackets => Set<Bracket>();
    public DbSet<BracketEntry> BracketEntries => Set<BracketEntry>();
    public DbSet<Match> Matches => Set<Match>();
    public DbSet<AthleteStatsSnapshot> AthleteStatsSnapshots => Set<AthleteStatsSnapshot>();
    public DbSet<AthleteRanking> AthleteRankings => Set<AthleteRanking>();
    public DbSet<NotificationSubscription> NotificationSubscriptions => Set<NotificationSubscription>();
    public DbSet<NotificationMessage> NotificationMessages => Set<NotificationMessage>();
    public DbSet<StreamSession> StreamSessions => Set<StreamSession>();
    public DbSet<TournamentStaffAssignment> TournamentStaffAssignments => Set<TournamentStaffAssignment>();
    public DbSet<AthleteStreamingPermission> AthleteStreamingPermissions => Set<AthleteStreamingPermission>();
    public DbSet<PaymentWebhookEvent> PaymentWebhookEvents => Set<PaymentWebhookEvent>();
    public DbSet<AthleteChatThread> AthleteChatThreads => Set<AthleteChatThread>();
    public DbSet<AthleteChatParticipant> AthleteChatParticipants => Set<AthleteChatParticipant>();
    public DbSet<AthleteChatMessage> AthleteChatMessages => Set<AthleteChatMessage>();
    public DbSet<AthleteChatMessageReport> AthleteChatMessageReports => Set<AthleteChatMessageReport>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserAccount>().HasIndex(x => x.Email).IsUnique();
        modelBuilder.Entity<UserRefreshToken>().HasIndex(x => x.TokenHash).IsUnique();
        modelBuilder.Entity<UserRefreshToken>().HasIndex(x => new { x.UserAccountId, x.ExpiresUtc });
        modelBuilder.Entity<AthleteProfile>().HasIndex(x => x.UserAccountId).IsUnique();
        modelBuilder.Entity<CoachProfile>().HasIndex(x => x.UserAccountId).IsUnique();
        modelBuilder.Entity<TournamentEvent>().HasIndex(x => new { x.State, x.City, x.StartUtc });
        modelBuilder.Entity<TournamentEvent>().HasIndex(x => x.CreatedByUserAccountId);
        modelBuilder.Entity<EventRegistration>().HasIndex(x => new { x.TournamentEventId, x.AthleteProfileId }).IsUnique();
        modelBuilder.Entity<Match>().HasIndex(x => new { x.BracketId, x.BoutNumber });
        modelBuilder.Entity<AthleteRanking>().HasIndex(x => new { x.Level, x.State, x.Rank });
        modelBuilder.Entity<NotificationSubscription>().HasIndex(x => new { x.UserAccountId, x.EventType, x.Channel });
        modelBuilder.Entity<StreamSession>().HasIndex(x => new { x.TournamentEventId, x.Status });
        modelBuilder.Entity<StreamSession>().HasIndex(x => new { x.TournamentEventId, x.AthleteProfileId, x.IsPersonalStream, x.Status });
        modelBuilder.Entity<TournamentStaffAssignment>().HasIndex(x => new { x.TournamentEventId, x.UserAccountId }).IsUnique();
        modelBuilder.Entity<TournamentStaffAssignment>().HasIndex(x => new { x.TournamentEventId, x.CanScoreMatches });
        modelBuilder.Entity<AthleteStreamingPermission>().HasIndex(x => new { x.AthleteProfileId, x.DelegateUserAccountId }).IsUnique();
        modelBuilder.Entity<PaymentWebhookEvent>().HasIndex(x => new { x.Provider, x.ProviderEventId }).IsUnique();
        modelBuilder.Entity<PaymentWebhookEvent>().HasIndex(x => new { x.ProcessingStatus, x.CreatedUtc });
        modelBuilder.Entity<AthleteChatThread>().HasIndex(x => x.DirectPairKey).IsUnique();
        modelBuilder.Entity<AthleteChatThread>().HasIndex(x => new { x.Kind, x.LastMessageUtc });
        modelBuilder.Entity<AthleteChatParticipant>().HasIndex(x => new { x.ThreadId, x.UserAccountId }).IsUnique();
        modelBuilder.Entity<AthleteChatParticipant>().HasIndex(x => new { x.UserAccountId, x.LastReadMessageUtc });
        modelBuilder.Entity<AthleteChatMessage>().HasIndex(x => new { x.ThreadId, x.CreatedUtc });
        modelBuilder.Entity<AthleteChatMessage>().HasIndex(x => new { x.UserAccountId, x.CreatedUtc });
        modelBuilder.Entity<AthleteChatMessageReport>().HasIndex(x => new { x.MessageId, x.ReportedByUserAccountId }).IsUnique();
        modelBuilder.Entity<AthleteChatMessageReport>().HasIndex(x => new { x.IsResolved, x.CreatedUtc });
    }
}
