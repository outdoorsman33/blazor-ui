using Microsoft.EntityFrameworkCore;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Infrastructure.Services;

public sealed class RankingService(WrestlingPlatformDbContext dbContext) : IRankingService
{
    private const decimal DefaultRating = 1200m;
    private const decimal KFactor = 24m;

    public async Task ApplyMatchResultAsync(
        Match match,
        Guid winnerAthleteId,
        int pointsForWinner,
        int pointsForLoser,
        CancellationToken cancellationToken = default)
    {
        if (match.AthleteAId is null || match.AthleteBId is null)
        {
            return;
        }

        var loserAthleteId = match.AthleteAId == winnerAthleteId ? match.AthleteBId!.Value : match.AthleteAId.Value;

        var athletes = await dbContext.AthleteProfiles
            .Where(x => x.Id == winnerAthleteId || x.Id == loserAthleteId)
            .ToDictionaryAsync(x => x.Id, cancellationToken);

        if (!athletes.TryGetValue(winnerAthleteId, out var winner) || !athletes.TryGetValue(loserAthleteId, out var loser))
        {
            return;
        }

        var winnerRanking = await GetOrCreateRankingAsync(winner, cancellationToken);
        var loserRanking = await GetOrCreateRankingAsync(loser, cancellationToken);

        var expectedWinner = 1m / (1m + (decimal)Math.Pow(10, (double)((loserRanking.RatingPoints - winnerRanking.RatingPoints) / 400m)));
        var expectedLoser = 1m - expectedWinner;

        winnerRanking.RatingPoints += KFactor * (1m - expectedWinner);
        loserRanking.RatingPoints += KFactor * (0m - expectedLoser);
        winnerRanking.SnapshotUtc = DateTime.UtcNow;
        loserRanking.SnapshotUtc = DateTime.UtcNow;

        await AddStatsSnapshotAsync(winner, true, pointsForWinner, pointsForLoser, match.ResultMethod, cancellationToken);
        await AddStatsSnapshotAsync(loser, false, pointsForLoser, pointsForWinner, match.ResultMethod, cancellationToken);

        await dbContext.SaveChangesAsync(cancellationToken);

        await RecalculateRanksAsync(winner.Level, winner.State, cancellationToken);
        if (winner.Level != loser.Level || !string.Equals(winner.State, loser.State, StringComparison.OrdinalIgnoreCase))
        {
            await RecalculateRanksAsync(loser.Level, loser.State, cancellationToken);
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private async Task<AthleteRanking> GetOrCreateRankingAsync(AthleteProfile athlete, CancellationToken cancellationToken)
    {
        var ranking = await dbContext.AthleteRankings
            .FirstOrDefaultAsync(x => x.AthleteProfileId == athlete.Id && x.Level == athlete.Level, cancellationToken);

        if (ranking is not null)
        {
            return ranking;
        }

        ranking = new AthleteRanking
        {
            AthleteProfileId = athlete.Id,
            Level = athlete.Level,
            State = athlete.State,
            RatingPoints = DefaultRating,
            Rank = 0,
            SnapshotUtc = DateTime.UtcNow
        };

        dbContext.AthleteRankings.Add(ranking);
        return ranking;
    }

    private async Task AddStatsSnapshotAsync(
        AthleteProfile athlete,
        bool isWin,
        int pointsFor,
        int pointsAgainst,
        string? resultMethod,
        CancellationToken cancellationToken)
    {
        var previous = await dbContext.AthleteStatsSnapshots
            .Where(x => x.AthleteProfileId == athlete.Id)
            .OrderByDescending(x => x.SnapshotUtc)
            .FirstOrDefaultAsync(cancellationToken);

        var snapshot = new AthleteStatsSnapshot
        {
            AthleteProfileId = athlete.Id,
            Level = athlete.Level,
            SnapshotUtc = DateTime.UtcNow,
            Wins = (previous?.Wins ?? 0) + (isWin ? 1 : 0),
            Losses = (previous?.Losses ?? 0) + (!isWin ? 1 : 0),
            Pins = (previous?.Pins ?? 0) + (resultMethod?.Contains("pin", StringComparison.OrdinalIgnoreCase) == true && isWin ? 1 : 0),
            TechFalls = (previous?.TechFalls ?? 0) + (resultMethod?.Contains("tech", StringComparison.OrdinalIgnoreCase) == true && isWin ? 1 : 0),
            MajorDecisions = (previous?.MajorDecisions ?? 0) + (resultMethod?.Contains("major", StringComparison.OrdinalIgnoreCase) == true && isWin ? 1 : 0),
            MatchPointsFor = (previous?.MatchPointsFor ?? 0) + pointsFor,
            MatchPointsAgainst = (previous?.MatchPointsAgainst ?? 0) + pointsAgainst
        };

        dbContext.AthleteStatsSnapshots.Add(snapshot);
    }

    private async Task RecalculateRanksAsync(CompetitionLevel level, string state, CancellationToken cancellationToken)
    {
        var ordered = await dbContext.AthleteRankings
            .Where(x => x.Level == level && x.State == state)
            .OrderByDescending(x => x.RatingPoints)
            .ToListAsync(cancellationToken);

        for (var i = 0; i < ordered.Count; i++)
        {
            ordered[i].Rank = i + 1;
        }
    }
}
