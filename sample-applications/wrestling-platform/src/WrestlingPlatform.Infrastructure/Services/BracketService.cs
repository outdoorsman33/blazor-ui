using Microsoft.EntityFrameworkCore;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Infrastructure.Services;

public sealed class BracketService(WrestlingPlatformDbContext dbContext) : IBracketService
{
    public async Task<BracketGenerationResult> GenerateAsync(BracketGenerationInput input, CancellationToken cancellationToken = default)
    {
        var baseQuery =
            from registration in dbContext.EventRegistrations
            join athlete in dbContext.AthleteProfiles on registration.AthleteProfileId equals athlete.Id
            where registration.TournamentEventId == input.EventId
                  && registration.Status == RegistrationStatus.Confirmed
                  && athlete.Level == input.Level
                  && athlete.WeightClass == input.WeightClass
            select athlete.Id;

        var athleteIds = await baseQuery.ToListAsync(cancellationToken);

        if (athleteIds.Count == 0)
        {
            throw new InvalidOperationException("No confirmed registrations found for this event, level, and weight class.");
        }

        athleteIds = input.Mode switch
        {
            BracketGenerationMode.Random => athleteIds.OrderBy(_ => Guid.NewGuid()).ToList(),
            BracketGenerationMode.Seeded => await OrderByRankingAsync(athleteIds, input.Level, cancellationToken),
            _ => athleteIds
        };

        var bracket = new Bracket
        {
            TournamentEventId = input.EventId,
            TournamentDivisionId = input.DivisionId,
            Level = input.Level,
            WeightClass = input.WeightClass,
            Mode = input.Mode
        };

        dbContext.Brackets.Add(bracket);
        await dbContext.SaveChangesAsync(cancellationToken);

        var entries = athleteIds
            .Select((athleteId, index) => new BracketEntry
            {
                BracketId = bracket.Id,
                AthleteProfileId = athleteId,
                Seed = index + 1
            })
            .ToList();

        dbContext.BracketEntries.AddRange(entries);

        var matches = BuildInitialBracket(bracket.Id, athleteIds);
        BracketProgressionEngine.ResolveFirstRoundByes(matches);
        BracketProgressionEngine.Resolve(matches);

        dbContext.Matches.AddRange(matches);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new BracketGenerationResult(bracket.Id, entries.Count, matches.Count);
    }

    private async Task<List<Guid>> OrderByRankingAsync(List<Guid> athleteIds, CompetitionLevel level, CancellationToken cancellationToken)
    {
        var rankings = await dbContext.AthleteRankings
            .Where(x => athleteIds.Contains(x.AthleteProfileId) && x.Level == level)
            .ToDictionaryAsync(x => x.AthleteProfileId, x => x.RatingPoints, cancellationToken);

        return athleteIds
            .OrderByDescending(id => rankings.GetValueOrDefault(id, 1200m))
            .ToList();
    }

    private static List<Match> BuildInitialBracket(Guid bracketId, IReadOnlyList<Guid> athleteIds)
    {
        var bracketSize = GetBracketSize(athleteIds.Count);
        var rounds = (int)Math.Log2(bracketSize);
        var seededSlots = new Guid?[bracketSize];

        for (var i = 0; i < athleteIds.Count; i++)
        {
            seededSlots[i] = athleteIds[i];
        }

        var matches = new List<Match>();

        for (var round = 1; round <= rounds; round++)
        {
            var matchCount = bracketSize >> round;
            for (var matchNumber = 1; matchNumber <= matchCount; matchNumber++)
            {
                Guid? athleteA = null;
                Guid? athleteB = null;

                if (round == 1)
                {
                    var slotIndex = (matchNumber - 1) * 2;
                    athleteA = seededSlots[slotIndex];
                    athleteB = seededSlots[slotIndex + 1];
                }

                matches.Add(new Match
                {
                    BracketId = bracketId,
                    Round = round,
                    MatchNumber = matchNumber,
                    BoutNumber = matchNumber,
                    AthleteAId = athleteA,
                    AthleteBId = athleteB,
                    Status = MatchStatus.Scheduled
                });
            }
        }

        return matches;
    }

    private static int GetBracketSize(int entrantCount)
    {
        var size = 1;
        while (size < entrantCount)
        {
            size <<= 1;
        }

        return Math.Max(size, 2);
    }
}
