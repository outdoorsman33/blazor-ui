using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Infrastructure.Services;

public static class BracketProgressionEngine
{
    public static void Resolve(List<Match> matches)
    {
        if (matches.Count == 0)
        {
            return;
        }

        var maxRound = matches.Max(x => x.Round);

        for (var round = 2; round <= maxRound; round++)
        {
            var currentRoundMatches = matches
                .Where(x => x.Round == round)
                .OrderBy(x => x.MatchNumber)
                .ToList();

            foreach (var match in currentRoundMatches)
            {
                if (IsManualCompletion(match))
                {
                    continue;
                }

                var feederMatchA = matches.FirstOrDefault(x => x.Round == round - 1 && x.MatchNumber == ((match.MatchNumber * 2) - 1));
                var feederMatchB = matches.FirstOrDefault(x => x.Round == round - 1 && x.MatchNumber == (match.MatchNumber * 2));

                if (feederMatchA is null || feederMatchB is null)
                {
                    continue;
                }

                if (IsResolved(feederMatchA))
                {
                    match.AthleteAId = feederMatchA.WinnerAthleteId;
                }

                if (IsResolved(feederMatchB))
                {
                    match.AthleteBId = feederMatchB.WinnerAthleteId;
                }

                if (!IsResolved(feederMatchA) || !IsResolved(feederMatchB))
                {
                    continue;
                }

                if (match.AthleteAId is null && match.AthleteBId is null)
                {
                    match.Status = MatchStatus.Cancelled;
                    match.WinnerAthleteId = null;
                    match.Score = null;
                    match.ResultMethod = "Empty";
                    match.CompletedUtc = DateTime.UtcNow;
                    continue;
                }

                if (match.AthleteAId is null || match.AthleteBId is null)
                {
                    match.Status = MatchStatus.Completed;
                    match.WinnerAthleteId = match.AthleteAId ?? match.AthleteBId;
                    match.Score = "BYE";
                    match.ResultMethod = "Bye";
                    match.CompletedUtc = DateTime.UtcNow;
                    continue;
                }

                match.Status = MatchStatus.Scheduled;
                match.WinnerAthleteId = null;
                match.Score = null;
                match.ResultMethod = null;
                match.CompletedUtc = null;
            }
        }
    }

    public static void ResolveFirstRoundByes(List<Match> matches)
    {
        foreach (var firstRoundMatch in matches.Where(x => x.Round == 1))
        {
            if (firstRoundMatch.AthleteAId is null && firstRoundMatch.AthleteBId is null)
            {
                firstRoundMatch.Status = MatchStatus.Cancelled;
                firstRoundMatch.ResultMethod = "Empty";
                firstRoundMatch.CompletedUtc = DateTime.UtcNow;
                continue;
            }

            if (firstRoundMatch.AthleteAId is null || firstRoundMatch.AthleteBId is null)
            {
                firstRoundMatch.Status = MatchStatus.Completed;
                firstRoundMatch.WinnerAthleteId = firstRoundMatch.AthleteAId ?? firstRoundMatch.AthleteBId;
                firstRoundMatch.Score = "BYE";
                firstRoundMatch.ResultMethod = "Bye";
                firstRoundMatch.CompletedUtc = DateTime.UtcNow;
            }
        }
    }

    private static bool IsResolved(Match match)
    {
        return match.Status is MatchStatus.Completed or MatchStatus.Cancelled;
    }

    private static bool IsManualCompletion(Match match)
    {
        return match.Status == MatchStatus.Completed
               && !string.Equals(match.ResultMethod, "Bye", StringComparison.OrdinalIgnoreCase)
               && !string.Equals(match.ResultMethod, "Empty", StringComparison.OrdinalIgnoreCase);
    }
}
