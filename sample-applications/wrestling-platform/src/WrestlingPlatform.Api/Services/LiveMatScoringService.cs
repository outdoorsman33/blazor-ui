using System.Collections.Concurrent;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Api.Services;

public interface ILiveMatScoringService
{
    MatScoreboardSnapshot GetOrCreate(Match match);

    MatchScoringRulesSnapshot GetRules(Match match);

    MatchScoringRulesSnapshot Configure(Match match, ConfigureMatchScoringRequest request);

    MatScoreboardSnapshot AddScoreEvent(Match match, AddMatScoreEventRequest request);

    MatScoreboardSnapshot Reset(Match match, string? reason);
}

public sealed class LiveMatScoringService : ILiveMatScoringService
{
    private readonly ConcurrentDictionary<Guid, MatchScoreboardState> _scoreboards = new();
    private readonly ConcurrentDictionary<Guid, MatchScoringConfiguration> _rulesByMatch = new();

    public MatScoreboardSnapshot GetOrCreate(Match match)
    {
        var state = _scoreboards.GetOrAdd(match.Id, _ => MatchScoreboardState.FromMatch(match));
        var rules = _rulesByMatch.GetOrAdd(match.Id, _ => MatchScoringConfiguration.CreateDefault());
        lock (state.SyncRoot)
        {
            state.SyncWithMatch(match);
            state.Style = rules.Style;
            state.Level = rules.Level;
            return state.ToSnapshot(rules);
        }
    }

    public MatchScoringRulesSnapshot GetRules(Match match)
    {
        var rules = _rulesByMatch.GetOrAdd(match.Id, _ => MatchScoringConfiguration.CreateDefault());
        return rules.ToSnapshot(match.Id);
    }

    public MatchScoringRulesSnapshot Configure(Match match, ConfigureMatchScoringRequest request)
    {
        if (request.RegulationPeriods is < 1 or > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(request.RegulationPeriods), "Regulation periods must be between 1 and 10.");
        }

        if (request.MaxOvertimePeriods is < 0 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(request.MaxOvertimePeriods), "Overtime periods must be between 0 and 8.");
        }

        var techFallGap = request.TechFallPointGap ?? WrestlingRuleBook.GetDefaultTechFallPointGap(request.Style);
        if (techFallGap is < 4 or > 30)
        {
            throw new ArgumentOutOfRangeException(nameof(request.TechFallPointGap), "Tech-fall threshold must be between 4 and 30.");
        }

        var normalizedOvertimeFormat = WrestlingRuleBook.NormalizeOvertimeFormat(request.Style, request.OvertimeFormat);
        var allowsOvertime = normalizedOvertimeFormat != OvertimeFormat.None;
        var maxOvertimePeriods = allowsOvertime
            ? Math.Max(1, request.MaxOvertimePeriods)
            : 0;

        var configured = new MatchScoringConfiguration(
            request.Style,
            request.Level,
            request.AutoEndEnabled,
            techFallGap,
            request.RegulationPeriods,
            WrestlingRuleBook.GetActionCatalog(request.Style),
            normalizedOvertimeFormat,
            maxOvertimePeriods,
            request.EndOnFirstOvertimeScore);

        _rulesByMatch.AddOrUpdate(match.Id, configured, (_, _) => configured);

        var state = _scoreboards.GetOrAdd(match.Id, _ => MatchScoreboardState.FromMatch(match));
        lock (state.SyncRoot)
        {
            state.Style = configured.Style;
            state.Level = configured.Level;
        }

        return configured.ToSnapshot(match.Id);
    }

    public MatScoreboardSnapshot AddScoreEvent(Match match, AddMatScoreEventRequest request)
    {
        var rules = _rulesByMatch.GetOrAdd(match.Id, _ => MatchScoringConfiguration.CreateDefault());
        if (request.Points is < 0 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Points), "Points must be between 0 and 8.");
        }

        var maxPeriods = rules.RegulationPeriods + rules.MaxOvertimePeriods;
        if (request.Period is < 1 || request.Period > maxPeriods)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Period), $"Period must be between 1 and {maxPeriods} for the configured rules.");
        }

        var isOvertimePeriod = request.Period > rules.RegulationPeriods;
        if (isOvertimePeriod && rules.OvertimeFormat == OvertimeFormat.None)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Period), "Overtime is disabled for this match.");
        }

        if (request.MatchClockSeconds is < 0 or > 420)
        {
            throw new ArgumentOutOfRangeException(nameof(request.MatchClockSeconds), "Match clock seconds must be between 0 and 420.");
        }

        var state = _scoreboards.GetOrAdd(match.Id, _ => MatchScoreboardState.FromMatch(match));
        lock (state.SyncRoot)
        {
            state.SyncWithMatch(match);
            state.Style = rules.Style;
            state.Level = rules.Level;

            if (state.IsFinal || state.Status == MatchStatus.Completed)
            {
                throw new InvalidOperationException("Match is already final. Reset or open a new match to continue scoring.");
            }

            var competitor = ResolveCompetitor(match, request);
            var action = ResolveAction(rules, request);
            var points = request.Points ?? action.DefaultPoints;
            if (points < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(request.Points), "Points cannot be negative.");
            }

            if (competitor == ScoreCompetitor.AthleteA)
            {
                state.AthleteAScore += points;
            }
            else
            {
                state.AthleteBScore += points;
            }

            state.CurrentPeriod = Math.Max(state.CurrentPeriod, request.Period);
            state.Status = MatchStatus.OnMat;
            state.UpdatedUtc = DateTime.UtcNow;

            var normalizedAction = request.ActionCode == ScoringActionCode.Custom
                ? string.IsNullOrWhiteSpace(request.ActionType) ? "Score" : request.ActionType.Trim()
                : action.Label;

            var scoreEvent = new MatScoreEventSnapshot(
                Guid.NewGuid(),
                state.UpdatedUtc,
                competitor,
                points,
                normalizedAction,
                request.Period,
                request.MatchClockSeconds,
                request.AthleteId,
                state.AthleteAScore,
                state.AthleteBScore);

            state.Events.Add(scoreEvent);

            var shouldForceFinal = action.EndsMatch || request.EndMatch;
            if (shouldForceFinal)
            {
                var reason = request.ActionCode switch
                {
                    ScoringActionCode.Fall => "Fall",
                    ScoringActionCode.Disqualification => "Disqualification",
                    ScoringActionCode.InjuryDefault => "Injury Default",
                    ScoringActionCode.TechnicalFall => "Technical Fall",
                    _ => action.EndsMatch ? action.Label : "Decision"
                };

                FinalizeMatch(state, match, competitor, reason);
            }
            else if (rules.AutoEndEnabled && Math.Abs(state.AthleteAScore - state.AthleteBScore) >= rules.TechFallPointGap)
            {
                var leader = state.AthleteAScore >= state.AthleteBScore ? ScoreCompetitor.AthleteA : ScoreCompetitor.AthleteB;
                FinalizeMatch(state, match, leader, "Technical Fall");
            }
            else if (rules.EndOnFirstOvertimeScore
                     && isOvertimePeriod
                     && state.AthleteAScore != state.AthleteBScore)
            {
                var overtimeLeader = state.AthleteAScore > state.AthleteBScore
                    ? ScoreCompetitor.AthleteA
                    : ScoreCompetitor.AthleteB;
                FinalizeMatch(state, match, overtimeLeader, "Overtime Sudden Victory");
            }

            return state.ToSnapshot(rules);
        }
    }

    public MatScoreboardSnapshot Reset(Match match, string? reason)
    {
        var state = _scoreboards.GetOrAdd(match.Id, _ => MatchScoreboardState.FromMatch(match));
        var rules = _rulesByMatch.GetOrAdd(match.Id, _ => MatchScoringConfiguration.CreateDefault());

        lock (state.SyncRoot)
        {
            state.SyncWithMatch(match);
            state.AthleteAScore = 0;
            state.AthleteBScore = 0;
            state.CurrentPeriod = 1;
            state.Status = MatchStatus.OnMat;
            state.UpdatedUtc = DateTime.UtcNow;
            state.WinnerAthleteId = null;
            state.LoserAthleteId = null;
            state.OutcomeReason = null;
            state.IsFinal = false;
            state.Events.Clear();

            if (!string.IsNullOrWhiteSpace(reason))
            {
                state.Events.Add(new MatScoreEventSnapshot(
                    Guid.NewGuid(),
                    state.UpdatedUtc,
                    ScoreCompetitor.AthleteA,
                    0,
                    $"Reset: {reason.Trim()}",
                    1,
                    null,
                    null,
                    state.AthleteAScore,
                    state.AthleteBScore));
            }

            return state.ToSnapshot(rules);
        }
    }

    private static void FinalizeMatch(MatchScoreboardState state, Match match, ScoreCompetitor preferredWinner, string reason)
    {
        var winner = ResolveWinner(state, preferredWinner);
        state.Status = MatchStatus.Completed;
        state.IsFinal = true;
        state.OutcomeReason = reason;
        state.WinnerAthleteId = winner switch
        {
            ScoreCompetitor.AthleteA => match.AthleteAId,
            ScoreCompetitor.AthleteB => match.AthleteBId,
            _ => null
        };

        state.LoserAthleteId = winner switch
        {
            ScoreCompetitor.AthleteA => match.AthleteBId,
            ScoreCompetitor.AthleteB => match.AthleteAId,
            _ => null
        };
    }

    private static ScoreCompetitor ResolveWinner(MatchScoreboardState state, ScoreCompetitor preferredWinner)
    {
        if (state.AthleteAScore > state.AthleteBScore)
        {
            return ScoreCompetitor.AthleteA;
        }

        if (state.AthleteBScore > state.AthleteAScore)
        {
            return ScoreCompetitor.AthleteB;
        }

        return preferredWinner;
    }

    private static ScoringActionDefinition ResolveAction(MatchScoringConfiguration rules, AddMatScoreEventRequest request)
    {
        if (request.ActionCode == ScoringActionCode.Custom)
        {
            return new ScoringActionDefinition(
                ScoringActionCode.Custom,
                string.IsNullOrWhiteSpace(request.ActionType) ? "Score" : request.ActionType.Trim(),
                request.Points ?? 0,
                EndsMatch: false,
                "Custom scoring action.");
        }

        var action = rules.Actions.FirstOrDefault(x => x.ActionCode == request.ActionCode);
        if (action is null)
        {
            throw new ArgumentOutOfRangeException(nameof(request.ActionCode), $"Action '{request.ActionCode}' is not valid for {rules.Style}.");
        }

        return action;
    }

    private static ScoreCompetitor ResolveCompetitor(Match match, AddMatScoreEventRequest request)
    {
        if (request.AthleteId is not null)
        {
            if (match.AthleteAId == request.AthleteId)
            {
                return ScoreCompetitor.AthleteA;
            }

            if (match.AthleteBId == request.AthleteId)
            {
                return ScoreCompetitor.AthleteB;
            }
        }

        return request.Competitor;
    }

    private sealed class MatchScoreboardState
    {
        public object SyncRoot { get; } = new();

        public Guid MatchId { get; private init; }

        public Guid? AthleteAId { get; private set; }

        public Guid? AthleteBId { get; private set; }

        public int AthleteAScore { get; set; }

        public int AthleteBScore { get; set; }

        public int CurrentPeriod { get; set; } = 1;

        public MatchStatus Status { get; set; } = MatchStatus.Scheduled;

        public WrestlingStyle Style { get; set; } = WrestlingStyle.Folkstyle;

        public CompetitionLevel Level { get; set; } = CompetitionLevel.HighSchool;

        public Guid? WinnerAthleteId { get; set; }

        public Guid? LoserAthleteId { get; set; }

        public string? OutcomeReason { get; set; }

        public bool IsFinal { get; set; }

        public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;

        public List<MatScoreEventSnapshot> Events { get; } = [];

        public static MatchScoreboardState FromMatch(Match match)
        {
            var (athleteAScore, athleteBScore) = ParseSeedScore(match.Score);
            return new MatchScoreboardState
            {
                MatchId = match.Id,
                AthleteAId = match.AthleteAId,
                AthleteBId = match.AthleteBId,
                AthleteAScore = athleteAScore,
                AthleteBScore = athleteBScore,
                Status = match.Status,
                WinnerAthleteId = match.WinnerAthleteId,
                LoserAthleteId = ResolveLoser(match),
                OutcomeReason = match.ResultMethod,
                IsFinal = match.Status == MatchStatus.Completed,
                CurrentPeriod = 1,
                UpdatedUtc = DateTime.UtcNow
            };
        }

        public void SyncWithMatch(Match match)
        {
            AthleteAId = match.AthleteAId;
            AthleteBId = match.AthleteBId;
            Status = match.Status;
            WinnerAthleteId = match.WinnerAthleteId;

            if (match.Status == MatchStatus.Completed)
            {
                IsFinal = true;
                OutcomeReason = match.ResultMethod;
                LoserAthleteId = ResolveLoser(match);
            }
        }

        public MatScoreboardSnapshot ToSnapshot(MatchScoringConfiguration rules)
        {
            return new MatScoreboardSnapshot(
                MatchId,
                AthleteAId,
                AthleteBId,
                AthleteAScore,
                AthleteBScore,
                CurrentPeriod,
                Status,
                UpdatedUtc,
                Events.ToList(),
                rules.Style,
                rules.Level,
                WinnerAthleteId,
                LoserAthleteId,
                OutcomeReason,
                IsFinal);
        }

        private static (int AthleteAScore, int AthleteBScore) ParseSeedScore(string? score)
        {
            if (string.IsNullOrWhiteSpace(score))
            {
                return (0, 0);
            }

            var normalized = score.Trim();
            var dashIndex = normalized.IndexOf('-');
            if (dashIndex <= 0 || dashIndex >= normalized.Length - 1)
            {
                return (0, 0);
            }

            var left = normalized[..dashIndex];
            var right = normalized[(dashIndex + 1)..];

            return int.TryParse(left, out var athleteAScore) && int.TryParse(right, out var athleteBScore)
                ? (Math.Max(0, athleteAScore), Math.Max(0, athleteBScore))
                : (0, 0);
        }

        private static Guid? ResolveLoser(Match match)
        {
            if (match.WinnerAthleteId is null)
            {
                return null;
            }

            if (match.WinnerAthleteId == match.AthleteAId)
            {
                return match.AthleteBId;
            }

            if (match.WinnerAthleteId == match.AthleteBId)
            {
                return match.AthleteAId;
            }

            return null;
        }
    }

    private sealed record MatchScoringConfiguration(
        WrestlingStyle Style,
        CompetitionLevel Level,
        bool AutoEndEnabled,
        int TechFallPointGap,
        int RegulationPeriods,
        List<ScoringActionDefinition> Actions,
        OvertimeFormat OvertimeFormat,
        int MaxOvertimePeriods,
        bool EndOnFirstOvertimeScore)
    {
        public static MatchScoringConfiguration CreateDefault()
        {
            var defaultStyle = WrestlingStyle.Folkstyle;
            return new MatchScoringConfiguration(
                defaultStyle,
                CompetitionLevel.HighSchool,
                AutoEndEnabled: true,
                TechFallPointGap: WrestlingRuleBook.GetDefaultTechFallPointGap(defaultStyle),
                RegulationPeriods: 3,
                WrestlingRuleBook.GetActionCatalog(defaultStyle),
                WrestlingRuleBook.GetDefaultOvertimeFormat(defaultStyle),
                MaxOvertimePeriods: 3,
                EndOnFirstOvertimeScore: false);
        }

        public MatchScoringRulesSnapshot ToSnapshot(Guid matchId)
        {
            return new MatchScoringRulesSnapshot(
                matchId,
                Style,
                Level,
                AutoEndEnabled,
                TechFallPointGap,
                RegulationPeriods,
                Actions.ToList(),
                OvertimeFormat,
                MaxOvertimePeriods,
                EndOnFirstOvertimeScore);
        }
    }

    private static class WrestlingRuleBook
    {
        public static OvertimeFormat GetDefaultOvertimeFormat(WrestlingStyle style)
        {
            return style switch
            {
                WrestlingStyle.Folkstyle => OvertimeFormat.FolkstyleStandard,
                WrestlingStyle.Freestyle => OvertimeFormat.FreestyleCriteria,
                WrestlingStyle.GrecoRoman => OvertimeFormat.GrecoCriteria,
                _ => OvertimeFormat.None
            };
        }

        public static OvertimeFormat NormalizeOvertimeFormat(WrestlingStyle style, OvertimeFormat requested)
        {
            if (requested == OvertimeFormat.TournamentCustom)
            {
                return requested;
            }

            return style switch
            {
                WrestlingStyle.Folkstyle when requested is OvertimeFormat.FolkstyleStandard or OvertimeFormat.FolkstyleSuddenVictoryOnly or OvertimeFormat.None => requested,
                WrestlingStyle.Freestyle when requested is OvertimeFormat.FreestyleCriteria or OvertimeFormat.None => requested,
                WrestlingStyle.GrecoRoman when requested is OvertimeFormat.GrecoCriteria or OvertimeFormat.None => requested,
                _ => GetDefaultOvertimeFormat(style)
            };
        }

        public static int GetDefaultTechFallPointGap(WrestlingStyle style)
        {
            return style switch
            {
                WrestlingStyle.Folkstyle => 15,
                WrestlingStyle.Freestyle => 10,
                WrestlingStyle.GrecoRoman => 8,
                _ => 10
            };
        }

        public static List<ScoringActionDefinition> GetActionCatalog(WrestlingStyle style)
        {
            var actions = new List<ScoringActionDefinition>();

            switch (style)
            {
                case WrestlingStyle.Folkstyle:
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Takedown, "Takedown", 3, false, "NFHS folkstyle takedown value."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Escape, "Escape", 1, false, "Defensive wrestler escapes control."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Reversal, "Reversal", 2, false, "Bottom wrestler reverses to top control."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.NearFall2, "Near Fall (2)", 2, false, "Near-fall count reached."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.NearFall3, "Near Fall (3)", 3, false, "Near-fall control extended."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.NearFall4, "Near Fall (4)", 4, false, "Near-fall criteria held for 5+ seconds."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Penalty, "Penalty", 1, false, "Penalty point awarded."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Fall, "Fall", 0, true, "Pin/fall ends the match immediately."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.InjuryDefault, "Injury Default", 0, true, "Opponent cannot continue due to injury."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Disqualification, "Disqualification", 0, true, "Opponent disqualified."));
                    break;
                case WrestlingStyle.Freestyle:
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Takedown, "Takedown", 2, false, "Standard takedown."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.TakedownHighAmplitude, "High Amplitude Takedown (4)", 4, false, "High-amplitude takedown."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Exposure, "Exposure", 2, false, "Turns opponent exposing back."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.ThrowHighAmplitude, "Grand Amplitude Throw (5)", 5, false, "Feet-to-danger high-amplitude action."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.PushOut, "Push Out", 1, false, "Opponent forced out of bounds."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Passivity, "Passivity", 1, false, "Passivity point awarded."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.CautionAndOne, "Caution +1", 1, false, "Caution and one point."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.CautionAndTwo, "Caution +2", 2, false, "Caution and two points."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Fall, "Fall", 0, true, "Pin/fall ends the match immediately."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.InjuryDefault, "Injury Default", 0, true, "Opponent cannot continue due to injury."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Disqualification, "Disqualification", 0, true, "Opponent disqualified."));
                    break;
                case WrestlingStyle.GrecoRoman:
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Takedown, "Takedown", 2, false, "Upper-body control takedown."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Exposure, "Exposure", 2, false, "Exposure of opponent's back."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.ThrowHighAmplitude, "Throw (5)", 5, false, "Grand amplitude throw."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.PushOut, "Push Out", 1, false, "Opponent forced out of bounds."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Passivity, "Passivity", 1, false, "Passivity point awarded."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.CautionAndOne, "Caution +1", 1, false, "Caution and one point."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.CautionAndTwo, "Caution +2", 2, false, "Caution and two points."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Fall, "Fall", 0, true, "Pin/fall ends the match immediately."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.InjuryDefault, "Injury Default", 0, true, "Opponent cannot continue due to injury."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Disqualification, "Disqualification", 0, true, "Opponent disqualified."));
                    break;
                default:
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Takedown, "Takedown", 2, false, "Standard score."));
                    actions.Add(new ScoringActionDefinition(ScoringActionCode.Fall, "Fall", 0, true, "Match-ending action."));
                    break;
            }

            actions.Add(new ScoringActionDefinition(ScoringActionCode.TechnicalFall, "Technical Fall", 0, true, "Force immediate technical-fall completion."));
            return actions;
        }
    }
}
