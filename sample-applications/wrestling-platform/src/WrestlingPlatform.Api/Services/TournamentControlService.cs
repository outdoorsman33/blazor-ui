using System.Collections.Concurrent;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Api.Services;

public interface ITournamentControlService
{
    TournamentControlSettings GetOrCreate(Guid eventId, int currentRegistrantCount);

    TournamentControlSettings Update(Guid eventId, int currentRegistrantCount, UpdateTournamentControlSettingsRequest request);

    TournamentControlSettings ReleaseBrackets(Guid eventId, int currentRegistrantCount);

    bool CanRegister(Guid eventId, int currentRegistrantCount, out string reason);

    bool AreBracketsReleased(Guid eventId, DateTime utcNow);

    BracketGenerationMode ResolveGenerationMode(Guid eventId, BracketGenerationMode requestedMode);
}

public sealed class TournamentControlService : ITournamentControlService
{
    private readonly ConcurrentDictionary<Guid, TournamentControlState> _states = new();

    public TournamentControlSettings GetOrCreate(Guid eventId, int currentRegistrantCount)
    {
        var state = _states.GetOrAdd(eventId, static _ => TournamentControlState.Default());
        return state.ToSnapshot(eventId, currentRegistrantCount);
    }

    public TournamentControlSettings Update(Guid eventId, int currentRegistrantCount, UpdateTournamentControlSettingsRequest request)
    {
        if (request.RegistrationCapEnabled && request.RegistrationCap is null or < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(request.RegistrationCap), "Registration cap must be at least 2 when cap is enabled.");
        }

        if (request.MaxOvertimePeriods is < 0 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(request.MaxOvertimePeriods), "Max overtime periods must be between 0 and 8.");
        }

        var state = _states.AddOrUpdate(
            eventId,
            _ => TournamentControlState.FromRequest(request),
            (_, existing) =>
            {
                existing.Apply(request);
                return existing;
            });

        return state.ToSnapshot(eventId, currentRegistrantCount);
    }

    public TournamentControlSettings ReleaseBrackets(Guid eventId, int currentRegistrantCount)
    {
        var state = _states.AddOrUpdate(
            eventId,
            _ =>
            {
                var created = TournamentControlState.Default();
                created.ManuallyReleasedUtc = DateTime.UtcNow;
                return created;
            },
            (_, existing) =>
            {
                existing.ManuallyReleasedUtc = DateTime.UtcNow;
                return existing;
            });

        return state.ToSnapshot(eventId, currentRegistrantCount);
    }

    public bool CanRegister(Guid eventId, int currentRegistrantCount, out string reason)
    {
        var state = _states.GetOrAdd(eventId, static _ => TournamentControlState.Default());
        if (!state.RegistrationCapEnabled)
        {
            reason = string.Empty;
            return true;
        }

        var cap = state.RegistrationCap ?? int.MaxValue;
        if (currentRegistrantCount < cap)
        {
            reason = string.Empty;
            return true;
        }

        reason = $"Registration cap reached ({cap}).";
        return false;
    }

    public bool AreBracketsReleased(Guid eventId, DateTime utcNow)
    {
        var state = _states.GetOrAdd(eventId, static _ => TournamentControlState.Default());
        return state.BracketReleaseMode switch
        {
            BracketReleaseMode.Immediate => true,
            BracketReleaseMode.Scheduled => state.BracketReleaseUtc is not null && state.BracketReleaseUtc <= utcNow,
            BracketReleaseMode.Manual => state.ManuallyReleasedUtc is not null,
            _ => true
        };
    }

    public BracketGenerationMode ResolveGenerationMode(Guid eventId, BracketGenerationMode requestedMode)
    {
        if (requestedMode != BracketGenerationMode.Manual)
        {
            return requestedMode;
        }

        var state = _states.GetOrAdd(eventId, static _ => TournamentControlState.Default());
        return state.BracketCreationMode switch
        {
            BracketCreationMode.Random => BracketGenerationMode.Random,
            BracketCreationMode.Seeded => BracketGenerationMode.Seeded,
            BracketCreationMode.AiSeeded => BracketGenerationMode.Seeded,
            _ => BracketGenerationMode.Manual
        };
    }

    private sealed class TournamentControlState
    {
        public TournamentFormat TournamentFormat { get; set; }
        public BracketReleaseMode BracketReleaseMode { get; set; }
        public DateTime? BracketReleaseUtc { get; set; }
        public BracketCreationMode BracketCreationMode { get; set; }
        public bool RegistrationCapEnabled { get; set; }
        public int? RegistrationCap { get; set; }
        public ScoringPreset ScoringPreset { get; set; }
        public bool StrictScoringEnforcement { get; set; }
        public OvertimeFormat OvertimeFormat { get; set; }
        public int MaxOvertimePeriods { get; set; }
        public bool EndOnFirstOvertimeScore { get; set; }
        public DateTime? ManuallyReleasedUtc { get; set; }

        public static TournamentControlState Default()
        {
            return new TournamentControlState
            {
                TournamentFormat = TournamentFormat.EliminationBracket,
                BracketReleaseMode = BracketReleaseMode.Immediate,
                BracketReleaseUtc = null,
                BracketCreationMode = BracketCreationMode.AiSeeded,
                RegistrationCapEnabled = false,
                RegistrationCap = null,
                ScoringPreset = ScoringPreset.NfhsHighSchool,
                StrictScoringEnforcement = true,
                OvertimeFormat = OvertimeFormat.FolkstyleStandard,
                MaxOvertimePeriods = 3,
                EndOnFirstOvertimeScore = false,
                ManuallyReleasedUtc = DateTime.UtcNow
            };
        }

        public static TournamentControlState FromRequest(UpdateTournamentControlSettingsRequest request)
        {
            return new TournamentControlState
            {
                TournamentFormat = request.TournamentFormat,
                BracketReleaseMode = request.BracketReleaseMode,
                BracketReleaseUtc = request.BracketReleaseUtc,
                BracketCreationMode = request.BracketCreationMode,
                RegistrationCapEnabled = request.RegistrationCapEnabled,
                RegistrationCap = request.RegistrationCapEnabled ? request.RegistrationCap : null,
                ScoringPreset = request.ScoringPreset,
                StrictScoringEnforcement = request.StrictScoringEnforcement,
                OvertimeFormat = request.OvertimeFormat,
                MaxOvertimePeriods = request.MaxOvertimePeriods,
                EndOnFirstOvertimeScore = request.EndOnFirstOvertimeScore,
                ManuallyReleasedUtc = request.BracketReleaseMode == BracketReleaseMode.Immediate ? DateTime.UtcNow : null
            };
        }

        public void Apply(UpdateTournamentControlSettingsRequest request)
        {
            TournamentFormat = request.TournamentFormat;
            BracketReleaseMode = request.BracketReleaseMode;
            BracketReleaseUtc = request.BracketReleaseUtc;
            BracketCreationMode = request.BracketCreationMode;
            RegistrationCapEnabled = request.RegistrationCapEnabled;
            RegistrationCap = request.RegistrationCapEnabled ? request.RegistrationCap : null;
            ScoringPreset = request.ScoringPreset;
            StrictScoringEnforcement = request.StrictScoringEnforcement;
            OvertimeFormat = request.OvertimeFormat;
            MaxOvertimePeriods = request.MaxOvertimePeriods;
            EndOnFirstOvertimeScore = request.EndOnFirstOvertimeScore;

            if (request.BracketReleaseMode == BracketReleaseMode.Immediate)
            {
                ManuallyReleasedUtc = DateTime.UtcNow;
            }

            if (request.BracketReleaseMode == BracketReleaseMode.Scheduled)
            {
                ManuallyReleasedUtc = null;
            }
        }

        public TournamentControlSettings ToSnapshot(Guid eventId, int currentRegistrantCount)
        {
            var cap = RegistrationCapEnabled ? RegistrationCap : null;
            var remaining = cap is null
                ? int.MaxValue
                : Math.Max(0, cap.Value - currentRegistrantCount);

            return new TournamentControlSettings(
                eventId,
                TournamentFormat,
                BracketReleaseMode,
                BracketReleaseUtc,
                BracketCreationMode,
                RegistrationCapEnabled,
                cap,
                currentRegistrantCount,
                remaining,
                ScoringPreset,
                StrictScoringEnforcement,
                OvertimeFormat,
                MaxOvertimePeriods,
                EndOnFirstOvertimeScore);
        }
    }
}
