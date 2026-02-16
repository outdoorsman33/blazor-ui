using System.Collections.Concurrent;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public interface IEventOpsChecklistService
{
    EventOpsChecklistState GetOrCreate(Guid eventId);

    EventOpsChecklistState Update(Guid eventId, UpdateEventOpsChecklistRequest request);

    EventOpsChecklistState MarkBracketsGenerated(Guid eventId);

    bool CanGenerateBrackets(Guid eventId, out string reason);
}

public sealed class EventOpsChecklistService : IEventOpsChecklistService
{
    private readonly ConcurrentDictionary<Guid, EventOpsChecklistState> _stateByEvent = new();

    public EventOpsChecklistState GetOrCreate(Guid eventId)
    {
        return _stateByEvent.GetOrAdd(eventId, BuildDefault);
    }

    public EventOpsChecklistState Update(Guid eventId, UpdateEventOpsChecklistRequest request)
    {
        return _stateByEvent.AddOrUpdate(
            eventId,
            id => ApplyUpdates(BuildDefault(id), request),
            (_, existing) => ApplyUpdates(existing, request));
    }

    public EventOpsChecklistState MarkBracketsGenerated(Guid eventId)
    {
        return _stateByEvent.AddOrUpdate(
            eventId,
            id => BuildDefault(id) with
            {
                BracketsGeneratedAfterScratchFreeze = true,
                UpdatedUtc = DateTime.UtcNow
            },
            (_, existing) => existing with
            {
                BracketsGeneratedAfterScratchFreeze = true,
                UpdatedUtc = DateTime.UtcNow
            });
    }

    public bool CanGenerateBrackets(Guid eventId, out string reason)
    {
        var state = GetOrCreate(eventId);
        if (!state.RequireScratchFreezeForBracketGeneration)
        {
            reason = string.Empty;
            return true;
        }

        if (!state.ScratchListFrozen)
        {
            reason = "Bracket generation blocked: scratch list must be frozen before brackets are generated.";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    private static EventOpsChecklistState BuildDefault(Guid eventId)
    {
        return new EventOpsChecklistState(
            eventId,
            DivisionsLocked: false,
            FormatAndRulesLocked: false,
            RegistrationDeadlineSet: false,
            RegistrationDeadlineUtc: null,
            SeedingStrategy: EventOpsSeedingStrategy.RankingsSeeded,
            ContingencyPrintReady: false,
            WeighInsCompleted: false,
            ScratchListFrozen: false,
            BracketsGeneratedAfterScratchFreeze: false,
            HeadTableReady: false,
            MatTablesReady: false,
            QrPostedForLiveResults: false,
            FinalResultsLocked: false,
            PlacingsExported: false,
            TeamPointsExported: false,
            AwardSheetsPrinted: false,
            FinalBracketsPublished: false,
            RequireScratchFreezeForBracketGeneration: true,
            UpdatedUtc: DateTime.UtcNow,
            Notes: "Initialize checklist before event day.");
    }

    private static EventOpsChecklistState ApplyUpdates(EventOpsChecklistState existing, UpdateEventOpsChecklistRequest request)
    {
        return existing with
        {
            DivisionsLocked = request.DivisionsLocked ?? existing.DivisionsLocked,
            FormatAndRulesLocked = request.FormatAndRulesLocked ?? existing.FormatAndRulesLocked,
            RegistrationDeadlineSet = request.RegistrationDeadlineSet ?? existing.RegistrationDeadlineSet,
            RegistrationDeadlineUtc = request.RegistrationDeadlineUtc ?? existing.RegistrationDeadlineUtc,
            SeedingStrategy = request.SeedingStrategy ?? existing.SeedingStrategy,
            ContingencyPrintReady = request.ContingencyPrintReady ?? existing.ContingencyPrintReady,
            WeighInsCompleted = request.WeighInsCompleted ?? existing.WeighInsCompleted,
            ScratchListFrozen = request.ScratchListFrozen ?? existing.ScratchListFrozen,
            HeadTableReady = request.HeadTableReady ?? existing.HeadTableReady,
            MatTablesReady = request.MatTablesReady ?? existing.MatTablesReady,
            QrPostedForLiveResults = request.QrPostedForLiveResults ?? existing.QrPostedForLiveResults,
            FinalResultsLocked = request.FinalResultsLocked ?? existing.FinalResultsLocked,
            PlacingsExported = request.PlacingsExported ?? existing.PlacingsExported,
            TeamPointsExported = request.TeamPointsExported ?? existing.TeamPointsExported,
            AwardSheetsPrinted = request.AwardSheetsPrinted ?? existing.AwardSheetsPrinted,
            FinalBracketsPublished = request.FinalBracketsPublished ?? existing.FinalBracketsPublished,
            RequireScratchFreezeForBracketGeneration = request.RequireScratchFreezeForBracketGeneration ?? existing.RequireScratchFreezeForBracketGeneration,
            Notes = string.IsNullOrWhiteSpace(request.Notes) ? existing.Notes : request.Notes.Trim(),
            UpdatedUtc = DateTime.UtcNow
        };
    }
}
