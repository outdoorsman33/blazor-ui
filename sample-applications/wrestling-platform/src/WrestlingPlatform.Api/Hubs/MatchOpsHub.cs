using Microsoft.AspNetCore.SignalR;

namespace WrestlingPlatform.Api.Hubs;

public static class MatchOpsHubGroups
{
    public static string ForMatch(Guid matchId) => $"match:{matchId:N}";

    public static string ForEvent(Guid eventId) => $"event:{eventId:N}";
}

public sealed class MatchOpsHub : Hub
{
    public Task JoinMatch(Guid matchId)
    {
        return Groups.AddToGroupAsync(Context.ConnectionId, MatchOpsHubGroups.ForMatch(matchId));
    }

    public Task LeaveMatch(Guid matchId)
    {
        return Groups.RemoveFromGroupAsync(Context.ConnectionId, MatchOpsHubGroups.ForMatch(matchId));
    }

    public Task JoinEvent(Guid eventId)
    {
        return Groups.AddToGroupAsync(Context.ConnectionId, MatchOpsHubGroups.ForEvent(eventId));
    }

    public Task LeaveEvent(Guid eventId)
    {
        return Groups.RemoveFromGroupAsync(Context.ConnectionId, MatchOpsHubGroups.ForEvent(eventId));
    }
}

