using Microsoft.EntityFrameworkCore;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Infrastructure.Services;

public sealed class NotificationDispatcher(
    WrestlingPlatformDbContext dbContext,
    IOutboundNotificationSender outboundNotificationSender) : INotificationDispatcher
{
    public async Task DispatchAsync(NotificationDispatchRequest request, CancellationToken cancellationToken = default)
    {
        var subscriptions = await dbContext.NotificationSubscriptions
            .Where(x => x.EventType == request.EventType)
            .Where(x => x.TournamentEventId == null || x.TournamentEventId == request.TournamentEventId)
            .Where(x => x.AthleteProfileId == null || x.AthleteProfileId == request.AthleteProfileId)
            .ToListAsync(cancellationToken);

        foreach (var subscription in subscriptions)
        {
            var message = new NotificationMessage
            {
                NotificationSubscriptionId = subscription.Id,
                TournamentEventId = request.TournamentEventId,
                MatchId = request.MatchId,
                EventType = request.EventType,
                Channel = subscription.Channel,
                Destination = subscription.Destination,
                Body = request.Body
            };

            dbContext.NotificationMessages.Add(message);

            try
            {
                await outboundNotificationSender.SendAsync(subscription.Channel, subscription.Destination, request.Body, cancellationToken);
                message.SentUtc = DateTime.UtcNow;
            }
            catch
            {
                message.SentUtc = null;
            }
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
