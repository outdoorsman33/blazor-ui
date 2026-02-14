using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Application.Services;

public interface IBracketService
{
    Task<BracketGenerationResult> GenerateAsync(BracketGenerationInput input, CancellationToken cancellationToken = default);
}

public interface IRankingService
{
    Task ApplyMatchResultAsync(
        Match match,
        Guid winnerAthleteId,
        int pointsForWinner,
        int pointsForLoser,
        CancellationToken cancellationToken = default);
}

public interface INotificationDispatcher
{
    Task DispatchAsync(NotificationDispatchRequest request, CancellationToken cancellationToken = default);
}

public interface IOutboundNotificationSender
{
    Task SendAsync(NotificationChannel channel, string destination, string body, CancellationToken cancellationToken = default);
}

public interface IPaymentGateway
{
    Task<PaymentIntentResult> CreatePaymentIntentAsync(
        EventRegistration registration,
        TournamentEvent tournamentEvent,
        CancellationToken cancellationToken = default);
}

public interface IPaymentWebhookReconciliationService
{
    Task<PaymentWebhookEnqueueResult> EnqueueAsync(PaymentWebhookIngress ingress, CancellationToken cancellationToken = default);

    Task<int> ProcessPendingAsync(int maxBatchSize, CancellationToken cancellationToken = default);
}