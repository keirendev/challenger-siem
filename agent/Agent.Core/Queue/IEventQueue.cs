using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Agent.Core.Queue;

public interface IEventQueue
{
    Task InitializeAsync(CancellationToken cancellationToken);

    Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken);

    Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken);

    Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken);

    Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken);

    Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken);

    Task<int> CountAsync(CancellationToken cancellationToken);

    Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken);
}
