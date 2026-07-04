using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Queue;

public interface IEventQueue
{
    Task InitializeAsync(CancellationToken cancellationToken);

    Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken);

    Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken);

    Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken);

    Task<int> CountAsync(CancellationToken cancellationToken);
}
