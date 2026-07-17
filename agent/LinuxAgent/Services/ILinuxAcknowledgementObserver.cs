using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Services;

public interface ILinuxAcknowledgementObserver
{
    bool HandlesSource(string? sourceId);

    Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken);

    Task RecordRejectedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken) => Task.CompletedTask;

    void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events);
}
