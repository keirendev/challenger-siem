using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Collectors;

public interface IWindowsEventCollector
{
    Task<long?> GetLatestRecordIdAsync(string channel, CancellationToken cancellationToken);

    Task<SourceHealthReport> ProbeChannelAsync(SourceManifestEntry source, CancellationToken cancellationToken);

    Task<IReadOnlyList<CollectedWindowsEvent>> ReadEventsAsync(
        string channel,
        long? afterRecordId,
        int maxEvents,
        CancellationToken cancellationToken);
}
