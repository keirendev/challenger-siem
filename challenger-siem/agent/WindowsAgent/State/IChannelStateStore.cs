namespace Challenger.Siem.WindowsAgent.State;

public interface IChannelStateStore
{
    Task<IReadOnlyDictionary<string, long>> LoadAsync(CancellationToken cancellationToken);

    Task<long?> GetLastRecordIdAsync(string channel, CancellationToken cancellationToken);

    Task SetLastRecordIdAsync(string channel, long recordId, CancellationToken cancellationToken);
}
