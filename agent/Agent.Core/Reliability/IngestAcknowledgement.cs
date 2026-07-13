using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Agent.Core.Reliability;

public static class IngestAcknowledgement
{
    public static long[] AcknowledgedQueueIds(IReadOnlyList<QueuedEvent> batch, IngestBatchResponse response)
    {
        var ids = response.AcceptedEventIds.Concat(response.DuplicateEventIds).ToHashSet();
        if (ids.Count > 0)
        {
            return batch.Where(item => ids.Contains(item.Envelope.EventId)).Select(item => item.QueueId).ToArray();
        }

        return response.Rejected == 0 && response.Accepted + response.Duplicates >= batch.Count
            ? batch.Select(item => item.QueueId).ToArray()
            : Array.Empty<long>();
    }

    public static long[] RejectedQueueIds(IReadOnlyList<QueuedEvent> batch, IngestBatchResponse response)
    {
        var ids = response.RejectedEventIds.ToHashSet();
        return batch.Where(item => ids.Contains(item.Envelope.EventId)).Select(item => item.QueueId).ToArray();
    }
}

public static class RetrySchedule
{
    public static TimeSpan Exponential(int attempts, int maximumSeconds)
    {
        if (attempts <= 0) return TimeSpan.Zero;
        return TimeSpan.FromSeconds(Math.Min(maximumSeconds, Math.Pow(2, Math.Min(attempts, 10))));
    }
}
