namespace Challenger.Siem.Agent.Core.Queue;

public sealed record QueueSourceWorkCounters(
    long EnqueuedEvents,
    long EnqueuedPayloadBytes,
    long AcknowledgedEvents,
    long AcknowledgedPayloadBytes)
{
    public long TotalPayloadBytes => SaturatingAdd(EnqueuedPayloadBytes, AcknowledgedPayloadBytes);

    private static long SaturatingAdd(long left, long right) =>
        left > long.MaxValue - right ? long.MaxValue : left + right;
}

public sealed record QueueWorkSnapshot(
    string GenerationId,
    IReadOnlyDictionary<string, QueueSourceWorkCounters> Sources)
{
    public static QueueWorkSnapshot Empty { get; } = new(
        "unavailable",
        new Dictionary<string, QueueSourceWorkCounters>(StringComparer.Ordinal));
}
