using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Journal;

public enum JournalReadStatus
{
    Success,
    Unavailable,
    PermissionDenied,
    InvalidCursor,
    Error
}

public enum JournalGapKind
{
    None,
    Rotation,
    Vacuum,
    InvalidCursor
}

public sealed record JournalReadResult(
    JournalReadStatus Status,
    IReadOnlyList<string> Records,
    JournalGapKind GapKind = JournalGapKind.None,
    string? ErrorCode = null);

public interface ILinuxJournalSource
{
    Task<JournalReadResult> ReadAsync(string? afterCursor, int maxRecords, int maxRecordBytes, CancellationToken cancellationToken);
}

public sealed record JournalCheckpointState(
    string? CollectedCursor = null,
    DateTimeOffset? CollectedEventTime = null,
    string? AcknowledgedCursor = null,
    DateTimeOffset? AcknowledgedEventTime = null);

public sealed record NormalizedJournalRecord(
    EventEnvelope Envelope,
    string Cursor,
    string BootId,
    long RealtimeMicroseconds,
    bool BinaryOrInvalidText,
    string EventFamily);

public sealed record JournalRuntimeSnapshot(
    IReadOnlyList<SourceManifestEntry> Manifest,
    IReadOnlyList<SourceHealthReport> Health,
    bool Throttled,
    string? CollectedCursor,
    string? AcknowledgedCursor);
