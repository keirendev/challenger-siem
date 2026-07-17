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

public enum SystemJournalVisibility
{
    Unknown,
    Verified,
    PermissionDenied,
    Unavailable,
    Error
}

public sealed record JournalReadResult(
    JournalReadStatus Status,
    IReadOnlyList<string> Records,
    JournalGapKind GapKind = JournalGapKind.None,
    string? ErrorCode = null,
    SystemJournalVisibility SystemJournalVisibility = SystemJournalVisibility.Unknown);

public interface ILinuxJournalSource
{
    Task<JournalReadResult> ReadAsync(string? afterCursor, int maxRecords, int maxRecordBytes, CancellationToken cancellationToken);
}

public sealed record JournalCheckpointState(
    string? CollectedCursor = null,
    DateTimeOffset? CollectedEventTime = null,
    string? AcknowledgedCursor = null,
    DateTimeOffset? AcknowledgedEventTime = null,
    DateTimeOffset? LastSuccessfulReadAt = null,
    IReadOnlyList<string>? ObservedSourceIds = null,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? ObservedFamilies = null,
    bool ActiveGap = false,
    string GapState = "none",
    long CumulativeGapCount = 0,
    string? ConfiguredScope = null);

public sealed record NormalizedJournalRecord(
    EventEnvelope Envelope,
    string Cursor,
    string BootId,
    long RealtimeMicroseconds,
    bool BinaryOrInvalidText,
    string EventFamily,
    IReadOnlyList<JournalSourceEvidence>? AdditionalEvidence = null);

public sealed record JournalSourceEvidence(string SourceId, string EventFamily);

public sealed record JournalRuntimeSnapshot(
    IReadOnlyList<SourceManifestEntry> Manifest,
    IReadOnlyList<SourceHealthReport> Health,
    bool Throttled,
    string? CollectedCursor,
    string? AcknowledgedCursor);
