using Challenger.Siem.Contracts.V2;

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
    IReadOnlyList<JournalInputRecord> Records,
    JournalGapKind GapKind = JournalGapKind.None,
    string? ErrorCode = null,
    SystemJournalVisibility SystemJournalVisibility = SystemJournalVisibility.Unknown)
{
    public JournalReadResult(
        JournalReadStatus Status,
        IReadOnlyList<string> Records,
        JournalGapKind GapKind = JournalGapKind.None,
        string? ErrorCode = null,
        SystemJournalVisibility SystemJournalVisibility = SystemJournalVisibility.Unknown)
        : this(
            Status,
            Records.Select(JournalInputRecord.FromRaw).ToArray(),
            GapKind,
            ErrorCode,
            SystemJournalVisibility)
    {
    }
}

public sealed record JournalInputRecord(
    string? RawJson = null,
    OversizedJournalRecord? Oversized = null,
    long? UnrecoverableOversizedBytes = null)
{
    public static JournalInputRecord FromRaw(string rawJson) => new(RawJson: rawJson);
    public static JournalInputRecord OmitOversized(OversizedJournalRecord oversized) => new(Oversized: oversized);
    public static JournalInputRecord UnrecoverableOversized(long recordBytes) =>
        new(UnrecoverableOversizedBytes: Math.Max(0, recordBytes));
}

public sealed record OversizedJournalRecord(
    string Cursor,
    string BootId,
    long RealtimeMicroseconds,
    DateTimeOffset EventTime,
    long RecordBytes)
{
    public bool HasValidIdentity() =>
        !string.IsNullOrWhiteSpace(Cursor)
        && Cursor.Length <= 1024
        && !string.IsNullOrWhiteSpace(BootId)
        && BootId.Length <= 128
        && RecordBytes > 0
        && TryEventTime(RealtimeMicroseconds, out var eventTime)
        && eventTime == EventTime;

    public static bool TryCreate(
        string? cursor,
        string? bootId,
        long realtimeMicroseconds,
        long recordBytes,
        out OversizedJournalRecord? record)
    {
        record = null;
        if (string.IsNullOrWhiteSpace(cursor)
            || cursor.Length > 1024
            || string.IsNullOrWhiteSpace(bootId)
            || bootId.Length > 128
            || recordBytes <= 0
            || !TryEventTime(realtimeMicroseconds, out var eventTime))
        {
            return false;
        }

        record = new(cursor, bootId, realtimeMicroseconds, eventTime, recordBytes);
        return true;
    }

    private static bool TryEventTime(long realtimeMicroseconds, out DateTimeOffset eventTime)
    {
        try
        {
            eventTime = DateTimeOffset.UnixEpoch.AddTicks(checked(realtimeMicroseconds * 10));
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            eventTime = default;
            return false;
        }
        catch (OverflowException)
        {
            eventTime = default;
            return false;
        }
    }
}

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
    string? ConfiguredScope = null,
    long OversizedRecordCount = 0,
    long OversizedRecordBytes = 0,
    OversizedJournalRecord? LastOversizedRecord = null);

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
