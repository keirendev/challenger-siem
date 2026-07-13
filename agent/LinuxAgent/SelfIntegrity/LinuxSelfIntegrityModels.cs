using System.Text.Json.Serialization;

namespace Challenger.Siem.LinuxAgent.SelfIntegrity;

public static class LinuxSelfIntegrityStates
{
    public const string Added = "added";
    public const string Changed = "changed";
    public const string Deleted = "deleted";
    public const string Unreadable = "unreadable";
    public const string Gap = "gap";
    public const string Drop = "drop";
    public const string Sample = "sample";
    public const string Unchanged = "unchanged";
}

public enum SelfIntegrityEntryKind { HashedFile, MetadataFile, Directory }

public sealed record SelfIntegrityAllowlistEntry(
    string PathId,
    string AbsolutePath,
    SelfIntegrityEntryKind Kind,
    int MaxBytes,
    string Privacy,
    bool SecretBearing)
{
    public bool HashContent => Kind == SelfIntegrityEntryKind.HashedFile;
}

public sealed record SelfIntegrityObservation(
    SelfIntegrityAllowlistEntry Entry,
    string State,
    string ErrorCode,
    string PathType,
    uint? OwnerId,
    uint? GroupId,
    UnixFileMode? Mode,
    long? SizeBytes,
    DateTimeOffset? MtimeUtc,
    string? Sha256)
{
    public string Signature => string.Join('|',
        State,
        ErrorCode,
        PathType,
        OwnerId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
        GroupId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
        Mode.HasValue ? Convert.ToString((int)Mode.Value, 8) : "",
        SizeBytes?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
        MtimeUtc?.UtcDateTime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
        Sha256 ?? "");
}

public sealed record LinuxSelfIntegrityState
{
    [JsonPropertyName("next_sequence")] public long NextSequence { get; init; } = 1;
    [JsonPropertyName("collected_sequence")] public long? CollectedSequence { get; init; }
    [JsonPropertyName("acknowledged_sequence")] public long? AcknowledgedSequence { get; init; }
    [JsonPropertyName("collected_at")] public DateTimeOffset? CollectedAt { get; init; }
    [JsonPropertyName("acknowledged_at")] public DateTimeOffset? AcknowledgedAt { get; init; }
    [JsonPropertyName("last_successful_scan_at")] public DateTimeOffset? LastSuccessfulScanAt { get; init; }
    [JsonPropertyName("signatures")] public IReadOnlyDictionary<string, string> Signatures { get; init; } = new Dictionary<string, string>(StringComparer.Ordinal);
}

public sealed record SelfIntegrityCollectedEvent(Challenger.Siem.Contracts.V1.EventEnvelope Envelope, long Sequence, string State);

public sealed record SelfIntegrityCollectionResult(
    IReadOnlyList<SelfIntegrityCollectedEvent> Events,
    IReadOnlyDictionary<string, string> NewSignatures,
    long NextSequence,
    bool CompletedScan,
    string HealthStatus,
    string ErrorCode,
    long GapCount,
    long DroppedCount,
    long SampledCount);

public sealed record SelfIntegrityPlanEntry(
    string PathId,
    string Path,
    string Handling,
    string State,
    string Reason,
    int MaxBytes,
    string Privacy);

public sealed record SelfIntegrityPlan(
    string PlanHash,
    string Platform,
    string FilesystemSupport,
    string RequiredPrivileges,
    string PrivacyImpact,
    string EstimatedOverhead,
    string SequencingAndLoss,
    string Rollback,
    IReadOnlyList<SelfIntegrityPlanEntry> Entries);
