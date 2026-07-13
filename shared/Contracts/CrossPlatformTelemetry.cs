using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

/// <summary>Stable platform values used by additive v1 cross-platform fields.</summary>
public static class TelemetryPlatforms
{
    public const string Windows = "windows";
    public const string Linux = "linux";
}

/// <summary>Stable source-kind values used by events, manifests, and source health.</summary>
public static class TelemetrySourceKinds
{
    public const string WindowsEventLog = "windows_event_log";
    public const string LinuxJournal = "linux_journal";
    public const string LinuxAudit = "linux_audit";
    public const string InventoryDiff = "inventory_diff";
    public const string AgentHealth = "agent_health";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        WindowsEventLog,
        LinuxJournal,
        LinuxAudit,
        InventoryDiff,
        AgentHealth
    };

    /// <summary>Returns true only for source kinds that are native to Linux.</summary>
    public static bool IsLinuxNative(string? value) => value is LinuxJournal or LinuxAudit;

    /// <summary>Returns true for source kinds that have the same semantics on every supported platform.</summary>
    public static bool IsPlatformNeutral(string? value) => value is InventoryDiff or AgentHealth;

    /// <summary>Returns true for additive source kinds that use platform-neutral identity and checkpoints.</summary>
    public static bool UsesPortableIdentity(string? value) => IsLinuxNative(value) || IsPlatformNeutral(value);

    /// <summary>Checks the explicit platform/source-kind compatibility matrix.</summary>
    public static bool IsValidForPlatform(string? sourceKind, string? platform) => sourceKind switch
    {
        WindowsEventLog => platform == TelemetryPlatforms.Windows,
        LinuxJournal or LinuxAudit => platform == TelemetryPlatforms.Linux,
        InventoryDiff or AgentHealth => platform is TelemetryPlatforms.Windows or TelemetryPlatforms.Linux,
        _ => false
    };
}

public static class SourceApplicabilityStatuses
{
    public const string Applicable = "applicable";
    public const string NotApplicable = "not_applicable";
    public const string Unknown = "unknown";
}

public static class SourceCheckpointKinds
{
    public const string Cursor = "cursor";
    public const string Sequence = "sequence";
    public const string CursorAndSequence = "cursor_and_sequence";
}

public static class DeduplicationAlgorithms
{
    public const string Sha256Uuid = "sha256_uuid";
}

public static class DeduplicationInputs
{
    public const string AgentId = "agent_id";
    public const string SourceId = "source_id";
    public const string CheckpointCursor = "checkpoint.cursor";
    public const string CheckpointSequence = "checkpoint.sequence";
    public const string EventCode = "event_code";
    public const string EventTime = "event_time";
    public const string RawSha256 = "raw_sha256";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        AgentId,
        SourceId,
        CheckpointCursor,
        CheckpointSequence,
        EventCode,
        EventTime,
        RawSha256
    };
}

/// <summary>A source-local position attached to an event or source acknowledgement.</summary>
public sealed record SourceCheckpoint
{
    [JsonPropertyName("cursor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Cursor { get; init; }

    [JsonPropertyName("sequence")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Sequence { get; init; }

    [JsonPropertyName("event_time")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? EventTime { get; init; }

    [JsonPropertyName("recorded_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? RecordedAt { get; init; }
}

/// <summary>Declares exactly which envelope values produced the deterministic event_id.</summary>
public sealed record EventDeduplicationMetadata
{
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; init; } = DeduplicationAlgorithms.Sha256Uuid;

    [JsonPropertyName("inputs")]
    public IReadOnlyList<string> Inputs { get; init; } = Array.Empty<string>();

    [JsonPropertyName("raw_sha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RawSha256 { get; init; }
}

/// <summary>Explicit disclosure of redaction/truncation applied before enqueueing.</summary>
public sealed record DataHandlingMetadata
{
    [JsonPropertyName("raw_size_bytes")]
    public int RawSizeBytes { get; init; }

    [JsonPropertyName("redaction_applied")]
    public bool RedactionApplied { get; init; }

    [JsonPropertyName("redacted_fields")]
    public IReadOnlyList<string> RedactedFields { get; init; } = Array.Empty<string>();

    [JsonPropertyName("truncation_applied")]
    public bool TruncationApplied { get; init; }

    [JsonPropertyName("truncated_fields")]
    public IReadOnlyList<string> TruncatedFields { get; init; } = Array.Empty<string>();

    [JsonPropertyName("original_size_bytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? OriginalSizeBytes { get; init; }
}

public sealed record ProcessTelemetryConcept
{
    [JsonPropertyName("pid")]
    public string? Pid { get; init; }

    [JsonPropertyName("parent_pid")]
    public string? ParentPid { get; init; }

    [JsonPropertyName("executable")]
    public string? Executable { get; init; }

    [JsonPropertyName("command_line")]
    public string? CommandLine { get; init; }
}

public sealed record UserTelemetryConcept
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("id")]
    public string? Id { get; init; }

    [JsonPropertyName("realm")]
    public string? Realm { get; init; }
}

public sealed record NetworkTelemetryConcept
{
    [JsonPropertyName("source_ip")]
    public string? SourceIp { get; init; }

    [JsonPropertyName("source_port")]
    public int? SourcePort { get; init; }

    [JsonPropertyName("destination_ip")]
    public string? DestinationIp { get; init; }

    [JsonPropertyName("destination_port")]
    public int? DestinationPort { get; init; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; init; }
}

public sealed record FileTelemetryConcept
{
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    [JsonPropertyName("operation")]
    public string? Operation { get; init; }

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; init; }
}

/// <summary>Canonical deterministic identity operations for additive portable-source v1 events.</summary>
public static class DeterministicEventIdentity
{
    private const char InputSeparator = '\u001f';
    private const string UtcTimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    /// <summary>
    /// Computes the declared sha256_uuid event identity from the event's ordered input paths.
    /// The raw_sha256 input is always derived from <see cref="EventEnvelope.Raw"/>, never trusted
    /// from the accompanying metadata.
    /// </summary>
    public static Guid ComputeSha256Uuid(EventEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var deduplication = envelope.Deduplication
            ?? throw new ArgumentException("Deduplication metadata is required.", nameof(envelope));
        if (!string.Equals(deduplication.Algorithm, DeduplicationAlgorithms.Sha256Uuid, StringComparison.Ordinal))
        {
            throw new ArgumentException("The deduplication algorithm is not sha256_uuid.", nameof(envelope));
        }

        var values = deduplication.Inputs.Select(input => ResolveInput(envelope, input));
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(InputSeparator, values)));
        digest[6] = (byte)((digest[6] & 0x0f) | 0x50);
        digest[8] = (byte)((digest[8] & 0x3f) | 0x80);
        return new Guid(digest.AsSpan(0, 16), bigEndian: true);
    }

    /// <summary>Computes lowercase SHA-256 over the compact UTF-8 JSON serialization of raw.</summary>
    public static string ComputeRawSha256(JsonElement raw) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(raw))).ToLowerInvariant();

    private static string ResolveInput(EventEnvelope envelope, string input) => input switch
    {
        DeduplicationInputs.AgentId when !string.IsNullOrWhiteSpace(envelope.AgentId) => envelope.AgentId,
        DeduplicationInputs.SourceId when !string.IsNullOrWhiteSpace(envelope.SourceId) => envelope.SourceId,
        DeduplicationInputs.CheckpointCursor when !string.IsNullOrEmpty(envelope.Checkpoint?.Cursor) => envelope.Checkpoint.Cursor,
        DeduplicationInputs.CheckpointSequence when envelope.Checkpoint?.Sequence is long sequence => sequence.ToString(CultureInfo.InvariantCulture),
        DeduplicationInputs.EventCode when !string.IsNullOrWhiteSpace(envelope.EventCode) => envelope.EventCode,
        DeduplicationInputs.EventTime when envelope.EventTime != default => envelope.EventTime.UtcDateTime.ToString(UtcTimestampFormat, CultureInfo.InvariantCulture),
        DeduplicationInputs.RawSha256 when envelope.Raw.ValueKind == JsonValueKind.Object => ComputeRawSha256(envelope.Raw),
        _ => throw new ArgumentException($"Deduplication input '{input}' cannot be resolved from the event.", nameof(envelope))
    };
}

public static class ContractLimits
{
    public const int RawPayloadMaxUtf8Bytes = 65_536;
    public const int MaxSourceEntries = 100;
    public const int MaxMetadataEntries = 64;
    public const int MaxMetadataListItems = 32;
}
