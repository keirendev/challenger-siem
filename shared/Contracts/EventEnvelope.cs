using System.Text.Json;
using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

/// <summary>
/// Backward-compatible event source constants. WindowsEventLog retains its original v1 value;
/// additive values identify Linux-native or platform-neutral source kinds for new clients.
/// </summary>
public static class EventSources
{
    public const string WindowsEventLog = TelemetrySourceKinds.WindowsEventLog;
    public const string LinuxJournal = TelemetrySourceKinds.LinuxJournal;
    public const string LinuxAudit = TelemetrySourceKinds.LinuxAudit;
    public const string InventoryDiff = TelemetrySourceKinds.InventoryDiff;
    public const string AgentHealth = TelemetrySourceKinds.AgentHealth;
}

public sealed record EventEnvelope
{
    [JsonPropertyName("event_id")]
    public Guid EventId { get; init; }

    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("source")]
    public string Source { get; init; } = EventSources.WindowsEventLog;

    [JsonPropertyName("source_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceId { get; init; }

    [JsonPropertyName("channel")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Channel { get; init; }

    [JsonPropertyName("provider")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Provider { get; init; }

    [JsonPropertyName("windows_event_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? WindowsEventId { get; init; }

    [JsonPropertyName("record_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? RecordId { get; init; }

    [JsonPropertyName("event_code")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EventCode { get; init; }

    [JsonPropertyName("facility")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Facility { get; init; }

    [JsonPropertyName("unit")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Unit { get; init; }

    [JsonPropertyName("checkpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SourceCheckpoint? Checkpoint { get; init; }

    [JsonPropertyName("deduplication")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public EventDeduplicationMetadata? Deduplication { get; init; }

    [JsonPropertyName("event_time")]
    public DateTimeOffset EventTime { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("ingest_time")]
    public DateTimeOffset? IngestTime { get; init; }

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "information";

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("normalized")]
    public NormalizedEventFields? Normalized { get; init; }

    [JsonPropertyName("raw")]
    public JsonElement Raw { get; init; }

    [JsonPropertyName("data_handling")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DataHandlingMetadata? DataHandling { get; init; }
}
