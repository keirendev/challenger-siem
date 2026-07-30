using System.Text.Json;
using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V2;

/// <summary>Linux and platform-neutral source kinds accepted by the v2 backend.</summary>
public static class EventSources
{
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
    public string Source { get; init; } = EventSources.LinuxJournal;

    [JsonPropertyName("source_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceId { get; init; }

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
