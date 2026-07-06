using System.Text.Json;
using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public static class EventSources
{
    public const string WindowsEventLog = "windows_event_log";
}

public sealed record EventEnvelope
{
    [JsonPropertyName("event_id")]
    public Guid EventId { get; init; }

    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("source")]
    public string Source { get; init; } = EventSources.WindowsEventLog;

    [JsonPropertyName("channel")]
    public string Channel { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = string.Empty;

    [JsonPropertyName("windows_event_id")]
    public int WindowsEventId { get; init; }

    [JsonPropertyName("record_id")]
    public long RecordId { get; init; }

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
}
