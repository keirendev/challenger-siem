using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V2;

public sealed record NetworkActivityResponse
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; init; } = "challenger-siem.network-activity.v2";

    [JsonPropertyName("generated_at_utc")]
    public DateTimeOffset GeneratedAtUtc { get; init; }

    [JsonPropertyName("activities")]
    public IReadOnlyList<NetworkActivityRecord> Activities { get; init; } = Array.Empty<NetworkActivityRecord>();

    [JsonPropertyName("page")]
    public EventSearchPageInfo Page { get; init; } = new();

    [JsonPropertyName("active_filters")]
    public IReadOnlyList<EventSearchFilterSummary> ActiveFilters { get; init; } = Array.Empty<EventSearchFilterSummary>();

    [JsonPropertyName("result_scope")]
    public string ResultScope { get; init; } = "retained_network_activity";

    [JsonPropertyName("geolocation_mode")]
    public string GeolocationMode { get; init; } = "cache_only";

    [JsonPropertyName("limitations")]
    public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record NetworkActivityRecord
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("event_id")]
    public Guid EventId { get; init; }

    [JsonPropertyName("event_citation")]
    public string EventCitation { get; init; } = string.Empty;

    [JsonPropertyName("event_time_utc")]
    public DateTimeOffset EventTimeUtc { get; init; }

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("source_id")]
    public string SourceId { get; init; } = string.Empty;

    [JsonPropertyName("event_code")]
    public string? EventCode { get; init; }

    [JsonPropertyName("evidence_mode")]
    public string EvidenceMode { get; init; } = "unknown";

    [JsonPropertyName("direction")]
    public string Direction { get; init; } = "unknown";

    [JsonPropertyName("local_ip")]
    public string? LocalIp { get; init; }

    [JsonPropertyName("local_port")]
    public int? LocalPort { get; init; }

    [JsonPropertyName("remote_ip")]
    public string? RemoteIp { get; init; }

    [JsonPropertyName("remote_port")]
    public int? RemotePort { get; init; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; init; }

    [JsonPropertyName("process_id")]
    public int? ProcessId { get; init; }

    [JsonPropertyName("process_instance_id")]
    public string? ProcessInstanceId { get; init; }

    [JsonPropertyName("process_image")]
    public string? ProcessImage { get; init; }

    [JsonPropertyName("process_command_line")]
    public string? ProcessCommandLine { get; init; }

    [JsonPropertyName("user_id")]
    public string? UserId { get; init; }

    [JsonPropertyName("attribution_confidence")]
    public string AttributionConfidence { get; init; } = "unattributed";

    [JsonPropertyName("attribution_source")]
    public string AttributionSource { get; init; } = "unavailable";

    [JsonPropertyName("attribution_limitations")]
    public IReadOnlyList<string> AttributionLimitations { get; init; } = Array.Empty<string>();

    [JsonPropertyName("process_identity_status")]
    public string ProcessIdentityStatus { get; init; } = "unknown";

    [JsonPropertyName("process_image_observation_source")]
    public string ProcessImageObservationSource { get; init; } = "unavailable";

    [JsonPropertyName("process_command_line_observation_source")]
    public string ProcessCommandLineObservationSource { get; init; } = "unavailable";

    [JsonPropertyName("process_observed_at_utc")]
    public DateTimeOffset? ProcessObservedAtUtc { get; init; }

    [JsonPropertyName("exact_execution_evidence")]
    public bool ExactExecutionEvidence { get; init; }

    [JsonPropertyName("first_seen_utc")]
    public DateTimeOffset? FirstSeenUtc { get; init; }

    [JsonPropertyName("last_seen_utc")]
    public DateTimeOffset? LastSeenUtc { get; init; }

    [JsonPropertyName("packet_count_delta")]
    public long? PacketCountDelta { get; init; }

    [JsonPropertyName("byte_count_delta")]
    public long? ByteCountDelta { get; init; }

    [JsonPropertyName("tcp_flags")]
    public IReadOnlyList<string> TcpFlags { get; init; } = Array.Empty<string>();

    [JsonPropertyName("geolocation_status")]
    public string GeolocationStatus { get; init; } = "pending";

    [JsonPropertyName("country")]
    public string? Country { get; init; }

    [JsonPropertyName("country_code")]
    public string? CountryCode { get; init; }

    [JsonPropertyName("city")]
    public string? City { get; init; }

    [JsonPropertyName("region")]
    public string? Region { get; init; }

    [JsonPropertyName("continent")]
    public string? Continent { get; init; }

    [JsonPropertyName("asn")]
    public long? Asn { get; init; }

    [JsonPropertyName("organization")]
    public string? Organization { get; init; }

    [JsonPropertyName("geolocation_fetched_at_utc")]
    public DateTimeOffset? GeolocationFetchedAtUtc { get; init; }
}
