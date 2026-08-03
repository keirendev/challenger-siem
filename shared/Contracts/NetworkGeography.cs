using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V2;

public sealed record NetworkGeographyResponse
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; init; } = "challenger-siem.network-geography.v2";

    [JsonPropertyName("retained_from_utc")]
    public DateTimeOffset? RetainedFromUtc { get; init; }

    [JsonPropertyName("retained_to_utc")]
    public DateTimeOffset? RetainedToUtc { get; init; }

    [JsonPropertyName("from_utc")]
    public DateTimeOffset? FromUtc { get; init; }

    [JsonPropertyName("to_utc")]
    public DateTimeOffset? ToUtc { get; init; }

    [JsonPropertyName("generated_at_utc")]
    public DateTimeOffset GeneratedAtUtc { get; init; }

    [JsonPropertyName("origin")]
    public NetworkGeographyOrigin? Origin { get; init; }

    [JsonPropertyName("map")]
    public NetworkGeographyMapConfiguration Map { get; init; } = new();

    [JsonPropertyName("summary")]
    public NetworkGeographySummary Summary { get; init; } = new();

    [JsonPropertyName("destinations")]
    public IReadOnlyList<NetworkGeographyDestination> Destinations { get; init; } = Array.Empty<NetworkGeographyDestination>();

    [JsonPropertyName("timeline")]
    public IReadOnlyList<NetworkGeographyTimelineBucket> Timeline { get; init; } = Array.Empty<NetworkGeographyTimelineBucket>();

    [JsonPropertyName("coverage")]
    public NetworkGeographyCoverage Coverage { get; init; } = new();

    [JsonPropertyName("active_filters")]
    public IReadOnlyList<EventSearchFilterSummary> ActiveFilters { get; init; } = Array.Empty<EventSearchFilterSummary>();

    [JsonPropertyName("result_scope")]
    public string ResultScope { get; init; } = string.Empty;

    [JsonPropertyName("limitations")]
    public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record NetworkGeographyOrigin
{
    [JsonPropertyName("label")]
    public string Label { get; init; } = string.Empty;

    [JsonPropertyName("latitude")]
    public double Latitude { get; init; }

    [JsonPropertyName("longitude")]
    public double Longitude { get; init; }
}

public sealed record NetworkGeographyMapConfiguration
{
    [JsonPropertyName("tile_url")]
    public string TileUrl { get; init; } = string.Empty;

    [JsonPropertyName("attribution")]
    public string Attribution { get; init; } = string.Empty;
}

public sealed record NetworkGeographySummary
{
    [JsonPropertyName("matched_lifecycle_events")]
    public long MatchedLifecycleEvents { get; init; }

    [JsonPropertyName("connection_observations")]
    public long ConnectionObservations { get; init; }

    [JsonPropertyName("unique_destinations")]
    public long UniqueDestinations { get; init; }

    [JsonPropertyName("returned_destinations")]
    public int ReturnedDestinations { get; init; }

    [JsonPropertyName("geolocated_destinations")]
    public int GeolocatedDestinations { get; init; }

    [JsonPropertyName("pending_destinations")]
    public int PendingDestinations { get; init; }

    [JsonPropertyName("unmapped_destinations")]
    public int UnmappedDestinations { get; init; }

    [JsonPropertyName("quota_limited_destinations")]
    public int QuotaLimitedDestinations { get; init; }

    [JsonPropertyName("candidate_truncated")]
    public bool CandidateTruncated { get; init; }

    [JsonPropertyName("result_truncated")]
    public bool ResultTruncated { get; init; }
}

public sealed record NetworkGeographyDestination
{
    [JsonPropertyName("destination_ip")]
    public string DestinationIp { get; init; } = string.Empty;

    [JsonPropertyName("connection_observations")]
    public long ConnectionObservations { get; init; }

    [JsonPropertyName("baseline_observations")]
    public long BaselineObservations { get; init; }

    [JsonPropertyName("new_observations")]
    public long NewObservations { get; init; }

    [JsonPropertyName("change_events")]
    public long ChangeEvents { get; init; }

    [JsonPropertyName("disappearance_events")]
    public long DisappearanceEvents { get; init; }

    [JsonPropertyName("lifecycle_events")]
    public long LifecycleEvents { get; init; }

    [JsonPropertyName("first_seen_utc")]
    public DateTimeOffset FirstSeenUtc { get; init; }

    [JsonPropertyName("last_seen_utc")]
    public DateTimeOffset LastSeenUtc { get; init; }

    [JsonPropertyName("protocols")]
    public IReadOnlyList<string> Protocols { get; init; } = Array.Empty<string>();

    [JsonPropertyName("destination_ports")]
    public IReadOnlyList<int> DestinationPorts { get; init; } = Array.Empty<int>();

    [JsonPropertyName("hostnames")]
    public IReadOnlyList<string> Hostnames { get; init; } = Array.Empty<string>();

    [JsonPropertyName("agent_ids")]
    public IReadOnlyList<string> AgentIds { get; init; } = Array.Empty<string>();

    [JsonPropertyName("process_images")]
    public IReadOnlyList<string> ProcessImages { get; init; } = Array.Empty<string>();

    [JsonPropertyName("geolocation_status")]
    public string GeolocationStatus { get; init; } = "pending";

    [JsonPropertyName("latitude")]
    public double? Latitude { get; init; }

    [JsonPropertyName("longitude")]
    public double? Longitude { get; init; }

    [JsonPropertyName("city")]
    public string? City { get; init; }

    [JsonPropertyName("region")]
    public string? Region { get; init; }

    [JsonPropertyName("country")]
    public string? Country { get; init; }

    [JsonPropertyName("country_code")]
    public string? CountryCode { get; init; }

    [JsonPropertyName("continent")]
    public string? Continent { get; init; }

    [JsonPropertyName("asn")]
    public long? Asn { get; init; }

    [JsonPropertyName("organization")]
    public string? Organization { get; init; }

    [JsonPropertyName("isp")]
    public string? Isp { get; init; }

    [JsonPropertyName("geolocation_fetched_at_utc")]
    public DateTimeOffset? GeolocationFetchedAtUtc { get; init; }
}

public sealed record NetworkGeographyTimelineBucket
{
    [JsonPropertyName("start_utc")]
    public DateTimeOffset StartUtc { get; init; }

    [JsonPropertyName("end_utc")]
    public DateTimeOffset EndUtc { get; init; }

    [JsonPropertyName("connection_observations")]
    public long ConnectionObservations { get; init; }

    [JsonPropertyName("lifecycle_events")]
    public long LifecycleEvents { get; init; }
}

public sealed record NetworkGeographyCoverage
{
    [JsonPropertyName("source_id")]
    public string SourceId { get; init; } = LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff;

    [JsonPropertyName("evidence_mode")]
    public string EvidenceMode { get; init; } = "snapshot_diff";

    [JsonPropertyName("source_status_counts")]
    public IReadOnlyDictionary<string, long> SourceStatusCounts { get; init; } = new Dictionary<string, long>(StringComparer.Ordinal);

    [JsonPropertyName("process_attribution_partial")]
    public bool ProcessAttributionPartial { get; init; }
}
