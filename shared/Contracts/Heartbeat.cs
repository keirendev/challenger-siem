using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record HeartbeatRequest
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("agent_version")]
    public string AgentVersion { get; init; } = string.Empty;

    [JsonPropertyName("os")]
    public string Os { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("host_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HostId { get; init; }

    [JsonPropertyName("last_event_time")]
    public DateTimeOffset? LastEventTime { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("queue_depth")]
    public int QueueDepth { get; init; }

    [JsonPropertyName("cpu_percent")]
    public decimal? CpuPercent { get; init; }

    [JsonPropertyName("memory_mb")]
    public int? MemoryMb { get; init; }

    [JsonPropertyName("resource_metrics")]
    public AgentResourceMetrics? ResourceMetrics { get; init; }

    [JsonPropertyName("config_hash")]
    public string? ConfigHash { get; init; }

    [JsonPropertyName("queue_metrics")]
    public QueueSloMetrics? QueueMetrics { get; init; }

    [JsonPropertyName("source_manifest")]
    public IReadOnlyList<SourceManifestEntry> SourceManifest { get; init; } = Array.Empty<SourceManifestEntry>();

    [JsonPropertyName("source_health")]
    public IReadOnlyList<SourceHealthReport> SourceHealth { get; init; } = Array.Empty<SourceHealthReport>();

    [JsonPropertyName("tamper_checks")]
    public TamperCheckSummary? TamperChecks { get; init; }
}
