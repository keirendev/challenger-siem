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

    [JsonPropertyName("last_event_time")]
    public DateTimeOffset? LastEventTime { get; init; }

    [JsonPropertyName("queue_depth")]
    public int QueueDepth { get; init; }

    [JsonPropertyName("cpu_percent")]
    public decimal? CpuPercent { get; init; }

    [JsonPropertyName("memory_mb")]
    public int? MemoryMb { get; init; }
}
