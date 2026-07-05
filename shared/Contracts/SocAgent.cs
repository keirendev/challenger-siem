using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record SocAgentAskRequest
{
    [JsonPropertyName("question")]
    public string Question { get; init; } = string.Empty;

    [JsonPropertyName("context_agent_id")]
    public string? ContextAgentId { get; init; }

    [JsonPropertyName("context_event_id")]
    public Guid? ContextEventId { get; init; }
}

public sealed record SocAgentAskResponse
{
    [JsonPropertyName("answer")]
    public string Answer { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = "local";

    [JsonPropertyName("model")]
    public string Model { get; init; } = "soc-agent-local";

    [JsonPropertyName("tool_runs")]
    public IReadOnlyList<SocAgentToolRunSummary> ToolRuns { get; init; } = Array.Empty<SocAgentToolRunSummary>();

    [JsonPropertyName("citations")]
    public IReadOnlyList<SocAgentCitation> Citations { get; init; } = Array.Empty<SocAgentCitation>();

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record SocAgentToolRunSummary
{
    [JsonPropertyName("tool_name")]
    public string ToolName { get; init; } = string.Empty;

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;

    [JsonPropertyName("row_count")]
    public int RowCount { get; init; }
}

public sealed record SocAgentCitation
{
    [JsonPropertyName("label")]
    public string Label { get; init; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonPropertyName("url")]
    public string Url { get; init; } = string.Empty;
}
