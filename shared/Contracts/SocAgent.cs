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

public sealed record SocAgentProviderStatusResponse
{
    [JsonPropertyName("status")]
    public string Status { get; init; } = "local";

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = "Local";

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = "Local soc-agent";

    [JsonPropertyName("model")]
    public string Model { get; init; } = "soc-agent-local-v1";

    [JsonPropertyName("auth_mode")]
    public string AuthMode { get; init; } = "local";

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("requires_connection")]
    public bool RequiresConnection { get; init; }

    [JsonPropertyName("connect_url")]
    public string? ConnectUrl { get; init; }

    [JsonPropertyName("connect_label")]
    public string? ConnectLabel { get; init; }

    [JsonPropertyName("data_may_leave_local_siem")]
    public bool DataMayLeaveLocalSiem { get; init; }

    [JsonPropertyName("checked_at")]
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record SocAgentSessionCreateRequest
{
    [JsonPropertyName("title")]
    public string? Title { get; init; }

    [JsonPropertyName("context_agent_id")]
    public string? ContextAgentId { get; init; }

    [JsonPropertyName("context_event_id")]
    public Guid? ContextEventId { get; init; }
}

public sealed record SocAgentSessionSummary
{
    [JsonPropertyName("session_id")]
    public Guid SessionId { get; init; }

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string Provider { get; init; } = "Local";

    [JsonPropertyName("model")]
    public string Model { get; init; } = "soc-agent-local-v1";

    [JsonPropertyName("status")]
    public string Status { get; init; } = "open";

    [JsonPropertyName("context_agent_id")]
    public string? ContextAgentId { get; init; }

    [JsonPropertyName("context_event_id")]
    public Guid? ContextEventId { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("updated_at")]
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("message_count")]
    public int MessageCount { get; init; }
}

public sealed record SocAgentChatMessageDto
{
    [JsonPropertyName("message_id")]
    public long MessageId { get; init; }

    [JsonPropertyName("session_id")]
    public Guid SessionId { get; init; }

    [JsonPropertyName("role")]
    public string Role { get; init; } = "operator";

    [JsonPropertyName("content")]
    public string Content { get; init; } = string.Empty;

    [JsonPropertyName("provider")]
    public string? Provider { get; init; }

    [JsonPropertyName("model")]
    public string? Model { get; init; }

    [JsonPropertyName("tool_runs")]
    public IReadOnlyList<SocAgentToolRunSummary> ToolRuns { get; init; } = Array.Empty<SocAgentToolRunSummary>();

    [JsonPropertyName("citations")]
    public IReadOnlyList<SocAgentCitation> Citations { get; init; } = Array.Empty<SocAgentCitation>();

    [JsonPropertyName("error_code")]
    public string? ErrorCode { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record SocAgentSessionDetailResponse
{
    [JsonPropertyName("session")]
    public SocAgentSessionSummary Session { get; init; } = new();

    [JsonPropertyName("messages")]
    public IReadOnlyList<SocAgentChatMessageDto> Messages { get; init; } = Array.Empty<SocAgentChatMessageDto>();

    [JsonPropertyName("provider_status")]
    public SocAgentProviderStatusResponse ProviderStatus { get; init; } = new();
}

public sealed record SocAgentChatRequest
{
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("context_agent_id")]
    public string? ContextAgentId { get; init; }

    [JsonPropertyName("context_event_id")]
    public Guid? ContextEventId { get; init; }
}

public sealed record SocAgentChatResponse
{
    [JsonPropertyName("session")]
    public SocAgentSessionSummary Session { get; init; } = new();

    [JsonPropertyName("user_message")]
    public SocAgentChatMessageDto UserMessage { get; init; } = new();

    [JsonPropertyName("assistant_message")]
    public SocAgentChatMessageDto AssistantMessage { get; init; } = new();

    [JsonPropertyName("provider_status")]
    public SocAgentProviderStatusResponse ProviderStatus { get; init; } = new();
}
