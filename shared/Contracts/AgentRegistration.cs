using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record AgentRegistrationRequest
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("machine_guid")]
    public string? MachineGuid { get; init; }

    [JsonPropertyName("os_version")]
    public string OsVersion { get; init; } = string.Empty;

    [JsonPropertyName("agent_version")]
    public string AgentVersion { get; init; } = string.Empty;
}

public sealed record AgentRegistrationResponse
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("api_token")]
    public string ApiToken { get; init; } = string.Empty;

    [JsonPropertyName("registered_at")]
    public DateTimeOffset RegisteredAt { get; init; }
}
