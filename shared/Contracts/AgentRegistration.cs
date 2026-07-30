using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V2;

public sealed record AgentRegistrationRequest
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    public string Platform { get; init; } = TelemetryPlatforms.Linux;

    [JsonPropertyName("host_id")]
    public string HostId { get; init; } = string.Empty;

    [JsonPropertyName("os_version")]
    public string OsVersion { get; init; } = string.Empty;

    [JsonPropertyName("agent_version")]
    public string AgentVersion { get; init; } = string.Empty;

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }
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
