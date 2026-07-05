using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record PlatformCapability
{
    [JsonPropertyName("capability_id")]
    public string CapabilityId { get; init; } = string.Empty;

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = "foundation_ready";

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;

    [JsonPropertyName("documentation_url")]
    public string DocumentationUrl { get; init; } = string.Empty;

    [JsonPropertyName("controls")]
    public IReadOnlyList<string> Controls { get; init; } = Array.Empty<string>();
}

public sealed record PlatformCapabilitiesResponse
{
    [JsonPropertyName("capabilities")]
    public IReadOnlyList<PlatformCapability> Capabilities { get; init; } = Array.Empty<PlatformCapability>();
}
