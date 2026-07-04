using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record EventSearchResponse
{
    [JsonPropertyName("events")]
    public IReadOnlyList<EventEnvelope> Events { get; init; } = Array.Empty<EventEnvelope>();
}
