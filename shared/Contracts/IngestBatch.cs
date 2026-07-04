using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public sealed record IngestBatchRequest
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("batch_id")]
    public Guid BatchId { get; init; }

    [JsonPropertyName("sent_at")]
    public DateTimeOffset SentAt { get; init; }

    [JsonPropertyName("events")]
    public IReadOnlyList<EventEnvelope> Events { get; init; } = Array.Empty<EventEnvelope>();
}

public sealed record IngestBatchResponse
{
    [JsonPropertyName("batch_id")]
    public Guid BatchId { get; init; }

    [JsonPropertyName("accepted")]
    public int Accepted { get; init; }

    [JsonPropertyName("rejected")]
    public int Rejected { get; init; }

    [JsonPropertyName("duplicates")]
    public int Duplicates { get; init; }

    [JsonPropertyName("accepted_event_ids")]
    public IReadOnlyList<Guid> AcceptedEventIds { get; init; } = Array.Empty<Guid>();

    [JsonPropertyName("duplicate_event_ids")]
    public IReadOnlyList<Guid> DuplicateEventIds { get; init; } = Array.Empty<Guid>();

    [JsonPropertyName("rejected_event_ids")]
    public IReadOnlyList<Guid> RejectedEventIds { get; init; } = Array.Empty<Guid>();
}
