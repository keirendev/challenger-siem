using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V2;

public sealed record ProcessActivityInvestigationResponse
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; init; } = "challenger-siem.process-activity-investigation.v2";

    [JsonPropertyName("generated_at_utc")]
    public DateTimeOffset GeneratedAtUtc { get; init; }

    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("from_utc")]
    public DateTimeOffset FromUtc { get; init; }

    [JsonPropertyName("to_utc")]
    public DateTimeOffset ToUtc { get; init; }

    [JsonPropertyName("selector")]
    public ProcessInvestigationSelector Selector { get; init; } = new();

    [JsonPropertyName("process_observations")]
    public IReadOnlyList<ProcessInvestigationEventFact> ProcessObservations { get; init; } = Array.Empty<ProcessInvestigationEventFact>();

    [JsonPropertyName("lineage")]
    public IReadOnlyList<ProcessInvestigationLineage> Lineage { get; init; } = Array.Empty<ProcessInvestigationLineage>();

    [JsonPropertyName("network_activity")]
    public IReadOnlyList<NetworkActivityRecord> NetworkActivity { get; init; } = Array.Empty<NetworkActivityRecord>();

    [JsonPropertyName("privilege_events")]
    public IReadOnlyList<ProcessInvestigationEventFact> PrivilegeEvents { get; init; } = Array.Empty<ProcessInvestigationEventFact>();

    [JsonPropertyName("adjacent_change_events")]
    public IReadOnlyList<ProcessInvestigationEventFact> AdjacentChangeEvents { get; init; } = Array.Empty<ProcessInvestigationEventFact>();

    [JsonPropertyName("source_qualifications")]
    public IReadOnlyList<ProcessInvestigationSourceQualification> SourceQualifications { get; init; } = Array.Empty<ProcessInvestigationSourceQualification>();

    [JsonPropertyName("coverage")]
    public ProcessInvestigationCoverageQualification Coverage { get; init; } = new();

    [JsonPropertyName("collections")]
    public IReadOnlyDictionary<string, ProcessInvestigationCollectionState> Collections { get; init; } = new Dictionary<string, ProcessInvestigationCollectionState>(StringComparer.Ordinal);

    [JsonPropertyName("warnings")]
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    [JsonPropertyName("limitations")]
    public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record ProcessInvestigationSelector
{
    [JsonPropertyName("kind")] public string Kind { get; init; } = string.Empty;
    [JsonPropertyName("process_instance_id")] public string? ProcessInstanceId { get; init; }
    [JsonPropertyName("process_id")] public int? ProcessId { get; init; }
    [JsonPropertyName("process_image")] public string? ProcessImage { get; init; }
    [JsonPropertyName("include_adjacent_changes")] public bool IncludeAdjacentChanges { get; init; }
}

public sealed record ProcessInvestigationEventFact
{
    [JsonPropertyName("agent_id")] public string AgentId { get; init; } = string.Empty;
    [JsonPropertyName("event_id")] public Guid EventId { get; init; }
    [JsonPropertyName("event_citation")] public string EventCitation { get; init; } = string.Empty;
    [JsonPropertyName("event_time_utc")] public DateTimeOffset EventTimeUtc { get; init; }
    [JsonPropertyName("source_id")] public string SourceId { get; init; } = string.Empty;
    [JsonPropertyName("event_code")] public string? EventCode { get; init; }
    [JsonPropertyName("category")] public string? Category { get; init; }
    [JsonPropertyName("action")] public string? Action { get; init; }
    [JsonPropertyName("message")] public string Message { get; init; } = string.Empty;
    [JsonPropertyName("process_instance_id")] public string? ProcessInstanceId { get; init; }
    [JsonPropertyName("parent_process_instance_id")] public string? ParentProcessInstanceId { get; init; }
    [JsonPropertyName("process_id")] public int? ProcessId { get; init; }
    [JsonPropertyName("parent_process_id")] public int? ParentProcessId { get; init; }
    [JsonPropertyName("process_image")] public string? ProcessImage { get; init; }
    [JsonPropertyName("process_command_line")] public string? ProcessCommandLine { get; init; }
    [JsonPropertyName("image_observation_source")] public string ImageObservationSource { get; init; } = "unavailable";
    [JsonPropertyName("image_observed_at_utc")] public DateTimeOffset? ImageObservedAtUtc { get; init; }
    [JsonPropertyName("command_observation_source")] public string CommandObservationSource { get; init; } = "unavailable";
    [JsonPropertyName("command_observed_at_utc")] public DateTimeOffset? CommandObservedAtUtc { get; init; }
    [JsonPropertyName("exact_execution_evidence")] public bool ExactExecutionEvidence { get; init; }
    [JsonPropertyName("correlation_method")] public string CorrelationMethod { get; init; } = "direct_event_selector";
    [JsonPropertyName("correlation_confidence")] public string CorrelationConfidence { get; init; } = "unknown";
    [JsonPropertyName("limitations")] public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record ProcessInvestigationLineage
{
    [JsonPropertyName("child_process_instance_id")] public string? ChildProcessInstanceId { get; init; }
    [JsonPropertyName("child_process_id")] public int? ChildProcessId { get; init; }
    [JsonPropertyName("parent_process_instance_id")] public string? ParentProcessInstanceId { get; init; }
    [JsonPropertyName("parent_process_id")] public int? ParentProcessId { get; init; }
    [JsonPropertyName("event_citation")] public string EventCitation { get; init; } = string.Empty;
    [JsonPropertyName("method")] public string Method { get; init; } = "same_process_snapshot";
    [JsonPropertyName("confidence")] public string Confidence { get; init; } = "polling_observation";
    [JsonPropertyName("limitations")] public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record ProcessInvestigationSourceQualification
{
    [JsonPropertyName("source_id")] public string SourceId { get; init; } = string.Empty;
    [JsonPropertyName("status")] public string Status { get; init; } = "unknown";
    [JsonPropertyName("observed_at_utc")] public DateTimeOffset? ObservedAtUtc { get; init; }
    [JsonPropertyName("active_gap")] public bool ActiveGap { get; init; }
    [JsonPropertyName("historical_gap_or_drop")] public bool HistoricalGapOrDrop { get; init; }
    [JsonPropertyName("gap_count")] public long? GapCount { get; init; }
    [JsonPropertyName("dropped_events")] public long? DroppedEvents { get; init; }
    [JsonPropertyName("citation")] public string Citation { get; init; } = string.Empty;
    [JsonPropertyName("citation_kind")] public string CitationKind { get; init; } = "source_health";
    [JsonPropertyName("limitations")] public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record ProcessInvestigationCoverageQualification
{
    [JsonPropertyName("status")] public string Status { get; init; } = "unknown";
    [JsonPropertyName("has_gap")] public bool HasGap { get; init; }
    [JsonPropertyName("history_ready_for_window")] public bool HistoryReadyForWindow { get; init; }
    [JsonPropertyName("citation")] public string Citation { get; init; } = string.Empty;
    [JsonPropertyName("limitations")] public IReadOnlyList<string> Limitations { get; init; } = Array.Empty<string>();
}

public sealed record ProcessInvestigationCollectionState
{
    [JsonPropertyName("limit")] public int Limit { get; init; }
    [JsonPropertyName("returned")] public int Returned { get; init; }
    [JsonPropertyName("truncated")] public bool Truncated { get; init; }
    [JsonPropertyName("next_cursor")] public string? NextCursor { get; init; }
}
