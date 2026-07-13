using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

public static class CaseStatuses
{
    public const string Draft = "draft";
    public const string Open = "open";
    public const string Investigating = "investigating";
    public const string PendingExternal = "pending_external";
    public const string Contained = "contained";
    public const string Resolved = "resolved";
    public const string Closed = "closed";
}

public static class CasePriorities
{
    public const string Low = "low";
    public const string Normal = "normal";
    public const string High = "high";
    public const string Urgent = "urgent";
}

public static class AlertDispositions
{
    public const string TruePositive = "true_positive";
    public const string FalsePositive = "false_positive";
    public const string Duplicate = "duplicate";
    public const string Benign = "benign";
    public const string AuthorizedActivity = "authorized_activity";
    public const string RetentionLimited = "retention_limited";
    public const string Unknown = "unknown";
}

public sealed record AlertActivityRecord
{
    [JsonPropertyName("activity_id")]
    public Guid ActivityId { get; init; }

    [JsonPropertyName("occurred_at")]
    public DateTimeOffset OccurredAt { get; init; }

    [JsonPropertyName("actor")]
    public string? Actor { get; init; }

    [JsonPropertyName("action")]
    public string Action { get; init; } = string.Empty;

    [JsonPropertyName("from_status")]
    public string? FromStatus { get; init; }

    [JsonPropertyName("to_status")]
    public string? ToStatus { get; init; }

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;
}

public sealed record AlertCaseLinkRecord
{
    [JsonPropertyName("case_id")]
    public Guid CaseId { get; init; }

    [JsonPropertyName("case_key")]
    public string CaseKey { get; init; } = string.Empty;

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = string.Empty;
}

public sealed record AlertMutationRequest
{
    [JsonPropertyName("expected_version")]
    public int ExpectedVersion { get; init; }

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("status")]
    public string? Status { get; init; }

    [JsonPropertyName("disposition")]
    public string? Disposition { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("summary")]
    public string? Summary { get; init; }

    [JsonPropertyName("suppressed_until")]
    public DateTimeOffset? SuppressedUntil { get; init; }

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public record CaseSummaryRecord
{
    [JsonPropertyName("case_id")]
    public Guid CaseId { get; init; }

    [JsonPropertyName("case_key")]
    public string CaseKey { get; init; } = string.Empty;

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = DetectionSeverities.Medium;

    [JsonPropertyName("priority")]
    public string Priority { get; init; } = CasePriorities.Normal;

    [JsonPropertyName("status")]
    public string Status { get; init; } = CaseStatuses.Open;

    [JsonPropertyName("disposition")]
    public string? Disposition { get; init; }

    [JsonPropertyName("version")]
    public int Version { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; }

    [JsonPropertyName("updated_at")]
    public DateTimeOffset UpdatedAt { get; init; }

    [JsonPropertyName("last_activity_at")]
    public DateTimeOffset LastActivityAt { get; init; }

    [JsonPropertyName("alert_count")]
    public int AlertCount { get; init; }

    [JsonPropertyName("evidence_count")]
    public int EvidenceCount { get; init; }
}

public sealed record CaseDetailRecord : CaseSummaryRecord
{
    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("closure_summary")]
    public string? ClosureSummary { get; init; }

    [JsonPropertyName("closure_criteria")]
    public string? ClosureCriteria { get; init; }

    [JsonPropertyName("coverage_gap_acknowledged")]
    public bool CoverageGapAcknowledged { get; init; }

    [JsonPropertyName("closed_at")]
    public DateTimeOffset? ClosedAt { get; init; }

    [JsonPropertyName("reopened_at")]
    public DateTimeOffset? ReopenedAt { get; init; }

    [JsonPropertyName("alerts")]
    public IReadOnlyList<CaseAlertLinkRecord> Alerts { get; init; } = Array.Empty<CaseAlertLinkRecord>();

    [JsonPropertyName("entities")]
    public IReadOnlyList<CaseEntityRecord> Entities { get; init; } = Array.Empty<CaseEntityRecord>();

    [JsonPropertyName("graphs")]
    public IReadOnlyList<CaseGraphLinkRecord> Graphs { get; init; } = Array.Empty<CaseGraphLinkRecord>();

    [JsonPropertyName("evidence")]
    public IReadOnlyList<CaseEvidenceRecord> Evidence { get; init; } = Array.Empty<CaseEvidenceRecord>();

    [JsonPropertyName("notes")]
    public IReadOnlyList<CaseNoteRecord> Notes { get; init; } = Array.Empty<CaseNoteRecord>();

    [JsonPropertyName("activity")]
    public IReadOnlyList<CaseActivityRecord> Activity { get; init; } = Array.Empty<CaseActivityRecord>();
}

public sealed record CaseAlertLinkRecord
{
    [JsonPropertyName("alert_id")]
    public Guid AlertId { get; init; }

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = string.Empty;

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = string.Empty;
}

public sealed record CaseEntityRecord
{
    [JsonPropertyName("case_entity_id")]
    public Guid CaseEntityId { get; init; }

    [JsonPropertyName("entity_type")]
    public string EntityType { get; init; } = string.Empty;

    [JsonPropertyName("entity_value")]
    public string EntityValue { get; init; } = string.Empty;

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = string.Empty;
}

public sealed record CaseGraphLinkRecord
{
    [JsonPropertyName("graph_id")]
    public Guid GraphId { get; init; }

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = string.Empty;
}

public sealed record CaseEvidenceRecord
{
    [JsonPropertyName("case_evidence_id")]
    public Guid CaseEvidenceId { get; init; }

    [JsonPropertyName("alert_id")]
    public Guid? AlertId { get; init; }

    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("event_id")]
    public Guid EventId { get; init; }

    [JsonPropertyName("event_time")]
    public DateTimeOffset? EventTime { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("evidence_kind")]
    public string EvidenceKind { get; init; } = "event";

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;

    [JsonPropertyName("telemetry_retention_state")]
    public string TelemetryRetentionState { get; init; } = "unknown";
}

public sealed record CaseNoteRecord
{
    [JsonPropertyName("note_id")]
    public Guid NoteId { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; }

    [JsonPropertyName("created_by")]
    public string? CreatedBy { get; init; }

    [JsonPropertyName("body")]
    public string Body { get; init; } = string.Empty;
}

public sealed record CaseActivityRecord
{
    [JsonPropertyName("activity_id")]
    public Guid ActivityId { get; init; }

    [JsonPropertyName("occurred_at")]
    public DateTimeOffset OccurredAt { get; init; }

    [JsonPropertyName("actor")]
    public string? Actor { get; init; }

    [JsonPropertyName("action")]
    public string Action { get; init; } = string.Empty;

    [JsonPropertyName("from_status")]
    public string? FromStatus { get; init; }

    [JsonPropertyName("to_status")]
    public string? ToStatus { get; init; }

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;
}

public sealed record CaseCreateRequest
{
    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = DetectionSeverities.Medium;

    [JsonPropertyName("priority")]
    public string Priority { get; init; } = CasePriorities.Normal;

    [JsonPropertyName("alert_ids")]
    public IReadOnlyList<Guid> AlertIds { get; init; } = Array.Empty<Guid>();

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public sealed record CaseMutationRequest
{
    [JsonPropertyName("expected_version")]
    public int ExpectedVersion { get; init; }

    [JsonPropertyName("title")]
    public string? Title { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("owner")]
    public string? Owner { get; init; }

    [JsonPropertyName("severity")]
    public string? Severity { get; init; }

    [JsonPropertyName("priority")]
    public string? Priority { get; init; }

    [JsonPropertyName("status")]
    public string? Status { get; init; }

    [JsonPropertyName("disposition")]
    public string? Disposition { get; init; }

    [JsonPropertyName("closure_summary")]
    public string? ClosureSummary { get; init; }

    [JsonPropertyName("closure_criteria")]
    public string? ClosureCriteria { get; init; }

    [JsonPropertyName("coverage_gap_acknowledged")]
    public bool CoverageGapAcknowledged { get; init; }

    [JsonPropertyName("confirm")]
    public bool Confirm { get; init; }

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public sealed record CaseNoteRequest
{
    [JsonPropertyName("body")]
    public string Body { get; init; } = string.Empty;

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public sealed record CaseAlertRequest
{
    [JsonPropertyName("alert_id")]
    public Guid AlertId { get; init; }

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = "related";

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public sealed record CaseEntityRequest
{
    [JsonPropertyName("entity_type")]
    public string EntityType { get; init; } = string.Empty;

    [JsonPropertyName("entity_value")]
    public string EntityValue { get; init; } = string.Empty;

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = "related";

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public sealed record CaseGraphRequest
{
    [JsonPropertyName("graph_id")]
    public Guid GraphId { get; init; }

    [JsonPropertyName("relationship")]
    public string Relationship { get; init; } = "investigation";

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}

public sealed record CaseEvidenceRequest
{
    [JsonPropertyName("alert_id")]
    public Guid? AlertId { get; init; }

    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("event_id")]
    public Guid EventId { get; init; }

    [JsonPropertyName("summary")]
    public string? Summary { get; init; }

    [JsonPropertyName("idempotency_key")]
    public string? IdempotencyKey { get; init; }
}
