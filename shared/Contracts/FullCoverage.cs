using System.Text.Json;
using System.Text.Json.Serialization;

namespace Challenger.Siem.Contracts.V1;

/// <summary>
/// Windows host coverage levels used by the full-coverage model.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WindowsCoverageLevel
{
    L0,
    L1,
    L2,
    L3,
    L4
}

/// <summary>
/// Source-health status values. These string values are used in API contracts and persisted rows.
/// </summary>
public static class SourceHealthStatuses
{
    public const string Healthy = "healthy";
    public const string Missing = "missing";
    public const string Disabled = "disabled";
    public const string Stale = "stale";
    public const string Degraded = "degraded";
    public const string PermissionDenied = "permission_denied";
    public const string Unsupported = "unsupported";
    public const string Error = "error";
    public const string NotApplicable = "not_applicable";
    public const string Excepted = "excepted";
}

public static class SourceRequirementKinds
{
    public const string Mandatory = "mandatory";
    public const string Optional = "optional";
    public const string RoleSpecific = "role_specific";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Mandatory,
        Optional,
        RoleSpecific
    };
}

public static class SourceEvidenceStatuses
{
    public const string Satisfied = "satisfied";
    public const string Observed = "observed";
    public const string NotObserved = "not_observed";
    public const string Missing = "missing";
    public const string Disabled = "disabled";
    public const string Stale = "stale";
    public const string Degraded = "degraded";
    public const string PermissionDenied = "permission_denied";
    public const string Unsupported = "unsupported";
    public const string NotApplicable = "not_applicable";
    public const string Excepted = "excepted";
    public const string Unknown = "unknown";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Satisfied,
        Observed,
        NotObserved,
        Missing,
        Disabled,
        Stale,
        Degraded,
        PermissionDenied,
        Unsupported,
        NotApplicable,
        Excepted,
        Unknown
    };
}

public static class AlertStatuses
{
    public const string New = "new";
    public const string Triaged = "triaged";
    public const string Closed = "closed";
    public const string Suppressed = "suppressed";
}

public static class DetectionSeverities
{
    public const string Informational = "informational";
    public const string Low = "low";
    public const string Medium = "medium";
    public const string High = "high";
    public const string Critical = "critical";
}

public static class QueuePressureStates
{
    public const string Unknown = "unknown";
    public const string Normal = "normal";
    public const string Warning = "warning";
    public const string High = "high";
    public const string Critical = "critical";
    public const string Full = "full";
    public const string Throttled = "throttled";
}

public static class QueueSendStates
{
    public const string Unknown = "unknown";
    public const string Idle = "idle";
    public const string Sending = "sending";
    public const string Succeeded = "succeeded";
    public const string BackingOff = "backing_off";
    public const string Failed = "failed";
    public const string Recovering = "recovering";
}

public static class HealthTransitionStates
{
    public const string Unknown = "unknown";
    public const string Healthy = "healthy";
    public const string Degraded = "degraded";
    public const string Recovering = "recovering";
    public const string Recovered = "recovered";
}

public sealed record SourceManifestEntry
{
    [JsonPropertyName("source_id")]
    public string SourceId { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("source_kind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceKind { get; init; }

    [JsonPropertyName("channel")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Channel { get; init; }

    [JsonPropertyName("source_namespace")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceNamespace { get; init; }

    [JsonPropertyName("facility")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Facility { get; init; }

    [JsonPropertyName("unit")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Unit { get; init; }

    [JsonPropertyName("applicability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Applicability { get; init; }

    [JsonPropertyName("applicability_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApplicabilityReason { get; init; }

    [JsonPropertyName("checkpoint_kind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CheckpointKind { get; init; }

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("coverage_level")]
    public WindowsCoverageLevel CoverageLevel { get; init; } = WindowsCoverageLevel.L1;

    [JsonPropertyName("required")]
    public bool Required { get; init; }

    [JsonPropertyName("requirement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Requirement { get; init; }

    [JsonPropertyName("applicable_roles")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ApplicableRoles { get; init; }

    [JsonPropertyName("enabled_by_default")]
    public bool EnabledByDefault { get; init; } = true;

    [JsonPropertyName("source_pack")]
    public string SourcePack { get; init; } = "windows-l2";

    [JsonPropertyName("parser_id")]
    public string ParserId { get; init; } = string.Empty;

    [JsonPropertyName("prerequisites")]
    public IReadOnlyList<string> Prerequisites { get; init; } = Array.Empty<string>();

    [JsonPropertyName("event_families")]
    public IReadOnlyList<string> EventFamilies { get; init; } = Array.Empty<string>();

    [JsonPropertyName("validation_scenarios")]
    public IReadOnlyList<string> ValidationScenarios { get; init; } = Array.Empty<string>();

    [JsonPropertyName("privacy")]
    public string Privacy { get; init; } = "standard";

    [JsonPropertyName("installer_managed")]
    public bool InstallerManaged { get; init; }
}

public sealed record SourceHealthReport
{
    [JsonPropertyName("source_id")]
    public string SourceId { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("source_kind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceKind { get; init; }

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("channel")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Channel { get; init; }

    [JsonPropertyName("source_namespace")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceNamespace { get; init; }

    [JsonPropertyName("facility")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Facility { get; init; }

    [JsonPropertyName("unit")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Unit { get; init; }

    [JsonPropertyName("applicability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Applicability { get; init; }

    [JsonPropertyName("applicability_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApplicabilityReason { get; init; }

    [JsonPropertyName("coverage_level")]
    public WindowsCoverageLevel CoverageLevel { get; init; } = WindowsCoverageLevel.L1;

    [JsonPropertyName("status")]
    public string Status { get; init; } = SourceHealthStatuses.Healthy;

    [JsonPropertyName("required")]
    public bool Required { get; init; }

    [JsonPropertyName("requirement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Requirement { get; init; }

    [JsonPropertyName("applicable_roles")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ApplicableRoles { get; init; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    [JsonPropertyName("last_event_time")]
    public DateTimeOffset? LastEventTime { get; init; }

    [JsonPropertyName("observed_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? ObservedAt { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("last_record_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? LastRecordId { get; init; }

    [JsonPropertyName("oldest_record_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? OldestRecordId { get; init; }

    [JsonPropertyName("newest_record_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? NewestRecordId { get; init; }

    [JsonPropertyName("collected_checkpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SourceCheckpoint? CollectedCheckpoint { get; init; }

    [JsonPropertyName("acknowledged_checkpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SourceCheckpoint? AcknowledgedCheckpoint { get; init; }

    [JsonPropertyName("log_size_bytes")]
    public long? LogSizeBytes { get; init; }

    [JsonPropertyName("retention_days")]
    public int? RetentionDays { get; init; }

    [JsonPropertyName("lag_seconds")]
    public long? LagSeconds { get; init; }

    [JsonPropertyName("silence_seconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? SilenceSeconds { get; init; }

    [JsonPropertyName("event_rate_per_minute")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public decimal? EventRatePerMinute { get; init; }

    [JsonPropertyName("error_code")]
    public string? ErrorCode { get; init; }

    [JsonPropertyName("error_message")]
    public string? ErrorMessage { get; init; }

    [JsonPropertyName("gap_detected")]
    public bool GapDetected { get; init; }

    [JsonPropertyName("cleared_detected")]
    public bool ClearedDetected { get; init; }

    [JsonPropertyName("bookmark_gap_detected")]
    public bool BookmarkGapDetected { get; init; }

    [JsonPropertyName("gap_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? GapCount { get; init; }

    [JsonPropertyName("permission_denied_since")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? PermissionDeniedSince { get; init; }

    [JsonPropertyName("recovered_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? RecoveredAt { get; init; }

    [JsonPropertyName("transition_state")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TransitionState { get; init; }

    [JsonPropertyName("transitioned_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? TransitionedAt { get; init; }

    [JsonPropertyName("dropped_events")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? DroppedEvents { get; init; }

    [JsonPropertyName("poison_events")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? PoisonEvents { get; init; }

    [JsonPropertyName("config_hash")]
    public string? ConfigHash { get; init; }

    [JsonPropertyName("source_version")]
    public string? SourceVersion { get; init; }

    [JsonPropertyName("prerequisite_statuses")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? PrerequisiteStatuses { get; init; }

    [JsonPropertyName("event_family_statuses")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? EventFamilyStatuses { get; init; }

    [JsonPropertyName("details")]
    public IReadOnlyDictionary<string, string> Details { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

public sealed record QueueSloMetrics
{
    [JsonPropertyName("queue_depth")]
    public int QueueDepth { get; init; }

    [JsonPropertyName("poison_depth")]
    public int PoisonDepth { get; init; }

    [JsonPropertyName("oldest_queued_age_seconds")]
    public long? OldestQueuedAgeSeconds { get; init; }

    [JsonPropertyName("queue_size_bytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? QueueSizeBytes { get; init; }

    [JsonPropertyName("max_size_bytes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? MaxSizeBytes { get; init; }

    [JsonPropertyName("used_percent")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public decimal? UsedPercent { get; init; }

    [JsonPropertyName("pressure_state")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PressureState { get; init; }

    [JsonPropertyName("send_state")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SendState { get; init; }

    [JsonPropertyName("backoff_seconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? BackoffSeconds { get; init; }

    [JsonPropertyName("last_attempt_time")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? LastAttemptTime { get; init; }

    [JsonPropertyName("last_failed_send_time")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? LastFailedSendTime { get; init; }

    [JsonPropertyName("last_successful_send_time")]
    public DateTimeOffset? LastSuccessfulSendTime { get; init; }

    [JsonPropertyName("last_recovery_time")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? LastRecoveryTime { get; init; }

    [JsonPropertyName("poison_events_total")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? PoisonEventsTotal { get; init; }

    [JsonPropertyName("dropped_events_total")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? DroppedEventsTotal { get; init; }

    [JsonPropertyName("max_size_mb")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int MaxSizeMb { get; init; }

    [JsonPropertyName("warning_size_percent")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int WarningSizePercent { get; init; }
}

public sealed record AgentResourceMetrics
{
    [JsonPropertyName("observed_at")]
    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("cpu_percent")]
    public decimal? CpuPercent { get; init; }

    [JsonPropertyName("rss_bytes")]
    public long? RssBytes { get; init; }

    [JsonPropertyName("managed_memory_bytes")]
    public long? ManagedMemoryBytes { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = "observed";
}

public sealed record CoverageSummary
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("target_level")]
    public WindowsCoverageLevel TargetLevel { get; init; } = WindowsCoverageLevel.L2;

    [JsonPropertyName("current_level")]
    public WindowsCoverageLevel CurrentLevel { get; init; } = WindowsCoverageLevel.L0;

    [JsonPropertyName("overall_status")]
    public string OverallStatus { get; init; } = SourceHealthStatuses.Missing;

    [JsonPropertyName("missing_mandatory_sources")]
    public int MissingMandatorySources { get; init; }

    [JsonPropertyName("stale_sources")]
    public int StaleSources { get; init; }

    [JsonPropertyName("error_sources")]
    public int ErrorSources { get; init; }

    [JsonPropertyName("degraded_sources")]
    public int DegradedSources { get; init; }

    [JsonPropertyName("permission_denied_sources")]
    public int PermissionDeniedSources { get; init; }

    [JsonPropertyName("unsupported_sources")]
    public int UnsupportedSources { get; init; }

    [JsonPropertyName("excepted_sources")]
    public int ExceptedSources { get; init; }

    [JsonPropertyName("not_applicable_sources")]
    public int NotApplicableSources { get; init; }

    [JsonPropertyName("queue_depth")]
    public int QueueDepth { get; init; }

    [JsonPropertyName("queue_metrics")]
    public QueueSloMetrics? QueueMetrics { get; init; }

    [JsonPropertyName("resource_metrics")]
    public AgentResourceMetrics? ResourceMetrics { get; init; }

    [JsonPropertyName("last_heartbeat_time")]
    public DateTimeOffset? LastHeartbeatTime { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }
}

public sealed record SourceHealthResponse
{
    [JsonPropertyName("summaries")]
    public IReadOnlyList<CoverageSummary> Summaries { get; init; } = Array.Empty<CoverageSummary>();

    [JsonPropertyName("sources")]
    public IReadOnlyList<SourceHealthReport> Sources { get; init; } = Array.Empty<SourceHealthReport>();
}

public sealed record TelemetryCoverageResponse
{
    [JsonPropertyName("generated_at")]
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("lookback_start")]
    public DateTimeOffset LookbackStart { get; init; } = DateTimeOffset.UtcNow.AddHours(-24);

    [JsonPropertyName("lookback_end")]
    public DateTimeOffset LookbackEnd { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("lookback_hours")]
    public int LookbackHours { get; init; } = 24;

    [JsonPropertyName("target_level")]
    public WindowsCoverageLevel TargetLevel { get; init; } = WindowsCoverageLevel.L2;

    [JsonPropertyName("agents")]
    public IReadOnlyList<AgentTelemetryCoverage> Agents { get; init; } = Array.Empty<AgentTelemetryCoverage>();
}

public sealed record AgentTelemetryCoverage
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("agent_status")]
    public string AgentStatus { get; init; } = string.Empty;

    [JsonPropertyName("last_seen")]
    public DateTimeOffset? LastSeen { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("target_level")]
    public WindowsCoverageLevel TargetLevel { get; init; } = WindowsCoverageLevel.L2;

    [JsonPropertyName("current_level")]
    public WindowsCoverageLevel CurrentLevel { get; init; } = WindowsCoverageLevel.L0;

    [JsonPropertyName("overall_status")]
    public string OverallStatus { get; init; } = SourceHealthStatuses.Missing;

    [JsonPropertyName("recent_event_count")]
    public int RecentEventCount { get; init; }

    [JsonPropertyName("expected_source_count")]
    public int ExpectedSourceCount { get; init; }

    [JsonPropertyName("reported_source_count")]
    public int ReportedSourceCount { get; init; }

    [JsonPropertyName("source_status_counts")]
    public IReadOnlyDictionary<string, int> SourceStatusCounts { get; init; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    [JsonPropertyName("queue_metrics")]
    public QueueSloMetrics? QueueMetrics { get; init; }

    [JsonPropertyName("resource_metrics")]
    public AgentResourceMetrics? ResourceMetrics { get; init; }

    [JsonPropertyName("missing_mandatory_sources")]
    public int MissingMandatorySources { get; init; }

    [JsonPropertyName("stale_sources")]
    public int StaleSources { get; init; }

    [JsonPropertyName("error_sources")]
    public int ErrorSources { get; init; }

    [JsonPropertyName("degraded_sources")]
    public int DegradedSources { get; init; }

    [JsonPropertyName("permission_denied_sources")]
    public int PermissionDeniedSources { get; init; }

    [JsonPropertyName("unsupported_sources")]
    public int UnsupportedSources { get; init; }

    [JsonPropertyName("excepted_sources")]
    public int ExceptedSources { get; init; }

    [JsonPropertyName("not_applicable_sources")]
    public int NotApplicableSources { get; init; }

    [JsonPropertyName("new_alert_count")]
    public int NewAlertCount { get; init; }

    [JsonPropertyName("alert_status_counts")]
    public IReadOnlyDictionary<string, int> AlertStatusCounts { get; init; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    [JsonPropertyName("active_graph_count")]
    public int ActiveGraphCount { get; init; }

    [JsonPropertyName("sources")]
    public IReadOnlyList<SourceTelemetryCoverage> Sources { get; init; } = Array.Empty<SourceTelemetryCoverage>();

    [JsonPropertyName("inventory")]
    public IReadOnlyList<InventoryTelemetryStatus> Inventory { get; init; } = Array.Empty<InventoryTelemetryStatus>();

    [JsonPropertyName("detection_prerequisites")]
    public IReadOnlyList<DetectionPrerequisiteTelemetryStatus> DetectionPrerequisites { get; init; } = Array.Empty<DetectionPrerequisiteTelemetryStatus>();

    [JsonPropertyName("gaps")]
    public IReadOnlyList<string> Gaps { get; init; } = Array.Empty<string>();
}

public sealed record SourceTelemetryCoverage
{
    [JsonPropertyName("source_id")]
    public string SourceId { get; init; } = string.Empty;

    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("channel")]
    public string Channel { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }

    [JsonPropertyName("source_kind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceKind { get; init; }

    [JsonPropertyName("source_namespace")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SourceNamespace { get; init; }

    [JsonPropertyName("applicability")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Applicability { get; init; }

    [JsonPropertyName("applicability_reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApplicabilityReason { get; init; }

    [JsonPropertyName("requirement")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Requirement { get; init; }

    [JsonPropertyName("applicable_roles")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ApplicableRoles { get; init; }

    [JsonPropertyName("prerequisite_statuses")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? PrerequisiteStatuses { get; init; }

    [JsonPropertyName("event_family_statuses")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, string>? EventFamilyStatuses { get; init; }

    [JsonPropertyName("coverage_level")]
    public WindowsCoverageLevel CoverageLevel { get; init; } = WindowsCoverageLevel.L1;

    [JsonPropertyName("required")]
    public bool Required { get; init; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    [JsonPropertyName("reported")]
    public bool Reported { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = SourceHealthStatuses.Missing;

    [JsonPropertyName("last_event_time")]
    public DateTimeOffset? LastEventTime { get; init; }

    [JsonPropertyName("observed_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? ObservedAt { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("lag_seconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? LagSeconds { get; init; }

    [JsonPropertyName("collected_checkpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SourceCheckpoint? CollectedCheckpoint { get; init; }

    [JsonPropertyName("acknowledged_checkpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SourceCheckpoint? AcknowledgedCheckpoint { get; init; }

    [JsonPropertyName("permission_denied_since")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? PermissionDeniedSince { get; init; }

    [JsonPropertyName("recovered_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? RecoveredAt { get; init; }

    [JsonPropertyName("silence_seconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? SilenceSeconds { get; init; }

    [JsonPropertyName("event_rate_per_minute")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public decimal? EventRatePerMinute { get; init; }

    [JsonPropertyName("gap_count")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? GapCount { get; init; }

    [JsonPropertyName("transition_state")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TransitionState { get; init; }

    [JsonPropertyName("transitioned_at")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? TransitionedAt { get; init; }

    [JsonPropertyName("dropped_events")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? DroppedEvents { get; init; }

    [JsonPropertyName("poison_events")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? PoisonEvents { get; init; }

    [JsonPropertyName("source_version")]
    public string? SourceVersion { get; init; }

    [JsonPropertyName("config_hash")]
    public string? ConfigHash { get; init; }

    [JsonPropertyName("details")]
    public IReadOnlyDictionary<string, string> Details { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    [JsonPropertyName("recent_event_count")]
    public int RecentEventCount { get; init; }

    [JsonPropertyName("reason")]
    public string Reason { get; init; } = string.Empty;

    [JsonPropertyName("event_search_url")]
    public string EventSearchUrl { get; init; } = string.Empty;

    [JsonPropertyName("source_health_url")]
    public string SourceHealthUrl { get; init; } = string.Empty;
}

public sealed record InventoryTelemetryStatus
{
    [JsonPropertyName("snapshot_type")]
    public string SnapshotType { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = SourceHealthStatuses.Missing;

    [JsonPropertyName("latest_collected_at")]
    public DateTimeOffset? LatestCollectedAt { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("item_count")]
    public int ItemCount { get; init; }

    [JsonPropertyName("reason")]
    public string Reason { get; init; } = string.Empty;

    [JsonPropertyName("url")]
    public string Url { get; init; } = string.Empty;
}

public sealed record DetectionPrerequisiteTelemetryStatus
{
    [JsonPropertyName("rule_id")]
    public string RuleId { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = DetectionSeverities.Medium;

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = "unknown";

    [JsonPropertyName("required_sources")]
    public IReadOnlyList<string> RequiredSources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("healthy_sources")]
    public IReadOnlyList<string> HealthySources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("missing_sources")]
    public IReadOnlyList<string> MissingSources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("stale_sources")]
    public IReadOnlyList<string> StaleSources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("recent_event_sources")]
    public IReadOnlyList<string> RecentEventSources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("required_fields")]
    public IReadOnlyList<string> RequiredFields { get; init; } = Array.Empty<string>();

    [JsonPropertyName("required_event_ids")]
    public IReadOnlyList<int> RequiredEventIds { get; init; } = Array.Empty<int>();

    [JsonPropertyName("required_event_categories")]
    public IReadOnlyList<string> RequiredEventCategories { get; init; } = Array.Empty<string>();

    [JsonPropertyName("required_event_actions")]
    public IReadOnlyList<string> RequiredEventActions { get; init; } = Array.Empty<string>();

    [JsonPropertyName("audit_policy_requirements")]
    public IReadOnlyList<string> AuditPolicyRequirements { get; init; } = Array.Empty<string>();

    [JsonPropertyName("inventory_requirements")]
    public IReadOnlyList<string> InventoryRequirements { get; init; } = Array.Empty<string>();

    [JsonPropertyName("optional_sources")]
    public IReadOnlyList<string> OptionalSources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("reason")]
    public string Reason { get; init; } = string.Empty;
}

public sealed record CoverageExceptionRecord
{
    [JsonPropertyName("agent_id")]
    public string? AgentId { get; init; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; init; }

    [JsonPropertyName("source_id")]
    public string SourceId { get; init; } = string.Empty;

    [JsonPropertyName("reason")]
    public string Reason { get; init; } = string.Empty;

    [JsonPropertyName("approved_by")]
    public string ApprovedBy { get; init; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public DateTimeOffset? ExpiresAt { get; init; }
}

public sealed record NormalizedEventFields
{
    [JsonPropertyName("category")]
    public string? Category { get; init; }

    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("outcome")]
    public string? Outcome { get; init; }

    [JsonPropertyName("user_name")]
    public string? UserName { get; init; }

    [JsonPropertyName("user_sid")]
    public string? UserSid { get; init; }

    [JsonPropertyName("target_user_name")]
    public string? TargetUserName { get; init; }

    [JsonPropertyName("logon_type")]
    public string? LogonType { get; init; }

    [JsonPropertyName("process_id")]
    public string? ProcessId { get; init; }

    [JsonPropertyName("parent_process_id")]
    public string? ParentProcessId { get; init; }

    [JsonPropertyName("process_image")]
    public string? ProcessImage { get; init; }

    [JsonPropertyName("parent_process_image")]
    public string? ParentProcessImage { get; init; }

    [JsonPropertyName("process_command_line")]
    public string? ProcessCommandLine { get; init; }

    [JsonPropertyName("source_ip")]
    public string? SourceIp { get; init; }

    [JsonPropertyName("source_port")]
    public string? SourcePort { get; init; }

    [JsonPropertyName("destination_ip")]
    public string? DestinationIp { get; init; }

    [JsonPropertyName("destination_port")]
    public string? DestinationPort { get; init; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; init; }

    [JsonPropertyName("service_name")]
    public string? ServiceName { get; init; }

    [JsonPropertyName("driver_name")]
    public string? DriverName { get; init; }

    [JsonPropertyName("object_name")]
    public string? ObjectName { get; init; }

    [JsonPropertyName("registry_key")]
    public string? RegistryKey { get; init; }

    [JsonPropertyName("file_path")]
    public string? FilePath { get; init; }

    [JsonPropertyName("hash")]
    public string? Hash { get; init; }

    [JsonPropertyName("rule_name")]
    public string? RuleName { get; init; }

    [JsonPropertyName("threat_name")]
    public string? ThreatName { get; init; }

    [JsonPropertyName("task_name")]
    public string? TaskName { get; init; }

    [JsonPropertyName("package_name")]
    public string? PackageName { get; init; }

    [JsonPropertyName("process")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ProcessTelemetryConcept? Process { get; init; }

    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UserTelemetryConcept? User { get; init; }

    [JsonPropertyName("network")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public NetworkTelemetryConcept? Network { get; init; }

    [JsonPropertyName("file")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FileTelemetryConcept? File { get; init; }

    [JsonPropertyName("entities")]
    public IReadOnlyList<EventEntity> Entities { get; init; } = Array.Empty<EventEntity>();

    [JsonPropertyName("labels")]
    public IReadOnlyDictionary<string, string> Labels { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

public sealed record EventEntity
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; init; } = string.Empty;

    [JsonPropertyName("role")]
    public string Role { get; init; } = string.Empty;
}

public sealed record AssetInventoryBatchRequest
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("sent_at")]
    public DateTimeOffset SentAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("snapshots")]
    public IReadOnlyList<AssetInventorySnapshot> Snapshots { get; init; } = Array.Empty<AssetInventorySnapshot>();
}

public sealed record AssetInventorySnapshot
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("hostname")]
    public string Hostname { get; init; } = string.Empty;

    [JsonPropertyName("snapshot_type")]
    public string SnapshotType { get; init; } = string.Empty;

    [JsonPropertyName("collected_at")]
    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("items")]
    public IReadOnlyList<InventoryItem> Items { get; init; } = Array.Empty<InventoryItem>();

    [JsonPropertyName("summary")]
    public IReadOnlyDictionary<string, string> Summary { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

public sealed record InventoryItem
{
    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string? Status { get; init; }

    [JsonPropertyName("identity")]
    public string? Identity { get; init; }

    [JsonPropertyName("metadata")]
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

public sealed record DetectionRuleMetadata
{
    [JsonPropertyName("rule_id")]
    public string RuleId { get; init; } = string.Empty;

    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = DetectionSeverities.Medium;

    [JsonPropertyName("confidence")]
    public string Confidence { get; init; } = "medium";

    [JsonPropertyName("category")]
    public string Category { get; init; } = string.Empty;

    [JsonPropertyName("required_sources")]
    public IReadOnlyList<string> RequiredSources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("required_fields")]
    public IReadOnlyList<string> RequiredFields { get; init; } = Array.Empty<string>();

    [JsonPropertyName("mitre_attack")]
    public IReadOnlyList<string> MitreAttack { get; init; } = Array.Empty<string>();

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;
}

public sealed record AlertRecord
{
    [JsonPropertyName("alert_id")]
    public Guid AlertId { get; init; }

    [JsonPropertyName("rule_id")]
    public string RuleId { get; init; } = string.Empty;

    [JsonPropertyName("rule_version")]
    public int RuleVersion { get; init; } = 1;

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = DetectionSeverities.Medium;

    [JsonPropertyName("confidence")]
    public string Confidence { get; init; } = "medium";

    [JsonPropertyName("status")]
    public string Status { get; init; } = AlertStatuses.New;

    [JsonPropertyName("agent_id")]
    public string? AgentId { get; init; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; init; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;

    [JsonPropertyName("affected_entities")]
    public IReadOnlyList<EventEntity> AffectedEntities { get; init; } = Array.Empty<EventEntity>();

    [JsonPropertyName("evidence")]
    public IReadOnlyList<AlertEvidenceRecord> Evidence { get; init; } = Array.Empty<AlertEvidenceRecord>();
}

public sealed record AlertEvidenceRecord
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; init; } = string.Empty;

    [JsonPropertyName("event_id")]
    public Guid EventId { get; init; }

    [JsonPropertyName("event_time")]
    public DateTimeOffset? EventTime { get; init; }

    [JsonPropertyName("host_timezone")]
    public HostTimezoneMetadata? HostTimezone { get; init; }

    [JsonPropertyName("channel")]
    public string? Channel { get; init; }

    [JsonPropertyName("windows_event_id")]
    public int? WindowsEventId { get; init; }

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = string.Empty;
}

public sealed record RoleSourcePackDesign
{
    [JsonPropertyName("role")]
    public string Role { get; init; } = string.Empty;

    [JsonPropertyName("sources")]
    public IReadOnlyList<string> Sources { get; init; } = Array.Empty<string>();

    [JsonPropertyName("parsers")]
    public IReadOnlyList<string> Parsers { get; init; } = Array.Empty<string>();

    [JsonPropertyName("detections")]
    public IReadOnlyList<string> Detections { get; init; } = Array.Empty<string>();

    [JsonPropertyName("validation")]
    public IReadOnlyList<string> Validation { get; init; } = Array.Empty<string>();

    [JsonPropertyName("privacy_notes")]
    public string PrivacyNotes { get; init; } = string.Empty;
}

public sealed record RedactionPolicy
{
    [JsonPropertyName("raw_json_allowed")]
    public bool RawJsonAllowed { get; init; }

    [JsonPropertyName("redacted_fields")]
    public IReadOnlyList<string> RedactedFields { get; init; } = Array.Empty<string>();

    [JsonPropertyName("max_command_line_length")]
    public int MaxCommandLineLength { get; init; } = 2048;

    [JsonPropertyName("max_script_block_length")]
    public int MaxScriptBlockLength { get; init; } = 4096;
}

public sealed record TamperCheckSummary
{
    [JsonPropertyName("binary_hash")]
    public string? BinaryHash { get; init; }

    [JsonPropertyName("config_hash")]
    public string? ConfigHash { get; init; }

    [JsonPropertyName("signature_status")]
    public string? SignatureStatus { get; init; }

    [JsonPropertyName("acl_status")]
    public string? AclStatus { get; init; }
}

public static class JsonElementExtensions
{
    public static JsonElement ToJsonElement<T>(this T value)
    {
        return JsonSerializer.SerializeToElement(value, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }
}
