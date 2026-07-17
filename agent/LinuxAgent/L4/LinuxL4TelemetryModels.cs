using System.Text.Json.Serialization;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.L4;

public static class LinuxL4TelemetryLimits
{
    public const int StateSchemaVersion = 1;
    public const int MaximumStateBytes = 512 * 1024;
    public const int MaximumPolicySnapshots = 16;
    public const int MaximumSloSamples = 122;
    public const long MaximumSequence = long.MaxValue - 10_000;
}

public sealed record LinuxL4SourceProgress
{
    [JsonPropertyName("next_sequence")] public long NextSequence { get; init; } = 1;
    [JsonPropertyName("collected_sequence")] public long CollectedSequence { get; init; }
    [JsonPropertyName("acknowledged_sequence")] public long AcknowledgedSequence { get; init; }
    [JsonPropertyName("pending_reservation_start")] public long? PendingReservationStart { get; init; }
    [JsonPropertyName("pending_reservation_end")] public long? PendingReservationEnd { get; init; }
    [JsonPropertyName("abandoned_through_sequence")] public long AbandonedThroughSequence { get; init; }
    [JsonPropertyName("recovery_gap_sequence")] public long? RecoveryGapSequence { get; init; }
    [JsonPropertyName("last_observed_at")] public DateTimeOffset? LastObservedAt { get; init; }
    [JsonPropertyName("last_event_at")] public DateTimeOffset? LastEventAt { get; init; }
    [JsonPropertyName("acknowledged_at")] public DateTimeOffset? AcknowledgedAt { get; init; }
    [JsonPropertyName("status")] public string Status { get; init; } = SourceHealthStatuses.Missing;
    [JsonPropertyName("error_code")] public string ErrorCode { get; init; } = "awaiting_first_sample";
    [JsonPropertyName("active_gap")] public bool ActiveGap { get; init; }
    [JsonPropertyName("gap_count")] public long GapCount { get; init; }
    [JsonPropertyName("dropped_count")] public long DroppedCount { get; init; }
    [JsonPropertyName("transition_state")] public string TransitionState { get; init; } = HealthTransitionStates.Unknown;
    [JsonPropertyName("transitioned_at")] public DateTimeOffset? TransitionedAt { get; init; }
}

public sealed record LinuxL4PolicyState
{
    [JsonPropertyName("progress")] public LinuxL4SourceProgress Progress { get; init; } = new();
    [JsonPropertyName("baseline_established")] public bool BaselineEstablished { get; init; }
    [JsonPropertyName("approved_baseline_hash")] public string? ApprovedBaselineHash { get; init; }
    [JsonPropertyName("baseline_signatures")] public IReadOnlyDictionary<string, string> BaselineSignatures { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    [JsonPropertyName("current_signatures")] public IReadOnlyDictionary<string, string> CurrentSignatures { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
}

public sealed record LinuxL4SloSample
{
    [JsonPropertyName("observed_at")] public DateTimeOffset ObservedAt { get; init; }
    [JsonPropertyName("coverage_started_at")] public DateTimeOffset? CoverageStartedAt { get; init; }
    [JsonPropertyName("cpu_percent_milli")] public long? CpuPercentMilli { get; init; }
    [JsonPropertyName("rss_bytes")] public long? RssBytes { get; init; }
    [JsonPropertyName("managed_memory_bytes")] public long? ManagedMemoryBytes { get; init; }
    [JsonPropertyName("write_bytes_per_second")] public long? WriteBytesPerSecond { get; init; }
}

public sealed record LinuxL4SloState
{
    [JsonPropertyName("progress")] public LinuxL4SourceProgress Progress { get; init; } = new();
    [JsonPropertyName("previous_observed_at")] public DateTimeOffset? PreviousObservedAt { get; init; }
    [JsonPropertyName("previous_processor_time_ticks")] public long? PreviousProcessorTimeTicks { get; init; }
    [JsonPropertyName("previous_write_bytes")] public long? PreviousWriteBytes { get; init; }
    [JsonPropertyName("previous_process_start_time_utc_ticks")] public long? PreviousProcessStartTimeUtcTicks { get; init; }
    [JsonPropertyName("samples")] public IReadOnlyList<LinuxL4SloSample> Samples { get; init; } = Array.Empty<LinuxL4SloSample>();
}

public sealed record LinuxL4TelemetryState
{
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; init; } = LinuxL4TelemetryLimits.StateSchemaVersion;
    [JsonPropertyName("policy")] public LinuxL4PolicyState Policy { get; init; } = new();
    [JsonPropertyName("slo")] public LinuxL4SloState Slo { get; init; } = new();
}

public sealed record LinuxL4StateReadResult(LinuxL4TelemetryState State, string ErrorCode);

public sealed record LinuxL4CollectionResult(
    string SourceId,
    IReadOnlyList<EventEnvelope> Events,
    LinuxL4TelemetryState NewState,
    string HealthStatus,
    string ErrorCode,
    bool ActiveGap,
    long GapCount,
    long DroppedCount,
    IReadOnlyDictionary<string, string> Details);

public sealed record LinuxAgentSloObservation(
    DateTimeOffset ObservedAt,
    TimeSpan TotalProcessorTime,
    int ProcessorCount,
    long? RssBytes,
    long? ManagedMemoryBytes,
    long? WriteBytes,
    long ProcessStartTimeUtcTicks);

public sealed record LinuxL4TelemetryPlan(
    string PlanHash,
    string CandidateBaselineHash,
    bool CandidateBaselineComplete,
    IReadOnlyDictionary<string, string> CandidateBaselineStates,
    IReadOnlyDictionary<string, string> CandidateBaselineBlockers,
    bool ActivationReady,
    IReadOnlyList<string> ActivationBlockers,
    bool Enabled,
    bool ApprovalHashMatches,
    bool BaselineHashMatches,
    IReadOnlyList<string> DeclaredRoles,
    IReadOnlyList<string> ApplicableRoleSources,
    IReadOnlyList<string> NotApplicableRoleSources,
    IReadOnlyList<string> PolicySnapshotTypes,
    string JournalScope,
    string RequiredPrivileges,
    string HostChanges,
    string Privacy,
    string Bounds,
    string Rollback);
