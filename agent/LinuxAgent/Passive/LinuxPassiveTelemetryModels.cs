using System.Text.Json.Serialization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Passive;

public static class PassiveReadStatuses
{
    public const string Success = "success";
    public const string Partial = "partial";
    public const string Missing = "missing";
    public const string PermissionDenied = "permission_denied";
    public const string Error = "error";
}

public static class LinuxPassiveTelemetryLimits
{
    public const int StateSchemaVersion = 1;
    public const int MaximumProcesses = 4096;
    public const int MaximumSockets = 8192;
    public const int PartialBaselineMissLimit = 12;
    public const int MaximumFamilyCountEntries = 8;
    public const int MaximumHealthDetailEntries = 32;
    public const long MaximumSequence = long.MaxValue - 10_000;
}

public sealed record PassiveReadResult<T>(
    IReadOnlyList<T> Items,
    string Status,
    string ErrorCode,
    bool Truncated,
    long BytesRead,
    long SkippedCount = 0,
    long VisibilityGapCount = 0,
    IReadOnlyDictionary<string, string>? Details = null,
    long ExpectedRaceSkipCount = 0,
    long CoverageGapReadSkipCount = 0);

public sealed record LinuxProcessObservation(
    string Key,
    string Signature,
    int ProcessId,
    int ParentProcessId,
    long StartTicks,
    string State,
    string Command,
    string? Executable,
    string? CommandLine,
    string? UserId,
    string? GroupId,
    string? EffectiveCapabilities,
    bool? NoNewPrivileges,
    int? SeccompMode,
    int? TracerProcessId,
    string? LoginUserId,
    string? CgroupSha256,
    bool CommandLineRedacted,
    bool CommandLineTruncated,
    bool InvalidText,
    bool EnrichmentPartial,
    bool CommandRedacted = false,
    bool ExecutableRedacted = false,
    bool ExecutableTruncated = false);

public sealed record LinuxProcessBaseline
{
    [JsonPropertyName("signature")] public string Signature { get; init; } = string.Empty;
    [JsonPropertyName("process_id")] public int ProcessId { get; init; }
    [JsonPropertyName("parent_process_id")] public int ParentProcessId { get; init; }
    [JsonPropertyName("enrichment_partial")] public bool EnrichmentPartial { get; init; }
    [JsonPropertyName("missed_partial_scans")] public int MissedPartialScans { get; init; }
}

public sealed record LinuxSocketObservation(
    string Key,
    string Signature,
    string Protocol,
    string State,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int? RemotePort,
    long? Inode,
    string? UserId,
    int Count);

public sealed record LinuxSocketBaseline
{
    [JsonPropertyName("signature")] public string Signature { get; init; } = string.Empty;
    [JsonPropertyName("protocol")] public string Protocol { get; init; } = string.Empty;
    [JsonPropertyName("state")] public string State { get; init; } = string.Empty;
    [JsonPropertyName("local_address")] public string LocalAddress { get; init; } = string.Empty;
    [JsonPropertyName("local_port")] public int LocalPort { get; init; }
    [JsonPropertyName("remote_address")] public string? RemoteAddress { get; init; }
    [JsonPropertyName("remote_port")] public int? RemotePort { get; init; }
    [JsonPropertyName("inode")] public long? Inode { get; init; }
    [JsonPropertyName("user_id")] public string? UserId { get; init; }
    [JsonPropertyName("count")] public int Count { get; init; } = 1;
    [JsonPropertyName("missed_partial_scans")] public int MissedPartialScans { get; init; }
}

public sealed record LinuxHostMetricsObservation
{
    [JsonPropertyName("observed_at")] public DateTimeOffset ObservedAt { get; init; }
    [JsonPropertyName("uptime_seconds")] public long? UptimeSeconds { get; init; }
    [JsonPropertyName("load_1_milli")] public long? Load1Milli { get; init; }
    [JsonPropertyName("load_5_milli")] public long? Load5Milli { get; init; }
    [JsonPropertyName("load_15_milli")] public long? Load15Milli { get; init; }
    [JsonPropertyName("memory_total_bytes")] public long? MemoryTotalBytes { get; init; }
    [JsonPropertyName("memory_available_bytes")] public long? MemoryAvailableBytes { get; init; }
    [JsonPropertyName("swap_free_bytes")] public long? SwapFreeBytes { get; init; }
    [JsonPropertyName("processes_running")] public long? ProcessesRunning { get; init; }
    [JsonPropertyName("processes_blocked")] public long? ProcessesBlocked { get; init; }
    [JsonPropertyName("cpu_total_ticks")] public long? CpuTotalTicks { get; init; }
    [JsonPropertyName("cpu_idle_ticks")] public long? CpuIdleTicks { get; init; }
    [JsonPropertyName("disk_read_sectors")] public long? DiskReadSectors { get; init; }
    [JsonPropertyName("disk_written_sectors")] public long? DiskWrittenSectors { get; init; }
    [JsonPropertyName("network_receive_bytes")] public long? NetworkReceiveBytes { get; init; }
    [JsonPropertyName("network_transmit_bytes")] public long? NetworkTransmitBytes { get; init; }
    [JsonPropertyName("cpu_pressure_some_avg10_milli")] public long? CpuPressureSomeAvg10Milli { get; init; }
    [JsonPropertyName("memory_pressure_some_avg10_milli")] public long? MemoryPressureSomeAvg10Milli { get; init; }
    [JsonPropertyName("io_pressure_some_avg10_milli")] public long? IoPressureSomeAvg10Milli { get; init; }
}

public sealed record PassiveSourceProgress
{
    [JsonPropertyName("next_sequence")] public long NextSequence { get; init; } = 1;
    [JsonPropertyName("collected_sequence")] public long CollectedSequence { get; init; }
    [JsonPropertyName("acknowledged_sequence")] public long AcknowledgedSequence { get; init; }
    [JsonPropertyName("last_scan_at")] public DateTimeOffset? LastScanAt { get; init; }
    [JsonPropertyName("last_event_at")] public DateTimeOffset? LastEventAt { get; init; }
    [JsonPropertyName("acknowledged_at")] public DateTimeOffset? AcknowledgedAt { get; init; }
    [JsonPropertyName("pending_reservation_start")] public long? PendingReservationStart { get; init; }
    [JsonPropertyName("pending_reservation_end")] public long? PendingReservationEnd { get; init; }
    [JsonPropertyName("abandoned_sequence_count")] public long AbandonedSequenceCount { get; init; }
    [JsonPropertyName("cumulative_gap_count")] public long CumulativeGapCount { get; init; }
    [JsonPropertyName("cumulative_read_skip_count")] public long CumulativeReadSkipCount { get; init; }
    [JsonPropertyName("cumulative_expected_race_skip_count")] public long CumulativeExpectedRaceSkipCount { get; init; }
    [JsonPropertyName("cumulative_coverage_gap_read_skip_count")] public long CumulativeCoverageGapReadSkipCount { get; init; }
    [JsonPropertyName("cumulative_dropped_count")] public long CumulativeDroppedCount { get; init; }
    [JsonPropertyName("cumulative_sampled_count")] public long CumulativeSampledCount { get; init; }
    [JsonPropertyName("cumulative_pressure_scan_count")] public long CumulativePressureScanCount { get; init; }
    [JsonPropertyName("active_gap_detected")] public bool ActiveGapDetected { get; init; }
    [JsonPropertyName("active_bookmark_gap_detected")] public bool ActiveBookmarkGapDetected { get; init; }
    [JsonPropertyName("deferred_count")] public long DeferredCount { get; init; }
    [JsonPropertyName("last_health_status")] public string LastHealthStatus { get; init; } = SourceHealthStatuses.Missing;
    [JsonPropertyName("last_health_error_code")] public string LastHealthErrorCode { get; init; } = "awaiting_first_scan";
    [JsonPropertyName("last_health_partial")] public bool LastHealthPartial { get; init; }
    [JsonPropertyName("last_health_details")] public IReadOnlyDictionary<string, string> LastHealthDetails { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    [JsonPropertyName("health_transition_state")] public string HealthTransitionState { get; init; } = HealthTransitionStates.Unknown;
    [JsonPropertyName("health_transitioned_at")] public DateTimeOffset? HealthTransitionedAt { get; init; }
    [JsonPropertyName("last_queue_depth_at_pressure")] public int? LastQueueDepthAtPressure { get; init; }
    [JsonPropertyName("last_queue_bytes_at_pressure")] public long? LastQueueBytesAtPressure { get; init; }
    [JsonPropertyName("family_counts")] public IReadOnlyDictionary<string, long> FamilyCounts { get; init; } =
        new Dictionary<string, long>(StringComparer.Ordinal);
}

public sealed record LinuxPassiveProcessState
{
    [JsonPropertyName("baseline_established")] public bool BaselineEstablished { get; init; }
    [JsonPropertyName("progress")] public PassiveSourceProgress Progress { get; init; } = new();
    [JsonPropertyName("baseline")] public IReadOnlyDictionary<string, LinuxProcessBaseline> Baseline { get; init; } =
        new Dictionary<string, LinuxProcessBaseline>(StringComparer.Ordinal);
}

public sealed record LinuxPassiveNetworkState
{
    [JsonPropertyName("baseline_established")] public bool BaselineEstablished { get; init; }
    [JsonPropertyName("progress")] public PassiveSourceProgress Progress { get; init; } = new();
    [JsonPropertyName("baseline")] public IReadOnlyDictionary<string, LinuxSocketBaseline> Baseline { get; init; } =
        new Dictionary<string, LinuxSocketBaseline>(StringComparer.Ordinal);
}

public sealed record LinuxPassiveMetricsState
{
    [JsonPropertyName("progress")] public PassiveSourceProgress Progress { get; init; } = new();
    [JsonPropertyName("previous")] public LinuxHostMetricsObservation? Previous { get; init; }
}

public sealed record LinuxPassiveTelemetryState
{
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; init; } = LinuxPassiveTelemetryLimits.StateSchemaVersion;
    [JsonPropertyName("boot_identity_sha256")] public string? BootIdentitySha256 { get; init; }
    [JsonPropertyName("process")] public LinuxPassiveProcessState Process { get; init; } = new();
    [JsonPropertyName("network")] public LinuxPassiveNetworkState Network { get; init; } = new();
    [JsonPropertyName("metrics")] public LinuxPassiveMetricsState Metrics { get; init; } = new();
}

public sealed record PassiveStateReadResult(LinuxPassiveTelemetryState State, string ErrorCode);

public sealed record PassiveCollectionResult(
    string SourceId,
    IReadOnlyList<EventEnvelope> Events,
    LinuxPassiveTelemetryState NewState,
    string HealthStatus,
    string ErrorCode,
    long GapCount,
    long ReadSkipCount,
    long DroppedCount,
    long DeferredCount,
    long SampledCount,
    bool Partial,
    IReadOnlyDictionary<string, string> Details,
    long ExpectedRaceSkipCount = 0,
    long CoverageGapReadSkipCount = 0);

public sealed record PassiveTelemetryPlanSource(
    string SourceId,
    IReadOnlyList<string> FixedInputs,
    string Evidence,
    string Privacy,
    string Bounds);

public sealed record PassiveTelemetryPlan(
    string PlanHash,
    string Platform,
    bool Enabled,
    bool ApprovalHashMatches,
    string RequiredPrivileges,
    string HostChanges,
    string Exclusions,
    string PressureOrdering,
    string StatePath,
    IReadOnlyList<PassiveTelemetryPlanSource> Sources);

public interface ILinuxProcessSnapshotSource
{
    Task<PassiveReadResult<LinuxProcessObservation>> ReadAsync(PassiveTelemetryOptions options, CancellationToken cancellationToken);
}

public interface ILinuxNetworkSnapshotSource
{
    Task<PassiveReadResult<LinuxSocketObservation>> ReadAsync(PassiveTelemetryOptions options, CancellationToken cancellationToken);
}

public interface ILinuxHostMetricsSource
{
    Task<PassiveReadResult<LinuxHostMetricsObservation>> ReadAsync(PassiveTelemetryOptions options, CancellationToken cancellationToken);
}
