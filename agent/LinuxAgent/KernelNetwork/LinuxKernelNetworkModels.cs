using System.Text.Json.Serialization;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public static class LinuxKernelNetworkConstants
{
    public const string HelperVersion = "challenger-siem-ebpf-helper-v1";
    public const string CollectorVersion = "linux-network-flow-summary-v2";
    public const string SocketPath = "/run/challenger-siem-ebpf/challenger-siem-ebpf.sock";
    public const string StatePath = "/var/lib/challenger-siem-agent/kernel-network-state.json";
    public const int MaximumFrameBytes = 16_384;
    public const int FlowMapEntries = 16_384;
    public const int OwnerMapEntries = 32_768;
    public const int RingBytes = 1024 * 1024;
    public const int MaximumRecordsPerDrain = 500;
    public const int MaximumDurableBatchEvents = 100;
    public const int MaximumDurableBatchBytes = 1024 * 1024;
}

public sealed record LinuxKernelNetworkFrame
{
    [JsonIgnore] public IReadOnlySet<string> PresentProperties { get; init; } = new HashSet<string>(StringComparer.Ordinal);
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; init; }
    [JsonPropertyName("helper_version")] public string HelperVersion { get; init; } = string.Empty;
    [JsonPropertyName("epoch")] public string Epoch { get; init; } = string.Empty;
    [JsonPropertyName("sequence")] public ulong Sequence { get; init; }
    [JsonPropertyName("type")] public string Type { get; init; } = string.Empty;
    [JsonPropertyName("event_code")] public string? EventCode { get; init; }
    [JsonPropertyName("payload_capture")] public bool PayloadCapture { get; init; }
    [JsonPropertyName("flow_capacity")] public int FlowCapacity { get; init; }
    [JsonPropertyName("owner_capacity")] public int OwnerCapacity { get; init; }
    [JsonPropertyName("ring_bytes")] public int RingBytes { get; init; }
    [JsonPropertyName("drain_seconds")] public int DrainSeconds { get; init; }
    [JsonPropertyName("max_records_per_drain")] public int MaxRecordsPerDrain { get; init; }
    [JsonPropertyName("family")] public int Family { get; init; }
    [JsonPropertyName("protocol")] public string? Protocol { get; init; }
    [JsonPropertyName("direction")] public string? Direction { get; init; }
    [JsonPropertyName("local_ip")] public string? LocalIp { get; init; }
    [JsonPropertyName("local_port")] public int LocalPort { get; init; }
    [JsonPropertyName("remote_ip")] public string? RemoteIp { get; init; }
    [JsonPropertyName("remote_port")] public int RemotePort { get; init; }
    [JsonPropertyName("process_id")] public uint ProcessId { get; init; }
    [JsonPropertyName("user_id")] public uint UserId { get; init; }
    [JsonPropertyName("process_name")] public string? ProcessName { get; init; }
    [JsonPropertyName("attribution_source")] public string? AttributionSource { get; init; }
    [JsonPropertyName("first_seen_unix_ns")] public ulong FirstSeenUnixNanoseconds { get; init; }
    [JsonPropertyName("last_seen_unix_ns")] public ulong LastSeenUnixNanoseconds { get; init; }
    [JsonPropertyName("packet_count_delta")] public ulong PacketCountDelta { get; init; }
    [JsonPropertyName("byte_count_delta")] public ulong ByteCountDelta { get; init; }
    [JsonPropertyName("tcp_flags_mask")] public uint TcpFlagsMask { get; init; }
    [JsonPropertyName("parse_failures")] public ulong ParseFailures { get; init; }
    [JsonPropertyName("unsupported_headers")] public ulong UnsupportedHeaders { get; init; }
    [JsonPropertyName("flow_map_full")] public ulong FlowMapFull { get; init; }
    [JsonPropertyName("owner_misses")] public ulong OwnerMisses { get; init; }
    [JsonPropertyName("ring_losses")] public ulong RingLosses { get; init; }
    [JsonPropertyName("ipc_send_failures")] public ulong IpcSendFailures { get; init; }
}

public sealed record LinuxKernelNetworkPendingFrame(
    LinuxKernelNetworkFrame Frame,
    DateTimeOffset EventTime);

public sealed record LinuxKernelNetworkReceivedFlow(
    LinuxKernelNetworkFrame Frame,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen);

public sealed record LinuxKernelNetworkDrain(
    IReadOnlyList<LinuxKernelNetworkReceivedFlow> Flows,
    LinuxKernelNetworkFrame Health,
    long ReceiveDurationMilliseconds);

public sealed record LinuxKernelNetworkDrainDiagnostics(
    int RecordCount,
    long SerializedBytes,
    int UniqueEnrichmentIdentities,
    int EnrichmentCacheHits,
    long ReceiveDurationMilliseconds,
    long PersistDurationMilliseconds);

public sealed record LinuxKernelNetworkSequenceAssignment(
    long AgentSequence,
    bool HelperGap);

public sealed record LinuxKernelNetworkState
{
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; init; } = 2;
    [JsonPropertyName("next_sequence")] public long NextSequence { get; init; } = 1;
    [JsonPropertyName("collected_sequence")] public long CollectedSequence { get; init; }
    [JsonPropertyName("acknowledged_sequence")] public long AcknowledgedSequence { get; init; }
    [JsonPropertyName("pending_reservation_start")] public long? PendingReservationStart { get; init; }
    [JsonPropertyName("pending_reservation_end")] public long? PendingReservationEnd { get; init; }
    [JsonPropertyName("pending_reservation_helper_epoch")] public string? PendingReservationHelperEpoch { get; init; }
    [JsonPropertyName("pending_reservation_helper_sequence")] public ulong? PendingReservationHelperSequence { get; init; }
    [JsonPropertyName("abandoned_through_sequence")] public long AbandonedThroughSequence { get; init; }
    [JsonPropertyName("last_helper_epoch")] public string? LastHelperEpoch { get; init; }
    [JsonPropertyName("last_helper_sequence")] public ulong LastHelperSequence { get; init; }
    [JsonPropertyName("observed_at")] public DateTimeOffset? ObservedAt { get; init; }
    [JsonPropertyName("last_event_at")] public DateTimeOffset? LastEventAt { get; init; }
    [JsonPropertyName("acknowledged_at")] public DateTimeOffset? AcknowledgedAt { get; init; }
    [JsonPropertyName("gap_count")] public long GapCount { get; init; }
    [JsonPropertyName("dropped_count")] public long DroppedCount { get; init; }
    [JsonPropertyName("parse_failures")] public ulong ParseFailures { get; init; }
    [JsonPropertyName("unsupported_headers")] public ulong UnsupportedHeaders { get; init; }
    [JsonPropertyName("flow_map_full")] public ulong FlowMapFull { get; init; }
    [JsonPropertyName("owner_misses")] public ulong OwnerMisses { get; init; }
    [JsonPropertyName("ring_losses")] public ulong RingLosses { get; init; }
    [JsonPropertyName("ipc_send_failures")] public ulong IpcSendFailures { get; init; }
    [JsonPropertyName("helper_restart_count")] public long HelperRestartCount { get; init; }
    [JsonPropertyName("helper_connection_failure_count")] public long HelperConnectionFailureCount { get; init; }
    [JsonPropertyName("queue_pressure_count")] public long QueuePressureCount { get; init; }
    [JsonPropertyName("last_drain_record_count")] public int LastDrainRecordCount { get; init; }
    [JsonPropertyName("high_water_drain_record_count")] public int HighWaterDrainRecordCount { get; init; }
    [JsonPropertyName("last_drain_serialized_bytes")] public long LastDrainSerializedBytes { get; init; }
    [JsonPropertyName("last_drain_unique_enrichment_identities")] public int LastDrainUniqueEnrichmentIdentities { get; init; }
    [JsonPropertyName("last_drain_enrichment_cache_hits")] public int LastDrainEnrichmentCacheHits { get; init; }
    [JsonPropertyName("last_drain_receive_duration_ms")] public long LastDrainReceiveDurationMilliseconds { get; init; }
    [JsonPropertyName("last_drain_persist_duration_ms")] public long LastDrainPersistDurationMilliseconds { get; init; }
    [JsonPropertyName("active_loss")] public bool ActiveLoss { get; init; }
    [JsonPropertyName("clean_health_frames")] public int CleanHealthFrames { get; init; }
    [JsonPropertyName("event_family_counts")] public IReadOnlyDictionary<string, long> EventFamilyCounts { get; init; } = new Dictionary<string, long>(StringComparer.Ordinal);
    [JsonPropertyName("last_error")] public string LastError { get; init; } = "awaiting_helper";
    [JsonPropertyName("last_connection_error")] public string LastConnectionError { get; init; } = "none";
}

public sealed record LinuxKernelNetworkPlan(
    string PlanHash,
    bool Enabled,
    bool ApprovalHashMatches,
    string Platform,
    string Architecture,
    string HelperVersion,
    string CollectorVersion,
    string HelperSha256,
    string SignerPublicKeySha256,
    string Dependencies,
    string IpcBoundary,
    string SignedBundle,
    string CgroupRoot,
    string SocketPath,
    string RequiredCapabilities,
    string PrivacyBoundary,
    string Attachments,
    string Bounds,
    string Rollback);

public sealed record LinuxKernelProcessMetadata(
    string? Executable,
    string? CommandLine,
    string? UserId,
    bool Redacted,
    bool Truncated,
    string Confidence);
