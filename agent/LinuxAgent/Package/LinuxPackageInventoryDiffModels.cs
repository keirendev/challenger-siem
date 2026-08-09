using System.Text.Json.Serialization;
using Challenger.Siem.Contracts.V2;

namespace Challenger.Siem.LinuxAgent.Package;

public static class LinuxPackageInventoryDiffConstants
{
    public const string StatePath = "/var/lib/challenger-siem-agent/package-inventory-diff-state.json";
    public const string CollectorVersion = "linux-package-inventory-diff-v1";
    public const int StateSchemaVersion = 1;
    public const int MaximumEventsPerObservation = 200;
    public const int MaximumStateBytes = 4 * 1024 * 1024;
    public const long MaximumSequence = long.MaxValue - 10_000;
}

public sealed record LinuxPackageBaselineEntry
{
    [JsonPropertyName("name")] public string Name { get; init; } = string.Empty;
    [JsonPropertyName("version")] public string Version { get; init; } = string.Empty;
}

public sealed record LinuxPackageInventoryDiffState
{
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; init; } = LinuxPackageInventoryDiffConstants.StateSchemaVersion;
    [JsonPropertyName("next_sequence")] public long NextSequence { get; init; } = 1;
    [JsonPropertyName("collected_sequence")] public long CollectedSequence { get; init; }
    [JsonPropertyName("acknowledged_sequence")] public long AcknowledgedSequence { get; init; }
    [JsonPropertyName("abandoned_through_sequence")] public long AbandonedThroughSequence { get; init; }
    [JsonPropertyName("pending_reservation_start")] public long? PendingReservationStart { get; init; }
    [JsonPropertyName("pending_reservation_end")] public long? PendingReservationEnd { get; init; }
    [JsonPropertyName("baseline_collected_at")] public DateTimeOffset? BaselineCollectedAt { get; init; }
    [JsonPropertyName("last_observed_at")] public DateTimeOffset? LastObservedAt { get; init; }
    [JsonPropertyName("last_event_at")] public DateTimeOffset? LastEventAt { get; init; }
    [JsonPropertyName("acknowledged_at")] public DateTimeOffset? AcknowledgedAt { get; init; }
    [JsonPropertyName("status")] public string Status { get; init; } = SourceHealthStatuses.Missing;
    [JsonPropertyName("error_code")] public string ErrorCode { get; init; } = "awaiting_package_inventory_baseline";
    [JsonPropertyName("active_gap")] public bool ActiveGap { get; init; }
    [JsonPropertyName("gap_count")] public long GapCount { get; init; }
    [JsonPropertyName("dropped_count")] public long DroppedCount { get; init; }
    [JsonPropertyName("transition_state")] public string TransitionState { get; init; } = HealthTransitionStates.Unknown;
    [JsonPropertyName("transitioned_at")] public DateTimeOffset? TransitionedAt { get; init; }
    [JsonPropertyName("producer")] public string Producer { get; init; } = "unknown";
    [JsonPropertyName("baseline")]
    public IReadOnlyDictionary<string, LinuxPackageBaselineEntry> Baseline { get; init; } =
        new Dictionary<string, LinuxPackageBaselineEntry>(StringComparer.Ordinal);
    [JsonPropertyName("family_counts")]
    public IReadOnlyDictionary<string, long> FamilyCounts { get; init; } =
        new Dictionary<string, long>(StringComparer.Ordinal);
}

public sealed record LinuxPackageStateReadResult(LinuxPackageInventoryDiffState State, string ErrorCode);

internal sealed record LinuxPackageChange(
    string Action,
    string Key,
    string PackageName,
    string? PreviousVersion,
    string? CurrentVersion);
