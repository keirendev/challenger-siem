using System.Globalization;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Services;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.L4;

public interface ILinuxInventoryObserver
{
    Task ObserveInventoryAsync(IReadOnlyList<AssetInventorySnapshot> snapshots, CancellationToken cancellationToken);
}

public sealed class LinuxL4TelemetryRuntime(
    IOptions<LinuxAgentOptions> configured,
    LinuxL4TelemetryStateStore stateStore,
    LinuxL4TelemetryCollector collector,
    IEventQueue queue,
    TimeProvider timeProvider) : ILinuxAcknowledgementObserver, ILinuxInventoryObserver
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly SemaphoreSlim collectionGate = new(1, 1);
    private readonly object sync = new();
    private LinuxL4TelemetryState state = new();
    private string stateError = "not_initialized";
    private bool initialized;
    private bool cleanupAttempted;
    private DateTimeOffset notBefore;
    private IReadOnlyList<AssetInventorySnapshot>? pendingInventory;

    public bool IsEnabledAndApproved => options.Journal.TargetCoverageLevel >= WindowsCoverageLevel.L4 && collector.IsEnabledAndApproved;
    private bool StateReady { get { lock (sync) return stateError is "none" or "collector_state_cleaned"; } }
    public bool CleanupRequested => !options.L4Telemetry.Enabled && options.L4Telemetry.CleanupStateOnDisable;
    public LinuxL4TelemetryState CurrentState { get { lock (sync) return state; } }

    public IReadOnlyList<SourceManifestEntry> Manifest => LinuxTelemetrySourceCatalog.L4
        .Where(entry => entry.SourceId is LinuxTelemetrySourceIds.PolicyPostureDrift or LinuxTelemetrySourceIds.AgentPerformanceSlo)
        .Select(entry => entry with
        {
            Applicability = SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = null
        })
        .ToArray();

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (initialized) return;
            var read = await stateStore.ReadAsync(cancellationToken);
            var recovered = RecoverReservations(read.State, timeProvider.GetUtcNow(), out var changed);
            if (changed) await stateStore.WriteAsync(recovered, cancellationToken);
            lock (sync)
            {
                state = recovered;
                stateError = read.ErrorCode;
                initialized = true;
                notBefore = timeProvider.GetUtcNow().AddSeconds(options.L4Telemetry.StartupDelaySeconds);
            }
        }
        finally { gate.Release(); }
    }

    public async Task CleanupIfDisabledAsync(CancellationToken cancellationToken)
    {
        if (!CleanupRequested) return;
        await stateStore.CleanupAsync(cancellationToken);
        lock (sync)
        {
            state = new();
            stateError = "collector_state_cleaned";
            initialized = true;
            cleanupAttempted = true;
        }
    }

    public async Task ObserveInventoryAsync(IReadOnlyList<AssetInventorySnapshot> snapshots, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        if (!IsEnabledAndApproved || !StateReady) return;
        lock (sync) pendingInventory = snapshots.ToArray();
        await CollectPendingPolicyAsync(cancellationToken);
    }

    public async Task CollectPendingPolicyAsync(CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        if (!IsEnabledAndApproved || !StateReady) return;
        await collectionGate.WaitAsync(cancellationToken);
        try
        {
            var now = timeProvider.GetUtcNow();
            var current = CurrentState;
            IReadOnlyList<AssetInventorySnapshot>? snapshots;
            lock (sync) snapshots = pendingInventory;
            if (snapshots is null) return;
            if (now < notBefore
                || current.Policy.Progress.LastObservedAt.HasValue
                    && now - current.Policy.Progress.LastObservedAt.Value < TimeSpan.FromSeconds(options.L4Telemetry.PostureIntervalSeconds)) return;
            var pressure = await PressureReasonAsync(cancellationToken);
            if (pressure is not null)
            {
                await RecordPressureStateAsync(LinuxTelemetrySourceIds.PolicyPostureDrift, pressure, cancellationToken);
                return;
            }
            var latestCollectedAt = snapshots.Count == 0 ? (DateTimeOffset?)null : snapshots.Max(item => item.CollectedAt);
            var staleAfter = TimeSpan.FromSeconds(options.InventoryIntervalSeconds + 300L);
            var invalidTime = !latestCollectedAt.HasValue
                || latestCollectedAt.Value > now.AddMinutes(5)
                || now - latestCollectedAt.Value > staleAfter;
            var result = invalidTime
                ? collector.BuildPressureGap(CurrentState, LinuxTelemetrySourceIds.PolicyPostureDrift,
                    options.AgentId, Environment.MachineName, "inventory_snapshot_stale")
                : collector.CollectPolicy(CurrentState, snapshots, options.AgentId, Environment.MachineName);
            await CommitAsync(result, cancellationToken);
            lock (sync)
            {
                if (ReferenceEquals(pendingInventory, snapshots)) pendingInventory = null;
            }
        }
        finally { collectionGate.Release(); }
    }

    public async Task CollectSloAsync(CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        if (!IsEnabledAndApproved || !StateReady) return;
        await collectionGate.WaitAsync(cancellationToken);
        try
        {
            var metrics = await queue.GetMetricsAsync(null, cancellationToken);
            var pressure = PressureReason(metrics);
            if (pressure is not null)
            {
                await RecordPressureStateAsync(LinuxTelemetrySourceIds.AgentPerformanceSlo, pressure, cancellationToken);
                return;
            }
            var result = await collector.CollectSloAsync(CurrentState, metrics, options.AgentId, Environment.MachineName, cancellationToken);
            await CommitAsync(result, cancellationToken);
        }
        finally { collectionGate.Release(); }
    }

    public IReadOnlyList<SourceHealthReport> Health()
    {
        lock (sync)
        {
            return Manifest.Select(manifest => BuildHealth(manifest, ProgressFor(state, manifest.SourceId))).ToArray();
        }
    }

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        var nonContiguousAccepted = false;
        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState;
            foreach (var group in events.Where(item => HandlesSource(item.SourceId) && item.Checkpoint?.Sequence is not null)
                .GroupBy(item => item.SourceId!, StringComparer.Ordinal))
            {
                var progress = ProgressFor(current, group.Key);
                var accepted = group.Select(item => item.Checkpoint!.Sequence!.Value)
                    .Where(sequence => sequence <= progress.CollectedSequence)
                    .ToHashSet();
                var acknowledgementBase = Math.Max(progress.AcknowledgedSequence, progress.AbandonedThroughSequence);
                var acknowledgementCursor = acknowledgementBase;
                while (acknowledgementCursor < progress.CollectedSequence && accepted.Contains(acknowledgementCursor + 1)) acknowledgementCursor++;
                var acknowledged = acknowledgementCursor > acknowledgementBase || acknowledgementBase == progress.AcknowledgedSequence
                    ? acknowledgementCursor
                    : progress.AcknowledgedSequence;
                var groupNonContiguous = accepted.Any(sequence => sequence > acknowledged);
                nonContiguousAccepted |= groupNonContiguous;
                var recoveryAcknowledged = progress.RecoveryGapSequence.HasValue
                    && acknowledged >= progress.RecoveryGapSequence.Value;
                var acknowledgementRecovered = !groupNonContiguous
                    && acknowledged > progress.AcknowledgedSequence
                    && progress.ErrorCode == "l4_acknowledgement_non_contiguous";
                progress = progress with
                {
                    AcknowledgedSequence = Math.Max(progress.AcknowledgedSequence, acknowledged),
                    AcknowledgedAt = acknowledged > progress.AcknowledgedSequence ? timeProvider.GetUtcNow() : progress.AcknowledgedAt,
                    ActiveGap = groupNonContiguous || (!acknowledgementRecovered && !recoveryAcknowledged && progress.ActiveGap),
                    RecoveryGapSequence = recoveryAcknowledged ? null : progress.RecoveryGapSequence,
                    Status = groupNonContiguous ? SourceHealthStatuses.Error
                        : acknowledgementRecovered ? SourceHealthStatuses.Degraded : progress.Status,
                    ErrorCode = groupNonContiguous ? "l4_acknowledgement_non_contiguous"
                        : acknowledgementRecovered ? "acknowledgement_recovered_pending_sample" : progress.ErrorCode,
                    GapCount = groupNonContiguous && progress.ErrorCode != "l4_acknowledgement_non_contiguous"
                        ? SaturatingAdd(progress.GapCount, 1) : progress.GapCount,
                    TransitionState = groupNonContiguous ? HealthTransitionStates.Degraded
                        : acknowledgementRecovered ? HealthTransitionStates.Recovering : progress.TransitionState,
                    TransitionedAt = groupNonContiguous || acknowledgementRecovered ? timeProvider.GetUtcNow() : progress.TransitionedAt
                };
                current = WithProgress(current, group.Key, progress);
            }
            await stateStore.WriteAsync(current, cancellationToken);
            lock (sync) state = current;
        }
        finally { gate.Release(); }
        if (nonContiguousAccepted)
            throw new InvalidOperationException("L4 acknowledgement contained a non-contiguous accepted sequence; accepted rows remain queued for safe retry.");
    }

    public bool HandlesSource(string? sourceId) => sourceId is LinuxTelemetrySourceIds.PolicyPostureDrift or LinuxTelemetrySourceIds.AgentPerformanceSlo;

    public async Task RecordRejectedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        var nonContiguousRejected = false;
        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState;
            var now = timeProvider.GetUtcNow();
            foreach (var group in events.Where(item => HandlesSource(item.SourceId) && item.Checkpoint?.Sequence is not null)
                .GroupBy(item => item.SourceId!, StringComparer.Ordinal))
            {
                var progress = ProgressFor(current, group.Key);
                var rejected = group.Select(item => item.Checkpoint!.Sequence!.Value)
                    .Where(sequence => sequence <= progress.CollectedSequence)
                    .Distinct().Order().ToArray();
                if (rejected.Length == 0) continue;
                var rejectionCursor = Math.Max(progress.AcknowledgedSequence, progress.AbandonedThroughSequence);
                var newlyRejected = 0L;
                var groupNonContiguous = false;
                foreach (var sequence in rejected)
                {
                    if (sequence <= rejectionCursor) continue;
                    if (sequence != rejectionCursor + 1)
                    {
                        groupNonContiguous = true;
                        break;
                    }
                    rejectionCursor = sequence;
                    newlyRejected++;
                }
                nonContiguousRejected |= groupNonContiguous;
                var error = groupNonContiguous ? "l4_rejection_non_contiguous" : "l4_server_rejected_sequence";
                progress = progress with
                {
                    AbandonedThroughSequence = Math.Max(progress.AbandonedThroughSequence, rejectionCursor),
                    RecoveryGapSequence = null,
                    ActiveGap = true,
                    GapCount = SaturatingAdd(progress.GapCount, newlyRejected),
                    DroppedCount = SaturatingAdd(progress.DroppedCount, newlyRejected),
                    Status = SourceHealthStatuses.Error,
                    ErrorCode = error,
                    TransitionState = HealthTransitionStates.Degraded,
                    TransitionedAt = now
                };
                current = WithProgress(current, group.Key, progress);
            }
            await stateStore.WriteAsync(current, cancellationToken);
            lock (sync) state = current;
        }
        finally { gate.Release(); }
        if (nonContiguousRejected)
            throw new InvalidOperationException("L4 rejection was not the next contiguous sequence; the row remains queued until earlier outcomes are durable.");
    }

    public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events)
    {
        lock (sync)
        {
            var now = timeProvider.GetUtcNow();
            foreach (var sourceId in events.Select(item => item.SourceId).Where(HandlesSource).Distinct(StringComparer.Ordinal))
            {
                var currentProgress = ProgressFor(state, sourceId!);
                if (currentProgress.ErrorCode is "l4_acknowledgement_non_contiguous" or "l4_rejection_non_contiguous") continue;
                var progress = currentProgress with
                {
                    Status = SourceHealthStatuses.Error,
                    ErrorCode = "l4_acknowledgement_state_write_failed",
                    ActiveGap = true,
                    GapCount = SaturatingAdd(ProgressFor(state, sourceId!).GapCount, 1),
                    TransitionState = HealthTransitionStates.Degraded,
                    TransitionedAt = now
                };
                state = WithProgress(state, sourceId!, progress);
            }
        }
    }

    private async Task CommitAsync(LinuxL4CollectionResult result, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState;
            current = RecoverReservations(current, timeProvider.GetUtcNow(), out var recovered);
            if (recovered) await stateStore.WriteAsync(current, cancellationToken);
            if (result.Events.Count == 0)
            {
                var merged = MergeSourceState(current, result.NewState, result.SourceId);
                await stateStore.WriteAsync(merged, cancellationToken);
                lock (sync) state = merged;
                return;
            }

            var start = result.Events.Min(item => item.Checkpoint!.Sequence!.Value);
            var end = result.Events.Max(item => item.Checkpoint!.Sequence!.Value);
            var progress = ProgressFor(current, result.SourceId);
            if (start != progress.NextSequence)
                throw new InvalidOperationException("L4 collection sequence does not start at the durable next sequence.");
            var reservedProgress = progress with
            {
                NextSequence = end + 1,
                PendingReservationStart = start,
                PendingReservationEnd = end
            };
            var reserved = WithProgress(current, result.SourceId, reservedProgress);
            await stateStore.WriteAsync(reserved, cancellationToken);
            lock (sync) state = reserved;

            foreach (var envelope in result.Events) await queue.EnqueueAsync(envelope, cancellationToken);

            var mergedResult = MergeSourceState(current, result.NewState, result.SourceId);
            var committedProgress = ProgressFor(mergedResult, result.SourceId) with
            {
                NextSequence = end + 1,
                CollectedSequence = end,
                AcknowledgedSequence = progress.AcknowledgedSequence,
                AcknowledgedAt = progress.AcknowledgedAt,
                PendingReservationStart = null,
                PendingReservationEnd = null
            };
            var committed = WithProgress(mergedResult, result.SourceId, committedProgress);
            await stateStore.WriteAsync(committed, cancellationToken);
            lock (sync) state = committed;
        }
        finally { gate.Release(); }
    }

    private async Task RecordPressureStateAsync(string sourceId, string reason, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState;
            var progress = ProgressFor(current, sourceId);
            var newlyActive = !progress.ActiveGap || !string.Equals(progress.ErrorCode, reason, StringComparison.Ordinal);
            progress = progress with
            {
                LastObservedAt = timeProvider.GetUtcNow(),
                Status = SourceHealthStatuses.Degraded,
                ErrorCode = reason,
                ActiveGap = true,
                GapCount = newlyActive ? SaturatingAdd(progress.GapCount, 1) : progress.GapCount,
                TransitionState = HealthTransitionStates.Degraded,
                TransitionedAt = newlyActive ? timeProvider.GetUtcNow() : progress.TransitionedAt
            };
            current = WithProgress(current, sourceId, progress);
            await stateStore.WriteAsync(current, cancellationToken);
            lock (sync) state = current;
        }
        finally { gate.Release(); }
    }

    private SourceHealthReport BuildHealth(SourceManifestEntry manifest, LinuxL4SourceProgress progress)
    {
        var now = timeProvider.GetUtcNow();
        var requested = options.Journal.TargetCoverageLevel >= WindowsCoverageLevel.L4 && options.L4Telemetry.Enabled;
        var enabled = IsEnabledAndApproved;
        var stateReady = StateReady;
        var status = enabled && !stateReady ? SourceHealthStatuses.Error
            : enabled ? progress.Status : SourceHealthStatuses.Disabled;
        var error = enabled && !stateReady ? stateError
            : enabled ? progress.ErrorCode
            : !requested ? "source_above_configured_level"
            : !collector.HasApprovedBaseline ? "l4_approved_baseline_missing"
            : "l4_approval_hash_missing_or_mismatch";
        var prerequisite = manifest.Prerequisites.ToDictionary(item => item, item => item switch
        {
            "explicit_l4_opt_in" => options.L4Telemetry.Enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
            "approval_hash_matches" => enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
            "approved_baseline_matches" => !stateReady ? SourceEvidenceStatuses.Degraded
                : state.Policy.BaselineEstablished
                && string.Equals(state.Policy.ApprovedBaselineHash, options.L4Telemetry.ApprovedBaselineHash, StringComparison.Ordinal)
                    ? SourceEvidenceStatuses.Satisfied : enabled ? SourceEvidenceStatuses.Degraded : SourceEvidenceStatuses.Disabled,
            "bounded_inventory_available" => !stateReady ? SourceEvidenceStatuses.Degraded
                : state.Policy.Progress.Status == SourceHealthStatuses.Healthy
                ? SourceEvidenceStatuses.Satisfied : enabled ? SourceEvidenceStatuses.Degraded : SourceEvidenceStatuses.Disabled,
            "resource_counters_available" => !stateReady ? SourceEvidenceStatuses.Degraded
                : state.Slo.Progress.ErrorCode == "slo_counter_unavailable"
                ? SourceEvidenceStatuses.Degraded : enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
            "slo_window_complete" => !stateReady ? SourceEvidenceStatuses.Degraded
                : state.Slo.Progress.ErrorCode == "slo_window_warmup"
                ? SourceEvidenceStatuses.Degraded : state.Slo.Progress.Status == SourceHealthStatuses.Healthy
                    ? SourceEvidenceStatuses.Satisfied : enabled ? SourceEvidenceStatuses.Degraded : SourceEvidenceStatuses.Disabled,
            _ => enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled
        }, StringComparer.Ordinal);
        var families = manifest.EventFamilies.ToDictionary(item => item, item => FamilyObserved(item, progress)
            ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved, StringComparer.Ordinal);
        return new SourceHealthReport
        {
            SourceId = manifest.SourceId,
            Platform = manifest.Platform,
            SourceKind = manifest.SourceKind,
            DisplayName = manifest.DisplayName,
            SourceNamespace = manifest.SourceNamespace,
            Applicability = manifest.Applicability,
            ApplicabilityReason = manifest.ApplicabilityReason,
            CoverageLevel = manifest.CoverageLevel,
            Status = status,
            Required = true,
            Requirement = SourceRequirementKinds.Mandatory,
            Enabled = enabled,
            ObservedAt = progress.LastObservedAt ?? now,
            LastEventTime = progress.LastEventAt,
            CollectedCheckpoint = new SourceCheckpoint { Sequence = progress.CollectedSequence, EventTime = progress.LastEventAt, RecordedAt = progress.LastObservedAt },
            AcknowledgedCheckpoint = new SourceCheckpoint { Sequence = progress.AcknowledgedSequence, EventTime = progress.AcknowledgedAt, RecordedAt = progress.AcknowledgedAt },
            LagSeconds = progress.LastObservedAt.HasValue ? Math.Max(0, (long)(now - progress.LastObservedAt.Value).TotalSeconds) : null,
            SilenceSeconds = progress.LastEventAt.HasValue ? Math.Max(0, (long)(now - progress.LastEventAt.Value).TotalSeconds) : null,
            EventRatePerMinute = 0,
            ErrorCode = error == "none" ? null : error,
            ErrorMessage = error == "none" ? null : error,
            GapDetected = progress.ActiveGap,
            BookmarkGapDetected = progress.ActiveGap,
            GapCount = progress.GapCount,
            TransitionState = progress.TransitionState,
            TransitionedAt = progress.TransitionedAt,
            DroppedEvents = progress.DroppedCount,
            PoisonEvents = 0,
            ConfigHash = collector.PlanHash,
            SourceVersion = LinuxL4TelemetryCollector.CollectorVersion,
            PrerequisiteStatuses = prerequisite,
            EventFamilyStatuses = families,
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["collector_state"] = enabled ? "enabled" : "disabled",
                ["approval_state"] = enabled ? "matched" : options.L4Telemetry.Enabled ? "missing_or_mismatched" : "not_requested",
                ["baseline_state"] = state.Policy.BaselineEstablished ? "established" : "not_established",
                ["plan_hash"] = collector.PlanHash,
                ["interval_seconds"] = (manifest.SourceId == LinuxTelemetrySourceIds.PolicyPostureDrift
                    ? options.L4Telemetry.PostureIntervalSeconds : options.L4Telemetry.SloSampleIntervalSeconds).ToString(CultureInfo.InvariantCulture),
                ["gap_count"] = progress.GapCount.ToString(CultureInfo.InvariantCulture),
                ["state_read_status"] = stateError,
                ["cleanup_state"] = cleanupAttempted ? "collector_state_removed" : "not_requested"
            }
        };
    }

    private async Task<string?> PressureReasonAsync(CancellationToken cancellationToken) => PressureReason(await queue.GetMetricsAsync(null, cancellationToken));

    private string? PressureReason(QueueSloMetrics metrics)
    {
        if ((long)metrics.QueueDepth + options.L4Telemetry.MaxEventsPerScan > options.L4Telemetry.QueuePauseDepth)
            return "l4_queue_row_pressure";
        if (metrics.QueueSizeBytes is not { } used || metrics.MaxSizeBytes is not { } maximum || maximum <= 0)
            return "l4_queue_byte_state_unknown";
        var warning = maximum * options.Queue.WarningSizePercent / 100;
        return used >= warning ? "l4_queue_byte_pressure" : null;
    }

    private static LinuxL4TelemetryState RecoverReservations(LinuxL4TelemetryState value, DateTimeOffset now, out bool changed)
    {
        changed = false;
        foreach (var sourceId in new[] { LinuxTelemetrySourceIds.PolicyPostureDrift, LinuxTelemetrySourceIds.AgentPerformanceSlo })
        {
            var progress = ProgressFor(value, sourceId);
            if (!progress.PendingReservationStart.HasValue) continue;
            var abandoned = progress.PendingReservationEnd!.Value - progress.PendingReservationStart.Value + 1;
            progress = progress with
            {
                PendingReservationStart = null,
                PendingReservationEnd = null,
                AbandonedThroughSequence = Math.Max(progress.AbandonedThroughSequence, progress.PendingReservationEnd.Value),
                RecoveryGapSequence = null,
                ActiveGap = true,
                GapCount = SaturatingAdd(progress.GapCount, abandoned),
                Status = SourceHealthStatuses.Degraded,
                ErrorCode = "interrupted_sequence_reservation",
                TransitionState = HealthTransitionStates.Degraded,
                TransitionedAt = now
            };
            value = WithProgress(value, sourceId, progress);
            changed = true;
        }
        return value;
    }

    private static LinuxL4SourceProgress ProgressFor(LinuxL4TelemetryState value, string sourceId) => sourceId switch
    {
        LinuxTelemetrySourceIds.PolicyPostureDrift => value.Policy.Progress,
        LinuxTelemetrySourceIds.AgentPerformanceSlo => value.Slo.Progress,
        _ => throw new ArgumentOutOfRangeException(nameof(sourceId))
    };

    private static LinuxL4TelemetryState WithProgress(LinuxL4TelemetryState value, string sourceId, LinuxL4SourceProgress progress) => sourceId switch
    {
        LinuxTelemetrySourceIds.PolicyPostureDrift => value with { Policy = value.Policy with { Progress = progress } },
        LinuxTelemetrySourceIds.AgentPerformanceSlo => value with { Slo = value.Slo with { Progress = progress } },
        _ => throw new ArgumentOutOfRangeException(nameof(sourceId))
    };

    private static LinuxL4TelemetryState MergeSourceState(LinuxL4TelemetryState current, LinuxL4TelemetryState result, string sourceId) => sourceId switch
    {
        LinuxTelemetrySourceIds.PolicyPostureDrift => current with { Policy = result.Policy },
        LinuxTelemetrySourceIds.AgentPerformanceSlo => current with { Slo = result.Slo },
        _ => throw new ArgumentOutOfRangeException(nameof(sourceId))
    };

    private bool FamilyObserved(string family, LinuxL4SourceProgress progress)
    {
        if (progress.CollectedSequence == 0) return false;
        return family switch
        {
            "policy_baseline" => state.Policy.BaselineEstablished,
            "policy_sample" or "slo_sample" => true,
            "policy_drift" => progress.ErrorCode == "policy_posture_drift_active",
            "policy_gap" or "slo_gap" => progress.ActiveGap,
            "slo_breach" => progress.ErrorCode is "slo_threshold_breached" or "slo_queue_health_breached",
            "slo_recovery" => progress.Status == SourceHealthStatuses.Healthy
                && progress.TransitionState == HealthTransitionStates.Recovered,
            _ => false
        };
    }

    private static long SaturatingAdd(long left, long right) => left > long.MaxValue - right ? long.MaxValue : left + right;
}
