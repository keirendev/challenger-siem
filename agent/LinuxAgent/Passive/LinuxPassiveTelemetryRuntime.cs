using System.Globalization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Services;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxPassiveTelemetryRuntime(
    IOptions<LinuxAgentOptions> configured,
    LinuxPassiveTelemetryStateStore stateStore,
    LinuxPassiveTelemetryCollector collector,
    TimeProvider timeProvider) : ILinuxAcknowledgementObserver
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly object sync = new();
    private readonly SemaphoreSlim mutationGate = new(1, 1);
    private readonly Dictionary<string, RuntimeHealth> health = LinuxTelemetrySourceCatalog.L3Passive
        .ToDictionary(entry => entry.SourceId, _ => new RuntimeHealth(), StringComparer.Ordinal);
    private LinuxPassiveTelemetryState state = new();
    private bool cleanupAttempted;
    private bool initialized;
    private bool ready;
    private string stateError = "none";

    public bool IsEnabledAndApproved => collector.IsEnabledAndApproved;
    public bool CleanupRequested => !options.PassiveTelemetry.Enabled && options.PassiveTelemetry.CleanupStateOnDisable;
    public bool IsReady { get { lock (sync) return ready; } }

    public LinuxPassiveTelemetryState CurrentState
    {
        get { lock (sync) return state; }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (!collector.IsEnabledAndApproved)
        {
            lock (sync)
            {
                initialized = false;
                ready = false;
                SetAllDisabled();
            }
            return;
        }

        await mutationGate.WaitAsync(cancellationToken);
        try
        {
            if (!collector.IsEnabledAndApproved) return;
            PassiveStateReadResult loaded;
            try
            {
                loaded = await stateStore.ReadAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                lock (sync) SetInitializationFailure("state_initialization_failed");
                return;
            }

            var recovered = AbandonPendingReservations(loaded.State, out var recoveredGaps);
            if (recoveredGaps > 0)
            {
                try
                {
                    await stateStore.WriteAsync(recovered, cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    lock (sync) SetInitializationFailure("state_recovery_write_failed");
                    return;
                }
            }
            lock (sync)
            {
                state = recovered;
                stateError = loaded.ErrorCode;
                initialized = true;
                ready = loaded.ErrorCode == "none";
                foreach (var pair in health)
                {
                    var progress = ProgressFor(pair.Key, recovered);
                    pair.Value.Status = ready ? progress.LastHealthStatus : SourceHealthStatuses.Error;
                    pair.Value.ErrorCode = ready ? progress.LastHealthErrorCode : loaded.ErrorCode;
                    pair.Value.CollectionStatus = pair.Value.Status;
                    pair.Value.CollectionErrorCode = pair.Value.ErrorCode;
                    pair.Value.TransitionState = progress.HealthTransitionState;
                    pair.Value.TransitionedAt = progress.HealthTransitionedAt;
                    pair.Value.Partial = progress.LastHealthPartial;
                    pair.Value.Details = progress.LastHealthDetails;
                    pair.Value.LastQueueDepth = progress.LastQueueDepthAtPressure;
                }
            }
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task CleanupIfDisabledAsync(CancellationToken cancellationToken)
    {
        if (!CleanupRequested) return;
        await mutationGate.WaitAsync(cancellationToken);
        try
        {
            lock (sync)
            {
                initialized = false;
                ready = false;
            }
            await stateStore.CleanupAsync(cancellationToken);
            lock (sync)
            {
                state = new();
                stateError = "none";
                cleanupAttempted = true;
                foreach (var item in health.Values)
                {
                    item.Status = SourceHealthStatuses.Disabled;
                    item.ErrorCode = "collector_state_cleaned";
                }
            }
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task CommitCollectionAsync(
        PassiveCollectionResult result,
        Func<IReadOnlyList<EventEnvelope>, CancellationToken, Task> enqueue,
        CancellationToken cancellationToken)
    {
        await mutationGate.WaitAsync(cancellationToken);
        try
        {
            LinuxPassiveTelemetryState current;
            lock (sync)
            {
                if (!initialized || !ready || !collector.IsEnabledAndApproved) return;
                current = state;
            }

            current = AbandonPendingReservation(current, result.SourceId, out _);
            if (result.Events.Count > 0)
            {
                current = Reserve(result, current);
                await stateStore.WriteAsync(current, cancellationToken);
                lock (sync) state = current;
            }

            try
            {
                await enqueue(result.Events, cancellationToken);
            }
            catch
            {
                lock (sync) RecordCommitFailure(result.SourceId, "queue_enqueue_failed");
                throw;
            }

            var merged = CommitSource(result, current);
            try
            {
                await stateStore.WriteAsync(merged, cancellationToken);
            }
            catch
            {
                lock (sync) RecordCommitFailure(result.SourceId, "state_commit_failed");
                throw;
            }
            lock (sync)
            {
                state = merged;
                stateError = "none";
                var item = health[result.SourceId];
                var progress = ProgressFor(result.SourceId, merged);
                var observedAt = progress.LastScanAt;
                item.CollectionStatus = progress.LastHealthStatus;
                item.CollectionErrorCode = progress.LastHealthErrorCode;
                if (!item.AcknowledgementPending)
                {
                    item.Status = progress.LastHealthStatus;
                    item.ErrorCode = progress.LastHealthErrorCode;
                    item.TransitionedAt = progress.HealthTransitionedAt;
                    item.TransitionState = progress.HealthTransitionState;
                }
                item.EmittedCount += result.Events.Count;
                item.FirstScanAt ??= observedAt;
                item.Partial = progress.LastHealthPartial;
                item.Details = progress.LastHealthDetails;
                item.LastQueueDepth = progress.LastQueueDepthAtPressure;
            }
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task RecordPressureAsync(
        string sourceId,
        int queueDepth,
        long? queueBytes,
        string pressureReason,
        CancellationToken cancellationToken)
    {
        await mutationGate.WaitAsync(cancellationToken);
        try
        {
            LinuxPassiveTelemetryState current;
            lock (sync)
            {
                if (!initialized || !ready || !collector.IsEnabledAndApproved) return;
                current = state;
            }
            var now = timeProvider.GetUtcNow();
            var progress = ProgressFor(sourceId, current);
            var details = new Dictionary<string, string>(progress.LastHealthDetails, StringComparer.Ordinal)
            {
                ["pressure_reason"] = Bound(pressureReason, 128),
                ["queue_depth"] = Math.Max(0, queueDepth).ToString(CultureInfo.InvariantCulture),
                ["queue_bytes"] = queueBytes?.ToString(CultureInfo.InvariantCulture) ?? "unknown"
            };
            var changed = progress.LastHealthStatus != SourceHealthStatuses.Degraded;
            progress = progress with
            {
                CumulativeGapCount = SaturatingAdd(progress.CumulativeGapCount, 1),
                CumulativePressureScanCount = SaturatingAdd(progress.CumulativePressureScanCount, 1),
                ActiveGapDetected = true,
                LastHealthStatus = SourceHealthStatuses.Degraded,
                LastHealthErrorCode = "passive_queue_pressure",
                LastHealthPartial = true,
                LastHealthDetails = BoundDetails(details),
                HealthTransitionState = changed ? HealthTransitionStates.Degraded : progress.HealthTransitionState,
                HealthTransitionedAt = changed ? now : progress.HealthTransitionedAt,
                LastQueueDepthAtPressure = Math.Max(0, queueDepth),
                LastQueueBytesAtPressure = queueBytes.HasValue ? Math.Max(0, queueBytes.Value) : null
            };
            var updated = ReplaceProgress(current, sourceId, progress);
            try
            {
                await stateStore.WriteAsync(updated, cancellationToken);
            }
            catch
            {
                lock (sync) RecordCommitFailure(sourceId, "pressure_state_write_failed");
                throw;
            }
            lock (sync)
            {
                state = updated;
                var item = health[sourceId];
                item.CollectionStatus = progress.LastHealthStatus;
                item.CollectionErrorCode = progress.LastHealthErrorCode;
                if (!item.AcknowledgementPending)
                {
                    item.Status = progress.LastHealthStatus;
                    item.ErrorCode = progress.LastHealthErrorCode;
                    item.TransitionState = progress.HealthTransitionState;
                    item.TransitionedAt = progress.HealthTransitionedAt;
                }
                item.Partial = true;
                item.Details = progress.LastHealthDetails;
                item.LastQueueDepth = progress.LastQueueDepthAtPressure;
            }
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        lock (sync)
        {
            if (!collector.IsEnabledAndApproved) return;
            if (!initialized || !ready) throw new InvalidOperationException("Passive acknowledgement state is not initialized.");
        }
        var acknowledged = events
            .Where(item => (item.SourceId is LinuxTelemetrySourceIds.ProcessSnapshotDiff
                or LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff
                or LinuxTelemetrySourceIds.HostBehaviourMetrics)
                && item.Checkpoint?.Sequence is not null)
            .GroupBy(item => item.SourceId!, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Max(item => item.Checkpoint!.Sequence!.Value), StringComparer.Ordinal);
        if (acknowledged.Count == 0) return;

        await mutationGate.WaitAsync(cancellationToken);
        try
        {
            LinuxPassiveTelemetryState updated;
            lock (sync)
            {
                if (!collector.IsEnabledAndApproved) return;
                if (!initialized || !ready) throw new InvalidOperationException("Passive acknowledgement state is not initialized.");
                var now = timeProvider.GetUtcNow();
                updated = state;
                if (acknowledged.TryGetValue(LinuxTelemetrySourceIds.ProcessSnapshotDiff, out var processSequence))
                    updated = updated with { Process = updated.Process with { Progress = Acknowledge(updated.Process.Progress, processSequence, now) } };
                if (acknowledged.TryGetValue(LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, out var networkSequence))
                    updated = updated with { Network = updated.Network with { Progress = Acknowledge(updated.Network.Progress, networkSequence, now) } };
                if (acknowledged.TryGetValue(LinuxTelemetrySourceIds.HostBehaviourMetrics, out var metricsSequence))
                    updated = updated with { Metrics = updated.Metrics with { Progress = Acknowledge(updated.Metrics.Progress, metricsSequence, now) } };
            }
            lock (sync)
            {
                if (ReferenceEquals(updated, state) || Equals(updated, state)) return;
            }
            await stateStore.WriteAsync(updated, cancellationToken);
            lock (sync)
            {
                state = updated;
                var now = timeProvider.GetUtcNow();
                foreach (var sourceId in acknowledged.Keys)
                {
                    var item = health[sourceId];
                    if (!item.AcknowledgementPending) continue;
                    item.AcknowledgementPending = false;
                    item.Status = item.CollectionStatus;
                    item.ErrorCode = item.CollectionErrorCode;
                    item.TransitionedAt = now;
                    item.TransitionState = item.Status == SourceHealthStatuses.Healthy
                        ? HealthTransitionStates.Healthy
                        : HealthTransitionStates.Degraded;
                }
            }
        }
        finally
        {
            mutationGate.Release();
        }
    }

    public bool HandlesSource(string? sourceId) => sourceId is
        LinuxTelemetrySourceIds.ProcessSnapshotDiff
        or LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff
        or LinuxTelemetrySourceIds.HostBehaviourMetrics;

    public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events)
    {
        lock (sync)
        {
            if (!initialized || !ready || !collector.IsEnabledAndApproved) return;
            foreach (var sourceId in events.Select(item => item.SourceId).Where(HandlesSource).Distinct(StringComparer.Ordinal))
            {
                var item = health[sourceId!];
                item.AcknowledgementPending = true;
                if (item.Status != SourceHealthStatuses.Error)
                {
                    item.TransitionedAt = timeProvider.GetUtcNow();
                    item.TransitionState = HealthTransitionStates.Degraded;
                }
                item.Status = SourceHealthStatuses.Error;
                item.ErrorCode = "passive_acknowledgement_state_write_failed";
            }
        }
    }

    public IReadOnlyList<SourceManifestEntry> Manifest => LinuxTelemetrySourceCatalog.L3Passive
        .Select(entry => entry with
        {
            Applicability = options.PassiveTelemetry.Enabled
                ? SourceApplicabilityStatuses.Applicable
                : SourceApplicabilityStatuses.Unknown,
            ApplicabilityReason = options.PassiveTelemetry.Enabled ? null : "explicit_opt_in_required"
        })
        .ToArray();

    public IReadOnlyList<SourceHealthReport> Health()
    {
        lock (sync)
        {
            return Manifest.Select(BuildHealth).ToArray();
        }
    }

    private SourceHealthReport BuildHealth(SourceManifestEntry manifest)
    {
        var runtime = health[manifest.SourceId];
        var progress = ProgressFor(manifest.SourceId, state);
        var enabled = collector.IsEnabledAndApproved;
        var status = enabled ? runtime.Status : SourceHealthStatuses.Disabled;
        var error = enabled ? runtime.ErrorCode : DisabledError();
        var now = timeProvider.GetUtcNow();
        var persistentGaps = SaturatingAdd(progress.CumulativeGapCount, progress.AbandonedSequenceCount);
        var persistentDrops = progress.CumulativeDroppedCount;
        var eventRate = EventRatePerMinute(runtime, now);
        var runtimeDetails = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["collector_state"] = enabled ? IsReady ? "enabled" : "initialization_failed" : "disabled",
            ["approval_state"] = enabled ? "matched" : options.PassiveTelemetry.Enabled ? "missing_or_mismatched" : "not_requested",
            ["plan_hash"] = collector.PlanHash,
            ["state_error"] = stateError,
            ["last_scan_at"] = progress.LastScanAt?.UtcDateTime.ToString("O", CultureInfo.InvariantCulture) ?? "never",
            ["gap_events"] = persistentGaps.ToString(CultureInfo.InvariantCulture),
            ["active_gap"] = progress.ActiveGapDetected ? "present" : "recovered_or_none",
            ["active_bookmark_gap"] = progress.ActiveBookmarkGapDetected ? "present" : "recovered_or_none",
            ["read_skips"] = progress.CumulativeReadSkipCount.ToString(CultureInfo.InvariantCulture),
            ["drop_events"] = persistentDrops.ToString(CultureInfo.InvariantCulture),
            ["deferred_events"] = progress.DeferredCount.ToString(CultureInfo.InvariantCulture),
            ["sample_events"] = progress.CumulativeSampledCount.ToString(CultureInfo.InvariantCulture),
            ["pressure_skipped_scans"] = progress.CumulativePressureScanCount.ToString(CultureInfo.InvariantCulture),
            ["visibility"] = progress.LastHealthPartial ? "partial" : "bounded",
            ["queue_depth_at_pressure"] = progress.LastQueueDepthAtPressure?.ToString(CultureInfo.InvariantCulture) ?? "none",
            ["queue_bytes_at_pressure"] = progress.LastQueueBytesAtPressure?.ToString(CultureInfo.InvariantCulture) ?? "none",
            ["cleanup_state"] = cleanupAttempted ? "collector_state_removed" : "not_requested",
            ["sequence_reservation"] = "durable_before_queue; interrupted reservations become explicit abandoned sequence gaps",
            ["pending_reservation"] = progress.PendingReservationStart.HasValue ? "present" : "none",
            ["acknowledgement_state"] = runtime.AcknowledgementPending ? "retry_pending" : "persisted"
        };
        // Runtime-owned health evidence is mandatory for interpreting the row. Add it first,
        // then retain as much collector detail as fits the shared portable-source limit.
        var details = BoundDetails(runtimeDetails, progress.LastHealthDetails);
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
            LastEventTime = progress.LastEventAt,
            ObservedAt = progress.LastScanAt,
            CollectedCheckpoint = manifest.Applicability == SourceApplicabilityStatuses.Applicable
                ? new SourceCheckpoint { Sequence = progress.CollectedSequence, EventTime = progress.LastEventAt, RecordedAt = progress.LastScanAt }
                : null,
            AcknowledgedCheckpoint = manifest.Applicability == SourceApplicabilityStatuses.Applicable
                ? new SourceCheckpoint { Sequence = progress.AcknowledgedSequence, EventTime = progress.AcknowledgedAt, RecordedAt = progress.AcknowledgedAt }
                : null,
            LagSeconds = progress.LastEventAt.HasValue ? Math.Max(0, (long)(now - progress.LastEventAt.Value).TotalSeconds) : null,
            SilenceSeconds = progress.LastEventAt.HasValue ? Math.Max(0, (long)(now - progress.LastEventAt.Value).TotalSeconds) : null,
            EventRatePerMinute = eventRate,
            ErrorCode = error,
            ErrorMessage = error,
            GapDetected = progress.ActiveGapDetected,
            BookmarkGapDetected = progress.ActiveBookmarkGapDetected,
            GapCount = persistentGaps,
            TransitionState = runtime.AcknowledgementPending ? runtime.TransitionState : progress.HealthTransitionState,
            TransitionedAt = runtime.AcknowledgementPending ? runtime.TransitionedAt : progress.HealthTransitionedAt,
            DroppedEvents = persistentDrops,
            PoisonEvents = 0,
            ConfigHash = collector.PlanHash,
            SourceVersion = LinuxPassiveTelemetryCollector.CollectorVersion,
            PrerequisiteStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["explicit_passive_telemetry_opt_in"] = options.PassiveTelemetry.Enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
                ["approval_hash_matches"] = enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
                [PrerequisiteFor(manifest.SourceId)] = status switch
                {
                    SourceHealthStatuses.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
                    SourceHealthStatuses.Missing => SourceEvidenceStatuses.Missing,
                    SourceHealthStatuses.Degraded or SourceHealthStatuses.Error => SourceEvidenceStatuses.Degraded,
                    SourceHealthStatuses.Disabled => SourceEvidenceStatuses.Disabled,
                    _ => SourceEvidenceStatuses.Satisfied
                }
            },
            EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                family => family,
                family => progress.FamilyCounts.GetValueOrDefault(family) > 0
                    ? SourceEvidenceStatuses.Observed
                    : SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal),
            Details = details
        };
    }

    private string DisabledError() => options.PassiveTelemetry.Enabled
        ? "passive_telemetry_approval_hash_missing_or_mismatch"
        : "collector_disabled";

    private static PassiveSourceProgress ProgressFor(string sourceId, LinuxPassiveTelemetryState value) => sourceId switch
    {
        LinuxTelemetrySourceIds.ProcessSnapshotDiff => value.Process.Progress,
        LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff => value.Network.Progress,
        _ => value.Metrics.Progress
    };

    private static string PrerequisiteFor(string sourceId) => sourceId switch
    {
        LinuxTelemetrySourceIds.ProcessSnapshotDiff => "procfs_process_metadata_readable",
        LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff => "procfs_network_metadata_readable",
        _ => "procfs_host_metrics_readable"
    };

    private static PassiveSourceProgress Acknowledge(PassiveSourceProgress progress, long sequence, DateTimeOffset now)
    {
        if (sequence <= progress.AcknowledgedSequence || sequence > progress.CollectedSequence) return progress;
        return progress with { AcknowledgedSequence = sequence, AcknowledgedAt = now };
    }

    private static LinuxPassiveTelemetryState Reserve(PassiveCollectionResult result, LinuxPassiveTelemetryState current)
    {
        var start = result.Events.Min(item => item.Checkpoint!.Sequence!.Value);
        var end = result.Events.Max(item => item.Checkpoint!.Sequence!.Value);
        var proposed = ProgressFor(result.SourceId, result.NewState);
        var currentProgress = ProgressFor(result.SourceId, current);
        if (start < currentProgress.NextSequence
            || end < start
            || end - start + 1 != result.Events.Count
            || proposed.NextSequence <= end)
        {
            throw new InvalidOperationException("Passive telemetry sequence reservation was non-monotonic.");
        }
        var progress = currentProgress with
        {
            NextSequence = Math.Max(currentProgress.NextSequence, proposed.NextSequence),
            PendingReservationStart = start,
            PendingReservationEnd = end
        };
        return ReplaceProgress(current, result.SourceId, progress);
    }

    private static LinuxPassiveTelemetryState CommitSource(PassiveCollectionResult result, LinuxPassiveTelemetryState current)
    {
        if (result.NewState.BootIdentitySha256 is { } proposedBootIdentity)
            current = LinuxBootIdentity.ApplyEpoch(current, proposedBootIdentity);
        var currentProgress = ProgressFor(result.SourceId, current);
        var sourceProgress = ProgressFor(result.SourceId, result.NewState);
        var healthChanged = !string.Equals(currentProgress.LastHealthStatus, result.HealthStatus, StringComparison.Ordinal);
        var recovered = result.HealthStatus == SourceHealthStatuses.Healthy
            && result.GapCount == 0
            && result.DeferredCount == 0
            && !result.Partial;
        var proposedProgress = sourceProgress with
        {
            NextSequence = Math.Max(currentProgress.NextSequence, sourceProgress.NextSequence),
            AcknowledgedSequence = currentProgress.AcknowledgedSequence,
            AcknowledgedAt = currentProgress.AcknowledgedAt,
            PendingReservationStart = null,
            PendingReservationEnd = null,
            AbandonedSequenceCount = currentProgress.AbandonedSequenceCount,
            CumulativeGapCount = SaturatingAdd(currentProgress.CumulativeGapCount, result.GapCount),
            CumulativeReadSkipCount = SaturatingAdd(currentProgress.CumulativeReadSkipCount, result.ReadSkipCount),
            CumulativeDroppedCount = SaturatingAdd(currentProgress.CumulativeDroppedCount, result.DroppedCount),
            CumulativeSampledCount = SaturatingAdd(currentProgress.CumulativeSampledCount, result.SampledCount),
            CumulativePressureScanCount = currentProgress.CumulativePressureScanCount,
            ActiveGapDetected = recovered ? false : currentProgress.ActiveGapDetected || result.GapCount > 0,
            ActiveBookmarkGapDetected = recovered ? false : currentProgress.ActiveBookmarkGapDetected,
            DeferredCount = result.DeferredCount,
            LastHealthStatus = result.HealthStatus,
            LastHealthErrorCode = Bound(result.ErrorCode, 128),
            LastHealthPartial = result.Partial,
            LastHealthDetails = BoundDetails(result.Details),
            HealthTransitionState = healthChanged ? TransitionFor(result.HealthStatus) : currentProgress.HealthTransitionState,
            HealthTransitionedAt = healthChanged ? sourceProgress.LastScanAt : currentProgress.HealthTransitionedAt,
            LastQueueDepthAtPressure = currentProgress.LastQueueDepthAtPressure,
            LastQueueBytesAtPressure = currentProgress.LastQueueBytesAtPressure
        };
        return result.SourceId switch
        {
            LinuxTelemetrySourceIds.ProcessSnapshotDiff => current with
            {
                Process = result.NewState.Process with { Progress = proposedProgress }
            },
            LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff => current with
            {
                Network = result.NewState.Network with { Progress = proposedProgress }
            },
            _ => current with
            {
                Metrics = result.NewState.Metrics with { Progress = proposedProgress }
            }
        };
    }

    private static LinuxPassiveTelemetryState AbandonPendingReservations(
        LinuxPassiveTelemetryState value,
        out long abandoned)
    {
        abandoned = 0;
        foreach (var sourceId in new[]
                 {
                     LinuxTelemetrySourceIds.ProcessSnapshotDiff,
                     LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff,
                     LinuxTelemetrySourceIds.HostBehaviourMetrics
                 })
        {
            value = AbandonPendingReservation(value, sourceId, out var sourceAbandoned);
            abandoned = SaturatingAdd(abandoned, sourceAbandoned);
        }
        return value;
    }

    private static LinuxPassiveTelemetryState AbandonPendingReservation(
        LinuxPassiveTelemetryState value,
        string sourceId,
        out long abandoned)
    {
        var progress = ProgressFor(sourceId, value);
        if (progress.PendingReservationStart is not { } start || progress.PendingReservationEnd is not { } end)
        {
            abandoned = 0;
            return value;
        }
        abandoned = end >= start ? end - start + 1 : 1;
        progress = progress with
        {
            PendingReservationStart = null,
            PendingReservationEnd = null,
            AbandonedSequenceCount = SaturatingAdd(progress.AbandonedSequenceCount, abandoned),
            ActiveBookmarkGapDetected = true
        };
        return ReplaceProgress(value, sourceId, progress);
    }

    private static LinuxPassiveTelemetryState ReplaceProgress(
        LinuxPassiveTelemetryState value,
        string sourceId,
        PassiveSourceProgress progress) => sourceId switch
        {
            LinuxTelemetrySourceIds.ProcessSnapshotDiff => value with
            {
                Process = value.Process with { Progress = progress }
            },
            LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff => value with
            {
                Network = value.Network with { Progress = progress }
            },
            _ => value with
            {
                Metrics = value.Metrics with { Progress = progress }
            }
        };

    private void SetAllDisabled()
    {
        foreach (var item in health.Values)
        {
            item.Status = SourceHealthStatuses.Disabled;
            item.ErrorCode = DisabledError();
        }
    }

    private void SetInitializationFailure(string error)
    {
        initialized = false;
        ready = false;
        stateError = error;
        foreach (var item in health.Values)
        {
            item.Status = SourceHealthStatuses.Error;
            item.ErrorCode = error;
        }
    }

    private void RecordCommitFailure(string sourceId, string error)
    {
        var item = health[sourceId];
        if (item.Status != SourceHealthStatuses.Error)
        {
            item.TransitionedAt = timeProvider.GetUtcNow();
            item.TransitionState = HealthTransitionStates.Degraded;
        }
        item.CollectionStatus = SourceHealthStatuses.Error;
        item.CollectionErrorCode = error;
        if (!item.AcknowledgementPending)
        {
            item.Status = SourceHealthStatuses.Error;
            item.ErrorCode = error;
        }
        item.Partial = true;
    }

    private static decimal EventRatePerMinute(RuntimeHealth value, DateTimeOffset now)
    {
        if (value.EmittedCount == 0 || value.FirstScanAt is null) return 0;
        var minutes = Math.Max(1m, (decimal)(now - value.FirstScanAt.Value).TotalMinutes);
        return Math.Round(value.EmittedCount / minutes, 3, MidpointRounding.AwayFromZero);
    }

    private static string Bound(string? value, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unknown";
        return value.Length <= maximum ? value : value[..maximum];
    }

    private static IReadOnlyDictionary<string, string> BoundDetails(
        params IReadOnlyDictionary<string, string>[] groups)
    {
        var bounded = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var values in groups)
        {
            foreach (var pair in values.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                if (bounded.Count >= LinuxPassiveTelemetryLimits.MaximumHealthDetailEntries) return bounded;
                var key = Bound(pair.Key, 64);
                if (bounded.ContainsKey(key)) continue;
                bounded[key] = Bound(pair.Value, 256);
            }
        }
        return bounded;
    }

    private static string TransitionFor(string healthStatus) =>
        healthStatus == SourceHealthStatuses.Healthy
            ? HealthTransitionStates.Healthy
            : HealthTransitionStates.Degraded;

    private static long SaturatingAdd(long left, long right) => left > long.MaxValue - right ? long.MaxValue : left + right;

    private sealed class RuntimeHealth
    {
        public string Status { get; set; } = SourceHealthStatuses.Disabled;
        public string ErrorCode { get; set; } = "collector_disabled";
        public string CollectionStatus { get; set; } = SourceHealthStatuses.Missing;
        public string CollectionErrorCode { get; set; } = "awaiting_first_scan";
        public bool AcknowledgementPending { get; set; }
        public DateTimeOffset? ObservedAt { get; set; }
        public DateTimeOffset? TransitionedAt { get; set; }
        public string TransitionState { get; set; } = HealthTransitionStates.Unknown;
        public long GapCount { get; set; }
        public long ReadSkipCount { get; set; }
        public long DroppedCount { get; set; }
        public long DeferredCount { get; set; }
        public long SampledCount { get; set; }
        public long EmittedCount { get; set; }
        public DateTimeOffset? FirstScanAt { get; set; }
        public bool Partial { get; set; }
        public int? LastQueueDepth { get; set; }
        public IReadOnlyDictionary<string, string> Details { get; set; } =
            new Dictionary<string, string>(StringComparer.Ordinal);
    }
}
