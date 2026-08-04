using System.Globalization;
using System.Runtime.InteropServices;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Services;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public sealed class LinuxKernelNetworkRuntime(
    IOptions<LinuxAgentOptions> configured,
    LinuxKernelNetworkStateStore store,
    TimeProvider timeProvider) : ILinuxAcknowledgementObserver
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly SemaphoreSlim gate = new(1, 1);
    private LinuxKernelNetworkState state = new();
    private bool initialized;

    public LinuxKernelNetworkPlan Plan => LinuxKernelNetworkPlanBuilder.Build(options);

    public SourceManifestEntry Manifest
    {
        get
        {
            var plan = Plan;
            var supported = OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64;
            return LinuxTelemetrySourceCatalog.KernelNetworkFlow with
            {
                Applicability = !supported ? SourceApplicabilityStatuses.Unsupported
                    : plan.Enabled && plan.ApprovalHashMatches ? SourceApplicabilityStatuses.Applicable
                    : SourceApplicabilityStatuses.Unknown,
                ApplicabilityReason = !supported ? "kernel_network_x86_64_only"
                    : !plan.Enabled ? "explicit_kernel_network_opt_in_required"
                    : !plan.ApprovalHashMatches ? "kernel_network_approval_hash_missing_or_mismatch"
                    : null
            };
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (initialized) return;
            state = await store.ReadAsync(cancellationToken);
            if (state.PendingReservationStart.HasValue || state.PendingReservationEnd.HasValue)
            {
                state = AbandonReservation(state);
                await store.WriteAsync(state, cancellationToken);
            }
            initialized = true;
        }
        finally { gate.Release(); }
    }

    public LinuxKernelNetworkState Snapshot()
    {
        gate.Wait();
        try { return state; }
        finally { gate.Release(); }
    }

    public async Task<LinuxKernelNetworkState> ObserveHelloAsync(LinuxKernelNetworkFrame frame, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        return await UpdateAsync(current =>
        {
            var restarted = current.LastHelperEpoch is not null
                && !string.Equals(current.LastHelperEpoch, frame.Epoch, StringComparison.Ordinal);
            var reconnectGap = !restarted
                && string.Equals(current.LastHelperEpoch, frame.Epoch, StringComparison.Ordinal)
                && frame.Sequence != current.LastHelperSequence + 1;
            return current with
            {
                LastHelperEpoch = frame.Epoch,
                LastHelperSequence = frame.Sequence > 0 ? frame.Sequence - 1 : 0,
                ObservedAt = timeProvider.GetUtcNow(),
                HelperRestartCount = restarted ? SaturatingIncrement(current.HelperRestartCount) : current.HelperRestartCount,
                GapCount = reconnectGap ? SaturatingIncrement(current.GapCount) : current.GapCount,
                ActiveLoss = current.ActiveLoss || reconnectGap,
                CleanHealthFrames = reconnectGap ? 0 : current.CleanHealthFrames,
                LastError = reconnectGap ? "helper_sequence_gap" : restarted ? "helper_restarted" : "none"
            };
        }, cancellationToken);
    }

    public async Task<(LinuxKernelNetworkState State, IReadOnlyList<LinuxKernelNetworkSequenceAssignment> Assignments)> CollectDrainAsync(
        IReadOnlyList<LinuxKernelNetworkPendingFrame> frames,
        LinuxKernelNetworkFrame health,
        Func<
            IReadOnlyList<LinuxKernelNetworkSequenceAssignment>,
            Func<int, LinuxKernelNetworkDrainDiagnostics?, Task>,
            Task> enqueueBeforeCheckpoint,
        CancellationToken cancellationToken)
    {
        if (frames.Count is <= 0 or > LinuxKernelNetworkConstants.MaximumRecordsPerDrain)
            throw new ArgumentOutOfRangeException(nameof(frames));
        await InitializeAsync(cancellationToken);
        var assignments = new List<LinuxKernelNetworkSequenceAssignment>(frames.Count);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (state.PendingReservationStart.HasValue || state.PendingReservationEnd.HasValue)
            {
                state = AbandonReservation(state);
                await store.WriteAsync(state, cancellationToken);
            }

            var projected = state;
            foreach (var pending in frames)
            {
                var frame = pending.Frame;
                var epochChanged = !string.Equals(projected.LastHelperEpoch, frame.Epoch, StringComparison.Ordinal);
                var expected = epochChanged ? frame.Sequence : projected.LastHelperSequence + 1;
                var helperGap = !epochChanged && frame.Sequence != expected;
                var agentSequence = checked(state.NextSequence + assignments.Count);
                assignments.Add(new(agentSequence, helperGap));
                projected = projected with
                {
                    LastHelperEpoch = frame.Epoch,
                    LastHelperSequence = frame.Sequence
                };
            }

            var reservationEnd = assignments[^1].AgentSequence;
            state = state with
            {
                NextSequence = checked(reservationEnd + 1),
                PendingReservationStart = assignments[0].AgentSequence,
                PendingReservationEnd = reservationEnd,
                PendingReservationHelperEpoch = health.Epoch,
                PendingReservationHelperSequence = health.Sequence
            };
            await store.WriteAsync(state, cancellationToken);

            var finalizedCount = 0;
            async Task FinalizeChunkAsync(int completedCount, LinuxKernelNetworkDrainDiagnostics? diagnostics)
            {
                if (completedCount <= finalizedCount || completedCount > frames.Count)
                    throw new InvalidOperationException("Kernel network drain chunks must finalize monotonically within the reservation.");
                if (completedCount == frames.Count != (diagnostics is not null))
                    throw new InvalidOperationException("Kernel network drain diagnostics are required only on the final chunk.");

                var updated = state;
                for (var index = finalizedCount; index < completedCount; index++)
                    updated = ApplyFlow(updated, frames[index], assignments[index]);
                if (completedCount == frames.Count)
                    updated = ApplyHealth(updated, health, diagnostics!) with
                    {
                        PendingReservationStart = null,
                        PendingReservationEnd = null,
                        PendingReservationHelperEpoch = null,
                        PendingReservationHelperSequence = null
                    };
                else
                    updated = updated with { PendingReservationStart = assignments[completedCount].AgentSequence };

                await store.WriteAsync(updated, cancellationToken);
                state = updated;
                finalizedCount = completedCount;
            }

            await enqueueBeforeCheckpoint(assignments, FinalizeChunkAsync);
            if (finalizedCount != frames.Count)
                throw new InvalidOperationException("Kernel network drain returned before its reserved sequence range was finalized.");
        }
        catch
        {
            if (state.PendingReservationStart.HasValue || state.PendingReservationEnd.HasValue)
            {
                state = AbandonReservation(state);
                try { await store.WriteAsync(state, CancellationToken.None); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            throw;
        }
        finally { gate.Release(); }
        return (state, assignments);
    }

    public async Task<LinuxKernelNetworkState> ObserveHealthAsync(LinuxKernelNetworkFrame frame, CancellationToken cancellationToken)
        => await ObserveHealthAsync(frame, diagnostics: null, cancellationToken);

    public async Task<LinuxKernelNetworkState> ObserveHealthAsync(
        LinuxKernelNetworkFrame frame,
        LinuxKernelNetworkDrainDiagnostics? diagnostics,
        CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        return await UpdateAsync(current => ApplyHealth(current, frame, diagnostics), cancellationToken);
    }

    public async Task ObserveConnectionFailureAsync(string error, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await UpdateAsync(current => current with
        {
            ObservedAt = timeProvider.GetUtcNow(),
            HelperConnectionFailureCount = SaturatingIncrement(current.HelperConnectionFailureCount),
            LastError = BoundError(error),
            LastConnectionError = BoundError(error)
        }, cancellationToken);
    }

    public async Task ObserveQueuePressureAsync(bool active, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await UpdateAsync(current => current with
        {
            ObservedAt = timeProvider.GetUtcNow(),
            QueuePressureCount = active ? SaturatingIncrement(current.QueuePressureCount) : current.QueuePressureCount,
            LastError = active ? "queue_pressure" : "none"
        }, cancellationToken);
    }

    public async Task ObserveErrorAsync(string error, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await UpdateAsync(current => current with { ObservedAt = timeProvider.GetUtcNow(), LastError = BoundError(error) }, cancellationToken);
    }

    public SourceHealthReport Health()
    {
        var manifest = Manifest;
        var plan = Plan;
        var current = Snapshot();
        var now = timeProvider.GetUtcNow();
        var enabled = manifest.Applicability == SourceApplicabilityStatuses.Applicable;
        var status = manifest.Applicability == SourceApplicabilityStatuses.Unsupported ? SourceHealthStatuses.Unsupported
            : !enabled ? SourceHealthStatuses.Disabled
            : current.ObservedAt is null ? SourceHealthStatuses.Missing
            : now - current.ObservedAt > TimeSpan.FromSeconds(45) ? SourceHealthStatuses.Stale
            : current.LastError != "none" || current.ActiveLoss ? SourceHealthStatuses.Degraded
            : SourceHealthStatuses.Healthy;
        long? silence = current.LastEventAt.HasValue ? Math.Max(0, (long)(now - current.LastEventAt.Value).TotalSeconds) : null;
        return new()
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
            Required = false,
            Requirement = SourceRequirementKinds.Optional,
            Enabled = enabled,
            LastEventTime = current.LastEventAt,
            ObservedAt = current.ObservedAt,
            CollectedCheckpoint = manifest.Applicability == SourceApplicabilityStatuses.Applicable
                ? new SourceCheckpoint { Sequence = current.CollectedSequence, EventTime = current.LastEventAt, RecordedAt = current.ObservedAt }
                : null,
            AcknowledgedCheckpoint = manifest.Applicability == SourceApplicabilityStatuses.Applicable
                ? new SourceCheckpoint { Sequence = current.AcknowledgedSequence, EventTime = current.AcknowledgedAt, RecordedAt = current.AcknowledgedAt }
                : null,
            LagSeconds = silence,
            SilenceSeconds = silence,
            ErrorCode = status == SourceHealthStatuses.Healthy ? "none" : current.LastError,
            ErrorMessage = status == SourceHealthStatuses.Healthy ? "none" : current.LastError,
            GapDetected = current.ActiveLoss,
            GapCount = current.GapCount,
            DroppedEvents = current.DroppedCount,
            ConfigHash = plan.PlanHash,
            SourceVersion = LinuxKernelNetworkConstants.CollectorVersion,
            PrerequisiteStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["explicit_kernel_network_opt_in"] = options.KernelNetworkTelemetry.Enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
                ["approval_hash_matches"] = plan.ApprovalHashMatches ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
                ["signed_fixed_helper"] = enabled && current.ObservedAt.HasValue ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.NotObserved,
                ["cgroup_v2"] = enabled && current.ObservedAt.HasValue ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.NotObserved,
                ["kernel_btf"] = enabled && current.ObservedAt.HasValue ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.NotObserved,
                ["cap_bpf"] = enabled && current.ObservedAt.HasValue ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.NotObserved,
                ["cap_perfmon"] = enabled && current.ObservedAt.HasValue ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.NotObserved,
                ["cap_net_admin"] = enabled && current.ObservedAt.HasValue ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.NotObserved
            },
            EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                family => family,
                family => current.EventFamilyCounts.GetValueOrDefault(family) > 0 ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal),
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["payload_capture"] = "false",
                ["helper_version"] = LinuxKernelNetworkConstants.HelperVersion,
                ["flow_map_entries"] = LinuxKernelNetworkConstants.FlowMapEntries.ToString(CultureInfo.InvariantCulture),
                ["parse_failures"] = current.ParseFailures.ToString(CultureInfo.InvariantCulture),
                ["unsupported_headers"] = current.UnsupportedHeaders.ToString(CultureInfo.InvariantCulture),
                ["flow_map_full"] = current.FlowMapFull.ToString(CultureInfo.InvariantCulture),
                ["owner_misses"] = current.OwnerMisses.ToString(CultureInfo.InvariantCulture),
                ["attribution_status"] = current.OwnerMisses > 0 ? "partial" : "complete_for_observed_flows",
                ["ring_losses"] = current.RingLosses.ToString(CultureInfo.InvariantCulture),
                ["ipc_send_failures"] = current.IpcSendFailures.ToString(CultureInfo.InvariantCulture),
                ["active_loss"] = current.ActiveLoss.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["helper_restart_count"] = current.HelperRestartCount.ToString(CultureInfo.InvariantCulture),
                ["helper_connection_failure_count"] = current.HelperConnectionFailureCount.ToString(CultureInfo.InvariantCulture),
                ["last_connection_error"] = current.LastConnectionError,
                ["queue_pressure_count"] = current.QueuePressureCount.ToString(CultureInfo.InvariantCulture),
                ["acknowledgement_gap"] = Math.Max(0, current.CollectedSequence - current.AcknowledgedSequence).ToString(CultureInfo.InvariantCulture),
                ["queue_pause_depth"] = options.KernelNetworkTelemetry.QueuePauseDepth.ToString(CultureInfo.InvariantCulture),
                ["last_drain_record_count"] = current.LastDrainRecordCount.ToString(CultureInfo.InvariantCulture),
                ["high_water_drain_record_count"] = current.HighWaterDrainRecordCount.ToString(CultureInfo.InvariantCulture),
                ["last_drain_serialized_bytes"] = current.LastDrainSerializedBytes.ToString(CultureInfo.InvariantCulture),
                ["last_drain_unique_enrichment_identities"] = current.LastDrainUniqueEnrichmentIdentities.ToString(CultureInfo.InvariantCulture),
                ["last_drain_enrichment_cache_hits"] = current.LastDrainEnrichmentCacheHits.ToString(CultureInfo.InvariantCulture),
                ["last_drain_receive_duration_ms"] = current.LastDrainReceiveDurationMilliseconds.ToString(CultureInfo.InvariantCulture),
                ["last_drain_persist_duration_ms"] = current.LastDrainPersistDurationMilliseconds.ToString(CultureInfo.InvariantCulture),
                ["abandoned_through_sequence"] = current.AbandonedThroughSequence.ToString(CultureInfo.InvariantCulture)
            }
        };
    }

    public bool HandlesSource(string? sourceId) => string.Equals(sourceId, LinuxTelemetrySourceIds.NetworkFlowSummary, StringComparison.Ordinal);

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        var highest = events.Select(item => item.Checkpoint?.Sequence).Where(item => item.HasValue).Select(item => item!.Value).DefaultIfEmpty().Max();
        if (highest <= 0) return;
        await InitializeAsync(cancellationToken);
        await UpdateAsync(current => highest <= current.AcknowledgedSequence ? current : current with
        {
            AcknowledgedSequence = Math.Min(highest, Math.Max(current.CollectedSequence, current.AbandonedThroughSequence)),
            AcknowledgedAt = timeProvider.GetUtcNow()
        }, cancellationToken);
    }

    public async Task RecordRejectedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await UpdateAsync(current => current with
        {
            DroppedCount = SaturatingAdd(current.DroppedCount, events.Count),
            GapCount = SaturatingAdd(current.GapCount, events.Count),
            LastError = "server_rejected_kernel_network_event"
        }, cancellationToken);
    }

    public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events)
    {
        gate.Wait();
        try { state = state with { LastError = "acknowledgement_state_write_failed" }; }
        finally { gate.Release(); }
    }

    private async Task<LinuxKernelNetworkState> UpdateAsync(Func<LinuxKernelNetworkState, LinuxKernelNetworkState> update, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var updated = update(state);
            await store.WriteAsync(updated, cancellationToken);
            state = updated;
            return updated;
        }
        finally { gate.Release(); }
    }

    private LinuxKernelNetworkState ApplyFlow(
        LinuxKernelNetworkState current,
        LinuxKernelNetworkPendingFrame pending,
        LinuxKernelNetworkSequenceAssignment assignment)
    {
        var frame = pending.Frame;
        var counterIncrease = CountersIncreased(current, frame);
        return current with
        {
            CollectedSequence = assignment.AgentSequence,
            LastHelperEpoch = frame.Epoch,
            LastHelperSequence = frame.Sequence,
            ObservedAt = timeProvider.GetUtcNow(),
            LastEventAt = pending.EventTime,
            GapCount = assignment.HelperGap ? SaturatingIncrement(current.GapCount) : current.GapCount,
            ParseFailures = frame.ParseFailures,
            UnsupportedHeaders = frame.UnsupportedHeaders,
            FlowMapFull = frame.FlowMapFull,
            OwnerMisses = frame.OwnerMisses,
            RingLosses = frame.RingLosses,
            IpcSendFailures = frame.IpcSendFailures,
            ActiveLoss = current.ActiveLoss || assignment.HelperGap || counterIncrease,
            CleanHealthFrames = assignment.HelperGap || counterIncrease ? 0 : current.CleanHealthFrames,
            EventFamilyCounts = IncrementFamily(current.EventFamilyCounts, frame.EventCode!),
            LastError = assignment.HelperGap ? "helper_sequence_gap"
                : counterIncrease ? "kernel_network_loss_observed"
                : current.LastError
        };
    }

    private LinuxKernelNetworkState ApplyHealth(
        LinuxKernelNetworkState current,
        LinuxKernelNetworkFrame frame,
        LinuxKernelNetworkDrainDiagnostics? diagnostics)
    {
        var epochChanged = !string.Equals(current.LastHelperEpoch, frame.Epoch, StringComparison.Ordinal);
        var helperGap = !epochChanged && frame.Sequence != current.LastHelperSequence + 1;
        var counterIncrease = CountersIncreased(current, frame);
        var cleanFrames = helperGap || counterIncrease ? 0 : Math.Min(3, current.CleanHealthFrames + 1);
        var activeLoss = helperGap || counterIncrease || current.ActiveLoss && cleanFrames < 3;
        return current with
        {
            LastHelperEpoch = frame.Epoch,
            LastHelperSequence = frame.Sequence,
            ObservedAt = timeProvider.GetUtcNow(),
            GapCount = helperGap ? SaturatingIncrement(current.GapCount) : current.GapCount,
            ParseFailures = frame.ParseFailures,
            UnsupportedHeaders = frame.UnsupportedHeaders,
            FlowMapFull = frame.FlowMapFull,
            OwnerMisses = frame.OwnerMisses,
            RingLosses = frame.RingLosses,
            IpcSendFailures = frame.IpcSendFailures,
            LastDrainRecordCount = diagnostics?.RecordCount ?? current.LastDrainRecordCount,
            HighWaterDrainRecordCount = diagnostics is null
                ? current.HighWaterDrainRecordCount
                : Math.Max(current.HighWaterDrainRecordCount, diagnostics.RecordCount),
            LastDrainSerializedBytes = diagnostics?.SerializedBytes ?? current.LastDrainSerializedBytes,
            LastDrainUniqueEnrichmentIdentities = diagnostics?.UniqueEnrichmentIdentities ?? current.LastDrainUniqueEnrichmentIdentities,
            LastDrainEnrichmentCacheHits = diagnostics?.EnrichmentCacheHits ?? current.LastDrainEnrichmentCacheHits,
            LastDrainReceiveDurationMilliseconds = diagnostics?.ReceiveDurationMilliseconds ?? current.LastDrainReceiveDurationMilliseconds,
            LastDrainPersistDurationMilliseconds = diagnostics?.PersistDurationMilliseconds ?? current.LastDrainPersistDurationMilliseconds,
            ActiveLoss = activeLoss,
            CleanHealthFrames = cleanFrames,
            LastError = helperGap ? "helper_sequence_gap"
                : counterIncrease ? "kernel_network_loss_observed"
                : activeLoss ? current.LastError
                : "none"
        };
    }

    private LinuxKernelNetworkState AbandonReservation(LinuxKernelNetworkState current)
    {
        var inferredEnd = current.NextSequence > 1 ? current.NextSequence - 1 : 0;
        var reservationEnd = Math.Max(current.PendingReservationEnd ?? 0, inferredEnd);
        return current with
        {
            PendingReservationStart = null,
            PendingReservationEnd = null,
            PendingReservationHelperEpoch = null,
            PendingReservationHelperSequence = null,
            AbandonedThroughSequence = Math.Max(current.AbandonedThroughSequence, reservationEnd),
            LastHelperEpoch = current.PendingReservationHelperEpoch ?? current.LastHelperEpoch,
            LastHelperSequence = current.PendingReservationHelperSequence ?? current.LastHelperSequence,
            ObservedAt = timeProvider.GetUtcNow(),
            GapCount = SaturatingIncrement(current.GapCount),
            ActiveLoss = true,
            CleanHealthFrames = 0,
            LastError = "kernel_network_sequence_reservation_abandoned"
        };
    }

    private static string BoundError(string value) => string.IsNullOrWhiteSpace(value) ? "unknown" : value.Trim().Length <= 96 ? value.Trim() : value.Trim()[..96];
    private static bool CountersIncreased(LinuxKernelNetworkState current, LinuxKernelNetworkFrame frame) =>
        frame.ParseFailures > current.ParseFailures
        || frame.UnsupportedHeaders > current.UnsupportedHeaders
        || frame.FlowMapFull > current.FlowMapFull
        || frame.RingLosses > current.RingLosses
        || frame.IpcSendFailures > current.IpcSendFailures;
    private static IReadOnlyDictionary<string, long> IncrementFamily(IReadOnlyDictionary<string, long> current, string family)
    {
        var result = new Dictionary<string, long>(current, StringComparer.Ordinal);
        result[family] = result.TryGetValue(family, out var count) ? SaturatingIncrement(count) : 1;
        return result;
    }
    private static long SaturatingIncrement(long value) => value == long.MaxValue ? value : value + 1;
    private static long SaturatingAdd(long value, long add) => value > long.MaxValue - add ? long.MaxValue : value + add;
}
