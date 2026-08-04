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

    public async Task<(LinuxKernelNetworkState State, long AgentSequence, bool HelperGap)> CollectAsync(
        LinuxKernelNetworkFrame frame,
        DateTimeOffset eventTime,
        Func<long, bool, Task> enqueueBeforeCheckpoint,
        CancellationToken cancellationToken)
    {
        var result = await CollectBatchAsync(
            [new LinuxKernelNetworkPendingFrame(frame, eventTime)],
            assignments => enqueueBeforeCheckpoint(assignments[0].AgentSequence, assignments[0].HelperGap),
            cancellationToken);
        var assignment = result.Assignments[0];
        return (result.State, assignment.AgentSequence, assignment.HelperGap);
    }

    public async Task<(LinuxKernelNetworkState State, IReadOnlyList<LinuxKernelNetworkSequenceAssignment> Assignments)> CollectBatchAsync(
        IReadOnlyList<LinuxKernelNetworkPendingFrame> frames,
        Func<IReadOnlyList<LinuxKernelNetworkSequenceAssignment>, Task> enqueueBeforeCheckpoint,
        CancellationToken cancellationToken)
    {
        if (frames.Count is <= 0 or > LinuxKernelNetworkConstants.MaximumRecordsPerDrain)
            throw new ArgumentOutOfRangeException(nameof(frames));
        await InitializeAsync(cancellationToken);
        LinuxKernelNetworkState updated = new();
        var assignments = new List<LinuxKernelNetworkSequenceAssignment>(frames.Count);
        await gate.WaitAsync(cancellationToken);
        try
        {
            updated = state;
            foreach (var pending in frames)
            {
                var frame = pending.Frame;
                var epochChanged = !string.Equals(updated.LastHelperEpoch, frame.Epoch, StringComparison.Ordinal);
                var expected = epochChanged ? frame.Sequence : updated.LastHelperSequence + 1;
                var helperGap = !epochChanged && frame.Sequence != expected;
                var counterIncrease = CountersIncreased(updated, frame);
                var agentSequence = updated.NextSequence;
                assignments.Add(new(agentSequence, helperGap));
                updated = updated with
                {
                    NextSequence = checked(agentSequence + 1),
                    CollectedSequence = agentSequence,
                    LastHelperEpoch = frame.Epoch,
                    LastHelperSequence = frame.Sequence,
                    ObservedAt = timeProvider.GetUtcNow(),
                    LastEventAt = pending.EventTime,
                    GapCount = helperGap ? SaturatingIncrement(updated.GapCount) : updated.GapCount,
                    ParseFailures = frame.ParseFailures,
                    UnsupportedHeaders = frame.UnsupportedHeaders,
                    FlowMapFull = frame.FlowMapFull,
                    OwnerMisses = frame.OwnerMisses,
                    RingLosses = frame.RingLosses,
                    IpcSendFailures = frame.IpcSendFailures,
                    ActiveLoss = updated.ActiveLoss || helperGap || counterIncrease,
                    CleanHealthFrames = helperGap || counterIncrease ? 0 : updated.CleanHealthFrames,
                    EventFamilyCounts = IncrementFamily(updated.EventFamilyCounts, frame.EventCode!),
                    LastError = helperGap ? "helper_sequence_gap" : counterIncrease ? "kernel_network_loss_observed" : updated.LastError
                };
            }
            await enqueueBeforeCheckpoint(assignments);
            await store.WriteAsync(updated, cancellationToken);
            state = updated;
        }
        finally { gate.Release(); }
        return (updated, assignments);
    }

    public async Task<LinuxKernelNetworkState> ObserveHealthAsync(LinuxKernelNetworkFrame frame, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        return await UpdateAsync(current =>
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
                ActiveLoss = activeLoss,
                CleanHealthFrames = cleanFrames,
                LastError = helperGap ? "helper_sequence_gap" : counterIncrease ? "kernel_network_loss_observed" : activeLoss ? current.LastError : "none"
            };
        }, cancellationToken);
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
                ["queue_pause_depth"] = options.KernelNetworkTelemetry.QueuePauseDepth.ToString(CultureInfo.InvariantCulture)
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
            AcknowledgedSequence = Math.Min(highest, current.CollectedSequence),
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
