using System.Globalization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.SelfIntegrity;

public sealed class LinuxSelfIntegrityRuntime(
    IOptions<LinuxAgentOptions> configured,
    LinuxSelfIntegrityStateStore stateStore,
    LinuxSelfIntegrityCollector collector,
    TimeProvider timeProvider)
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly object sync = new();
    private LinuxSelfIntegrityState state = new();
    private string status = SourceHealthStatuses.Disabled;
    private string errorCode = "collector_disabled";
    private DateTimeOffset? observedAt;
    private DateTimeOffset? transitionedAt;
    private string transitionState = HealthTransitionStates.Unknown;
    private long gapCount;
    private long droppedCount;
    private long sampledCount;
    private bool cleanupAttempted;

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        var loaded = await stateStore.ReadAsync(cancellationToken);
        lock (sync)
        {
            state = loaded;
            status = DetermineDisabledStatus();
            errorCode = DetermineDisabledError();
        }
    }

    public LinuxSelfIntegrityState CurrentState { get { lock (sync) return state; } }
    public bool IsEnabledAndApproved => collector.IsEnabledAndApproved;
    public bool CleanupRequested => !options.SelfIntegrity.Enabled && options.SelfIntegrity.CleanupStateOnDisable;

    public async Task CleanupIfDisabledAsync(CancellationToken cancellationToken)
    {
        if (!CleanupRequested) return;
        await stateStore.CleanupAsync(cancellationToken);
        lock (sync)
        {
            state = new();
            cleanupAttempted = true;
            status = SourceHealthStatuses.Disabled;
            errorCode = "collector_state_cleaned";
            observedAt = timeProvider.GetUtcNow();
            transitionedAt = observedAt;
            transitionState = HealthTransitionStates.Recovered;
        }
    }

    public async Task RecordCollectedAsync(SelfIntegrityCollectionResult result, CancellationToken cancellationToken)
    {
        var collectedAt = timeProvider.GetUtcNow();
        var highestSequence = result.Events.Count == 0 ? state.CollectedSequence : result.Events.Max(item => item.Sequence);
        await stateStore.WriteCollectedAsync(result.NewSignatures, result.NextSequence, highestSequence, collectedAt, cancellationToken);
        var loaded = await stateStore.ReadAsync(cancellationToken);
        lock (sync)
        {
            state = loaded;
            status = result.HealthStatus;
            errorCode = result.ErrorCode;
            observedAt = collectedAt;
            gapCount += result.GapCount;
            droppedCount += result.DroppedCount;
            sampledCount += result.SampledCount;
            transitionedAt = collectedAt;
            transitionState = status == SourceHealthStatuses.Healthy ? HealthTransitionStates.Healthy : HealthTransitionStates.Degraded;
        }
    }

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        var latest = events
            .Where(item => item.Source == EventSources.AgentHealth
                && item.SourceId == LinuxTelemetrySourceIds.AgentSelfIntegrity
                && item.Checkpoint?.Sequence is not null)
            .LastOrDefault();
        if (latest?.Checkpoint?.Sequence is not long sequence) return;
        await stateStore.WriteAcknowledgedAsync(sequence, timeProvider.GetUtcNow(), cancellationToken);
        var loaded = await stateStore.ReadAsync(cancellationToken);
        lock (sync) state = loaded;
    }

    public SourceManifestEntry Manifest => LinuxTelemetrySourceCatalog.SelfIntegritySnapshot with
    {
        Applicability = options.SelfIntegrity.Enabled ? SourceApplicabilityStatuses.Applicable : SourceApplicabilityStatuses.Unknown,
        ApplicabilityReason = options.SelfIntegrity.Enabled ? null : "explicit_opt_in_required"
    };

    public SourceHealthReport Health()
    {
        lock (sync)
        {
            var manifest = Manifest;
            var now = timeProvider.GetUtcNow();
            var approved = collector.IsEnabledAndApproved;
            var enabled = approved;
            var currentStatus = enabled ? status : DetermineDisabledStatus();
            var currentError = enabled ? errorCode : DetermineDisabledError();
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
                Status = currentStatus,
                Required = false,
                Requirement = SourceRequirementKinds.Optional,
                Enabled = enabled,
                ObservedAt = now,
                LastEventTime = state.CollectedAt,
                CollectedCheckpoint = new SourceCheckpoint { Sequence = state.CollectedSequence ?? 0, EventTime = state.CollectedAt, RecordedAt = state.CollectedAt },
                AcknowledgedCheckpoint = new SourceCheckpoint { Sequence = state.AcknowledgedSequence ?? 0, EventTime = state.AcknowledgedAt, RecordedAt = state.AcknowledgedAt },
                LagSeconds = state.CollectedAt.HasValue ? Math.Max(0, (long)(now - state.CollectedAt.Value).TotalSeconds) : null,
                SilenceSeconds = state.CollectedAt.HasValue ? Math.Max(0, (long)(now - state.CollectedAt.Value).TotalSeconds) : null,
                EventRatePerMinute = 0,
                ErrorCode = currentError,
                ErrorMessage = currentError,
                GapDetected = gapCount > 0,
                BookmarkGapDetected = gapCount > 0,
                GapCount = gapCount,
                TransitionState = transitionState,
                TransitionedAt = transitionedAt,
                DroppedEvents = droppedCount,
                PoisonEvents = 0,
                ConfigHash = collector.PlanHash,
                SourceVersion = LinuxSelfIntegrityCollector.CollectorVersion,
                PrerequisiteStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["explicit_self_integrity_opt_in"] = options.SelfIntegrity.Enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
                    ["approval_hash_matches"] = approved ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled,
                    ["allowlist_paths_readable"] = currentStatus == SourceHealthStatuses.PermissionDenied ? SourceEvidenceStatuses.PermissionDenied : enabled ? SourceEvidenceStatuses.Satisfied : SourceEvidenceStatuses.Disabled
                },
                EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["self_integrity_snapshot"] = enabled && state.CollectedSequence.HasValue ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved
                },
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["collector_state"] = enabled ? "enabled" : "disabled",
                    ["approval_state"] = approved ? "matched" : options.SelfIntegrity.Enabled ? "missing_or_mismatched" : "not_requested",
                    ["plan_hash"] = collector.PlanHash,
                    ["allowlist_entry_count"] = LinuxSelfIntegrityCollector.Allowlist.Count.ToString(CultureInfo.InvariantCulture),
                    ["interval_seconds"] = options.SelfIntegrity.IntervalSeconds.ToString(CultureInfo.InvariantCulture),
                    ["queue_pause_depth"] = options.SelfIntegrity.QueuePauseDepth.ToString(CultureInfo.InvariantCulture),
                    ["gap_events"] = gapCount.ToString(CultureInfo.InvariantCulture),
                    ["drop_events"] = droppedCount.ToString(CultureInfo.InvariantCulture),
                    ["sample_events"] = sampledCount.ToString(CultureInfo.InvariantCulture),
                    ["cleanup_state"] = cleanupAttempted ? "collector_state_removed" : "not_requested"
                }
            };
        }
    }

    private string DetermineDisabledStatus() => options.SelfIntegrity.Enabled && !collector.IsEnabledAndApproved
        ? SourceHealthStatuses.Disabled
        : SourceHealthStatuses.Disabled;

    private string DetermineDisabledError() => options.SelfIntegrity.Enabled && !collector.IsEnabledAndApproved
        ? "self_integrity_approval_hash_missing_or_mismatch"
        : "collector_disabled";
}
