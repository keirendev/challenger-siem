using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.Passive;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.L4;

public sealed class LinuxL4TelemetryCollector(
    IOptions<LinuxAgentOptions> configured,
    ILinuxAgentSloSource sloSource,
    TimeProvider timeProvider)
{
    public const string CollectorVersion = "linux-l4-telemetry-v1";
    public const long MaximumRssBytes = 250L * 1024 * 1024;
    public const long MaximumAverageWriteBytesPerSecond = 1024L * 1024;
    public const long MaximumAverageCpuPercentMilli = 2_000;
    public const long MaximumP95CpuPercentMilli = 5_000;

    public static readonly IReadOnlyList<string> PolicySnapshotTypes =
    [
        "linux_agent_integrity",
        "linux_firewall",
        "linux_mandatory_access_control",
        "linux_secure_boot",
        "linux_ssh"
    ];

    private readonly LinuxAgentOptions options = configured.Value;

    public string PlanHash => ComputePlanHash(options);
    public bool HasApprovedBaseline => IsSha256(options.L4Telemetry.ApprovedBaselineHash);
    public bool IsEnabledAndApproved => IsConfigurationApproved(options);

    public static bool IsConfigurationApproved(LinuxAgentOptions configured) =>
        configured.L4Telemetry.Enabled
        && configured.HasValidL4TelemetryBounds()
        && configured.HasValidL4ActivationBounds()
        && configured.PassiveTelemetry.Enabled
        && configured.HasValidPassiveTelemetryBounds()
        && string.Equals(configured.PassiveTelemetry.ApprovedPlanHash,
            LinuxPassiveTelemetryCollector.ComputePlanHash(configured), StringComparison.Ordinal)
        && IsSha256(configured.L4Telemetry.ApprovedBaselineHash)
        && string.Equals(configured.L4Telemetry.ApprovedPlanHash, ComputePlanHash(configured), StringComparison.Ordinal);

    public static string ComputePlanHash(LinuxAgentOptions configured)
    {
        var l4 = configured.L4Telemetry;
        var canonical = string.Join('\n',
            CollectorVersion,
            $"target_coverage_level={configured.Journal.TargetCoverageLevel}",
            $"journal_enabled={configured.Journal.Enabled}",
            $"journal_scope={LinuxJournalScopes.Configured(configured.Journal)}",
            $"approved_baseline_hash={l4.ApprovedBaselineHash}",
            $"declared_roles={string.Join(',', configured.Journal.DeclaredRoles.Order(StringComparer.Ordinal))}",
            $"passive_telemetry_enabled={configured.PassiveTelemetry.Enabled}",
            $"passive_telemetry_approved_plan_hash={configured.PassiveTelemetry.ApprovedPlanHash}",
            $"startup_delay={l4.StartupDelaySeconds}",
            $"heartbeat_interval={configured.HeartbeatIntervalSeconds}",
            $"posture_interval={l4.PostureIntervalSeconds}",
            $"inventory_interval={configured.InventoryIntervalSeconds}",
            $"inventory_collection_timeout={configured.Inventory.CollectionTimeoutSeconds}",
            $"inventory_max_serialized_bytes={configured.Inventory.MaxSerializedBytes}",
            $"slo_sample_interval={l4.SloSampleIntervalSeconds}",
            $"slo_window_minutes={l4.SloWindowMinutes}",
            $"scan_timeout={l4.ScanTimeoutSeconds}",
            $"queue_pause={l4.QueuePauseDepth}",
            $"passive_queue_pause={configured.PassiveTelemetry.QueuePauseDepth}",
            $"journal_queue_pause={configured.Journal.QueuePauseDepth}",
            $"queue_max_size_mb={configured.Queue.MaxSizeMb}",
            $"queue_warning_size_percent={configured.Queue.WarningSizePercent}",
            $"queue_max_backoff_seconds={configured.Queue.MaxBackoffSeconds}",
            $"max_events={l4.MaxEventsPerScan}",
            $"cleanup_on_disable={l4.CleanupStateOnDisable}",
            $"state_path={l4.StatePath}",
            $"policy_snapshots={string.Join(',', PolicySnapshotTypes)}",
            $"slo_thresholds=average_cpu_milli<{MaximumAverageCpuPercentMilli},p95_cpu_milli<{MaximumP95CpuPercentMilli},rss_bytes<{MaximumRssBytes},write_bytes_per_second<{MaximumAverageWriteBytesPerSecond}",
            "slo_inputs=process_total_processor_time,process_rss,managed_memory,/proc/self/io:write_bytes,queue_metrics",
            $"role_inputs=existing_{LinuxJournalScopes.Configured(configured.Journal)}_systemd_journal_identifier_and_unit_only",
            "exclusions=raw_inventory_values,raw_policy_files,sql,dns_queries,file_paths,container_environment,credentials,payloads");
        return Sha256(canonical);
    }

    public LinuxL4TelemetryPlan Preflight(IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var candidate = ComputeBaseline(snapshots);
        var planHash = PlanHash;
        var journalScope = LinuxJournalScopes.Configured(options.Journal);
        var activationBlockers = BuildActivationBlockers(options, candidate, planHash);
        var roleManifest = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
                WindowsCoverageLevel.L4,
                options.Journal.DeclaredRoles,
                new HashSet<string>(StringComparer.Ordinal))
            .Where(item => item.CoverageLevel == WindowsCoverageLevel.L4
                && item.Requirement == SourceRequirementKinds.RoleSpecific)
            .ToArray();
        return new(
            planHash,
            candidate.Hash,
            candidate.Complete,
            candidate.States,
            candidate.Blockers,
            activationBlockers.Count == 0,
            activationBlockers,
            options.L4Telemetry.Enabled,
            string.Equals(options.L4Telemetry.ApprovedPlanHash, planHash, StringComparison.Ordinal),
            string.Equals(options.L4Telemetry.ApprovedBaselineHash, candidate.Hash, StringComparison.Ordinal),
            options.Journal.DeclaredRoles.Order(StringComparer.Ordinal).ToArray(),
            roleManifest.Where(item => item.Applicability == SourceApplicabilityStatuses.Applicable)
                .Select(item => item.SourceId).Order(StringComparer.Ordinal).ToArray(),
            roleManifest.Where(item => item.Applicability == SourceApplicabilityStatuses.NotApplicable)
                .Select(item => item.SourceId).Order(StringComparer.Ordinal).ToArray(),
            PolicySnapshotTypes,
            journalScope,
            "Existing unprivileged agent identity only; denied inventory remains explicit and no access is widened.",
            "None. This pack fingerprints already-sanitized bounded inventory and reads only its own process counters and queue metrics.",
            journalScope == LinuxJournalScopes.AllAccessibleLocal
                ? "Only SHA-256 posture signatures, aggregate SLO values, source state, and fixed role labels are emitted by L4. Its shared journal input may include high-sensitivity user-service text already readable by the agent; bounded redaction cannot guarantee arbitrary messages are secret-free."
                : "Only SHA-256 posture signatures, aggregate SLO values, source state, and fixed role labels are emitted; raw inventory values and application payloads are excluded.",
            $"journal_scope={journalScope}; posture={options.L4Telemetry.PostureIntervalSeconds}s from one-time consumption of completed inventory at upstream cadence {options.InventoryIntervalSeconds}s; slo={options.L4Telemetry.SloSampleIntervalSeconds}s/{options.L4Telemetry.SloWindowMinutes}m; deadline={options.L4Telemetry.ScanTimeoutSeconds}s; queue_pause={options.L4Telemetry.QueuePauseDepth}; max_events={options.L4Telemetry.MaxEventsPerScan}; L1-L3 source approvals remain separate prerequisites and can still cap server coverage below L4.",
            $"Disable Agent:L4Telemetry:Enabled; optional cleanup removes only {options.L4Telemetry.StatePath}.");
    }

    private static IReadOnlyList<string> BuildActivationBlockers(
        LinuxAgentOptions configured,
        BaselineCandidate candidate,
        string planHash)
    {
        var blockers = new List<string>(18);
        if (!configured.HasValidL4TelemetryBounds()) blockers.Add("l4_telemetry_bounds_invalid");
        if (!configured.HasValidJournalBounds()) blockers.Add("journal_bounds_invalid");
        if (!configured.PassiveTelemetry.Enabled) blockers.Add("passive_telemetry_disabled");
        if (!configured.HasValidPassiveTelemetryBounds()) blockers.Add("passive_telemetry_bounds_invalid");
        if (!string.Equals(configured.PassiveTelemetry.ApprovedPlanHash,
                LinuxPassiveTelemetryCollector.ComputePlanHash(configured), StringComparison.Ordinal))
            blockers.Add("passive_telemetry_approval_hash_mismatch");
        if (configured.HeartbeatIntervalSeconds <= 0) blockers.Add("heartbeat_interval_invalid");
        if ((long)configured.L4Telemetry.SloSampleIntervalSeconds
            + configured.L4Telemetry.ScanTimeoutSeconds
            + configured.HeartbeatIntervalSeconds > 270)
            blockers.Add("slo_freshness_budget_exceeded");
        if ((long)configured.L4Telemetry.PostureIntervalSeconds
            + configured.Inventory.CollectionTimeoutSeconds
            + configured.HeartbeatIntervalSeconds > 6_900)
            blockers.Add("policy_freshness_budget_exceeded");
        if (configured.Journal.TargetCoverageLevel != WindowsCoverageLevel.L4)
            blockers.Add("journal_target_not_l4");
        if (!configured.Journal.Enabled) blockers.Add("journal_disabled");
        if (configured.Journal.DeclaredRoles is not { Length: > 0 })
            blockers.Add("declared_roles_missing");
        else if (configured.Journal.DeclaredRoles.Any(role => !LinuxDeclaredRoles.IsKnown(role)))
            blockers.Add("declared_role_unsupported");
        if (!candidate.Complete) blockers.Add("candidate_baseline_incomplete");
        if (!IsSha256(configured.L4Telemetry.ApprovedBaselineHash))
            blockers.Add("approved_baseline_hash_missing_or_invalid");
        else if (!string.Equals(configured.L4Telemetry.ApprovedBaselineHash, candidate.Hash, StringComparison.Ordinal))
            blockers.Add("approved_baseline_hash_mismatch");
        if (!IsSha256(configured.L4Telemetry.ApprovedPlanHash))
            blockers.Add("approved_plan_hash_missing_or_invalid");
        else if (!string.Equals(configured.L4Telemetry.ApprovedPlanHash, planHash, StringComparison.Ordinal))
            blockers.Add("approved_plan_hash_mismatch");
        return blockers;
    }

    public LinuxL4CollectionResult CollectPolicy(
        LinuxL4TelemetryState previous,
        IReadOnlyList<AssetInventorySnapshot> snapshots,
        string agentId,
        string hostname)
    {
        var now = timeProvider.GetUtcNow();
        var candidate = ComputeBaseline(snapshots);
        if (!candidate.Complete)
        {
            return PolicyGap(previous, agentId, hostname, "inventory_snapshot_incomplete", now);
        }
        if (!string.Equals(candidate.Hash, options.L4Telemetry.ApprovedBaselineHash, StringComparison.Ordinal)
            && !previous.Policy.BaselineEstablished)
        {
            return PolicyGap(previous, agentId, hostname, "approved_baseline_mismatch", now);
        }
        if (previous.Policy.BaselineEstablished
            && !string.Equals(previous.Policy.ApprovedBaselineHash, options.L4Telemetry.ApprovedBaselineHash, StringComparison.Ordinal))
        {
            return PolicyGap(previous, agentId, hostname, "approved_baseline_changed", now);
        }
        if (previous.Policy.BaselineEstablished
            && (!previous.Policy.BaselineSignatures.Keys.Order(StringComparer.Ordinal).SequenceEqual(PolicySnapshotTypes, StringComparer.Ordinal)
                || !string.Equals(ComputeAggregateHash(previous.Policy.BaselineSignatures), options.L4Telemetry.ApprovedBaselineHash, StringComparison.Ordinal)))
        {
            return PolicyGap(previous, agentId, hostname, "baseline_state_integrity_mismatch", now);
        }

        var events = new List<EventEnvelope>();
        var sequence = previous.Policy.Progress.NextSequence;
        var recoveryGapSequence = previous.Policy.Progress.RecoveryGapSequence;
        if (previous.Policy.Progress.ActiveGap && !recoveryGapSequence.HasValue)
        {
            recoveryGapSequence = sequence;
            events.Add(BuildGapEvent(
                LinuxTelemetrySourceIds.PolicyPostureDrift,
                EventSources.InventoryDiff,
                sequence++,
                now,
                agentId,
                hostname,
                $"recovered_from_{previous.Policy.Progress.ErrorCode}"));
        }
        var baseline = previous.Policy.BaselineEstablished
            ? previous.Policy.BaselineSignatures
            : candidate.Signatures;
        var currentBefore = previous.Policy.CurrentSignatures;

        if (!previous.Policy.BaselineEstablished)
        {
            events.Add(BuildEvent(
                LinuxTelemetrySourceIds.PolicyPostureDrift, EventSources.InventoryDiff,
                "policy_baseline", "baseline", sequence++, now, agentId, hostname,
                new SortedDictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["schema"] = CollectorVersion,
                    ["state"] = "baseline",
                    ["baseline_hash"] = candidate.Hash,
                    ["snapshot_count"] = candidate.Signatures.Count,
                    ["content_collected"] = false
                }));
        }
        else
        {
            foreach (var type in PolicySnapshotTypes)
            {
                var baselineSignature = baseline[type];
                var currentSignature = candidate.Signatures[type];
                var priorSignature = currentBefore.GetValueOrDefault(type, baselineSignature);
                string? action = null;
                if (!string.Equals(currentSignature, baselineSignature, StringComparison.Ordinal)
                    && !string.Equals(currentSignature, priorSignature, StringComparison.Ordinal)) action = "drift";
                else if (string.Equals(currentSignature, baselineSignature, StringComparison.Ordinal)
                    && !string.Equals(priorSignature, baselineSignature, StringComparison.Ordinal)) action = "restored";
                if (action is null) continue;
                if (events.Count >= options.L4Telemetry.MaxEventsPerScan - 1) break;
                events.Add(BuildEvent(
                    LinuxTelemetrySourceIds.PolicyPostureDrift, EventSources.InventoryDiff,
                    $"policy_{action}", action, sequence++, now, agentId, hostname,
                    new SortedDictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["schema"] = CollectorVersion,
                        ["state"] = action,
                        ["snapshot_type"] = type,
                        ["baseline_sha256"] = baselineSignature,
                        ["current_sha256"] = currentSignature,
                        ["content_collected"] = false
                    }));
            }
        }

        events.Add(BuildEvent(
            LinuxTelemetrySourceIds.PolicyPostureDrift, EventSources.InventoryDiff,
            "policy_sample", "sample", sequence++, now, agentId, hostname,
            new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["schema"] = CollectorVersion,
                ["state"] = "sample",
                ["baseline_hash"] = options.L4Telemetry.ApprovedBaselineHash,
                ["current_hash"] = candidate.Hash,
                ["drifted_snapshot_count"] = candidate.Signatures.Count(pair => !string.Equals(pair.Value, baseline[pair.Key], StringComparison.Ordinal)),
                ["content_collected"] = false
            }));

        var driftedCount = candidate.Signatures.Count(pair => !string.Equals(pair.Value, baseline[pair.Key], StringComparison.Ordinal));
        var policyStatus = driftedCount > 0 ? SourceHealthStatuses.Degraded : SourceHealthStatuses.Healthy;
        var policyError = driftedCount > 0 ? "policy_posture_drift_active" : "none";
        var progress = UpdatedProgress(previous.Policy.Progress, sequence, events, now, policyStatus, policyError,
            previous.Policy.Progress.ActiveGap, 0, 0) with { RecoveryGapSequence = recoveryGapSequence };
        var policy = previous.Policy with
        {
            Progress = progress,
            BaselineEstablished = true,
            ApprovedBaselineHash = options.L4Telemetry.ApprovedBaselineHash,
            BaselineSignatures = new Dictionary<string, string>(baseline, StringComparer.Ordinal),
            CurrentSignatures = new Dictionary<string, string>(candidate.Signatures, StringComparer.Ordinal)
        };
        return new(
            LinuxTelemetrySourceIds.PolicyPostureDrift,
            events,
            previous with { Policy = policy },
            policyStatus,
            policyError,
            false,
            0,
            0,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["baseline_state"] = previous.Policy.BaselineEstablished ? "verified" : "established",
                ["snapshot_count"] = candidate.Signatures.Count.ToString(CultureInfo.InvariantCulture),
                ["drifted_snapshot_count"] = driftedCount.ToString(CultureInfo.InvariantCulture)
            });
    }

    public async Task<LinuxL4CollectionResult> CollectSloAsync(
        LinuxL4TelemetryState previous,
        QueueSloMetrics queueMetrics,
        string agentId,
        string hostname,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.L4Telemetry.ScanTimeoutSeconds));
        LinuxAgentSloObservation observation;
        try { observation = await sloSource.ObserveAsync(timeout.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return BuildPressureGap(previous, LinuxTelemetrySourceIds.AgentPerformanceSlo, agentId, hostname, "slo_scan_timeout");
        }
        var prior = previous.Slo;
        var elapsed = prior.PreviousObservedAt.HasValue ? (observation.ObservedAt - prior.PreviousObservedAt.Value).TotalSeconds : 0;
        long? cpuMilli = null;
        long? writeRate = null;
        if (elapsed > 0 && prior.PreviousProcessorTimeTicks.HasValue)
        {
            var processorDelta = observation.TotalProcessorTime.Ticks - prior.PreviousProcessorTimeTicks.Value;
            if (processorDelta >= 0)
                cpuMilli = (long)Math.Round(processorDelta / (double)TimeSpan.TicksPerSecond / elapsed / Math.Max(1, observation.ProcessorCount) * 100_000d,
                    MidpointRounding.AwayFromZero);
        }
        if (elapsed > 0 && prior.PreviousWriteBytes.HasValue && observation.WriteBytes.HasValue)
        {
            var writeDelta = observation.WriteBytes.Value - prior.PreviousWriteBytes.Value;
            if (writeDelta >= 0) writeRate = (long)Math.Round(writeDelta / elapsed, MidpointRounding.AwayFromZero);
        }

        var processorDeltaTicks = prior.PreviousProcessorTimeTicks.HasValue
            ? observation.TotalProcessorTime.Ticks - prior.PreviousProcessorTimeTicks.Value : 0;
        var writeDeltaBytes = prior.PreviousWriteBytes.HasValue && observation.WriteBytes.HasValue
            ? observation.WriteBytes.Value - prior.PreviousWriteBytes.Value : 0;
        var discontinuity = prior.PreviousObservedAt.HasValue
            && (elapsed <= 0
                || elapsed > options.L4Telemetry.SloSampleIntervalSeconds * 3L
                || prior.PreviousProcessStartTimeUtcTicks.HasValue
                    && prior.PreviousProcessStartTimeUtcTicks.Value != observation.ProcessStartTimeUtcTicks
                || prior.PreviousProcessorTimeTicks.HasValue && processorDeltaTicks < 0
                || prior.PreviousWriteBytes.HasValue && observation.WriteBytes.HasValue && writeDeltaBytes < 0);

        var currentSample = new LinuxL4SloSample
        {
            ObservedAt = observation.ObservedAt,
            CoverageStartedAt = elapsed > 0 ? prior.PreviousObservedAt : null,
            CpuPercentMilli = cpuMilli,
            RssBytes = observation.RssBytes,
            ManagedMemoryBytes = observation.ManagedMemoryBytes,
            WriteBytesPerSecond = writeRate
        };
        var cutoff = observation.ObservedAt.AddMinutes(-options.L4Telemetry.SloWindowMinutes);
        var retainedSamples = discontinuity ? Array.Empty<LinuxL4SloSample>() : prior.Samples.Where(sample => sample.ObservedAt >= cutoff);
        var samples = retainedSamples.Append(currentSample)
            .TakeLast(LinuxL4TelemetryLimits.MaximumSloSamples).ToArray();
        var requiredSamples = Math.Max(2, (int)Math.Ceiling(options.L4Telemetry.SloWindowMinutes * 60d / options.L4Telemetry.SloSampleIntervalSeconds));
        var completeSamples = samples.Where(sample => sample.CoverageStartedAt.HasValue
            && sample.CpuPercentMilli.HasValue && sample.RssBytes.HasValue && sample.WriteBytesPerSecond.HasValue).ToArray();
        var coveredWindowSeconds = completeSamples.Length == 0
            ? 0
            : Math.Max(0, (long)(observation.ObservedAt - completeSamples.Min(sample => sample.CoverageStartedAt!.Value)).TotalSeconds);
        var requiredWindowSeconds = options.L4Telemetry.SloWindowMinutes * 60L;
        var warmup = completeSamples.Length < requiredSamples || coveredWindowSeconds < requiredWindowSeconds;
        var metricsUnavailable = observation.RssBytes is null || observation.WriteBytes is null;
        var averageCpu = completeSamples.Length == 0 ? null : (long?)Math.Round(completeSamples.Average(item => item.CpuPercentMilli!.Value), MidpointRounding.AwayFromZero);
        var p95Cpu = Percentile95(completeSamples.Select(item => item.CpuPercentMilli!.Value));
        var maximumRss = completeSamples.Length == 0 ? null : completeSamples.Max(item => item.RssBytes);
        var managedMemorySamples = completeSamples.Where(item => item.ManagedMemoryBytes.HasValue)
            .Select(item => item.ManagedMemoryBytes!.Value).ToArray();
        long? boundedMaximumManagedMemory = managedMemorySamples.Length == 0 ? null : managedMemorySamples.Max();
        var averageWrites = completeSamples.Length == 0 ? null : (long?)Math.Round(completeSamples.Average(item => item.WriteBytesPerSecond!.Value), MidpointRounding.AwayFromZero);
        var breached = !warmup && !metricsUnavailable
            && (averageCpu >= MaximumAverageCpuPercentMilli
                || p95Cpu >= MaximumP95CpuPercentMilli
                || maximumRss >= MaximumRssBytes
                || averageWrites >= MaximumAverageWriteBytesPerSecond);
        var queueHealthy = queueMetrics.PoisonDepth == 0
            && queueMetrics.DroppedEventsTotal == 0
            && queueMetrics.PressureState == QueuePressureStates.Normal
            && (queueMetrics.QueueDepth == 0 && queueMetrics.OldestQueuedAgeSeconds is null
                || queueMetrics.QueueDepth > 0
                    && queueMetrics.OldestQueuedAgeSeconds is not null
                    && queueMetrics.OldestQueuedAgeSeconds <= Math.Max(300, options.Queue.MaxBackoffSeconds * 2L));
        var status = discontinuity ? SourceHealthStatuses.Degraded
            : metricsUnavailable ? SourceHealthStatuses.Degraded
            : warmup ? SourceHealthStatuses.Degraded
            : breached || !queueHealthy ? SourceHealthStatuses.Degraded
            : SourceHealthStatuses.Healthy;
        var error = discontinuity ? "slo_counter_discontinuity"
            : metricsUnavailable ? "slo_counter_unavailable"
            : warmup ? "slo_window_warmup"
            : !queueHealthy ? "slo_queue_health_breached"
            : breached ? "slo_threshold_breached"
            : "none";
        var priorStatus = prior.Progress.Status;
        var action = discontinuity ? "gap" : breached || !queueHealthy ? "breach"
            : status == SourceHealthStatuses.Healthy && priorStatus == SourceHealthStatuses.Degraded ? "recovery" : "sample";
        var sequence = prior.Progress.NextSequence;
        var events = new List<EventEnvelope>();
        var recoveryGapSequence = prior.Progress.RecoveryGapSequence;
        if (prior.Progress.ActiveGap && !recoveryGapSequence.HasValue)
        {
            recoveryGapSequence = sequence;
            events.Add(BuildGapEvent(
                LinuxTelemetrySourceIds.AgentPerformanceSlo,
                EventSources.AgentHealth,
                sequence++,
                observation.ObservedAt,
                agentId,
                hostname,
                $"recovered_from_{prior.Progress.ErrorCode}"));
        }
        var evt = BuildEvent(
            LinuxTelemetrySourceIds.AgentPerformanceSlo, EventSources.AgentHealth,
            $"slo_{action}", action, sequence++, observation.ObservedAt, agentId, hostname,
            new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["schema"] = CollectorVersion,
                ["state"] = action,
                ["window_minutes"] = options.L4Telemetry.SloWindowMinutes,
                ["sample_count"] = completeSamples.Length,
                ["required_sample_count"] = requiredSamples,
                ["covered_window_seconds"] = coveredWindowSeconds,
                ["average_cpu_percent_milli"] = averageCpu,
                ["p95_cpu_percent_milli"] = p95Cpu,
                ["maximum_rss_bytes"] = maximumRss,
                ["maximum_managed_memory_bytes"] = boundedMaximumManagedMemory,
                ["average_write_bytes_per_second"] = averageWrites,
                ["queue_depth"] = queueMetrics.QueueDepth,
                ["queue_size_bytes"] = queueMetrics.QueueSizeBytes,
                ["queue_oldest_age_seconds"] = queueMetrics.OldestQueuedAgeSeconds,
                ["queue_poison_depth"] = queueMetrics.PoisonDepth,
                ["queue_pressure_state"] = queueMetrics.PressureState,
                ["content_collected"] = false
            });
        events.Add(evt);
        if (discontinuity && !recoveryGapSequence.HasValue) recoveryGapSequence = evt.Checkpoint!.Sequence;
        var progress = UpdatedProgress(prior.Progress, sequence, events, observation.ObservedAt, status, error,
            prior.Progress.ActiveGap || discontinuity, discontinuity ? 1 : 0, 0) with
        {
            RecoveryGapSequence = recoveryGapSequence
        };
        var slo = prior with
        {
            Progress = progress,
            PreviousObservedAt = observation.ObservedAt,
            PreviousProcessorTimeTicks = observation.TotalProcessorTime.Ticks,
            PreviousWriteBytes = observation.WriteBytes,
            PreviousProcessStartTimeUtcTicks = observation.ProcessStartTimeUtcTicks,
            Samples = samples
        };
        return new(
            LinuxTelemetrySourceIds.AgentPerformanceSlo,
            events,
            previous with { Slo = slo },
            status,
            error,
            false,
            0,
            0,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["window_state"] = warmup ? "warmup" : "complete",
                ["sample_count"] = completeSamples.Length.ToString(CultureInfo.InvariantCulture),
                ["required_sample_count"] = requiredSamples.ToString(CultureInfo.InvariantCulture),
                ["covered_window_seconds"] = coveredWindowSeconds.ToString(CultureInfo.InvariantCulture),
                ["threshold_state"] = discontinuity ? "counter_discontinuity" : breached ? "breached" : warmup ? "not_evaluated" : "met",
                ["queue_state"] = queueHealthy ? "met" : "breached"
            });
    }

    public LinuxL4CollectionResult BuildPressureGap(LinuxL4TelemetryState previous, string sourceId, string agentId, string hostname, string reason)
    {
        var now = timeProvider.GetUtcNow();
        if (sourceId == LinuxTelemetrySourceIds.PolicyPostureDrift) return PolicyGap(previous, agentId, hostname, reason, now);
        var sequence = previous.Slo.Progress.NextSequence;
        var evt = BuildGapEvent(sourceId, EventSources.AgentHealth, sequence++, now, agentId, hostname, reason);
        var progress = UpdatedProgress(previous.Slo.Progress, sequence, [evt], now, SourceHealthStatuses.Degraded, reason, true, 1, 0) with
        {
            RecoveryGapSequence = previous.Slo.Progress.RecoveryGapSequence ?? evt.Checkpoint!.Sequence
        };
        return new(sourceId, [evt], previous with { Slo = previous.Slo with { Progress = progress } },
            SourceHealthStatuses.Degraded, reason, true, 1, 0, new Dictionary<string, string> { ["gap_reason"] = reason });
    }

    private LinuxL4CollectionResult PolicyGap(LinuxL4TelemetryState previous, string agentId, string hostname, string reason, DateTimeOffset now)
    {
        var sequence = previous.Policy.Progress.NextSequence;
        var evt = BuildGapEvent(LinuxTelemetrySourceIds.PolicyPostureDrift, EventSources.InventoryDiff, sequence++, now, agentId, hostname, reason);
        var progress = UpdatedProgress(previous.Policy.Progress, sequence, [evt], now, SourceHealthStatuses.Degraded, reason, true, 1, 0) with
        {
            RecoveryGapSequence = previous.Policy.Progress.RecoveryGapSequence ?? evt.Checkpoint!.Sequence
        };
        return new(LinuxTelemetrySourceIds.PolicyPostureDrift, [evt], previous with { Policy = previous.Policy with { Progress = progress } },
            SourceHealthStatuses.Degraded, reason, true, 1, 0, new Dictionary<string, string> { ["gap_reason"] = reason });
    }

    private static BaselineCandidate ComputeBaseline(
        IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var byType = snapshots.GroupBy(item => item.SnapshotType, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(item => item.CollectedAt).First(), StringComparer.Ordinal);
        var signatures = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var states = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var blockers = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var complete = true;
        foreach (var type in PolicySnapshotTypes)
        {
            if (!byType.TryGetValue(type, out var snapshot))
            {
                states[type] = "missing";
                blockers[type] = "snapshot_missing";
                complete = false;
                continue;
            }
            if (snapshot.Items is null || snapshot.Summary is null)
            {
                states[type] = "invalid_contract";
                blockers[type] = "snapshot_invalid_contract";
                complete = false;
                continue;
            }
            var state = snapshot.Summary.GetValueOrDefault("state", "unknown");
            var error = snapshot.Summary.GetValueOrDefault("error_code", "unknown");
            states[type] = $"{state}:{error}";
            if (snapshot.Summary.GetValueOrDefault("truncated") == "true")
            {
                blockers[type] = $"snapshot_truncated:{error}";
                complete = false;
                continue;
            }
            if (state is not ("success" or "not_applicable"))
            {
                blockers[type] = $"snapshot_{state}:{error}";
                complete = false;
                continue;
            }
            var combinedEvidenceBlocker = ValidateCombinedEvidence(type, snapshot);
            if (combinedEvidenceBlocker is not null)
            {
                blockers[type] = combinedEvidenceBlocker;
                complete = false;
                continue;
            }
            var canonical = new StringBuilder(type);
            foreach (var pair in snapshot.Summary.OrderBy(item => item.Key, StringComparer.Ordinal))
                canonical.Append('\n').Append("summary:").Append(pair.Key).Append('=').Append(pair.Value);
            foreach (var item in snapshot.Items.OrderBy(item => item.Kind, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal).ThenBy(item => item.Identity, StringComparer.Ordinal))
            {
                canonical.Append('\n').Append("item:").Append(item.Kind).Append('|').Append(item.Name).Append('|')
                    .Append(item.Status).Append('|').Append(item.Identity);
                foreach (var pair in item.Metadata.OrderBy(value => value.Key, StringComparer.Ordinal))
                    canonical.Append('|').Append(pair.Key).Append('=').Append(pair.Value);
            }
            signatures[type] = Sha256(canonical.ToString());
        }
        return new(ComputeAggregateHash(signatures), signatures,
            complete && signatures.Count == PolicySnapshotTypes.Count, states, blockers);
    }

    private static string? ValidateCombinedEvidence(string type, AssetInventorySnapshot snapshot)
    {
        if (type == "linux_agent_integrity")
        {
            var configState = CombinedChildState(snapshot.Summary, "source_1_state");
            var executableState = CombinedChildState(snapshot.Summary, "source_2_state");
            var hasConfig = snapshot.Items.Any(item => item.Kind == "agent_integrity" && item.Name == "configuration");
            var hasExecutable = snapshot.Items.Any(item => item.Kind == "agent_integrity" && item.Name == "executable");
            return configState == "success" && executableState == "success" && hasConfig && hasExecutable
                ? null
                : $"agent_integrity_components_incomplete:config={configState},executable={executableState},config_item={(hasConfig ? "present" : "missing")},executable_item={(hasExecutable ? "present" : "missing")}";
        }
        if (type == "linux_mandatory_access_control")
        {
            var appArmorState = CombinedChildState(snapshot.Summary, "source_1_state");
            var selinuxState = CombinedChildState(snapshot.Summary, "source_2_state");
            var validAlternativeState = new[] { "success", "unavailable", "not_applicable" };
            var statesValid = validAlternativeState.Contains(appArmorState, StringComparer.Ordinal)
                && validAlternativeState.Contains(selinuxState, StringComparer.Ordinal);
            var appArmorObserved = appArmorState == "success"
                && snapshot.Items.Any(item => item.Kind == "mandatory_access_control" && item.Name == "apparmor");
            var selinuxObserved = selinuxState == "success"
                && snapshot.Items.Any(item => item.Kind == "mandatory_access_control" && item.Name == "selinux");
            return statesValid && (appArmorObserved || selinuxObserved)
                ? null
                : $"mandatory_access_control_providers_incomplete:apparmor={appArmorState},selinux={selinuxState}";
        }
        return null;
    }

    private static string CombinedChildState(IReadOnlyDictionary<string, string> summary, string key)
    {
        var state = summary.GetValueOrDefault(key);
        return state is "success" or "unavailable" or "not_applicable" or "permission_denied" or "timeout" or "malformed"
            ? state
            : "unknown";
    }

    private sealed record BaselineCandidate(
        string Hash,
        IReadOnlyDictionary<string, string> Signatures,
        bool Complete,
        IReadOnlyDictionary<string, string> States,
        IReadOnlyDictionary<string, string> Blockers);

    private static string ComputeAggregateHash(IEnumerable<KeyValuePair<string, string>> signatures) =>
        Sha256(string.Join('\n', signatures.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{pair.Key}={pair.Value}")));

    private static LinuxL4SourceProgress UpdatedProgress(
        LinuxL4SourceProgress prior,
        long nextSequence,
        IReadOnlyList<EventEnvelope> events,
        DateTimeOffset now,
        string status,
        string error,
        bool activeGap,
        long gapIncrement,
        long droppedIncrement) => prior with
        {
            NextSequence = nextSequence,
            CollectedSequence = events.Count == 0 ? prior.CollectedSequence : events.Max(item => item.Checkpoint!.Sequence!.Value),
            LastObservedAt = now,
            LastEventAt = events.Count == 0 ? prior.LastEventAt : now,
            Status = status,
            ErrorCode = error,
            ActiveGap = activeGap,
            GapCount = SaturatingAdd(prior.GapCount, gapIncrement),
            DroppedCount = SaturatingAdd(prior.DroppedCount, droppedIncrement),
            TransitionState = status == SourceHealthStatuses.Healthy
                ? prior.Status == SourceHealthStatuses.Healthy ? HealthTransitionStates.Healthy : HealthTransitionStates.Recovered
                : HealthTransitionStates.Degraded,
            TransitionedAt = now,
            PendingReservationStart = null,
            PendingReservationEnd = null
        };

    private static EventEnvelope BuildGapEvent(string sourceId, string source, long sequence, DateTimeOffset now, string agentId, string hostname, string reason) =>
        BuildEvent(sourceId, source, sourceId == LinuxTelemetrySourceIds.PolicyPostureDrift ? "policy_gap" : "slo_gap", "gap",
            sequence, now, agentId, hostname, new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["schema"] = CollectorVersion,
                ["state"] = "gap",
                ["reason"] = reason,
                ["content_collected"] = false
            });

    private static EventEnvelope BuildEvent(
        string sourceId,
        string source,
        string eventCode,
        string action,
        long sequence,
        DateTimeOffset now,
        string agentId,
        string hostname,
        SortedDictionary<string, object?> raw)
    {
        var rawElement = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(raw, JsonDefaults.Options), JsonDefaults.Options);
        var rawHash = DeterministicEventIdentity.ComputeRawSha256(rawElement);
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = source,
            SourceId = sourceId,
            EventCode = eventCode,
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = now, RecordedAt = now },
            EventTime = now,
            Severity = action is "drift" or "breach" or "gap" ? "warning" : "information",
            Message = sourceId == LinuxTelemetrySourceIds.PolicyPostureDrift
                ? $"Linux policy posture {action}."
                : $"Linux agent performance SLO {action}.",
            Normalized = new NormalizedEventFields { Category = sourceId == LinuxTelemetrySourceIds.PolicyPostureDrift ? "policy_posture" : "agent_health", Action = action },
            Raw = rawElement,
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode, DeduplicationInputs.RawSha256],
                RawSha256 = rawHash
            },
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(rawElement, JsonDefaults.Options).Length,
                RedactionApplied = false,
                RedactedFields = [],
                TruncationApplied = false,
                TruncatedFields = []
            }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private static long? Percentile95(IEnumerable<long> values)
    {
        var sorted = values.Order().ToArray();
        if (sorted.Length == 0) return null;
        var index = Math.Max(0, (int)Math.Ceiling(sorted.Length * 0.95) - 1);
        return sorted[index];
    }

    private static string Sha256(string value) => "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static bool IsSha256(string? value) => value is not null && value.Length == 71 && value.StartsWith("sha256:", StringComparison.Ordinal)
        && value.AsSpan(7).ToString().All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static long SaturatingAdd(long left, long right) => left > long.MaxValue - right ? long.MaxValue : left + right;
}
