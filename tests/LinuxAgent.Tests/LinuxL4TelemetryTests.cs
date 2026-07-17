using System.Text.Json;
using System.Net;
using System.Net.Http.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.L4;
using Challenger.Siem.LinuxAgent.Passive;
using Challenger.Siem.LinuxAgent.Services;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxL4TelemetryTests
{
    private static readonly DateTimeOffset Start = new(2026, 7, 16, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CatalogAndConfigurationRequireExplicitKnownRoleL4Activation()
    {
        var options = BaseOptions();
        options.L4Telemetry.Enabled = false;
        Assert.False(options.L4Telemetry.Enabled);
        Assert.True(options.HasValidL4TelemetryBounds());
        options.HeartbeatIntervalSeconds = 3_600;
        Assert.True(options.HasValidL4TelemetryBounds());
        options.HeartbeatIntervalSeconds = 60;
        Assert.Equal(2, LinuxTelemetrySourceCatalog.L4.Count(item => item.Requirement == SourceRequirementKinds.Mandatory));
        Assert.Equal(6, LinuxTelemetrySourceCatalog.L4.Count(item => item.Requirement == SourceRequirementKinds.RoleSpecific));
        Assert.Contains(LinuxTelemetrySourceCatalog.L4, item => item.SourceId == LinuxTelemetrySourceIds.PolicyPostureDrift
            && item.SourceKind == TelemetrySourceKinds.InventoryDiff && item.CheckpointKind == SourceCheckpointKinds.Sequence);
        Assert.Contains(LinuxTelemetrySourceCatalog.L4, item => item.SourceId == LinuxTelemetrySourceIds.AgentPerformanceSlo
            && item.SourceKind == TelemetrySourceKinds.AgentHealth && item.CheckpointKind == SourceCheckpointKinds.Sequence);

        options.L4Telemetry.Enabled = true;
        Assert.True(options.HasValidL4TelemetryBounds());
        options.Journal.DeclaredRoles = [];
        Assert.False(options.HasValidJournalBounds());
        Assert.False(options.HasValidL4TelemetryBounds());
        options.Journal.DeclaredRoles = ["unknown_role"];
        Assert.False(options.HasValidJournalBounds());
        Assert.False(options.HasValidL4TelemetryBounds());
        options.Journal.DeclaredRoles = ["general_server"];
        options.L4Telemetry.MaxEventsPerScan = 5;
        Assert.False(options.HasValidL4TelemetryBounds());
        options.L4Telemetry.MaxEventsPerScan = 7;
        options.L4Telemetry.PostureIntervalSeconds = options.InventoryIntervalSeconds - 1;
        Assert.False(options.HasValidL4TelemetryBounds());
        options.L4Telemetry.PostureIntervalSeconds = 3601;
        Assert.False(options.HasValidL4TelemetryBounds());
        options.L4Telemetry.PostureIntervalSeconds = 3600;
        options.L4Telemetry.SloSampleIntervalSeconds = 241;
        Assert.False(options.HasValidL4TelemetryBounds());
        options.L4Telemetry.SloSampleIntervalSeconds = 240;
        options.L4Telemetry.ScanTimeoutSeconds = 30;
        Assert.False(options.HasValidL4TelemetryBounds());
        options.L4Telemetry.SloSampleIntervalSeconds = 180;
        Assert.True(options.HasValidL4TelemetryBounds());
        options.HeartbeatIntervalSeconds = 61;
        Assert.False(options.HasValidL4TelemetryBounds());
        options.HeartbeatIntervalSeconds = 60;
    }

    [Fact]
    public void PreflightUsesTwoPassBaselineAndBindsEveryActivationBoundary()
    {
        var options = BaseOptions();
        var source = new SyntheticSloSource();
        var collector = Collector(options, source);
        var snapshots = CompleteSnapshots();

        var candidate = collector.Preflight(snapshots);
        Assert.True(candidate.CandidateBaselineComplete);
        Assert.StartsWith("sha256:", candidate.CandidateBaselineHash, StringComparison.Ordinal);
        Assert.False(candidate.BaselineHashMatches);
        Assert.Empty(candidate.CandidateBaselineBlockers);
        Assert.All(candidate.CandidateBaselineStates.Values, state => Assert.Equal("success:none", state));
        Assert.False(candidate.ActivationReady);
        Assert.Contains("approved_baseline_hash_missing_or_invalid", candidate.ActivationBlockers);
        Assert.Contains("approved_plan_hash_missing_or_invalid", candidate.ActivationBlockers);
        Assert.Empty(candidate.ApplicableRoleSources);
        Assert.Equal(6, candidate.NotApplicableRoleSources.Count);
        var firstPlan = candidate.PlanHash;

        options.L4Telemetry.ApprovedBaselineHash = candidate.CandidateBaselineHash;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var approved = collector.Preflight(snapshots);
        Assert.NotEqual(firstPlan, approved.PlanHash);
        Assert.True(approved.BaselineHashMatches);
        Assert.True(approved.ApprovalHashMatches);
        Assert.True(approved.ActivationReady);
        Assert.Empty(approved.ActivationBlockers);
        Assert.True(collector.IsEnabledAndApproved);

        options.Journal.DeclaredRoles = ["web_server"];
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var webPlan = collector.Preflight(snapshots);
        Assert.Equal([LinuxTelemetrySourceIds.RoleWeb], webPlan.ApplicableRoleSources);
        Assert.DoesNotContain(LinuxTelemetrySourceIds.RoleWeb, webPlan.NotApplicableRoleSources);

        options.Journal.DeclaredRoles = ["workstation"];
        Assert.NotEqual(options.L4Telemetry.ApprovedPlanHash, LinuxL4TelemetryCollector.ComputePlanHash(options));
        options.Journal.DeclaredRoles = ["general_server"];
        options.L4Telemetry.SloWindowMinutes++;
        Assert.NotEqual(options.L4Telemetry.ApprovedPlanHash, LinuxL4TelemetryCollector.ComputePlanHash(options));
        options.L4Telemetry.SloWindowMinutes--;
        options.Queue.WarningSizePercent++;
        Assert.NotEqual(options.L4Telemetry.ApprovedPlanHash, LinuxL4TelemetryCollector.ComputePlanHash(options));
        options.Queue.WarningSizePercent--;
        options.HeartbeatIntervalSeconds++;
        Assert.NotEqual(options.L4Telemetry.ApprovedPlanHash, LinuxL4TelemetryCollector.ComputePlanHash(options));
        options.HeartbeatIntervalSeconds--;
        options.Journal.IncludeAccessibleUserJournals = !options.Journal.IncludeAccessibleUserJournals;
        Assert.NotEqual(options.L4Telemetry.ApprovedPlanHash, LinuxL4TelemetryCollector.ComputePlanHash(options));
    }

    [Fact]
    public void DisabledPreflightReportsEveryActivationOnlyBlockerBeforeApproval()
    {
        var options = BaseOptions();
        options.L4Telemetry.Enabled = false;
        var collector = Collector(options, new SyntheticSloSource());
        var snapshots = CompleteSnapshots();
        var candidate = collector.Preflight(snapshots);
        options.L4Telemetry.ApprovedBaselineHash = candidate.CandidateBaselineHash;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);

        var readyWhileDisabled = collector.Preflight(snapshots);
        Assert.True(readyWhileDisabled.ActivationReady);
        Assert.False(LinuxL4TelemetryCollector.IsConfigurationApproved(options));

        options.HeartbeatIntervalSeconds = 3_600;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var stale = collector.Preflight(snapshots);
        Assert.False(stale.ActivationReady);
        Assert.Contains("slo_freshness_budget_exceeded", stale.ActivationBlockers);
        Assert.Contains("policy_freshness_budget_exceeded", stale.ActivationBlockers);

        options.HeartbeatIntervalSeconds = 60;
        options.Journal.Enabled = false;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var journalDisabled = collector.Preflight(snapshots);
        Assert.False(journalDisabled.ActivationReady);
        Assert.Contains("journal_disabled", journalDisabled.ActivationBlockers);

        options.Journal.Enabled = true;
        options.Journal.DeclaredRoles = [];
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var rolesMissing = collector.Preflight(snapshots);
        Assert.False(rolesMissing.ActivationReady);
        Assert.Contains("declared_roles_missing", rolesMissing.ActivationBlockers);

        options.Journal.DeclaredRoles = ["unsupported_role"];
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var unsupportedRole = collector.Preflight(snapshots);
        Assert.False(unsupportedRole.ActivationReady);
        Assert.Contains("declared_role_unsupported", unsupportedRole.ActivationBlockers);

        options.Journal.DeclaredRoles = ["general_server"];
        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L3;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var wrongTarget = collector.Preflight(snapshots);
        Assert.False(wrongTarget.ActivationReady);
        Assert.Contains("journal_target_not_l4", wrongTarget.ActivationBlockers);

        options.Journal.TargetCoverageLevel = WindowsCoverageLevel.L4;
        options.PassiveTelemetry.Enabled = false;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var passiveDisabled = collector.Preflight(snapshots);
        Assert.False(passiveDisabled.ActivationReady);
        Assert.Contains("passive_telemetry_disabled", passiveDisabled.ActivationBlockers);
        options.L4Telemetry.Enabled = true;
        Assert.False(collector.IsEnabledAndApproved);
        options.L4Telemetry.Enabled = false;

        options.PassiveTelemetry.Enabled = true;
        options.PassiveTelemetry.ApprovedPlanHash = "sha256:" + new string('f', 64);
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var passiveMismatched = collector.Preflight(snapshots);
        Assert.False(passiveMismatched.ActivationReady);
        Assert.Contains("passive_telemetry_approval_hash_mismatch", passiveMismatched.ActivationBlockers);
        options.L4Telemetry.Enabled = true;
        Assert.False(collector.IsEnabledAndApproved);
        options.L4Telemetry.Enabled = false;
        options.PassiveTelemetry.ApprovedPlanHash = LinuxPassiveTelemetryCollector.ComputePlanHash(options);

        options.L4Telemetry.Enabled = true;
        options.HeartbeatIntervalSeconds = 3_600;
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        Assert.False(LinuxL4TelemetryCollector.IsConfigurationApproved(options));
    }

    [Fact]
    public void DisabledPreflightAndRuntimeApprovalRejectInvalidCoreL4Bounds()
    {
        var options = BaseOptions();
        options.L4Telemetry.Enabled = false;
        var collector = Collector(options, new SyntheticSloSource());
        var snapshots = CompleteSnapshots();
        options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;

        void AssertCoreBoundsBlocked()
        {
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var plan = collector.Preflight(snapshots);
            Assert.False(plan.ActivationReady);
            Assert.Contains("l4_telemetry_bounds_invalid", plan.ActivationBlockers);
            options.L4Telemetry.Enabled = true;
            Assert.False(LinuxL4TelemetryCollector.IsConfigurationApproved(options));
            options.L4Telemetry.Enabled = false;
        }

        options.L4Telemetry.SloSampleIntervalSeconds = 10;
        AssertCoreBoundsBlocked();
        options.L4Telemetry.SloSampleIntervalSeconds = 60;

        options.L4Telemetry.MaxEventsPerScan = 1;
        AssertCoreBoundsBlocked();
        options.L4Telemetry.MaxEventsPerScan = 100;

        var fixedStatePath = options.L4Telemetry.StatePath;
        options.L4Telemetry.StatePath = "/tmp/synthetic-unsafe-l4-state.json";
        AssertCoreBoundsBlocked();
        options.L4Telemetry.StatePath = fixedStatePath;
    }

    [Fact]
    public void IncompleteOrDeniedPolicyEvidenceCannotBecomeAnApprovedHealthyBaseline()
    {
        var options = BaseOptions();
        var collector = Collector(options, new SyntheticSloSource());
        var snapshots = CompleteSnapshots().ToArray();
        snapshots[1] = snapshots[1] with
        {
            Items = Array.Empty<InventoryItem>(),
            Summary = new Dictionary<string, string>
            {
                ["state"] = "permission_denied",
                ["error_code"] = "synthetic_failure",
                ["truncated"] = "false"
            }
        };
        var plan = collector.Preflight(snapshots);
        Assert.False(plan.CandidateBaselineComplete);
        Assert.Equal("permission_denied:synthetic_failure", plan.CandidateBaselineStates["linux_firewall"]);
        Assert.Equal("snapshot_permission_denied:synthetic_failure", plan.CandidateBaselineBlockers["linux_firewall"]);

        options.L4Telemetry.ApprovedBaselineHash = plan.CandidateBaselineHash;
        var result = collector.CollectPolicy(new(), snapshots, options.AgentId, "SYNTHETIC-LINUX-01");
        Assert.Equal(SourceHealthStatuses.Degraded, result.HealthStatus);
        Assert.Equal("inventory_snapshot_incomplete", result.ErrorCode);
        Assert.False(result.NewState.Policy.BaselineEstablished);
        Assert.Single(result.Events, item => item.EventCode == "policy_gap");
    }

    [Fact]
    public void CombinedPolicyInputsCannotHideMissingIntegrityOrDeniedMacEvidence()
    {
        var options = BaseOptions();
        var collector = Collector(options, new SyntheticSloSource());
        var snapshots = CompleteSnapshots().ToArray();

        var integrityIndex = Array.FindIndex(snapshots, item => item.SnapshotType == "linux_agent_integrity");
        snapshots[integrityIndex] = snapshots[integrityIndex] with
        {
            Items = snapshots[integrityIndex].Items.Where(item => item.Name == "configuration").ToArray(),
            Summary = new Dictionary<string, string>(snapshots[integrityIndex].Summary, StringComparer.Ordinal)
            {
                ["source_1_state"] = "success",
                ["source_2_state"] = "unavailable"
            }
        };
        var missingExecutable = collector.Preflight(snapshots);
        Assert.False(missingExecutable.CandidateBaselineComplete);
        Assert.Contains("executable=unavailable", missingExecutable.CandidateBaselineBlockers["linux_agent_integrity"], StringComparison.Ordinal);

        snapshots = CompleteSnapshots().ToArray();
        snapshots[integrityIndex] = snapshots[integrityIndex] with
        {
            Items = snapshots[integrityIndex].Items.Where(item => item.Name == "executable").ToArray(),
            Summary = new Dictionary<string, string>(snapshots[integrityIndex].Summary, StringComparer.Ordinal)
            {
                ["source_1_state"] = "permission_denied",
                ["source_2_state"] = "success"
            }
        };
        var deniedConfig = collector.Preflight(snapshots);
        Assert.False(deniedConfig.CandidateBaselineComplete);
        Assert.Contains("config=permission_denied", deniedConfig.CandidateBaselineBlockers["linux_agent_integrity"], StringComparison.Ordinal);

        snapshots = CompleteSnapshots().ToArray();
        var macIndex = Array.FindIndex(snapshots, item => item.SnapshotType == "linux_mandatory_access_control");
        snapshots[macIndex] = snapshots[macIndex] with
        {
            Summary = new Dictionary<string, string>(snapshots[macIndex].Summary, StringComparer.Ordinal)
            {
                ["source_1_state"] = "success",
                ["source_2_state"] = "permission_denied"
            }
        };
        var deniedAlternative = collector.Preflight(snapshots);
        Assert.False(deniedAlternative.CandidateBaselineComplete);
        Assert.Contains("selinux=permission_denied", deniedAlternative.CandidateBaselineBlockers["linux_mandatory_access_control"], StringComparison.Ordinal);

        snapshots[macIndex] = snapshots[macIndex] with
        {
            Items = Array.Empty<InventoryItem>(),
            Summary = new Dictionary<string, string>(snapshots[macIndex].Summary, StringComparer.Ordinal)
            {
                ["source_1_state"] = "unavailable",
                ["source_2_state"] = "not_applicable"
            }
        };
        var noObservedProvider = collector.Preflight(snapshots);
        Assert.False(noObservedProvider.CandidateBaselineComplete);
        Assert.Contains("providers_incomplete", noObservedProvider.CandidateBaselineBlockers["linux_mandatory_access_control"], StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyBaselineDriftStableDriftAndRestoreAreHonestAndBounded()
    {
        var options = BaseOptions();
        options.L4Telemetry.MaxEventsPerScan = 7;
        var collector = Collector(options, new SyntheticSloSource());
        var baseline = CompleteSnapshots();
        options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(baseline).CandidateBaselineHash;

        var first = collector.CollectPolicy(new(), baseline, options.AgentId, "SYNTHETIC-LINUX-01");
        Assert.Equal(SourceHealthStatuses.Healthy, first.HealthStatus);
        Assert.Equal(2, first.Events.Count);
        Assert.Contains(first.Events, item => item.EventCode == "policy_baseline" && item.Normalized!.Action == "baseline");
        Assert.Contains(first.Events, item => item.EventCode == "policy_sample" && item.Normalized!.Action == "sample");
        Assert.DoesNotContain("synthetic-value", JsonSerializer.Serialize(first.Events), StringComparison.Ordinal);

        var drifted = ChangeSnapshot(baseline, "linux_firewall", "changed");
        var second = collector.CollectPolicy(first.NewState, drifted, options.AgentId, "SYNTHETIC-LINUX-01");
        Assert.Equal(SourceHealthStatuses.Degraded, second.HealthStatus);
        Assert.Equal("policy_posture_drift_active", second.ErrorCode);
        var drift = Assert.Single(second.Events, item => item.EventCode == "policy_drift");
        Assert.Equal("drift", drift.Normalized!.Action);
        Assert.Equal("linux_firewall", drift.Raw.GetProperty("snapshot_type").GetString());

        var stable = collector.CollectPolicy(second.NewState, drifted, options.AgentId, "SYNTHETIC-LINUX-01");
        Assert.Equal(SourceHealthStatuses.Degraded, stable.HealthStatus);
        Assert.DoesNotContain(stable.Events, item => item.EventCode == "policy_drift");
        Assert.Single(stable.Events, item => item.EventCode == "policy_sample");

        var restored = collector.CollectPolicy(stable.NewState, baseline, options.AgentId, "SYNTHETIC-LINUX-01");
        Assert.Equal(SourceHealthStatuses.Healthy, restored.HealthStatus);
        Assert.Single(restored.Events, item => item.EventCode == "policy_restored" && item.Normalized!.Action == "restored");
        Assert.All(first.Events.Concat(second.Events).Concat(stable.Events).Concat(restored.Events), item =>
            Assert.Equal(DeterministicEventIdentity.ComputeSha256Uuid(item), item.EventId));
        Assert.All(new[] { first, second, stable, restored }, item => Assert.InRange(item.Events.Count, 1, options.L4Telemetry.MaxEventsPerScan));
    }

    [Fact]
    public void TamperedStoredBaselineCannotClearOrRedefineApprovedDrift()
    {
        var options = BaseOptions();
        var collector = Collector(options, new SyntheticSloSource());
        var snapshots = CompleteSnapshots();
        options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
        var baseline = collector.CollectPolicy(new(), snapshots, options.AgentId, "SYNTHETIC-LINUX-01").NewState;
        var tamperedSignatures = baseline.Policy.BaselineSignatures.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        tamperedSignatures["linux_firewall"] = "sha256:" + new string('f', 64);
        var tampered = baseline with { Policy = baseline.Policy with { BaselineSignatures = tamperedSignatures } };

        var result = collector.CollectPolicy(tampered, snapshots, options.AgentId, "SYNTHETIC-LINUX-01");
        Assert.Equal(SourceHealthStatuses.Degraded, result.HealthStatus);
        Assert.Equal("baseline_state_integrity_mismatch", result.ErrorCode);
        Assert.Single(result.Events, item => item.EventCode == "policy_gap");
    }

    [Fact]
    public async Task SloWarmupPassBreachQueueFailureAndCounterResetAreExplicit()
    {
        var options = BaseOptions();
        options.L4Telemetry.SloSampleIntervalSeconds = 120;
        options.L4Telemetry.SloWindowMinutes = 10;
        var source = new SyntheticSloSource(
            Observation(Start, 1, 1000),
            Observation(Start.AddMinutes(2), 1.1, 2000),
            Observation(Start.AddMinutes(4), 1.2, 3000),
            Observation(Start.AddMinutes(6), 1.3, 4000),
            Observation(Start.AddMinutes(8), 1.4, 5000),
            Observation(Start.AddMinutes(10), 1.5, 6000),
            Observation(Start.AddMinutes(12), 121.5, 7000),
            Observation(Start.AddMinutes(14), 121.6, 8000),
            Observation(Start.AddMinutes(16), 200, 9000, processEpoch: 2));
        var collector = Collector(options, source);
        var metrics = HealthyQueue();

        var first = await collector.CollectSloAsync(new(), metrics, options.AgentId, "SYNTHETIC-LINUX-01", default);
        Assert.Equal("slo_window_warmup", first.ErrorCode);
        var warmup = first;
        for (var index = 0; index < 4; index++)
        {
            warmup = await collector.CollectSloAsync(warmup.NewState, metrics, options.AgentId, "SYNTHETIC-LINUX-01", default);
            Assert.Equal("slo_window_warmup", warmup.ErrorCode);
        }
        var passed = await collector.CollectSloAsync(warmup.NewState, metrics, options.AgentId, "SYNTHETIC-LINUX-01", default);
        Assert.Equal(SourceHealthStatuses.Healthy, passed.HealthStatus);

        var breached = await collector.CollectSloAsync(passed.NewState, metrics, options.AgentId, "SYNTHETIC-LINUX-01", default);
        Assert.Equal(SourceHealthStatuses.Degraded, breached.HealthStatus);
        Assert.Equal("slo_threshold_breached", breached.ErrorCode);
        Assert.Equal("slo_breach", Assert.Single(breached.Events).EventCode);

        var queueFailed = await collector.CollectSloAsync(breached.NewState,
            metrics with { PoisonDepth = 1 }, options.AgentId, "SYNTHETIC-LINUX-01", default);
        Assert.Equal("slo_queue_health_breached", queueFailed.ErrorCode);

        var reset = await collector.CollectSloAsync(queueFailed.NewState, metrics, options.AgentId, "SYNTHETIC-LINUX-01", default);
        Assert.Equal("slo_counter_discontinuity", reset.ErrorCode);
        Assert.Equal("slo_gap", Assert.Single(reset.Events).EventCode);
        Assert.Single(reset.NewState.Slo.Samples);
        Assert.True(reset.NewState.Slo.Progress.ActiveGap);
    }

    [Fact]
    public async Task SloCannotBecomeHealthyBeforeTheFullRollingWindowIsCovered()
    {
        var options = BaseOptions();
        options.L4Telemetry.SloSampleIntervalSeconds = 60;
        options.L4Telemetry.SloWindowMinutes = 15;
        var observations = Enumerable.Range(0, 16)
            .Select(index => Observation(Start.AddMinutes(index), 1 + index * 0.01, 1_000 + index * 100L))
            .ToArray();
        var collector = Collector(options, new SyntheticSloSource(observations));
        var state = new LinuxL4TelemetryState();
        LinuxL4CollectionResult? result = null;
        for (var index = 0; index < observations.Length; index++)
        {
            result = await collector.CollectSloAsync(state, HealthyQueue(), options.AgentId, "SYNTHETIC-LINUX-01", default);
            state = result.NewState;
            if (index < 15) Assert.Equal("slo_window_warmup", result.ErrorCode);
        }

        Assert.NotNull(result);
        Assert.Equal(SourceHealthStatuses.Healthy, result.HealthStatus);
        Assert.Equal("none", result.ErrorCode);
        Assert.Equal(900, result.Events.Single().Raw.GetProperty("covered_window_seconds").GetInt64());
        Assert.Equal(25L * 1024 * 1024, result.Events.Single().Raw.GetProperty("maximum_managed_memory_bytes").GetInt64());
    }

    [Fact]
    public async Task UnknownRequiredQueueMetricsFailTheSloClosed()
    {
        var options = BaseOptions();
        options.L4Telemetry.SloSampleIntervalSeconds = 120;
        options.L4Telemetry.SloWindowMinutes = 10;
        var collector = Collector(options, new SyntheticSloSource(
            Observation(Start, 1, 1000),
            Observation(Start.AddMinutes(2), 1.1, 2000),
            Observation(Start.AddMinutes(4), 1.2, 3000),
            Observation(Start.AddMinutes(6), 1.3, 4000),
            Observation(Start.AddMinutes(8), 1.4, 5000),
            Observation(Start.AddMinutes(10), 1.5, 6000)));
        var state = (await collector.CollectSloAsync(new(), HealthyQueue(), options.AgentId, "SYNTHETIC-LINUX-01", default)).NewState;
        for (var index = 0; index < 4; index++)
            state = (await collector.CollectSloAsync(state, HealthyQueue(), options.AgentId, "SYNTHETIC-LINUX-01", default)).NewState;

        var unknown = await collector.CollectSloAsync(state,
            HealthyQueue() with { QueueDepth = 1, OldestQueuedAgeSeconds = null, PressureState = null, DroppedEventsTotal = null },
            options.AgentId, "SYNTHETIC-LINUX-01", default);
        Assert.Equal(SourceHealthStatuses.Degraded, unknown.HealthStatus);
        Assert.Equal("slo_queue_health_breached", unknown.ErrorCode);
    }

    [Fact]
    public async Task RuntimePersistsPrivateStateReservesBeforeQueueAndAcknowledgesAfterCommit()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var statePath = Path.Combine(root, "l4-state.json");
            var snapshots = CompleteSnapshots();
            var slo = new SyntheticSloSource(Observation(Start, 1, 1000));
            var collector = Collector(options, slo);
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var queue = new MemoryQueue(HealthyQueue());
            var store = new LinuxL4TelemetryStateStore(statePath, root);
            var clock = new TestTimeProvider(Start);
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options), store, collector, queue, clock);

            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);
            Assert.Equal(2, queue.Events.Count);
            Assert.Equal(2, runtime.CurrentState.Policy.Progress.CollectedSequence);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(statePath));

            await runtime.RecordAcknowledgedAsync(queue.Events, default);
            Assert.Equal(2, runtime.CurrentState.Policy.Progress.AcknowledgedSequence);
            var health = Assert.Single(runtime.Health(), item => item.SourceId == LinuxTelemetrySourceIds.PolicyPostureDrift);
            Assert.Equal(SourceHealthStatuses.Healthy, health.Status);
            Assert.Equal(health.CollectedCheckpoint!.Sequence, health.AcknowledgedCheckpoint!.Sequence);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task AcknowledgementCannotJumpAcrossALowerMissingSequence()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-ack-order-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var statePath = Path.Combine(root, "state.json");
            var snapshots = CompleteSnapshots();
            var collector = Collector(options, new SyntheticSloSource());
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var queue = new MemoryQueue(HealthyQueue());
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options),
                new LinuxL4TelemetryStateStore(statePath, root), collector, queue, new TestTimeProvider(Start));
            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);
            Assert.Equal(2, queue.Events.Count);

            await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.RecordAcknowledgedAsync([queue.Events[1]], default));
            Assert.Equal(0, runtime.CurrentState.Policy.Progress.AcknowledgedSequence);
            Assert.Equal("l4_acknowledgement_non_contiguous", runtime.CurrentState.Policy.Progress.ErrorCode);
            Assert.True(runtime.CurrentState.Policy.Progress.ActiveGap);

            await runtime.RecordAcknowledgedAsync(queue.Events, default);
            Assert.Equal(2, runtime.CurrentState.Policy.Progress.AcknowledgedSequence);
            Assert.Equal("acknowledgement_recovered_pending_sample", runtime.CurrentState.Policy.Progress.ErrorCode);
            Assert.False(runtime.CurrentState.Policy.Progress.ActiveGap);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ServerRejectedSequenceIsDurablyAbandonedWithoutQueueHeadDeadlock(int rejectedIndex)
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-rejected-sequence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var snapshots = CompleteSnapshots();
            var clock = new TestTimeProvider(Start);
            var collector = new LinuxL4TelemetryCollector(Options.Create(options), new SyntheticSloSource(), clock);
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var queue = new DrainerQueue();
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options),
                new LinuxL4TelemetryStateStore(Path.Combine(root, "l4-state.json"), root), collector, queue, clock);
            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);
            Assert.Equal(2, await queue.CountAsync(default));

            var journal = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(Path.Combine(root, "journal-state.json")), clock);
            await journal.InitializeAsync("test", "synthetic", default);
            var handler = new RejectOneThenAcceptHandler(rejectedIndex);
            using var http = new HttpClient(handler) { BaseAddress = options.ServerBaseUrl };
            var drainer = new LinuxQueueDrainer(Options.Create(options), queue,
                new SiemIngestClient(http, options), journal, acknowledgementObservers: [runtime]);

            await drainer.DrainAsync(default);
            if (await queue.CountAsync(default) > 0) await drainer.DrainAsync(default);
            Assert.Equal(0, await queue.CountAsync(default));
            Assert.Single(queue.PoisonedQueueIds);
            Assert.True(queue.DeletedQueueIds.Count >= 1);
            Assert.Equal(rejectedIndex + 1, runtime.CurrentState.Policy.Progress.AbandonedThroughSequence);
            Assert.True(runtime.CurrentState.Policy.Progress.AcknowledgedSequence >= (rejectedIndex == 0 ? 2 : 1));
            Assert.True(runtime.CurrentState.Policy.Progress.ActiveGap);
            Assert.Equal(1, runtime.CurrentState.Policy.Progress.DroppedCount);
            Assert.Equal("l4_server_rejected_sequence", runtime.CurrentState.Policy.Progress.ErrorCode);
            Assert.NotEqual(SourceHealthStatuses.Healthy,
                runtime.Health().Single(item => item.SourceId == LinuxTelemetrySourceIds.PolicyPostureDrift).Status);

            clock.Advance(TimeSpan.FromHours(1));
            var freshSnapshots = snapshots.Select(item => item with { CollectedAt = clock.GetUtcNow() }).ToArray();
            await runtime.ObserveInventoryAsync(freshSnapshots, default);
            Assert.Contains(queue.Pending, item => item.Envelope.EventCode == "policy_gap");
            await drainer.DrainAsync(default);
            Assert.Equal(0, await queue.CountAsync(default));
            Assert.False(runtime.CurrentState.Policy.Progress.ActiveGap);
            Assert.True(runtime.CurrentState.Policy.Progress.GapCount >= 1);
            Assert.Equal(1, runtime.CurrentState.Policy.Progress.DroppedCount);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task RejectionCannotAbandonAnEarlierUnseenSequence()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-rejection-gap-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var snapshots = CompleteSnapshots();
            var collector = Collector(options, new SyntheticSloSource());
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var queue = new MemoryQueue(HealthyQueue());
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options),
                new LinuxL4TelemetryStateStore(Path.Combine(root, "state.json"), root), collector, queue, new TestTimeProvider(Start));
            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);
            var ordered = queue.Events.OrderBy(item => item.Checkpoint!.Sequence).ToArray();

            await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.RecordRejectedAsync([ordered[1]], default));
            Assert.Equal(0, runtime.CurrentState.Policy.Progress.AbandonedThroughSequence);
            Assert.Equal(0, runtime.CurrentState.Policy.Progress.DroppedCount);
            Assert.Equal("l4_rejection_non_contiguous", runtime.CurrentState.Policy.Progress.ErrorCode);
            var gapCount = runtime.CurrentState.Policy.Progress.GapCount;
            await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.RecordRejectedAsync([ordered[1]], default));
            Assert.Equal(gapCount, runtime.CurrentState.Policy.Progress.GapCount);
            runtime.RecordAcknowledgementFailure([ordered[1]]);
            Assert.Equal("l4_rejection_non_contiguous", runtime.CurrentState.Policy.Progress.ErrorCode);
            Assert.Equal(gapCount, runtime.CurrentState.Policy.Progress.GapCount);

            await runtime.RecordAcknowledgedAsync([ordered[0]], default);
            await runtime.RecordRejectedAsync([ordered[1]], default);
            Assert.Equal(2, runtime.CurrentState.Policy.Progress.AbandonedThroughSequence);
            Assert.Equal(1, runtime.CurrentState.Policy.Progress.AcknowledgedSequence);
            Assert.Equal(1, runtime.CurrentState.Policy.Progress.DroppedCount);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("web_server", "nginx", "linux-role-web")]
    [InlineData("database_server", "postgresql", "linux-role-database")]
    [InlineData("dns_server", "named", "linux-role-dns")]
    [InlineData("file_server", "smbd", "linux-role-file-server")]
    [InlineData("container_host", "containerd", "linux-role-container")]
    [InlineData("identity_server", "sssd", "linux-role-identity")]
    public void DeclaredRoleClassificationUsesFixedIdentityAndDropsApplicationPayload(
        string role, string identifier, string expectedSourceId)
    {
        var options = BaseOptions();
        options.Journal.DeclaredRoles = [role];
        options.L4Telemetry.ApprovedBaselineHash = "sha256:" + new string('0', 64);
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        var record = JournalRecord(identifier, $"{identifier}.service", "SYNTHETIC_SECRET_CANARY SQL SELECT token=private DNS=query.invalid /private/path");

        Assert.True(new LinuxJournalNormalizer().TryNormalize(record, options, Start, out var normalized, out var error), error);
        Assert.Equal(expectedSourceId, normalized!.Envelope.SourceId);
        Assert.Equal(LinuxTelemetrySourceCatalog.L4RolePackId, normalized.Envelope.Normalized!.Labels["linux.source_pack"]);
        Assert.DoesNotContain("SYNTHETIC_SECRET_CANARY", normalized.Envelope.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("query.invalid", normalized.Envelope.Raw.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain("/private/path", normalized.Envelope.Raw.GetRawText(), StringComparison.Ordinal);
        Assert.Contains("role-application-message-redacted", normalized.Envelope.Raw.GetRawText(), StringComparison.Ordinal);

        options.Journal.DeclaredRoles = ["general_server"];
        Assert.True(new LinuxJournalNormalizer().TryNormalize(record, options, Start, out var generic, out error), error);
        Assert.Equal(LinuxTelemetrySourceIds.JournalL1, generic!.Envelope.SourceId);
    }

    [Theory]
    [InlineData("web_server", "nginx", "linux-role-web", "web_service")]
    [InlineData("database_server", "postgresql", "linux-role-database", "database_service")]
    [InlineData("file_server", "smbd", "linux-role-file-server", "file_service")]
    [InlineData("identity_server", "sssd", "linux-role-identity", "identity_service")]
    public void RoleServiceLifecycleWinsSafelyAndRetainsL2Evidence(
        string role, string identity, string sourceId, string family)
    {
        var options = ApprovedRoleOptions(role);
        var record = RoleCollisionRecord(identity, $"{identity}.service", "start", pam: false);

        Assert.True(new LinuxJournalNormalizer().TryNormalize(record, options, Start, out var normalized, out var error), error);
        Assert.Equal(sourceId, normalized!.Envelope.SourceId);
        Assert.Equal(family, normalized.EventFamily);
        var secondary = Assert.Single(normalized.AdditionalEvidence!);
        Assert.Equal(LinuxTelemetrySourceIds.ServiceChange, secondary.SourceId);
        Assert.Equal("service_start", secondary.EventFamily);
        Assert.Equal(LinuxTelemetrySourceIds.ServiceChange, normalized.Envelope.Normalized!.Labels["linux.secondary_source_id"]);
        Assert.Contains("role-application-message-redacted", normalized.Envelope.Raw.GetRawText(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("database_server", "postgresql", "linux-role-database", "database_authentication")]
    [InlineData("file_server", "smbd", "linux-role-file-server", "file_authentication")]
    [InlineData("identity_server", "sssd", "linux-role-identity", "identity_authentication")]
    public void RolePamAuthenticationWinsSafelyAndRetainsLoginEvidence(
        string role, string identity, string sourceId, string family)
    {
        var options = ApprovedRoleOptions(role);
        var record = RoleCollisionRecord("pam_unix", $"{identity}.service", action: null, pam: true);

        Assert.True(new LinuxJournalNormalizer().TryNormalize(record, options, Start, out var normalized, out var error), error);
        Assert.Equal(sourceId, normalized!.Envelope.SourceId);
        Assert.Equal(family, normalized.EventFamily);
        var secondary = Assert.Single(normalized.AdditionalEvidence!);
        Assert.Equal(LinuxTelemetrySourceIds.LoginSession, secondary.SourceId);
        Assert.Equal("login", secondary.EventFamily);
        Assert.DoesNotContain("SYNTHETIC_ROLE_PAYLOAD", normalized.Envelope.Raw.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public void RolePamSessionWithoutActionUsesStructuredPamType()
    {
        var options = ApprovedRoleOptions("identity_server");
        var record = RoleCollisionRecord("pam_unix", "sssd.service", action: null, pam: true, pamType: "open_session");

        Assert.True(new LinuxJournalNormalizer().TryNormalize(record, options, Start, out var normalized, out var error), error);
        Assert.Equal(LinuxTelemetrySourceIds.RoleIdentity, normalized!.Envelope.SourceId);
        Assert.Equal("identity_authentication", normalized.EventFamily);
        Assert.Equal("session_start", normalized.Envelope.Normalized!.Action);
        Assert.Equal(LinuxTelemetrySourceIds.LoginSession, Assert.Single(normalized.AdditionalEvidence!).SourceId);
    }

    [Theory]
    [InlineData("create", "container_create")]
    [InlineData("start", "container_start")]
    [InlineData("stop", "container_stop")]
    [InlineData("destroy", "container_destroy")]
    public void ContainerRuntimeLifecycleFamilyIsReachableWithoutConfusingSystemdServiceLifecycle(
        string rawAction, string normalizedAction)
    {
        var options = ApprovedRoleOptions("container_host");
        var runtimeRecord = RoleCollisionRecord("containerd", "containerd.service", rawAction, pam: false);
        Assert.True(new LinuxJournalNormalizer().TryNormalize(runtimeRecord, options, Start, out var runtime, out var error), error);
        Assert.Equal(LinuxTelemetrySourceIds.RoleContainer, runtime!.Envelope.SourceId);
        Assert.Equal("container_lifecycle", runtime.EventFamily);
        Assert.Equal(normalizedAction, runtime.Envelope.Normalized!.Action);

        var systemd = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["__CURSOR"] = "s=synthetic-container-systemd",
            ["__REALTIME_TIMESTAMP"] = "1784160000000000",
            ["_BOOT_ID"] = "syntheticbootid000000000000000001",
            ["_TRANSPORT"] = "journal",
            ["_SYSTEMD_UNIT"] = "containerd.service",
            ["SYSLOG_IDENTIFIER"] = "systemd",
            ["MESSAGE_ID"] = "39f53479d3a045ac8e11786248231fbf",
            ["MESSAGE"] = "Synthetic service lifecycle."
        });
        Assert.True(new LinuxJournalNormalizer().TryNormalize(systemd, options, Start, out var service, out error), error);
        Assert.Equal("container_service", service!.EventFamily);
        Assert.Equal("service_start", service.Envelope.Normalized!.Action);
    }

    [Fact]
    public async Task RoleCollectionAndHealthStayDisabledUntilTheExactL4ApprovalMatches()
    {
        var options = BaseOptions();
        options.Journal.DeclaredRoles = ["web_server"];
        options.L4Telemetry.Enabled = false;
        var record = JournalRecord("nginx", "nginx.service", "synthetic web event");
        var normalizer = new LinuxJournalNormalizer();
        Assert.True(normalizer.TryNormalize(record, options, Start, out var disabledEvent, out var error), error);
        Assert.Equal(LinuxTelemetrySourceIds.JournalL1, disabledEvent!.Envelope.SourceId);

        options.L4Telemetry.Enabled = true;
        options.L4Telemetry.ApprovedBaselineHash = "sha256:" + new string('0', 64);
        options.L4Telemetry.ApprovedPlanHash = "sha256:" + new string('1', 64);
        Assert.True(normalizer.TryNormalize(record, options, Start, out var mismatchedEvent, out error), error);
        Assert.Equal(LinuxTelemetrySourceIds.JournalL1, mismatchedEvent!.Envelope.SourceId);

        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-role-gate-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(Path.Combine(root, "state.json")), new TestTimeProvider(Start));
            await runtime.InitializeAsync("test", "synthetic", default);
            var health = Assert.Single(runtime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.RoleWeb);
            Assert.Equal(SourceHealthStatuses.Disabled, health.Status);
            Assert.False(health.Enabled);
            Assert.Equal("l4_approval_hash_missing_or_mismatch", health.ErrorCode);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task InterruptedReservationBecomesANonReusedGapAndRetriesThePolicySemantics()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-reservation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var statePath = Path.Combine(root, "state.json");
            var snapshots = CompleteSnapshots();
            var collector = Collector(options, new SyntheticSloSource());
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var store = new LinuxL4TelemetryStateStore(statePath, root);
            var failed = new LinuxL4TelemetryRuntime(Options.Create(options), store, collector,
                new FailingQueue(HealthyQueue()), new TestTimeProvider(Start));
            await failed.InitializeAsync(default);

            await Assert.ThrowsAsync<IOException>(() => failed.ObserveInventoryAsync(snapshots, default));
            Assert.Equal(1, failed.CurrentState.Policy.Progress.PendingReservationStart);
            Assert.Equal(3, failed.CurrentState.Policy.Progress.NextSequence);
            Assert.False(failed.CurrentState.Policy.BaselineEstablished);

            var recoveredQueue = new MemoryQueue(HealthyQueue());
            var recovered = new LinuxL4TelemetryRuntime(Options.Create(options), store, collector, recoveredQueue, new TestTimeProvider(Start));
            await recovered.InitializeAsync(default);
            Assert.Null(recovered.CurrentState.Policy.Progress.PendingReservationStart);
            Assert.True(recovered.CurrentState.Policy.Progress.ActiveGap);
            Assert.Equal(2, recovered.CurrentState.Policy.Progress.GapCount);
            await recovered.ObserveInventoryAsync(snapshots, default);
            Assert.Equal(new long[] { 3, 4, 5 }, recoveredQueue.Events.Select(item => item.Checkpoint!.Sequence!.Value));
            Assert.Equal("policy_gap", recoveredQueue.Events[0].EventCode);
            Assert.True(recovered.CurrentState.Policy.BaselineEstablished);
            Assert.True(recovered.CurrentState.Policy.Progress.ActiveGap);
            Assert.Equal(3, recovered.CurrentState.Policy.Progress.RecoveryGapSequence);
            await recovered.RecordAcknowledgedAsync(recoveredQueue.Events, default);
            Assert.False(recovered.CurrentState.Policy.Progress.ActiveGap);
            Assert.Null(recovered.CurrentState.Policy.Progress.RecoveryGapSequence);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task PressureIsCoalescedInStateWithoutAddingEventsToThePressuredQueue()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-pressure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var statePath = Path.Combine(root, "state.json");
            var snapshots = CompleteSnapshots();
            var collector = Collector(options, new SyntheticSloSource());
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var pressureMetrics = HealthyQueue() with { QueueSizeBytes = 450L * 1024 * 1024 };
            var queue = new MemoryQueue(pressureMetrics);
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options),
                new LinuxL4TelemetryStateStore(statePath, root), collector, queue, new TestTimeProvider(Start));
            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);
            await runtime.ObserveInventoryAsync(snapshots, default);

            Assert.Empty(queue.Events);
            Assert.True(runtime.CurrentState.Policy.Progress.ActiveGap);
            Assert.Equal(1, runtime.CurrentState.Policy.Progress.GapCount);
            Assert.Equal("l4_queue_byte_pressure", runtime.CurrentState.Policy.Progress.ErrorCode);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task StaleInventoryIsConsumedOnceAndCannotRefreshPolicyObservation()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-stale-inventory-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var statePath = Path.Combine(root, "state.json");
            var snapshots = CompleteSnapshots();
            var collector = Collector(options, new SyntheticSloSource());
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var clock = new TestTimeProvider(Start.AddHours(2));
            var queue = new MemoryQueue(HealthyQueue());
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options),
                new LinuxL4TelemetryStateStore(statePath, root), collector, queue, clock);
            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);
            Assert.Single(queue.Events, item => item.EventCode == "policy_gap");
            var observedAt = runtime.CurrentState.Policy.Progress.LastObservedAt;

            clock.Advance(TimeSpan.FromHours(2));
            await runtime.CollectPendingPolicyAsync(default);
            Assert.Single(queue.Events);
            Assert.Equal(observedAt, runtime.CurrentState.Policy.Progress.LastObservedAt);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task CorruptPrivateStateFailsClosedInsteadOfSilentlyRebaselining()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-corrupt-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.L4Telemetry.StartupDelaySeconds = 0;
            var statePath = Path.Combine(root, "state.json");
            await File.WriteAllTextAsync(statePath, "{malformed");
            File.SetUnixFileMode(statePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var snapshots = CompleteSnapshots();
            var collector = Collector(options, new SyntheticSloSource());
            options.L4Telemetry.ApprovedBaselineHash = collector.Preflight(snapshots).CandidateBaselineHash;
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var queue = new MemoryQueue(HealthyQueue());
            var runtime = new LinuxL4TelemetryRuntime(Options.Create(options),
                new LinuxL4TelemetryStateStore(statePath, root), collector, queue, new TestTimeProvider(Start));
            await runtime.InitializeAsync(default);
            await runtime.ObserveInventoryAsync(snapshots, default);

            Assert.Empty(queue.Events);
            Assert.False(runtime.CurrentState.Policy.BaselineEstablished);
            var health = Assert.Single(runtime.Health(), item => item.SourceId == LinuxTelemetrySourceIds.PolicyPostureDrift);
            Assert.Equal(SourceHealthStatuses.Error, health.Status);
            Assert.Equal("state_malformed", health.ErrorCode);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task QuietDeclaredRoleUsesPersistedSuccessfulJournalReadNotHeartbeatNow()
    {
        var root = Path.Combine(Path.GetTempPath(), "challenger-l4-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            options.Journal.DeclaredRoles = ["web_server"];
            options.L4Telemetry.ApprovedBaselineHash = "sha256:" + new string('0', 64);
            options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
            var statePath = Path.Combine(root, "state.json");
            var clock = new TestTimeProvider(Start);
            var store = new LinuxStateStore(statePath);
            var runtime = new LinuxJournalRuntime(Options.Create(options), store, clock);
            await runtime.InitializeAsync("test", "synthetic", default);
            await runtime.RecordCollectedAsync(GenericRecord(options.AgentId), default);
            runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Array.Empty<string>()));
            await runtime.RecordSuccessfulReadObservationAsync(default);

            var role = Assert.Single(runtime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.RoleWeb);
            Assert.Equal(SourceHealthStatuses.Healthy, role.Status);
            Assert.Equal("none", role.Details!["gap_state"]);
            Assert.Equal(Start, role.ObservedAt);
            Assert.All(role.EventFamilyStatuses!.Values, value => Assert.Equal(SourceEvidenceStatuses.NotObserved, value));
            Assert.Equal(SourceEvidenceStatuses.Satisfied, role.PrerequisiteStatuses!["declared_role_web_server"]);

            clock.Advance(TimeSpan.FromHours(1));
            var restarted = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(statePath), clock);
            await restarted.InitializeAsync("test", "synthetic", default);
            var persisted = Assert.Single(restarted.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.RoleWeb);
            Assert.Equal(Start, persisted.ObservedAt);

            var contractedOptions = BaseOptions();
            contractedOptions.Journal.DeclaredRoles = ["general_server"];
            contractedOptions.L4Telemetry.ApprovedBaselineHash = options.L4Telemetry.ApprovedBaselineHash;
            contractedOptions.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(contractedOptions);
            var contracted = new LinuxJournalRuntime(Options.Create(contractedOptions), new LinuxStateStore(statePath), clock);
            await contracted.InitializeAsync("test", "synthetic", default);
            var historicalRole = Assert.Single(contracted.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.RoleWeb);
            Assert.Equal(SourceApplicabilityStatuses.NotApplicable, historicalRole.Applicability);
            Assert.Equal("declared_roles_do_not_require_source", historicalRole.ApplicabilityReason);
            Assert.Equal(SourceHealthStatuses.NotApplicable, historicalRole.Status);
            Assert.False(historicalRole.Enabled);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task InitialBoundedJournalHistoryGapRecoversWithoutRestartAndRetainsHistory()
    {
        var root = Path.Combine(Path.GetTempPath(), "challenger-journal-gap-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = BaseOptions();
            var statePath = Path.Combine(root, "state.json");
            var clock = new TestTimeProvider(Start);
            var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(statePath), clock);
            await runtime.InitializeAsync("test", "synthetic", default);
            runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Enumerable.Repeat("{}", options.Journal.MaxRecordsPerPoll).ToArray()));
            runtime.RecordGap("bounded_history_window");
            await runtime.RecordCollectedAsync(GenericRecord(options.AgentId), default);
            var gapped = Assert.Single(runtime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.JournalL1);
            Assert.Equal(SourceHealthStatuses.Error, gapped.Status);
            Assert.True(gapped.GapDetected);
            Assert.Equal(1, gapped.GapCount);

            clock.Advance(TimeSpan.FromSeconds(5));
            runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Array.Empty<string>()));
            await runtime.RecordSuccessfulReadObservationAsync(default);
            var recovered = Assert.Single(runtime.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.JournalL1);
            Assert.Equal(SourceHealthStatuses.Healthy, recovered.Status);
            Assert.False(recovered.GapDetected);
            Assert.Equal(1, recovered.GapCount);

            var restarted = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(statePath), clock);
            await restarted.InitializeAsync("test", "synthetic", default);
            var persisted = Assert.Single(restarted.Snapshot().Health, item => item.SourceId == LinuxTelemetrySourceIds.JournalL1);
            Assert.False(persisted.GapDetected);
            Assert.Equal(1, persisted.GapCount);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static LinuxAgentOptions BaseOptions()
    {
        var options = new LinuxAgentOptions
        {
            AgentId = "synthetic-l4-agent",
            ServerBaseUrl = new Uri("https://siem.example.invalid"),
            ApiToken = "synthetic-test-token",
            Journal = new JournalOptions
            {
                TargetCoverageLevel = WindowsCoverageLevel.L4,
                DeclaredRoles = ["general_server"]
            },
            PassiveTelemetry = new PassiveTelemetryOptions { Enabled = true },
            L4Telemetry = new L4TelemetryOptions { Enabled = true, StartupDelaySeconds = 0 },
            Queue = new QueueOptions { Path = "unused" },
            State = new StateOptions { Path = "unused" }
        };
        options.PassiveTelemetry.ApprovedPlanHash = LinuxPassiveTelemetryCollector.ComputePlanHash(options);
        return options;
    }

    private static LinuxL4TelemetryCollector Collector(LinuxAgentOptions options, ILinuxAgentSloSource source) =>
        new(Options.Create(options), source, new TestTimeProvider(Start));

    private static IReadOnlyList<AssetInventorySnapshot> CompleteSnapshots() => LinuxL4TelemetryCollector.PolicySnapshotTypes
        .Select(type =>
        {
            IReadOnlyList<InventoryItem> items = type switch
            {
                "linux_agent_integrity" =>
                [
                    new InventoryItem { Kind = "agent_integrity", Name = "configuration", Status = "expected_permissions" },
                    new InventoryItem { Kind = "agent_integrity", Name = "executable", Status = "expected_permissions",
                        Metadata = new Dictionary<string, string> { ["sha256"] = new string('0', 64) } }
                ],
                "linux_mandatory_access_control" =>
                [new InventoryItem { Kind = "mandatory_access_control", Name = "apparmor", Status = "enabled" }],
                _ => [new InventoryItem
                {
                    Kind = "synthetic_posture",
                    Name = type,
                    Status = "observed",
                    Metadata = new Dictionary<string, string> { ["state"] = "synthetic-value" }
                }]
            };
            var summary = new Dictionary<string, string>
            {
                ["state"] = "success",
                ["error_code"] = "none",
                ["truncated"] = "false",
                ["item_count"] = items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)
            };
            if (type == "linux_agent_integrity")
            {
                summary["source_1_state"] = "success";
                summary["source_2_state"] = "success";
            }
            else if (type == "linux_mandatory_access_control")
            {
                summary["source_1_state"] = "success";
                summary["source_2_state"] = "unavailable";
            }
            return new AssetInventorySnapshot
            {
                AgentId = "synthetic-l4-agent",
                Hostname = "SYNTHETIC-LINUX-01",
                SnapshotType = type,
                CollectedAt = Start,
                Items = items,
                Summary = summary
            };
        }).ToArray();

    private static IReadOnlyList<AssetInventorySnapshot> ChangeSnapshot(IReadOnlyList<AssetInventorySnapshot> snapshots, string type, string value) =>
        snapshots.Select(snapshot => snapshot.SnapshotType != type ? snapshot : snapshot with
        {
            Items = [snapshot.Items[0] with { Status = value }]
        }).ToArray();

    private static LinuxAgentSloObservation Observation(DateTimeOffset at, double processorSeconds, long writeBytes, long processEpoch = 1) =>
        new(at, TimeSpan.FromSeconds(processorSeconds), 4, 100L * 1024 * 1024, 25L * 1024 * 1024, writeBytes, processEpoch);

    private static QueueSloMetrics HealthyQueue() => new()
    {
        QueueDepth = 0,
        QueueSizeBytes = 0,
        MaxSizeBytes = 512L * 1024 * 1024,
        PressureState = QueuePressureStates.Normal,
        PoisonDepth = 0,
        DroppedEventsTotal = 0
    };

    private static string JournalRecord(string identifier, string unit, string message) => JsonSerializer.Serialize(new Dictionary<string, object>
    {
        ["__CURSOR"] = "s=synthetic-l4-cursor",
        ["__REALTIME_TIMESTAMP"] = "1784160000000000",
        ["_BOOT_ID"] = "syntheticbootid000000000000000001",
        ["_TRANSPORT"] = "journal",
        ["_SYSTEMD_UNIT"] = unit,
        ["SYSLOG_IDENTIFIER"] = identifier,
        ["PRIORITY"] = "5",
        ["ACTION"] = "security_event",
        ["RESULT"] = "success",
        ["MESSAGE"] = message.Replace("token=private", "token=synthetic-private-value-with-padding", StringComparison.Ordinal),
        ["_CMDLINE"] = $"/usr/bin/{identifier} --token=SYNTHETIC_SECRET_CANARY"
    });

    private static LinuxAgentOptions ApprovedRoleOptions(string role)
    {
        var options = BaseOptions();
        options.Journal.DeclaredRoles = [role];
        options.L4Telemetry.ApprovedBaselineHash = "sha256:" + new string('0', 64);
        options.L4Telemetry.ApprovedPlanHash = LinuxL4TelemetryCollector.ComputePlanHash(options);
        return options;
    }

    private static string RoleCollisionRecord(string identifier, string unit, string? action, bool pam, string pamType = "auth")
    {
        var fields = new Dictionary<string, object>
        {
            ["__CURSOR"] = "s=synthetic-l4-collision",
            ["__REALTIME_TIMESTAMP"] = "1784160000000000",
            ["_BOOT_ID"] = "syntheticbootid000000000000000001",
            ["_TRANSPORT"] = "journal",
            ["_SYSTEMD_UNIT"] = unit,
            ["SYSLOG_IDENTIFIER"] = identifier,
            ["PRIORITY"] = "5",
            ["RESULT"] = "success",
            ["MESSAGE"] = "SYNTHETIC_ROLE_PAYLOAD"
        };
        if (action is not null) fields["ACTION"] = action;
        if (pam)
        {
            fields["PAM_SERVICE"] = unit[..^".service".Length];
            fields["PAM_TYPE"] = pamType;
            fields["PAM_USER"] = "synthetic-user";
        }
        return JsonSerializer.Serialize(fields);
    }

    private static NormalizedJournalRecord GenericRecord(string agentId)
    {
        var envelope = new EventEnvelope
        {
            EventId = Guid.NewGuid(),
            AgentId = agentId,
            Hostname = "SYNTHETIC-LINUX-01",
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.LinuxJournal,
            SourceId = LinuxTelemetrySourceIds.JournalL1,
            EventTime = Start,
            Checkpoint = new SourceCheckpoint { Cursor = "s=generic", EventTime = Start, RecordedAt = Start }
        };
        return new(envelope, "s=generic", "syntheticbootid000000000000000001", 1784160000000000, false, "system");
    }

    private sealed class SyntheticSloSource(params LinuxAgentSloObservation[] observations) : ILinuxAgentSloSource
    {
        private readonly Queue<LinuxAgentSloObservation> values = new(observations);
        public Task<LinuxAgentSloObservation> ObserveAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(values.Count > 0 ? values.Dequeue() : Observation(Start, 1, 1000));
        }
    }

    private sealed class TestTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset value = now;
        public override DateTimeOffset GetUtcNow() => value;
        public void Advance(TimeSpan duration) => value = value.Add(duration);
    }

    private sealed class MemoryQueue(QueueSloMetrics metrics) : IEventQueue
    {
        public List<EventEnvelope> Events { get; } = [];
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) { Events.Add(envelope); return Task.CompletedTask; }
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<QueuedEvent>>(Array.Empty<QueuedEvent>());
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(Events.Count);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) => Task.FromResult(metrics with { QueueDepth = Events.Count });
    }

    private sealed class FailingQueue(QueueSloMetrics metrics) : IEventQueue
    {
        private bool failed;
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken)
        {
            if (!failed) { failed = true; throw new IOException("synthetic queue failure"); }
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<QueuedEvent>>(Array.Empty<QueuedEvent>());
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(0);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) => Task.FromResult(metrics);
    }

    private sealed class DrainerQueue : IEventQueue
    {
        private long nextId = 1;
        public List<QueuedEvent> Pending { get; } = [];
        public List<long> DeletedQueueIds { get; } = [];
        public List<long> PoisonedQueueIds { get; } = [];
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken)
        {
            Pending.Add(new QueuedEvent(nextId++, envelope, 0, null));
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<QueuedEvent>>(Pending.Take(maxEvents).ToArray());
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken)
        {
            DeletedQueueIds.AddRange(queueIds);
            Pending.RemoveAll(item => queueIds.Contains(item.QueueId));
            return Task.CompletedTask;
        }
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken)
        {
            PoisonedQueueIds.AddRange(queueIds);
            Pending.RemoveAll(item => queueIds.Contains(item.QueueId));
            return Task.CompletedTask;
        }
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(Pending.Count);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) =>
            Task.FromResult(HealthyQueue() with { QueueDepth = Pending.Count });
    }

    private sealed class RejectOneThenAcceptHandler(int rejectedIndex) : HttpMessageHandler
    {
        private int calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            var batchId = document.RootElement.GetProperty("batch_id").GetGuid();
            var ids = document.RootElement.GetProperty("events").EnumerateArray()
                .Select(item => item.GetProperty("event_id").GetGuid()).ToArray();
            var first = Interlocked.Increment(ref calls) == 1;
            var accepted = first ? ids.Where((_, index) => index != rejectedIndex).ToArray() : ids;
            var rejected = first ? ids.Where((_, index) => index == rejectedIndex).ToArray() : Array.Empty<Guid>();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new IngestBatchResponse
                {
                    BatchId = batchId,
                    Accepted = accepted.Length,
                    Rejected = rejected.Length,
                    AcceptedEventIds = accepted,
                    RejectedEventIds = rejected
                })
            };
        }
    }
}
