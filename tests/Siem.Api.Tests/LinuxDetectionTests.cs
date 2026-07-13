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
    }

    [Fact]
    public void LinuxRulesHavePositiveAndNegativeSyntheticStructuredFixtures()
    {
        var engine = new DetectionEngine();
        foreach (var (ruleId, positive, negative, healthSource) in LinuxRuleCases())
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
        Assert.False(denied.PrerequisitesMet);
        Assert.False(denied.Matched);
        Assert.Equal("low", denied.EffectiveConfidence);
        Assert.Contains("suppressed", denied.Reason, StringComparison.OrdinalIgnoreCase);

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

        var now = DateTimeOffset.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(index => LinuxJournalEvent(
                LinuxTelemetrySourceIds.Ssh,
                "authentication",
                "authenticate",
                "failure",
                now.AddMinutes(-index),
                sourceIp: "192.0.2.10",
                targetUser: "synthetic-user"))
            .ToArray();
        var batch = new IngestBatchRequest { AgentId = agentId, BatchId = Guid.NewGuid(), SentAt = now, Events = events };
        var eventRepository = new EventRepository(dataSource);
        var alertRepository = new AlertRepository(dataSource);
        var storeResult = await eventRepository.StoreEventsAsync(batch, CancellationToken.None);
        await alertRepository.RunLinuxDetectionsAsync(batch, storeResult.AcceptedEventIds, new DetectionEngine(), CancellationToken.None);

        var duplicateStore = await eventRepository.StoreEventsAsync(batch, CancellationToken.None);
        await alertRepository.RunLinuxDetectionsAsync(batch, duplicateStore.AcceptedEventIds, new DetectionEngine(), CancellationToken.None);

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
        yield return ("firewall.change.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.Firewall, "firewall", "policy_change", "success", sourceIp: "192.0.2.30", destinationIp: "198.51.100.30", destinationPort: "22"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.Firewall, "firewall", "status", "success", sourceIp: "192.0.2.30", destinationIp: "198.51.100.30", destinationPort: "22"),
            LinuxTelemetrySourceIds.Firewall);
        yield return ("tamper.agent-log-source-silence.linux",
            LinuxJournalEvent(LinuxTelemetrySourceIds.AgentLogTamper, "tamper", "log_corruption", "failure"),
            LinuxJournalEvent(LinuxTelemetrySourceIds.AgentLogTamper, "tamper", "agent_status", "success"),
            LinuxTelemetrySourceIds.AgentLogTamper);
        yield return ("tamper.agent-self-integrity.linux",
            PortableEvent(EventSources.InventoryDiff, "linux-agent-self-integrity-snapshot", "agent_self_integrity_change", new NormalizedEventFields { Category = "tamper", Action = "agent_integrity_change", Outcome = "success", FilePath = "/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent", Hash = new string('a', 64) }),
            PortableEvent(EventSources.InventoryDiff, "linux-agent-self-integrity-snapshot", "inventory_observed", new NormalizedEventFields { Category = "inventory", Action = "observed", Outcome = "success", FilePath = "/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent" }),
            "linux-agent-self-integrity-snapshot");
    }

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
