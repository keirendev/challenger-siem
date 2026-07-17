using System.Text.Json;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class PortableNestedTelemetryTests(IntegrationTestDatabase database)
{
    [PostgresFact]
    public async Task NestedProcessNetworkAndFileTelemetryIsDenormalizedAndSearchableWithoutBackfill()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var agentId = $"portable-nested-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-NESTED-01";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);

        var eventTime = DateTimeOffset.Parse("2026-07-13T12:00:00Z");
        var raw = JsonSerializer.SerializeToElement(new { fixture = "synthetic-only", sequence = 1 });
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.InventoryDiff,
            SourceId = "synthetic-portable-nested",
            EventCode = "synthetic_nested_observed",
            EventTime = eventTime,
            Severity = "information",
            Message = "Synthetic nested process, network, and file telemetry fixture.",
            Checkpoint = new SourceCheckpoint { Sequence = 1, EventTime = eventTime, RecordedAt = eventTime },
            Deduplication = new EventDeduplicationMetadata
            {
                Inputs =
                [
                    DeduplicationInputs.AgentId,
                    DeduplicationInputs.SourceId,
                    DeduplicationInputs.CheckpointSequence,
                    DeduplicationInputs.EventCode
                ]
            },
            Normalized = new NormalizedEventFields
            {
                Category = "process",
                Action = "observe",
                Outcome = "success",
                Process = new ProcessTelemetryConcept
                {
                    Pid = "4242",
                    ParentPid = "41",
                    Executable = "/usr/bin/synthetic-worker",
                    CommandLine = "/usr/bin/synthetic-worker --observe"
                },
                Network = new NetworkTelemetryConcept
                {
                    SourceIp = "192.0.2.44",
                    SourcePort = 42424,
                    DestinationIp = "198.51.100.55",
                    DestinationPort = 443,
                    Protocol = "tcp"
                },
                File = new FileTelemetryConcept
                {
                    Path = "/opt/synthetic/synthetic.conf",
                    Operation = "observe",
                    Sha256 = new string('a', 64)
                }
            },
            Raw = raw,
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length,
                RedactedFields = Array.Empty<string>(),
                TruncatedFields = Array.Empty<string>()
            }
        };
        envelope = envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };

        var repository = new EventRepository(dataSource);
        var stored = await repository.StoreEventsAsync(new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = eventTime,
            Events = [envelope]
        }, CancellationToken.None);
        Assert.Equal(1, stored.Accepted);

        await using (var denormalized = dataSource.CreateCommand("""
            select process_image, process_command_line, source_ip, destination_ip, file_path
            from events
            where agent_id = @agent_id and event_id = @event_id;
            """))
        {
            denormalized.Parameters.AddWithValue("agent_id", agentId);
            denormalized.Parameters.AddWithValue("event_id", envelope.EventId);
            await using var reader = await denormalized.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("/usr/bin/synthetic-worker", reader.GetString(0));
            Assert.Equal("/usr/bin/synthetic-worker --observe", reader.GetString(1));
            Assert.Equal("192.0.2.44", reader.GetString(2));
            Assert.Equal("198.51.100.55", reader.GetString(3));
            Assert.Equal("/opt/synthetic/synthetic.conf", reader.GetString(4));
        }

        await using (var retainNestedOnly = dataSource.CreateCommand("""
            update events
            set process_image = null,
                process_command_line = null,
                source_ip = null,
                destination_ip = null,
                file_path = null
            where agent_id = @agent_id and event_id = @event_id;
            """))
        {
            retainNestedOnly.Parameters.AddWithValue("agent_id", agentId);
            retainNestedOnly.Parameters.AddWithValue("event_id", envelope.EventId);
            Assert.Equal(1, await retainNestedOnly.ExecuteNonQueryAsync());
        }

        var results = await repository.SearchEventsAsync(new EventSearchQuery
        {
            AgentId = agentId,
            ProcessImage = "synthetic-worker",
            ProcessCommandLine = "--observe",
            SourceIp = "192.0.2.44",
            SourcePort = "42424",
            DestinationIp = "198.51.100.55",
            DestinationPort = "443",
            Protocol = "tcp",
            FilePath = "synthetic.conf",
            Limit = 10
        }, CancellationToken.None);
        var result = Assert.Single(results);
        Assert.Equal(envelope.EventId, result.EventId);

        var detail = await repository.GetEventAsync(agentId, envelope.EventId, CancellationToken.None);
        Assert.NotNull(detail);
        Assert.Equal("4242", detail.Normalized?.Process?.Pid);
        Assert.Equal("41", detail.Normalized?.Process?.ParentPid);
        Assert.Equal("/usr/bin/synthetic-worker", detail.Normalized?.Process?.Executable);
        Assert.Equal(443, detail.Normalized?.Network?.DestinationPort);
        Assert.Equal("/opt/synthetic/synthetic.conf", detail.Normalized?.File?.Path);
        Assert.Equal(new string('a', 64), detail.Normalized?.File?.Sha256);
    }

    [PostgresFact]
    public async Task GlobalLinuxCoverageSummaryHonorsRequestedTargetAndHealthyL3Evidence()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var agentId = $"linux-l3-summary-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-LINUX-L3";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);
        var now = DateTimeOffset.UtcNow;
        var sourceHealth = LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L3)
            .Select(entry => CoverageReport(entry, now))
            .ToArray();
        await new HeartbeatRepository(dataSource).InsertHeartbeatAsync(new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "1.2.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = $"{agentId}-host",
            LastEventTime = now,
            QueueDepth = 0,
            SourceHealth = sourceHealth
        }, CancellationToken.None);

        var repository = new SourceHealthRepository(dataSource);
        var l3 = await repository.SearchAsync(null, WindowsCoverageLevel.L3, CancellationToken.None);
        var l3Summary = Assert.Single(l3.Summaries, summary => summary.AgentId == agentId);
        Assert.Equal(WindowsCoverageLevel.L3, l3Summary.TargetLevel);
        Assert.Equal(WindowsCoverageLevel.L3, l3Summary.CurrentLevel);

        var l2 = await repository.SearchAsync(null, WindowsCoverageLevel.L2, CancellationToken.None);
        var l2Summary = Assert.Single(l2.Summaries, summary => summary.AgentId == agentId);
        Assert.Equal(WindowsCoverageLevel.L2, l2Summary.TargetLevel);
        Assert.Equal(WindowsCoverageLevel.L2, l2Summary.CurrentLevel);

        var review = new ReviewRepository(dataSource);
        var fullInventory = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, agentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        Assert.Equal(WindowsCoverageLevel.L3, Assert.Single(fullInventory).CurrentCoverageLevel);

        var incompleteAgentId = $"linux-l3-incomplete-{Guid.NewGuid():N}";
        const string incompleteHostname = "SYNTHETIC-LINUX-L3-INCOMPLETE";
        await InsertSyntheticAgentAsync(dataSource, incompleteAgentId, incompleteHostname);
        var incompleteHealth = LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L2)
            .Concat(LinuxTelemetrySourceCatalog.L3Passive.Take(1))
            .Select(entry => CoverageReport(entry, now))
            .ToArray();
        await new HeartbeatRepository(dataSource).InsertHeartbeatAsync(new HeartbeatRequest
        {
            AgentId = incompleteAgentId,
            Hostname = incompleteHostname,
            AgentVersion = "1.2.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = $"{incompleteAgentId}-host",
            LastEventTime = now,
            QueueDepth = 0,
            SourceHealth = incompleteHealth
        }, CancellationToken.None);

        var incompleteCoverage = await repository.SearchAsync(null, WindowsCoverageLevel.L3, CancellationToken.None);
        var incompleteSummary = Assert.Single(incompleteCoverage.Summaries, summary => summary.AgentId == incompleteAgentId);
        Assert.Equal(WindowsCoverageLevel.L2, incompleteSummary.CurrentLevel);
        Assert.Equal(LinuxTelemetrySourceCatalog.L3Passive.Count - 1, incompleteSummary.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Missing, incompleteSummary.OverallStatus);
        var incompleteInventory = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, incompleteAgentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        var incompleteInventoryItem = Assert.Single(incompleteInventory);
        Assert.Equal(WindowsCoverageLevel.L2, incompleteInventoryItem.CurrentCoverageLevel);
        Assert.Equal(LinuxTelemetrySourceCatalog.L3Passive.Count - 1, incompleteInventoryItem.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Missing, incompleteInventoryItem.CoverageStatus);
    }

    [PostgresFact]
    public async Task FullHeartbeatSnapshotMarksPreviouslyReportedOmittedSourceMissing()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var agentId = $"linux-source-omission-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-LINUX-SOURCE-OMISSION";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);
        var now = DateTimeOffset.UtcNow;
        var l1 = CoverageReport(LinuxTelemetrySourceCatalog.L1.Single(), now);
        var passive = CoverageReport(LinuxTelemetrySourceCatalog.L3Passive.First(), now);

        await InsertHeartbeatAsync(dataSource, agentId, hostname, now, [l1, passive]);
        await InsertHeartbeatAsync(dataSource, agentId, hostname, now.AddMinutes(1), [l1 with { ObservedAt = now.AddMinutes(1) }]);

        await using var command = dataSource.CreateCommand("""
            select status, enabled, error_code, gap_detected, transition_state, details ->> 'omission_reason'
            from source_health
            where agent_id = @agent_id and source_id = @source_id;
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("source_id", passive.SourceId);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(SourceHealthStatuses.Missing, reader.GetString(0));
        Assert.False(reader.GetBoolean(1));
        Assert.Equal("source_omitted_from_latest_heartbeat", reader.GetString(2));
        Assert.True(reader.GetBoolean(3));
        Assert.Equal("degraded", reader.GetString(4));
        Assert.Equal("source_omitted_from_latest_heartbeat", reader.GetString(5));

        var scoped = await new SourceHealthRepository(dataSource).SearchAsync(agentId, WindowsCoverageLevel.L3, CancellationToken.None);
        var summary = Assert.Single(scoped.Summaries);
        Assert.Equal(LinuxTelemetrySourceCatalog.L3Passive.Count, summary.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Missing, summary.OverallStatus);
    }

    [PostgresFact]
    public async Task LinuxCoverageStatusScopesDisabledL3ToTheRequestedOrAchievedLevel()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var now = DateTimeOffset.UtcNow;
        var disabledAgentId = $"linux-l3-disabled-{Guid.NewGuid():N}";
        const string disabledHostname = "SYNTHETIC-LINUX-L3-DISABLED";
        await InsertSyntheticAgentAsync(dataSource, disabledAgentId, disabledHostname);

        var healthyL2WithDisabledL3 = LinuxTelemetrySourceCatalog.ExpectedFor(
                WindowsCoverageLevel.L2,
                includeOptional: false)
            .Select(entry => CoverageReport(entry, now))
            .Concat(LinuxTelemetrySourceCatalog.L3Passive.Select(entry => CoverageReport(entry, now) with
            {
                Applicability = SourceApplicabilityStatuses.Unknown,
                ApplicabilityReason = "explicit_opt_in_required",
                Status = SourceHealthStatuses.Disabled,
                Enabled = false,
                LastEventTime = null
            }))
            .ToArray();
        await InsertHeartbeatAsync(dataSource, disabledAgentId, disabledHostname, now, healthyL2WithDisabledL3);

        var sourceHealth = new SourceHealthRepository(dataSource);
        var l1 = await sourceHealth.SearchAsync(null, WindowsCoverageLevel.L1, CancellationToken.None);
        var l1Summary = Assert.Single(l1.Summaries, summary => summary.AgentId == disabledAgentId);
        Assert.Equal(WindowsCoverageLevel.L1, l1Summary.CurrentLevel);
        Assert.Equal(0, l1Summary.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Healthy, l1Summary.OverallStatus);

        var l2 = await sourceHealth.SearchAsync(null, WindowsCoverageLevel.L2, CancellationToken.None);
        var l2Summary = Assert.Single(l2.Summaries, summary => summary.AgentId == disabledAgentId);
        Assert.Equal(WindowsCoverageLevel.L2, l2Summary.TargetLevel);
        Assert.Equal(WindowsCoverageLevel.L2, l2Summary.CurrentLevel);
        Assert.Equal(0, l2Summary.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Healthy, l2Summary.OverallStatus);

        var review = new ReviewRepository(dataSource);
        var disabledInventory = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, disabledAgentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        var disabledItem = Assert.Single(disabledInventory);
        Assert.Equal(WindowsCoverageLevel.L2, disabledItem.CurrentCoverageLevel);
        Assert.Equal(0, disabledItem.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Healthy, disabledItem.CoverageStatus);

        var degradedAgentId = $"linux-l3-degraded-{Guid.NewGuid():N}";
        const string degradedHostname = "SYNTHETIC-LINUX-L3-DEGRADED";
        await InsertSyntheticAgentAsync(dataSource, degradedAgentId, degradedHostname);
        var healthyL2WithDegradedL3 = LinuxTelemetrySourceCatalog.ExpectedFor(
                WindowsCoverageLevel.L2,
                includeOptional: false)
            .Select(entry => CoverageReport(entry, now))
            .Concat(LinuxTelemetrySourceCatalog.L3Passive.Select(entry => CoverageReport(entry, now) with
            {
                Applicability = SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = null,
                Status = SourceHealthStatuses.Degraded,
                Enabled = true,
                LastEventTime = now
            }))
            .ToArray();
        await InsertHeartbeatAsync(dataSource, degradedAgentId, degradedHostname, now, healthyL2WithDegradedL3);

        var degradedInventory = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, degradedAgentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        var degradedItem = Assert.Single(degradedInventory);
        Assert.Equal(WindowsCoverageLevel.L2, degradedItem.CurrentCoverageLevel);
        Assert.Equal(0, degradedItem.MissingMandatorySources);
        Assert.Equal(LinuxTelemetrySourceCatalog.L3Passive.Count, degradedItem.DegradedSources);
        Assert.Equal(SourceHealthStatuses.Degraded, degradedItem.CoverageStatus);

        var approvalMismatchAgentId = $"linux-l3-approval-mismatch-{Guid.NewGuid():N}";
        const string approvalMismatchHostname = "SYNTHETIC-LINUX-L3-APPROVAL-MISMATCH";
        await InsertSyntheticAgentAsync(dataSource, approvalMismatchAgentId, approvalMismatchHostname);
        var healthyL2WithApprovalMismatch = LinuxTelemetrySourceCatalog.ExpectedFor(
                WindowsCoverageLevel.L2,
                includeOptional: false)
            .Select(entry => CoverageReport(entry, now))
            .Concat(LinuxTelemetrySourceCatalog.L3Passive.Select(entry => CoverageReport(entry, now) with
            {
                Applicability = SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = null,
                Status = SourceHealthStatuses.Disabled,
                Enabled = false,
                LastEventTime = null
            }))
            .ToArray();
        await InsertHeartbeatAsync(
            dataSource,
            approvalMismatchAgentId,
            approvalMismatchHostname,
            now,
            healthyL2WithApprovalMismatch);

        var approvalMismatchInventory = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, approvalMismatchAgentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        var approvalMismatchItem = Assert.Single(approvalMismatchInventory);
        Assert.Equal(WindowsCoverageLevel.L2, approvalMismatchItem.CurrentCoverageLevel);
        Assert.Equal(LinuxTelemetrySourceCatalog.L3Passive.Count, approvalMismatchItem.MissingMandatorySources);
        Assert.Equal(SourceHealthStatuses.Missing, approvalMismatchItem.CoverageStatus);
    }

    [PostgresFact]
    public async Task StrictLinuxL4IsConsistentAcrossGlobalSourceHealthAndAssetReview()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var now = DateTimeOffset.UtcNow;
        var agentId = $"linux-l4-strict-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-LINUX-L4-STRICT";
        await InsertSyntheticAgentAsync(dataSource, agentId, hostname);

        var healthyL4 = LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L4)
            .Select(entry => CoverageReport(entry, now))
            .ToArray();
        await InsertHeartbeatAsync(dataSource, agentId, hostname, now, healthyL4);

        var sourceHealth = new SourceHealthRepository(dataSource);
        var global = await sourceHealth.SearchAsync(null, WindowsCoverageLevel.L4, CancellationToken.None);
        Assert.Equal(
            WindowsCoverageLevel.L4,
            Assert.Single(global.Summaries, summary => summary.AgentId == agentId).CurrentLevel);

        var review = new ReviewRepository(dataSource);
        var assets = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, agentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        Assert.Equal(WindowsCoverageLevel.L4, Assert.Single(assets).CurrentCoverageLevel);

        var exceptedLowerSource = LinuxTelemetrySourceCatalog.L2Security
            .First(entry => entry.Requirement == SourceRequirementKinds.Mandatory)
            .SourceId;
        await using (var command = dataSource.CreateCommand("""
            update source_health
            set status = 'excepted'
            where agent_id = @agent_id and source_id = @source_id;
            """))
        {
            command.Parameters.AddWithValue("agent_id", agentId);
            command.Parameters.AddWithValue("source_id", exceptedLowerSource);
            await command.ExecuteNonQueryAsync();
        }

        var cappedGlobal = await sourceHealth.SearchAsync(null, WindowsCoverageLevel.L4, CancellationToken.None);
        Assert.Equal(
            WindowsCoverageLevel.L3,
            Assert.Single(cappedGlobal.Summaries, summary => summary.AgentId == agentId).CurrentLevel);
        var cappedAssets = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, agentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        Assert.Equal(WindowsCoverageLevel.L3, Assert.Single(cappedAssets).CurrentCoverageLevel);

        var unattemptedAgentId = $"linux-l4-unattempted-{Guid.NewGuid():N}";
        const string unattemptedHostname = "SYNTHETIC-LINUX-L4-UNATTEMPTED";
        await InsertSyntheticAgentAsync(dataSource, unattemptedAgentId, unattemptedHostname);
        var unattempted = LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L3)
            .Select(entry => CoverageReport(entry, now))
            .Concat(LinuxTelemetrySourceCatalog.L4.Select(entry => CoverageReport(entry, now) with
            {
                Applicability = entry.Requirement == SourceRequirementKinds.RoleSpecific
                    ? SourceApplicabilityStatuses.Unknown
                    : SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = entry.Requirement == SourceRequirementKinds.RoleSpecific
                    ? "host_role_not_declared"
                    : null,
                Status = SourceHealthStatuses.Disabled,
                Enabled = false,
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["approval_state"] = "not_requested"
                }
            }))
            .ToArray();
        await InsertHeartbeatAsync(dataSource, unattemptedAgentId, unattemptedHostname, now, unattempted);

        var unattemptedAssets = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, unattemptedAgentId, null, "all", null, null, null, null, null, null),
            TimeSpan.FromDays(1),
            CancellationToken.None);
        var unattemptedAsset = Assert.Single(unattemptedAssets);
        Assert.Equal(WindowsCoverageLevel.L3, unattemptedAsset.CurrentCoverageLevel);
        Assert.Equal(0, unattemptedAsset.MissingMandatorySources);
    }

    private static async Task InsertSyntheticAgentAsync(NpgsqlDataSource dataSource, string agentId, string hostname)
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

    private static Task InsertHeartbeatAsync(
        NpgsqlDataSource dataSource,
        string agentId,
        string hostname,
        DateTimeOffset now,
        IReadOnlyList<SourceHealthReport> sourceHealth) =>
        new HeartbeatRepository(dataSource).InsertHeartbeatAsync(new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "1.2.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = $"{agentId}-host",
            LastEventTime = now,
            QueueDepth = 0,
            SourceHealth = sourceHealth
        }, CancellationToken.None);

    private static SourceHealthReport CoverageReport(SourceManifestEntry entry, DateTimeOffset now)
    {
        var unsupported = entry.Applicability == SourceApplicabilityStatuses.Unsupported;
        var roleSpecific = entry.Requirement == SourceRequirementKinds.RoleSpecific;
        var applicability = unsupported
            ? SourceApplicabilityStatuses.Unsupported
            : roleSpecific
                ? SourceApplicabilityStatuses.NotApplicable
                : SourceApplicabilityStatuses.Applicable;
        var status = unsupported
            ? SourceHealthStatuses.Unsupported
            : roleSpecific
                ? SourceHealthStatuses.NotApplicable
                : SourceHealthStatuses.Healthy;
        return new SourceHealthReport
        {
            SourceId = entry.SourceId,
            DisplayName = entry.DisplayName,
            Platform = TelemetryPlatforms.Linux,
            SourceKind = entry.SourceKind,
            SourceNamespace = entry.SourceNamespace,
            Applicability = applicability,
            ApplicabilityReason = roleSpecific ? "synthetic_role_not_applicable" : entry.ApplicabilityReason,
            CoverageLevel = entry.CoverageLevel,
            Status = status,
            Required = entry.Required,
            Requirement = entry.Requirement,
            ApplicableRoles = entry.ApplicableRoles,
            Enabled = !unsupported && !roleSpecific,
            LastEventTime = status == SourceHealthStatuses.Healthy ? now : null,
            ObservedAt = now,
            PrerequisiteStatuses = entry.Prerequisites.ToDictionary(
                item => item,
                _ => status == SourceHealthStatuses.Healthy
                    ? SourceEvidenceStatuses.Satisfied
                    : status == SourceHealthStatuses.Unsupported
                        ? SourceEvidenceStatuses.Unsupported
                        : SourceEvidenceStatuses.NotApplicable,
                StringComparer.Ordinal),
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                item => item,
                _ => status == SourceHealthStatuses.Healthy
                    ? SourceEvidenceStatuses.Observed
                    : status == SourceHealthStatuses.Unsupported
                        ? SourceEvidenceStatuses.Unsupported
                        : SourceEvidenceStatuses.NotApplicable,
                StringComparer.Ordinal),
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
        };
    }
}
