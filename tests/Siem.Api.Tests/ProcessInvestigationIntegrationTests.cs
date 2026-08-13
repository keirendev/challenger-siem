using System.Text.Json;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V2;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class ProcessInvestigationIntegrationTests(IntegrationTestDatabase database)
{
    [PostgresFact]
    public async Task ExactProcessInstanceNeverMergesPidReuseAndKeepsNetworkCitation()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"process-investigation-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-PROCESS-HOST";
        await using (var agent = dataSource.CreateCommand("""
            insert into agents(agent_id,hostname,os_version,agent_version,platform,host_id,api_token_hash)
            values(@agent_id,@hostname,'synthetic','2.12.0-test','linux',@host_id,'synthetic-hash');
            """))
        {
            agent.Parameters.AddWithValue("agent_id", agentId);
            agent.Parameters.AddWithValue("hostname", hostname);
            agent.Parameters.AddWithValue("host_id", $"{agentId}-host");
            await agent.ExecuteNonQueryAsync();
        }

        var time = DateTimeOffset.Parse("2026-08-13T01:00:00Z");
        var firstInstance = new string('a', 64);
        var reusedInstance = new string('b', 64);
        var first = ProcessEvent(agentId, hostname, time.AddMinutes(-10), 1, firstInstance, 4242, "/usr/bin/synthetic-first");
        var reused = ProcessEvent(agentId, hostname, time.AddMinutes(-2), 2, reusedInstance, 4242, "/usr/bin/synthetic-reused");
        var network = NetworkEvent(agentId, hostname, time.AddMinutes(-9), 3, firstInstance, 4242);
        var legacyPrivilege = PrivilegeEvent(agentId, hostname, time.AddMinutes(-8), 4, null, 4242);
        var reusedPrivilege = PrivilegeEvent(agentId, hostname, time.AddMinutes(-1), 5, reusedInstance, 4242);
        var stored = await new EventRepository(dataSource).StoreEventsAsync(new()
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = time,
            Events = [first, reused, network, legacyPrivilege, reusedPrivilege]
        }, default);
        Assert.Equal(5, stored.Accepted);

        var geo = new IpGeolocationService(
            Options.Create(new TrafficMapOptions { Enabled = false }),
            new TestHostEnvironment(),
            new TestHttpClientFactory(),
            TimeProvider.System,
            NullLogger<IpGeolocationService>.Instance);
        var networkRepository = new NetworkActivityRepository(dataSource, geo, TimeProvider.System);
        var repository = new ProcessInvestigationRepository(
            dataSource,
            networkRepository,
            new SourceHealthRepository(dataSource),
            TimeProvider.System);
        var result = await repository.InvestigateAsync(new()
        {
            AgentId = agentId,
            From = time.AddHours(-1),
            To = time,
            ProcessInstanceId = firstInstance,
            Limit = 50
        }, default);

        var observation = Assert.Single(result.ProcessObservations);
        Assert.Equal(firstInstance, observation.ProcessInstanceId);
        Assert.Equal("/usr/bin/synthetic-first", observation.ProcessImage);
        Assert.DoesNotContain(result.ProcessObservations, item => item.ProcessInstanceId == reusedInstance);
        var activity = Assert.Single(result.NetworkActivity);
        Assert.Equal(firstInstance, activity.ProcessInstanceId);
        Assert.Equal(network.EventId, activity.EventId);
        Assert.Equal($"event:{agentId}/{network.EventId}", activity.EventCitation);
        Assert.False(activity.ExactExecutionEvidence);
        var privilege = Assert.Single(result.PrivilegeEvents);
        Assert.Equal(legacyPrivilege.EventId, privilege.EventId);
        Assert.Null(privilege.ProcessInstanceId);
        Assert.DoesNotContain(result.PrivilegeEvents, item => item.EventId == reusedPrivilege.EventId);
    }

    private static EventEnvelope ProcessEvent(
        string agentId,
        string hostname,
        DateTimeOffset time,
        long sequence,
        string instanceId,
        int pid,
        string image)
    {
        var raw = JsonSerializer.SerializeToElement(new
        {
            schema = "linux-process-snapshot-v1",
            process_instance_id = instanceId,
            process_key = instanceId,
            process_id = pid,
            executable = image
        });
        var envelope = Base(agentId, hostname, time, sequence, LinuxTelemetrySourceIds.ProcessSnapshotDiff, "process_observed") with
        {
            Message = "Synthetic process snapshot observation.",
            Normalized = new()
            {
                Category = "process",
                Action = "observed",
                ProcessId = pid.ToString(),
                ProcessInstanceId = instanceId,
                ProcessImage = image,
                Process = new()
                {
                    InstanceId = instanceId,
                    Pid = pid.ToString(),
                    Executable = image,
                    ImageObservationSource = "process_snapshot_poll",
                    CommandLineObservationSource = "process_snapshot_poll",
                    ObservedAt = time,
                    ExactExecutionEvidence = false
                }
            },
            Raw = raw,
            DataHandling = new() { RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length }
        };
        return WithIdentity(envelope);
    }

    private static EventEnvelope NetworkEvent(
        string agentId,
        string hostname,
        DateTimeOffset time,
        long sequence,
        string instanceId,
        int pid)
    {
        var raw = JsonSerializer.SerializeToElement(new
        {
            schema = "linux-network-snapshot-v2",
            evidence_mode = "snapshot_diff",
            owner_process_instance_id = instanceId,
            owner_process_id = pid,
            owner_confidence = "exact_inode_current_scan",
            remote_address = "198.51.100.20",
            remote_port = 443
        });
        var envelope = Base(agentId, hostname, time, sequence, LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, "socket_observed") with
        {
            Message = "Synthetic network socket snapshot observation.",
            Normalized = new()
            {
                Category = "network",
                Action = "observed",
                ProcessId = pid.ToString(),
                ProcessInstanceId = instanceId,
                Process = new()
                {
                    InstanceId = instanceId,
                    Pid = pid.ToString(),
                    ImageObservationSource = "socket_owner_process_snapshot",
                    CommandLineObservationSource = "socket_owner_process_snapshot",
                    ObservedAt = time,
                    ExactExecutionEvidence = false
                },
                Network = new()
                {
                    LocalIp = "192.0.2.10",
                    LocalPort = 50000,
                    RemoteIp = "198.51.100.20",
                    RemotePort = 443,
                    Protocol = "tcp",
                    Direction = "unknown",
                    EvidenceMode = "snapshot_diff",
                    AttributionConfidence = "exact_inode_current_scan",
                    AttributionSource = "snapshot_inode_owner",
                    ProcessIdentityStatus = "observed_same_process_scan"
                }
            },
            Raw = raw,
            DataHandling = new() { RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length }
        };
        return WithIdentity(envelope);
    }

    private static EventEnvelope PrivilegeEvent(
        string agentId,
        string hostname,
        DateTimeOffset time,
        long sequence,
        string? instanceId,
        int pid)
    {
        var raw = JsonSerializer.SerializeToElement(new
        {
            process_id = pid,
            process_instance_id = instanceId,
            command = "synthetic-privilege-check"
        });
        var envelope = Base(agentId, hostname, time, sequence, LinuxTelemetrySourceIds.Privilege, "privilege_observed") with
        {
            Message = "Synthetic privilege observation.",
            Normalized = new()
            {
                Category = "authentication",
                Action = "privilege_observed",
                ProcessId = pid.ToString(),
                ProcessInstanceId = instanceId,
                Process = new()
                {
                    InstanceId = instanceId,
                    Pid = pid.ToString(),
                    CommandLine = "synthetic-privilege-check",
                    CommandLineObservationSource = "privilege_journal_record",
                    ObservedAt = time,
                    ExactExecutionEvidence = false
                }
            },
            Raw = raw,
            DataHandling = new() { RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length }
        };
        return WithIdentity(envelope);
    }

    private static EventEnvelope Base(
        string agentId,
        string hostname,
        DateTimeOffset time,
        long sequence,
        string sourceId,
        string eventCode) => new()
    {
        AgentId = agentId,
        Hostname = hostname,
        Platform = TelemetryPlatforms.Linux,
        Source = EventSources.InventoryDiff,
        SourceId = sourceId,
        EventCode = eventCode,
        EventTime = time,
        Severity = "information",
        Checkpoint = new() { Sequence = sequence, EventTime = time, RecordedAt = time },
        Deduplication = new()
        {
            Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode]
        }
    };

    private static EventEnvelope WithIdentity(EventEnvelope envelope) =>
        envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Siem.Api.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
