using System.Text.Json;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V2;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Data.Sqlite;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class NetworkActivityIntegrationTests(IntegrationTestDatabase database)
{
    [PostgresFact]
    public async Task SearchCorrelatesKernelFlowProcessCountersAndCitationWithoutGeoWrites()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"network-activity-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-FLOW-HOST";
        await using (var agent = dataSource.CreateCommand("""
            insert into agents(agent_id,hostname,os_version,agent_version,platform,host_id,api_token_hash)
            values(@agent_id,@hostname,'synthetic','2.6.0-test','linux',@host_id,'synthetic-hash');
            """))
        {
            agent.Parameters.AddWithValue("agent_id", agentId);
            agent.Parameters.AddWithValue("hostname", hostname);
            agent.Parameters.AddWithValue("host_id", $"{agentId}-host");
            await agent.ExecuteNonQueryAsync();
        }

        var time = DateTimeOffset.Parse("2026-08-03T10:00:00Z");
        var processInstanceId = new string('a', 64);
        var value = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.InventoryDiff,
            SourceId = LinuxTelemetrySourceIds.NetworkFlowSummary,
            EventCode = "network_flow_sample",
            EventTime = time,
            Severity = "information",
            Message = "Synthetic kernel network flow.",
            Checkpoint = new() { Sequence = 1, EventTime = time, RecordedAt = time },
            Deduplication = new()
            {
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode]
            },
            Normalized = new()
            {
                Category = "network",
                Action = "flow_sample",
                ProcessId = "4242",
                ProcessInstanceId = processInstanceId,
                ProcessImage = "/usr/bin/synthetic-probe",
                ProcessCommandLine = "synthetic-probe --no-payload",
                Process = new()
                {
                    InstanceId = processInstanceId,
                    Pid = "4242",
                    Executable = "/usr/bin/synthetic-probe",
                    CommandLine = "synthetic-probe --no-payload",
                    ImageObservationSource = "kernel_flow_procfs_enrichment",
                    CommandLineObservationSource = "kernel_flow_procfs_enrichment",
                    ObservedAt = time,
                    ExactExecutionEvidence = false
                },
                User = new() { Id = "1000" },
                Network = new()
                {
                    SourceIp = "192.0.2.10", SourcePort = 41000,
                    DestinationIp = "203.0.113.53", DestinationPort = 53, Protocol = "udp",
                    LocalIp = "192.0.2.10", LocalPort = 41000,
                    RemoteIp = "203.0.113.53", RemotePort = 53,
                    Direction = "outbound", PacketCountDelta = 1, ByteCountDelta = 28,
                    IntervalStartedAt = time.AddSeconds(-10), IntervalEndedAt = time,
                    EvidenceMode = "kernel_flow", AttributionConfidence = "kernel_current_task_procfs_enriched",
                    AttributionSource = "current_task", ProcessIdentityStatus = "observed_stable_procfs_identity"
                }
            },
            Raw = JsonSerializer.SerializeToElement(new { schema = "synthetic-flow-v1", payload_capture = false }),
            DataHandling = new() { RawSizeBytes = 64 }
        };
        value = value with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(value) };
        Assert.Equal(1, (await new EventRepository(dataSource).StoreEventsAsync(new()
        {
            AgentId = agentId, BatchId = Guid.NewGuid(), SentAt = time, Events = [value]
        }, default)).Accepted);

        var geoOptions = Options.Create(new TrafficMapOptions { Enabled = false });
        var geolocation = new IpGeolocationService(geoOptions, new TestHostEnvironment(), new TestHttpClientFactory(), TimeProvider.System, NullLogger<IpGeolocationService>.Instance);
        var repository = new NetworkActivityRepository(dataSource, geolocation, TimeProvider.System);
        var result = await repository.SearchAsync(new()
        {
            AgentId = agentId,
            ProcessInstanceId = processInstanceId,
            RemoteIp = "203.0.113.53",
            EvidenceMode = "kernel_flow",
            Direction = "outbound",
            AttributedOnly = true,
            Limit = 10
        }, allowGeolocationLookup: false, default);

        var activity = Assert.Single(result.Activities);
        Assert.Equal(value.EventId, activity.EventId);
        Assert.Equal($"event:{agentId}/{value.EventId}", activity.EventCitation);
        Assert.Equal(4242, activity.ProcessId);
        Assert.Equal(processInstanceId, activity.ProcessInstanceId);
        Assert.Equal("/usr/bin/synthetic-probe", activity.ProcessImage);
        Assert.Equal(1, activity.PacketCountDelta);
        Assert.Equal(28, activity.ByteCountDelta);
        Assert.Equal("outbound", activity.Direction);
        Assert.Equal("kernel_flow", activity.EvidenceMode);
        Assert.Equal("current_task", activity.AttributionSource);
        Assert.Equal("observed_stable_procfs_identity", activity.ProcessIdentityStatus);
        Assert.Equal("kernel_flow_procfs_enrichment", activity.ProcessCommandLineObservationSource);
        Assert.False(activity.ExactExecutionEvidence);
        Assert.Equal("unmapped", activity.GeolocationStatus);
        Assert.Equal("cache_only_no_writes", result.GeolocationMode);
        Assert.False(result.Page.HasNext);
    }

    [PostgresFact]
    public async Task CountryProcessDirectionPaginationAndSnapshotFallbackStayCitedCacheOnlyAndRawFree()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"network-country-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-COUNTRY-HOST";
        await using (var agent = dataSource.CreateCommand("""
            insert into agents(agent_id,hostname,os_version,agent_version,platform,host_id,api_token_hash)
            values(@agent_id,@hostname,'synthetic','2.6.0-test','linux',@host_id,'synthetic-hash');
            """))
        {
            agent.Parameters.AddWithValue("agent_id", agentId);
            agent.Parameters.AddWithValue("hostname", hostname);
            agent.Parameters.AddWithValue("host_id", $"{agentId}-host");
            await agent.ExecuteNonQueryAsync();
        }

        var time = DateTimeOffset.Parse("2026-08-03T10:00:00Z");
        var events = new[]
        {
            NetworkEvent(agentId, hostname, time, 1, "network_flow_started", LinuxTelemetrySourceIds.NetworkFlowSummary, "kernel_flow", "outbound", "/usr/bin/synthetic-country-probe", 2, 80),
            NetworkEvent(agentId, hostname, time.AddMinutes(-1), 2, "network_flow_sample", LinuxTelemetrySourceIds.NetworkFlowSummary, "kernel_flow", "outbound", "/usr/bin/synthetic-country-probe", 3, 120),
            NetworkEvent(agentId, hostname, time.AddMinutes(-2), 3, "socket_observed", LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, "snapshot_diff", "unknown", null, null, null)
        };
        Assert.Equal(3, (await new EventRepository(dataSource).StoreEventsAsync(new()
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = time,
            Events = events
        }, default)).Accepted);

        var directory = Path.Combine(Path.GetTempPath(), $"challenger-network-country-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var cachePath = Path.Combine(directory, "geolocation.sqlite3");
            var factory = new CountingHttpClientFactory();
            var geoOptions = Options.Create(new TrafficMapOptions
            {
                Enabled = true,
                Geolocation = new() { Enabled = true, CachePath = cachePath }
            });
            var geolocation = new IpGeolocationService(
                geoOptions,
                new TestHostEnvironment { ContentRootPath = directory },
                factory,
                TimeProvider.System,
                NullLogger<IpGeolocationService>.Instance);
            await geolocation.GetCachedAsync(["192.0.2.1"], default);
            await using (var cache = new SqliteConnection($"Data Source={cachePath};Mode=ReadWrite"))
            {
                await cache.OpenAsync();
                await using var command = cache.CreateCommand();
                command.CommandText = """
                    insert into ip_geolocation_cache(
                        ip,status,latitude,longitude,city,region,country,country_code,continent,asn,organization,isp,provider,fetched_at_utc,expires_at_utc)
                    values('203.0.113.53','ready',39.9,116.4,'Synthetic City','Synthetic Region','Synthetic Country','CN','AS',4134,'Synthetic Network','Synthetic ISP','synthetic',@fetched,@expires);
                    """;
                command.Parameters.AddWithValue("@fetched", time.ToString("O"));
                command.Parameters.AddWithValue("@expires", time.AddDays(30).ToString("O"));
                await command.ExecuteNonQueryAsync();
            }

            var repository = new NetworkActivityRepository(dataSource, geolocation, TimeProvider.System);
            var first = await repository.SearchAsync(new()
            {
                AgentId = agentId,
                CountryCode = "CN",
                Direction = "outbound",
                ProcessImage = "country-probe",
                AttributedOnly = true,
                Limit = 1
            }, allowGeolocationLookup: false, default);

            var firstActivity = Assert.Single(first.Activities);
            Assert.Equal("CN", firstActivity.CountryCode);
            Assert.Equal("kernel_flow", firstActivity.EvidenceMode);
            Assert.Equal("network_flow_started", firstActivity.EventCode);
            Assert.True(first.Page.HasNext);
            Assert.NotNull(first.Page.NextCursor);
            Assert.Equal("cache_only_no_writes", first.GeolocationMode);
            Assert.Contains(first.Limitations, limitation => limitation.Contains("source health", StringComparison.OrdinalIgnoreCase));

            var next = await repository.SearchAsync(new()
            {
                AgentId = agentId,
                CountryCode = "CN",
                Direction = "outbound",
                ProcessImage = "country-probe",
                AttributedOnly = true,
                Limit = 1,
                Cursor = first.Page.NextCursor
            }, allowGeolocationLookup: false, default);
            Assert.Equal("network_flow_sample", Assert.Single(next.Activities).EventCode);
            Assert.NotEqual(firstActivity.EventCitation, next.Activities[0].EventCitation);

            var snapshot = await repository.SearchAsync(new()
            {
                AgentId = agentId,
                EvidenceMode = "snapshot_diff",
                Limit = 10
            }, allowGeolocationLookup: false, default);
            var snapshotActivity = Assert.Single(snapshot.Activities);
            Assert.Equal("unknown", snapshotActivity.Direction);
            Assert.Equal("unattributed", snapshotActivity.AttributionConfidence);
            Assert.Null(snapshotActivity.PacketCountDelta);

            var serialized = JsonSerializer.Serialize(first);
            Assert.DoesNotContain("\"raw\"", serialized, StringComparison.Ordinal);
            Assert.DoesNotContain("owners", serialized, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, factory.CreateCalls);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static EventEnvelope NetworkEvent(
        string agentId,
        string hostname,
        DateTimeOffset time,
        long sequence,
        string eventCode,
        string sourceId,
        string evidenceMode,
        string direction,
        string? processImage,
        long? packetCount,
        long? byteCount)
    {
        var raw = JsonSerializer.SerializeToElement(new
        {
            schema = sourceId == LinuxTelemetrySourceIds.NetworkFlowSummary ? "synthetic-flow-v1" : "synthetic-snapshot-v2",
            payload_capture = false,
            owners = sourceId == LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff
                ? new[] { new { process_id = 1, command_line = "synthetic-owner --bounded" } }
                : null
        });
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.InventoryDiff,
            SourceId = sourceId,
            EventCode = eventCode,
            EventTime = time,
            Severity = "information",
            Message = "Synthetic retained network activity.",
            Checkpoint = new() { Sequence = sequence, EventTime = time, RecordedAt = time },
            Deduplication = new()
            {
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode]
            },
            Normalized = new()
            {
                Category = "network",
                Action = eventCode,
                ProcessId = processImage is null ? null : "4242",
                ProcessImage = processImage,
                ProcessCommandLine = processImage is null ? null : "synthetic-country-probe --no-payload",
                User = processImage is null ? null : new() { Id = "1000" },
                Network = new()
                {
                    SourceIp = "192.0.2.10",
                    SourcePort = 41000,
                    DestinationIp = "203.0.113.53",
                    DestinationPort = 53,
                    Protocol = "udp",
                    LocalIp = "192.0.2.10",
                    LocalPort = 41000,
                    RemoteIp = "203.0.113.53",
                    RemotePort = 53,
                    Direction = direction,
                    PacketCountDelta = packetCount,
                    ByteCountDelta = byteCount,
                    IntervalStartedAt = time.AddSeconds(-10),
                    IntervalEndedAt = time,
                    EvidenceMode = evidenceMode,
                    AttributionConfidence = processImage is null ? "unattributed" : "kernel_current_task_procfs_enriched"
                }
            },
            Raw = raw,
            DataHandling = new() { RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    private sealed class CountingHttpClientFactory : IHttpClientFactory
    {
        public int CreateCalls { get; private set; }
        public HttpClient CreateClient(string name)
        {
            CreateCalls++;
            return new HttpClient();
        }
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Synthetic";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
