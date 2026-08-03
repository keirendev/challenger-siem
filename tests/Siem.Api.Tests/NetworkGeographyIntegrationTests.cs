using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V2;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class NetworkGeographyIntegrationTests(IntegrationTestDatabase database)
{
    [PostgresFact]
    public async Task AggregationSeparatesConnectionObservationsFromLifecycleEventsAndFiltersSource()
    {
        await using var dataSource = NpgsqlDataSource.Create(database.RequireConnectionString());
        var agentId = $"network-map-{Guid.NewGuid():N}";
        const string hostname = "SYNTHETIC-MAP-HOST";
        await using (var agent = dataSource.CreateCommand("""
            insert into agents(agent_id,hostname,os_version,agent_version,platform,host_id,api_token_hash)
            values(@agent_id,@hostname,'synthetic','2.5.0-test','linux',@host_id,'synthetic-hash');
            """))
        {
            agent.Parameters.AddWithValue("agent_id", agentId);
            agent.Parameters.AddWithValue("hostname", hostname);
            agent.Parameters.AddWithValue("host_id", $"{agentId}-host");
            await agent.ExecuteNonQueryAsync();
        }

        var start = DateTimeOffset.Parse("2026-08-03T10:00:00Z");
        var repository = new EventRepository(dataSource);
        var socketEvents = new[] { "socket_baseline", "socket_observed", "socket_changed", "socket_disappeared" }
            .Select((code, index) => Envelope(agentId, hostname, code, start.AddMinutes(index), index + 1, LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, "8.8.8.8"))
            .Concat(Enumerable.Range(0, 10).Select(index => Envelope(
                agentId, hostname, "socket_changed", start.AddMinutes(10 + index), 10 + index,
                LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, "8.8.8.8", 10000 + index, $"/usr/bin/synthetic-client-{index}")));
        var events = socketEvents
            .Append(Envelope(agentId, hostname, "socket_observed", start.AddMinutes(5), 5, "synthetic-unrelated-source", "1.1.1.1"))
            .ToArray();
        var stored = await repository.StoreEventsAsync(new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = start,
            Events = events
        }, CancellationToken.None);
        Assert.Equal(15, stored.Accepted);

        var options = Options.Create(new TrafficMapOptions
        {
            Enabled = true,
            PublicBaseUrl = "http://127.0.0.1:5081",
            Origin = new() { Label = "Synthetic origin", Latitude = 0, Longitude = 0 },
            Geolocation = new() { Enabled = false }
        });
        var geo = new IpGeolocationService(options, new TestHostEnvironment(), new TestHttpClientFactory(), TimeProvider.System, NullLogger<IpGeolocationService>.Instance);
        var geography = new NetworkGeographyRepository(dataSource, geo, options, TimeProvider.System);
        var result = await geography.GetAsync(new NetworkGeographyQuery { AgentId = agentId, Limit = 10 }, CancellationToken.None);

        var destination = Assert.Single(result.Destinations);
        Assert.Equal("8.8.8.8", destination.DestinationIp);
        Assert.Equal(2, destination.ConnectionObservations);
        Assert.Equal(14, destination.LifecycleEvents);
        Assert.Equal(1, destination.BaselineObservations);
        Assert.Equal(1, destination.NewObservations);
        Assert.Equal(11, destination.ChangeEvents);
        Assert.Equal(1, destination.DisappearanceEvents);
        Assert.Equal(8, destination.DestinationPorts.Count);
        Assert.Equal(8, destination.ProcessImages.Count);
        Assert.Equal("disabled", destination.GeolocationStatus);
        Assert.DoesNotContain(result.Destinations, item => item.DestinationIp == "1.1.1.1");
        Assert.Equal(14, result.Summary.MatchedLifecycleEvents);
        Assert.Equal(2, result.Summary.ConnectionObservations);
        Assert.Equal(1, result.Summary.UniqueDestinations);
        Assert.NotNull(result.RetainedFromUtc);
        Assert.NotNull(result.FromUtc);
        Assert.True(result.Timeline.Count <= 200);

        var filtered = await geography.GetAsync(new NetworkGeographyQuery
        {
            AgentId = agentId,
            DestinationPort = 10009,
            ProcessImage = "synthetic-client-9",
            From = start.AddMinutes(19),
            To = start.AddMinutes(19),
            Limit = 10
        }, CancellationToken.None);
        Assert.Equal(1, Assert.Single(filtered.Destinations).LifecycleEvents);
        Assert.Equal(0, filtered.Summary.ConnectionObservations);
    }

    private static EventEnvelope Envelope(
        string agentId,
        string hostname,
        string code,
        DateTimeOffset time,
        long sequence,
        string sourceId,
        string destinationIp,
        int destinationPort = 443,
        string processImage = "/usr/bin/synthetic-client")
    {
        var value = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.InventoryDiff,
            SourceId = sourceId,
            EventCode = code,
            EventTime = time,
            Severity = "information",
            Message = "Synthetic network geography evidence.",
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = time, RecordedAt = time },
            Deduplication = new EventDeduplicationMetadata
            {
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode]
            },
            Normalized = new NormalizedEventFields
            {
                Category = "network",
                Action = code["socket_".Length..],
                ProcessImage = processImage,
                Network = new() { SourceIp = "192.0.2.10", SourcePort = 50000, DestinationIp = destinationIp, DestinationPort = destinationPort, Protocol = "tcp" }
            },
            Raw = System.Text.Json.JsonSerializer.SerializeToElement(new { fixture = "synthetic-network-map" }),
            DataHandling = new() { RawSizeBytes = 36 }
        };
        return value with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(value) };
    }

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Synthetic";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
