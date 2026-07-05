using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class ServerIntegrationTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "integration-enrollment-token";
    private const string ReviewToken = "integration-review-token";

    [PostgresFact]
    public async Task RegistrationIngestHeartbeatSearchAndIngestionErrorsUsePostgres()
    {
        var connectionString = database.RequireConnectionString();
        var agentId = $"it-agent-{Guid.NewGuid():N}";
        var hostname = "IT-HOST";
        var now = DateTimeOffset.UtcNow;
        var eventId = Guid.NewGuid();
        var duplicateEventId = Guid.NewGuid();
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var invalidRegistration = await client.PostAsJsonAsync("/api/v1/agents/register", new AgentRegistrationRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            OsVersion = "Windows Test",
            AgentVersion = "0.3.0-test"
        }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, invalidRegistration.StatusCode);
        }

        var firstToken = await RegisterAsync(client, agentId, hostname, "0.3.0-test");
        var secondToken = await RegisterAsync(client, agentId, hostname, "0.3.0-test");
        Assert.NotEqual(firstToken, secondToken);

        using (var oldTokenResponse = await SendJsonWithBearerAsync(
            client,
            "/api/v1/agents/heartbeat",
            CreateHeartbeat(agentId, hostname, queueDepth: 0),
            firstToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, oldTokenResponse.StatusCode);
        }

        var batch = new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = now,
            Events = new[]
            {
                CreateEvent(agentId, hostname, eventId, "System", 6005, now.AddMinutes(-2), "unique integration marker"),
                CreateEvent(agentId, hostname, duplicateEventId, "Application", 1000, now.AddMinutes(-1), "application marker")
            }
        };

        var ingest = await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", batch, secondToken);
        Assert.Equal(2, ingest.Accepted);
        Assert.Equal(0, ingest.Duplicates);
        Assert.Contains(eventId, ingest.AcceptedEventIds);

        var duplicate = await PostJsonWithBearerAsync<IngestBatchResponse>(client, "/api/v1/ingest/events", batch, secondToken);
        Assert.Equal(0, duplicate.Accepted);
        Assert.Equal(2, duplicate.Duplicates);
        Assert.Contains(eventId, duplicate.DuplicateEventIds);

        await PostJsonWithBearerAsync<JsonElement>(client, "/api/v1/agents/heartbeat", CreateHeartbeat(agentId, hostname, queueDepth: 7), secondToken);

        var search = await GetJsonWithReviewTokenAsync<EventSearchResponse>(client,
            $"/api/v1/events?agent_id={Uri.EscapeDataString(agentId)}&hostname={hostname}&channel=System&windows_event_id=6005&category=system&action=observed&from={Uri.EscapeDataString(now.AddHours(-1).ToString("O"))}&to={Uri.EscapeDataString(now.AddHours(1).ToString("O"))}&keyword=unique&limit=999");
        Assert.InRange(search.Events.Count, 1, 500);
        var stored = Assert.Single(search.Events, item => item.EventId == eventId);
        Assert.NotNull(stored.IngestTime);
        Assert.Equal("System", stored.Channel);
        Assert.Equal("system", stored.Normalized?.Category);

        var sourceHealth = await GetJsonWithReviewTokenAsync<SourceHealthResponse>(client,
            $"/api/v1/source-health?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains(sourceHealth.Summaries, summary => summary.AgentId == agentId);
        Assert.Contains(sourceHealth.Sources, source => source.SourceId == "system");

        var rules = await GetJsonWithReviewTokenAsync<JsonElement>(client, "/api/v1/detections/rules");
        Assert.True(rules.GetProperty("rules").GetArrayLength() >= 10);

        var invalidBatchId = Guid.NewGuid();
        var invalidBatch = batch with
        {
            BatchId = invalidBatchId,
            Events = new[] { batch.Events[0] with { EventId = Guid.NewGuid(), AgentId = "other-agent" } }
        };
        using (var invalidIngest = await SendJsonWithBearerAsync(client, "/api/v1/ingest/events", invalidBatch, secondToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, invalidIngest.StatusCode);
        }

        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await AssertDatabaseStateAsync(dataSource, agentId, invalidBatchId);
    }

    [PostgresFact]
    public async Task DisabledAgentTokenIsRejectedUntilRegistrationReactivatesAgent()
    {
        var connectionString = database.RequireConnectionString();
        var agentId = $"reactivate-agent-{Guid.NewGuid():N}";
        var hostname = "REACTIVATE-HOST";
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var disabledToken = await RegisterAsync(client, agentId, hostname, "0.3.0-test");
        await SetAgentStatusAsync(connectionString, agentId, "disabled");

        using (var disabledHeartbeat = await SendJsonWithBearerAsync(
            client,
            "/api/v1/agents/heartbeat",
            CreateHeartbeat(agentId, hostname, queueDepth: 0),
            disabledToken))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, disabledHeartbeat.StatusCode);
        }

        var reactivatedToken = await RegisterAsync(client, agentId, hostname, "0.3.1-test");
        Assert.NotEqual(disabledToken, reactivatedToken);
        await PostJsonWithBearerAsync<JsonElement>(client, "/api/v1/agents/heartbeat", CreateHeartbeat(agentId, hostname, queueDepth: 1), reactivatedToken);

        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("select status from agents where agent_id = @agent_id;");
        command.Parameters.AddWithValue("agent_id", agentId);
        var status = Convert.ToString(await command.ExecuteScalarAsync(CancellationToken.None));
        Assert.Equal("active", status);
    }

    private static WebApplicationFactory<Program> CreateFactory(string connectionString)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SiemDatabase"] = connectionString,
                    ["Auth:EnrollmentToken"] = EnrollmentToken,
                    ["Auth:ReviewToken"] = ReviewToken,
                    ["Ingestion:MaxEventsPerBatch"] = "500"
                });
            });
        });
    }

    private static async Task<string> RegisterAsync(HttpClient client, string agentId, string hostname, string agentVersion)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register")
        {
            Content = JsonContent.Create(new AgentRegistrationRequest
            {
                AgentId = agentId,
                Hostname = hostname,
                MachineGuid = Guid.NewGuid().ToString("N"),
                OsVersion = "Windows Test",
                AgentVersion = agentVersion
            }, options: JsonOptions.Default)
        };
        request.Headers.Add("X-Enrollment-Token", EnrollmentToken);

        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var registration = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>(JsonOptions.Default, CancellationToken.None);
        return registration?.ApiToken ?? throw new InvalidOperationException("Registration response did not include a token.");
    }

    private static async Task<T> PostJsonWithBearerAsync<T>(HttpClient client, string path, object body, string token)
    {
        using var response = await SendJsonWithBearerAsync(client, path, body, token);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task<HttpResponseMessage> SendJsonWithBearerAsync(HttpClient client, string path, object body, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body, options: JsonOptions.Default)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request, CancellationToken.None);
    }

    private static async Task<T> GetJsonWithReviewTokenAsync<T>(HttpClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", ReviewToken);
        using var response = await client.SendAsync(request, CancellationToken.None);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<T>(JsonOptions.Default, CancellationToken.None);
        return result ?? throw new InvalidOperationException($"Response from {path} was empty.");
    }

    private static async Task SetAgentStatusAsync(string connectionString, string agentId, string status)
    {
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("""
            update agents
            set status = @status, updated_at = now()
            where agent_id = @agent_id;
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("status", status);
        await command.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private static HeartbeatRequest CreateHeartbeat(string agentId, string hostname, int queueDepth)
    {
        return new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "0.3.0-test",
            Os = "Windows Test",
            LastEventTime = DateTimeOffset.UtcNow,
            QueueDepth = queueDepth,
            CpuPercent = null,
            MemoryMb = 123,
            ConfigHash = "synthetic-config-hash",
            QueueMetrics = new QueueSloMetrics
            {
                QueueDepth = queueDepth,
                PoisonDepth = 0,
                MaxSizeMb = 512,
                WarningSizePercent = 80
            },
            SourceHealth = new[]
            {
                new SourceHealthReport
                {
                    SourceId = "system",
                    DisplayName = "Windows System",
                    Channel = "System",
                    CoverageLevel = WindowsCoverageLevel.L1,
                    Status = SourceHealthStatuses.Healthy,
                    Required = true,
                    Enabled = true,
                    NewestRecordId = 1234
                }
            }
        };
    }

    private static EventEnvelope CreateEvent(
        string agentId,
        string hostname,
        Guid eventId,
        string channel,
        int windowsEventId,
        DateTimeOffset eventTime,
        string marker)
    {
        return new EventEnvelope
        {
            EventId = eventId,
            AgentId = agentId,
            Hostname = hostname,
            Source = EventSources.WindowsEventLog,
            Channel = channel,
            Provider = "IntegrationProvider",
            WindowsEventId = windowsEventId,
            RecordId = Random.Shared.NextInt64(1, long.MaxValue),
            EventTime = eventTime,
            Severity = "information",
            Message = $"Integration event {marker}",
            Normalized = new NormalizedEventFields
            {
                Category = channel == "System" ? "system" : "application",
                Action = "observed",
                Entities = new[] { new EventEntity { Type = "host", Value = hostname, Role = "observed" } }
            },
            Raw = JsonSerializer.SerializeToElement(new { marker, agentId })
        };
    }

    private static async Task AssertDatabaseStateAsync(NpgsqlDataSource dataSource, string agentId, Guid invalidBatchId)
    {
        await using (var eventCommand = dataSource.CreateCommand("select count(*) from events where agent_id = @agent_id;"))
        {
            eventCommand.Parameters.AddWithValue("agent_id", agentId);
            var eventCount = Convert.ToInt32(await eventCommand.ExecuteScalarAsync(CancellationToken.None));
            Assert.Equal(2, eventCount);
        }

        await using (var heartbeatCommand = dataSource.CreateCommand("select queue_depth from agent_heartbeats where agent_id = @agent_id order by heartbeat_time desc limit 1;"))
        {
            heartbeatCommand.Parameters.AddWithValue("agent_id", agentId);
            var queueDepth = Convert.ToInt32(await heartbeatCommand.ExecuteScalarAsync(CancellationToken.None));
            Assert.Equal(7, queueDepth);
        }

        await using (var errorCommand = dataSource.CreateCommand("select count(*) from ingestion_errors where agent_id = @agent_id and batch_id = @batch_id and error_code = 'validation_failed';"))
        {
            errorCommand.Parameters.AddWithValue("agent_id", agentId);
            errorCommand.Parameters.AddWithValue("batch_id", invalidBatchId);
            var errorCount = Convert.ToInt32(await errorCommand.ExecuteScalarAsync(CancellationToken.None));
            Assert.Equal(1, errorCount);
        }
    }

    private static class JsonOptions
    {
        public static readonly JsonSerializerOptions Default = new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
        };
    }
}
