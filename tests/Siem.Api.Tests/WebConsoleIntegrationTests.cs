using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class WebConsoleIntegrationTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "web-integration-enrollment-token";
    private const string ReviewToken = "web-integration-review-token";

    [PostgresFact]
    public async Task WebConsoleDisplaysSeededAgentHeartbeatAndEventData()
    {
        var connectionString = database.RequireConnectionString();
        var agentId = $"web-agent-{Guid.NewGuid():N}";
        var hostname = "WEB-HOST";
        var eventId = Guid.NewGuid();
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var agentToken = await RegisterAsync(client, agentId, hostname);
        await PostWithBearerAsync(client, "/api/v1/agents/heartbeat", new HeartbeatRequest
        {
            AgentId = agentId,
            Hostname = hostname,
            AgentVersion = "0.3.0-web-test",
            Os = "Windows Test",
            LastEventTime = DateTimeOffset.UtcNow,
            QueueDepth = 3,
            MemoryMb = 64,
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
                    NewestRecordId = 6005
                }
            }
        }, agentToken);

        await PostWithBearerAsync(client, "/api/v1/ingest/events", new IngestBatchRequest
        {
            AgentId = agentId,
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                new EventEnvelope
                {
                    EventId = eventId,
                    AgentId = agentId,
                    Hostname = hostname,
                    Source = EventSources.WindowsEventLog,
                    Channel = "System",
                    Provider = "WebSmokeProvider",
                    WindowsEventId = 6005,
                    RecordId = Random.Shared.NextInt64(1, long.MaxValue),
                    EventTime = DateTimeOffset.UtcNow,
                    Severity = "information",
                    Message = $"Web console smoke marker {agentId}",
                    Normalized = new NormalizedEventFields { Category = "system", Action = "observed" },
                    Raw = JsonSerializer.SerializeToElement(new { web_marker = agentId })
                }
            }
        }, agentToken);

        await LoginAsync(client);

        var dashboard = await GetHtmlAsync(client, "/");
        Assert.Contains("Dashboard", dashboard, StringComparison.Ordinal);
        Assert.Contains("total agents", dashboard, StringComparison.Ordinal);

        var agents = await GetHtmlAsync(client, $"/agents?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains(agentId, agents, StringComparison.Ordinal);
        Assert.Contains(hostname, agents, StringComparison.Ordinal);
        Assert.Contains("3", agents, StringComparison.Ordinal);
        Assert.Contains("L1", agents, StringComparison.Ordinal);

        var coverage = await GetHtmlAsync(client, $"/agents/detail?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains("Host coverage", coverage, StringComparison.Ordinal);
        Assert.Contains("Windows System", coverage, StringComparison.Ordinal);

        var events = await GetHtmlAsync(client, $"/events?agent_id={Uri.EscapeDataString(agentId)}&keyword={Uri.EscapeDataString(agentId)}&category=system&limit=10");
        Assert.Contains(agentId, events, StringComparison.Ordinal);
        Assert.Contains("WebSmokeProvider", events, StringComparison.Ordinal);

        var detail = await GetHtmlAsync(client, $"/events/detail?agent_id={Uri.EscapeDataString(agentId)}&event_id={eventId}");
        Assert.Contains(eventId.ToString(), detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Raw JSON", detail, StringComparison.Ordinal);
        Assert.Contains(agentId, detail, StringComparison.Ordinal);
        Assert.Contains("Entities", detail, StringComparison.Ordinal);

        var alerts = await GetHtmlAsync(client, "/alerts");
        Assert.Contains("Alerts", alerts, StringComparison.Ordinal);
        Assert.Contains("No alerts match", alerts, StringComparison.Ordinal);

        var auditPolicy = await GetHtmlAsync(client, "/audit-policy");
        Assert.Contains("Audit policy drift", auditPolicy, StringComparison.Ordinal);
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
                    ["Auth:ReviewToken"] = ReviewToken
                });
            });
        });
    }

    private static async Task<string> RegisterAsync(HttpClient client, string agentId, string hostname)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register")
        {
            Content = JsonContent.Create(new AgentRegistrationRequest
            {
                AgentId = agentId,
                Hostname = hostname,
                MachineGuid = null,
                OsVersion = "Windows Test",
                AgentVersion = "0.3.0-web-test"
            })
        };
        request.Headers.Add("X-Enrollment-Token", EnrollmentToken);
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var registration = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>();
        return registration?.ApiToken ?? throw new InvalidOperationException("Registration response did not include a token.");
    }

    private static async Task PostWithBearerAsync(HttpClient client, string path, object payload, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(payload)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    private static async Task LoginAsync(HttpClient client)
    {
        var login = await GetHtmlAsync(client, "/login");
        var token = ExtractAntiforgeryToken(login);
        using var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["ReviewToken"] = ReviewToken,
            ["ReturnUrl"] = "/"
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    private static async Task<string> GetHtmlAsync(HttpClient client, string path)
    {
        using var response = await client.GetAsync(path);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }

    private static string ExtractAntiforgeryToken(string html)
    {
        var match = Regex.Match(
            html,
            "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"",
            RegexOptions.CultureInvariant);
        Assert.True(match.Success, "Login page should contain an antiforgery token.");
        return WebUtility.HtmlDecode(match.Groups["token"].Value);
    }
}
