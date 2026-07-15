using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class WebConsoleIntegrationTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "web-integration-enrollment-token";
    private const string OperatorPassword = "Synthetic-Web-Admin1!";
    private const string ViewerPassword = "Synthetic-Web-Viewer1!";

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
            HostTimezone = SyntheticPacificTimezone(),
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
                    NewestRecordId = 6005,
                    HostTimezone = SyntheticPacificTimezone()
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
                    HostTimezone = SyntheticPacificTimezone(),
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
        Assert.Contains("Skip to main content", dashboard, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Primary\"", dashboard, StringComparison.Ordinal);
        Assert.Contains("Global search", dashboard, StringComparison.Ordinal);
        Assert.Contains("Cases", dashboard, StringComparison.Ordinal);
        Assert.Contains("Detections", dashboard, StringComparison.Ordinal);
        Assert.Contains("Dashboards", dashboard, StringComparison.Ordinal);
        Assert.Contains("Administration", dashboard, StringComparison.Ordinal);
        Assert.Contains("class=\"app-frame\"", dashboard, StringComparison.Ordinal);
        Assert.Contains("Security overview", dashboard, StringComparison.Ordinal);
        Assert.Contains("Recent alerts", dashboard, StringComparison.Ordinal);
        Assert.Contains("Active agents", dashboard, StringComparison.Ordinal);
        Assert.Contains("retired agents", dashboard, StringComparison.Ordinal);

        var agents = await GetHtmlAsync(client, $"/agents?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains(agentId, agents, StringComparison.Ordinal);
        Assert.Contains(hostname, agents, StringComparison.Ordinal);
        Assert.Contains("Agent results", agents, StringComparison.Ordinal);
        Assert.Contains("Page 1", agents, StringComparison.Ordinal);
        Assert.Contains("3", agents, StringComparison.Ordinal);
        Assert.Contains("L1", agents, StringComparison.Ordinal);

        var coverage = await GetHtmlAsync(client, $"/agents/detail?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains("Host coverage", coverage, StringComparison.Ordinal);
        Assert.Contains("Windows System", coverage, StringComparison.Ordinal);
        Assert.Contains("host timezone", coverage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Pacific Standard Time", coverage, StringComparison.Ordinal);

        using (var globalSearchResponse = await client.PostAsync("/events?handler=GlobalSearch", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiforgeryToken(dashboard),
            ["GlobalSearch"] = agentId
        })))
        {
            Assert.Equal(HttpStatusCode.OK, globalSearchResponse.StatusCode);
            var globalSearchHtml = await globalSearchResponse.Content.ReadAsStringAsync();
            Assert.Contains("Global search scope", globalSearchHtml, StringComparison.Ordinal);
            Assert.Contains(agentId, globalSearchHtml, StringComparison.Ordinal);
            Assert.DoesNotContain("keyword=", globalSearchHtml, StringComparison.OrdinalIgnoreCase);
        }

        var events = await GetHtmlAsync(client, $"/events?agent_id={Uri.EscapeDataString(agentId)}&keyword={Uri.EscapeDataString(agentId)}&category=system&limit=10");
        Assert.Contains(agentId, events, StringComparison.Ordinal);
        Assert.Contains("Event results", events, StringComparison.Ordinal);
        Assert.Contains("agent_id:", events, StringComparison.Ordinal);
        Assert.Contains("WebSmokeProvider", events, StringComparison.Ordinal);
        Assert.Contains("Host time (Pacific Standard Time", events, StringComparison.Ordinal);

        var detail = await GetHtmlAsync(client, $"/events/detail?agent_id={Uri.EscapeDataString(agentId)}&event_id={eventId}");
        Assert.Contains(eventId.ToString(), detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Raw JSON", detail, StringComparison.Ordinal);
        Assert.Contains(agentId, detail, StringComparison.Ordinal);
        Assert.Contains("Entities", detail, StringComparison.Ordinal);
        Assert.Contains("Event host time", detail, StringComparison.Ordinal);
        Assert.Contains("Pacific Standard Time", detail, StringComparison.Ordinal);

        var alerts = await GetHtmlAsync(client, "/alerts");
        Assert.Contains("Alerts", alerts, StringComparison.Ordinal);
        Assert.Contains("Alert results", alerts, StringComparison.Ordinal);

        var auditPolicy = await GetHtmlAsync(client, "/audit-policy");
        Assert.Contains("Audit policy drift", auditPolicy, StringComparison.Ordinal);

        var socAgent = await GetHtmlAsync(client, $"/soc-agent?agent_id={Uri.EscapeDataString(agentId)}");
        Assert.Contains("soc-agent workspace", socAgent, StringComparison.Ordinal);
        Assert.Contains("Provider status", socAgent, StringComparison.Ordinal);
        Assert.Contains("Recent chats", socAgent, StringComparison.Ordinal);
        Assert.Contains("Live tool activity", socAgent, StringComparison.Ordinal);
        Assert.Contains("Send a soc-agent message", socAgent, StringComparison.Ordinal);
        var socAgentToken = ExtractAntiforgeryToken(socAgent);
        using (var chatResponse = await client.PostAsync("/soc-agent?handler=Send", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = socAgentToken,
            ["Message"] = $"Summarize synthetic marker {agentId}",
            ["ComposerContextAgentId"] = agentId
        })))
        {
            Assert.Equal(HttpStatusCode.Redirect, chatResponse.StatusCode);
            var chatLocation = chatResponse.Headers.Location?.OriginalString ?? throw new InvalidOperationException("soc-agent chat did not redirect to the session.");
            var chatThread = await GetHtmlAsync(client, chatLocation);
            Assert.Contains("Operator", chatThread, StringComparison.Ordinal);
            Assert.Contains("soc-agent", chatThread, StringComparison.Ordinal);
            Assert.Contains("Tool activity", chatThread, StringComparison.Ordinal);
            Assert.Contains("Citations", chatThread, StringComparison.Ordinal);
            Assert.Contains("Delete chat", chatThread, StringComparison.Ordinal);
            Assert.Contains("Confirm deletion", chatThread, StringComparison.Ordinal);
            Assert.Contains(agentId, chatThread, StringComparison.Ordinal);

            var sessionId = ExtractSessionId(chatLocation);
            var deleteToken = ExtractAntiforgeryToken(chatThread);
            using var deleteResponse = await client.PostAsync($"/soc-agent?handler=DeleteSession&session_id={sessionId}", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = deleteToken,
                ["DeleteSessionId"] = sessionId.ToString(),
                ["SessionId"] = sessionId.ToString(),
                ["ContextAgentId"] = agentId,
                ["ConfirmDelete"] = "true"
            }));
            Assert.Equal(HttpStatusCode.Redirect, deleteResponse.StatusCode);
            var deleteLocation = deleteResponse.Headers.Location?.OriginalString ?? throw new InvalidOperationException("soc-agent delete did not redirect.");
            var afterDelete = await GetHtmlAsync(client, deleteLocation);
            Assert.Contains("Deleted soc-agent chat session", afterDelete, StringComparison.Ordinal);
            Assert.DoesNotContain(sessionId.ToString(), afterDelete, StringComparison.OrdinalIgnoreCase);
        }
    }

    [PostgresFact]
    public async Task ViewerNavigationOmitsPrivilegedWorkspacesAndShowsForbiddenState()
    {
        var connectionString = database.RequireConnectionString();
        EnsureTestOperator(connectionString, "synthetic-web-viewer", "Synthetic Web Viewer", "viewer", ViewerPassword);
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        await LoginAsync(client, "synthetic-web-viewer", ViewerPassword);

        var dashboard = await GetHtmlAsync(client, "/");
        Assert.Contains("Current role viewer", dashboard, StringComparison.Ordinal);
        Assert.Contains("Overview", dashboard, StringComparison.Ordinal);
        Assert.Contains("Search", dashboard, StringComparison.Ordinal);
        Assert.Contains("Assets", dashboard, StringComparison.Ordinal);
        Assert.Contains("Alerts", dashboard, StringComparison.Ordinal);
        Assert.Contains("Dashboards", dashboard, StringComparison.Ordinal);
        Assert.DoesNotContain("Investigation graphs</a>", dashboard, StringComparison.Ordinal);
        Assert.DoesNotContain("soc-agent</a>", dashboard, StringComparison.Ordinal);
        Assert.DoesNotContain("Administration", dashboard, StringComparison.Ordinal);

        using var denied = await client.GetAsync("/soc-agent");
        Assert.Equal(HttpStatusCode.Redirect, denied.StatusCode);
        Assert.Contains("/forbidden", denied.Headers.Location?.OriginalString ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        var forbidden = await GetHtmlAsync(client, denied.Headers.Location!.OriginalString);
        Assert.Contains("Access forbidden", forbidden, StringComparison.Ordinal);
        Assert.Contains("viewer", forbidden, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task ViewerGlobalSearchUsesPermittedMetadataAndKeepsSensitiveTermsOutOfUrls()
    {
        var connectionString = database.RequireConnectionString();
        EnsureTestOperator(connectionString, "synthetic-web-viewer", "Synthetic Web Viewer", "viewer", ViewerPassword);
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var matchingAgentId = $"viewer-global-{Guid.NewGuid():N}";
        var otherAgentId = $"viewer-global-other-{Guid.NewGuid():N}";
        var sensitiveMarker = $"sensitive-global-marker-{Guid.NewGuid():N}";

        var matchingToken = await RegisterAsync(client, matchingAgentId, "VIEWER-GLOBAL-HOST");
        var otherToken = await RegisterAsync(client, otherAgentId, "VIEWER-GLOBAL-OTHER");
        await PostWithBearerAsync(client, "/api/v1/ingest/events", new IngestBatchRequest
        {
            AgentId = matchingAgentId,
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                new EventEnvelope
                {
                    EventId = Guid.NewGuid(),
                    AgentId = matchingAgentId,
                    Hostname = "VIEWER-GLOBAL-HOST",
                    Source = EventSources.WindowsEventLog,
                    Channel = "System",
                    Provider = "MetadataProvider",
                    WindowsEventId = 6005,
                    RecordId = Random.Shared.NextInt64(1, long.MaxValue),
                    EventTime = DateTimeOffset.UtcNow,
                    HostTimezone = SyntheticPacificTimezone(),
                    Severity = "information",
                    Message = "Viewer metadata global-search match",
                    Normalized = new NormalizedEventFields { Category = "system", Action = "observed" },
                    Raw = JsonSerializer.SerializeToElement(new { synthetic = true })
                }
            }
        }, matchingToken);
        await PostWithBearerAsync(client, "/api/v1/ingest/events", new IngestBatchRequest
        {
            AgentId = otherAgentId,
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                new EventEnvelope
                {
                    EventId = Guid.NewGuid(),
                    AgentId = otherAgentId,
                    Hostname = "VIEWER-GLOBAL-OTHER",
                    Source = EventSources.WindowsEventLog,
                    Channel = "Application",
                    Provider = "SensitiveMessageProvider",
                    WindowsEventId = 7001,
                    RecordId = Random.Shared.NextInt64(1, long.MaxValue),
                    EventTime = DateTimeOffset.UtcNow.AddSeconds(-1),
                    HostTimezone = SyntheticPacificTimezone(),
                    Severity = "warning",
                    Message = $"Viewer must not match this sensitive marker {sensitiveMarker}",
                    Normalized = new NormalizedEventFields { Category = "application", Action = "observed" },
                    Raw = JsonSerializer.SerializeToElement(new { sensitive_marker = sensitiveMarker })
                }
            }
        }, otherToken);

        await LoginAsync(client, "synthetic-web-viewer", ViewerPassword);
        var dashboard = await GetHtmlAsync(client, "/");
        using (var metadataResponse = await client.PostAsync("/events?handler=GlobalSearch", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiforgeryToken(dashboard),
            ["GlobalSearch"] = matchingAgentId
        })))
        {
            Assert.Equal(HttpStatusCode.OK, metadataResponse.StatusCode);
            var html = await metadataResponse.Content.ReadAsStringAsync();
            Assert.Contains(matchingAgentId, html, StringComparison.Ordinal);
            Assert.DoesNotContain(otherAgentId, html, StringComparison.Ordinal);
            Assert.DoesNotContain("keyword=", html, StringComparison.OrdinalIgnoreCase);
        }

        dashboard = await GetHtmlAsync(client, "/");
        using (var sensitiveResponse = await client.PostAsync("/events?handler=GlobalSearch", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = ExtractAntiforgeryToken(dashboard),
            ["GlobalSearch"] = sensitiveMarker
        })))
        {
            Assert.Equal(HttpStatusCode.OK, sensitiveResponse.StatusCode);
            Assert.DoesNotContain(Uri.EscapeDataString(sensitiveMarker), sensitiveResponse.RequestMessage?.RequestUri?.OriginalString ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            var html = await sensitiveResponse.Content.ReadAsStringAsync();
            Assert.Contains("No matching permitted event metadata", html, StringComparison.Ordinal);
            Assert.DoesNotContain(otherAgentId, html, StringComparison.Ordinal);
            Assert.DoesNotContain(sensitiveMarker, html, StringComparison.OrdinalIgnoreCase);
            AssertHtmlUrlsDoNotContain(html, sensitiveMarker);
        }
    }

    [PostgresFact]
    public async Task AgentInventoryDefaultsToActiveAgentsAndCleanupRetiresOnlyStaleActiveRows()
    {
        var connectionString = database.RequireConnectionString();
        var prefix = $"cleanup-agent-{Guid.NewGuid():N}";
        var recentAgentId = $"{prefix}-recent";
        var staleAgentId = $"{prefix}-stale";
        var disabledAgentId = $"{prefix}-disabled";
        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        await RegisterAsync(client, recentAgentId, "CLEANUP-RECENT");
        await RegisterAsync(client, staleAgentId, "CLEANUP-STALE");
        await RegisterAsync(client, disabledAgentId, "CLEANUP-DISABLED");
        await MarkAgentStateAsync(connectionString, staleAgentId, disabledAgentId);

        await LoginAsync(client);

        var defaultInventory = await GetHtmlAsync(client, $"/agents?agent_id={Uri.EscapeDataString(prefix)}");
        Assert.Contains(recentAgentId, defaultInventory, StringComparison.Ordinal);
        Assert.Contains(staleAgentId, defaultInventory, StringComparison.Ordinal);
        Assert.DoesNotContain(disabledAgentId, defaultInventory, StringComparison.Ordinal);
        Assert.Contains("Eligible active agents", defaultInventory, StringComparison.Ordinal);

        var disabledInventory = await GetHtmlAsync(client, $"/agents?agent_id={Uri.EscapeDataString(prefix)}&status=disabled");
        Assert.Contains(disabledAgentId, disabledInventory, StringComparison.Ordinal);
        Assert.Contains("retired", disabledInventory, StringComparison.Ordinal);
        Assert.DoesNotContain(recentAgentId, disabledInventory, StringComparison.Ordinal);

        var antiForgeryToken = ExtractAntiforgeryToken(defaultInventory);
        string validationRedirect;
        using (var validationResponse = await client.PostAsync("/agents?handler=CleanupStale", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgeryToken,
            ["agent_id"] = prefix,
            ["health"] = "stale",
            ["status"] = "active",
            ["page"] = "2"
        })))
        {
            validationRedirect = AssertAgentInventoryRedirect(validationResponse, prefix, "stale", "active", "2");
        }

        var validationInventory = await GetHtmlAsync(client, validationRedirect);
        Assert.Contains("Confirm the non-destructive stale-agent cleanup before retiring agents.", validationInventory, StringComparison.Ordinal);
        Assert.Contains("Agent results", validationInventory, StringComparison.Ordinal);
        Assert.Contains("Page 2", validationInventory, StringComparison.Ordinal);
        Assert.DoesNotContain("Developer Exception Page", validationInventory, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("InvalidOperationException", validationInventory, StringComparison.OrdinalIgnoreCase);

        antiForgeryToken = ExtractAntiforgeryToken(validationInventory);
        string cleanupRedirect;
        using (var cleanupResponse = await client.PostAsync("/agents?handler=CleanupStale", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgeryToken,
            ["ConfirmCleanup"] = "true",
            ["agent_id"] = prefix,
            ["health"] = "stale",
            ["status"] = "active",
            ["page"] = "2"
        })))
        {
            cleanupRedirect = AssertAgentInventoryRedirect(cleanupResponse, prefix, "stale", "active", "2");
        }

        var cleanupInventory = await GetHtmlAsync(client, cleanupRedirect);
        Assert.Contains("Retired ", cleanupInventory, StringComparison.Ordinal);
        Assert.Contains("stale active agent(s)", cleanupInventory, StringComparison.Ordinal);
        Assert.Contains("Agent results", cleanupInventory, StringComparison.Ordinal);
        Assert.Contains("Page 2", cleanupInventory, StringComparison.Ordinal);
        Assert.DoesNotContain("Developer Exception Page", cleanupInventory, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("InvalidOperationException", cleanupInventory, StringComparison.OrdinalIgnoreCase);

        var activeAfterCleanup = await GetHtmlAsync(client, $"/agents?agent_id={Uri.EscapeDataString(prefix)}&status=active");
        Assert.Contains(recentAgentId, activeAfterCleanup, StringComparison.Ordinal);
        Assert.DoesNotContain(staleAgentId, activeAfterCleanup, StringComparison.Ordinal);
        Assert.DoesNotContain(disabledAgentId, activeAfterCleanup, StringComparison.Ordinal);

        var retiredAfterCleanup = await GetHtmlAsync(client, $"/agents?agent_id={Uri.EscapeDataString(prefix)}&status=disabled");
        Assert.Contains(staleAgentId, retiredAfterCleanup, StringComparison.Ordinal);
        Assert.Contains(disabledAgentId, retiredAfterCleanup, StringComparison.Ordinal);
    }

    private static WebApplicationFactory<Program> CreateFactory(string connectionString)
    {
        EnsureTestOperator(connectionString);
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SiemDatabase"] = connectionString,
                    ["Auth:EnrollmentToken"] = EnrollmentToken,
                    ["SocAgent:Provider"] = "Local",
                    ["SocAgent:ProviderDisplayName"] = "Local soc-agent",
                    ["SocAgent:AuthMode"] = "Local",
                    ["SocAgent:Model"] = "soc-agent-local-v1",
                    ["SocAgent:ExternalCallsEnabled"] = "false"
                });
            });
        });
    }


    private static void EnsureTestOperator(string connectionString)
    {
        EnsureTestOperator(connectionString, "synthetic-web-admin", "Synthetic Web Admin", "admin", OperatorPassword);
    }

    private static void EnsureTestOperator(string connectionString, string username, string displayName, string role, string password)
    {
        using var connection=new NpgsqlConnection(connectionString); connection.Open(); using var command=connection.CreateCommand();
        command.CommandText="insert into operators(operator_id,username,normalized_username,display_name,role,password_hash) values(@id,@username,@normalized_username,@display_name,@role,@hash) on conflict(normalized_username) do update set password_hash=excluded.password_hash,role=excluded.role,display_name=excluded.display_name,enabled=true;";
        command.Parameters.AddWithValue("id",Guid.NewGuid());
        command.Parameters.AddWithValue("username",username);
        command.Parameters.AddWithValue("normalized_username",username.ToUpperInvariant());
        command.Parameters.AddWithValue("display_name",displayName);
        command.Parameters.AddWithValue("role",role);
        command.Parameters.AddWithValue("hash",new Challenger.Siem.Api.Auth.OperatorPasswordHasher().Hash(password));
        command.ExecuteNonQuery();
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
                AgentVersion = "0.3.0-web-test",
                HostTimezone = SyntheticPacificTimezone()
            })
        };
        request.Headers.Add("X-Enrollment-Token", EnrollmentToken);
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var registration = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>();
        return registration?.ApiToken ?? throw new InvalidOperationException("Registration response did not include a token.");
    }

    private static HostTimezoneMetadata SyntheticPacificTimezone() => new()
    {
        Id = "Pacific Standard Time",
        DisplayName = "(UTC-08:00) Pacific Time (US & Canada)",
        StandardName = "Pacific Standard Time",
        DaylightName = "Pacific Daylight Time",
        BaseUtcOffsetMinutes = -480,
        UtcOffsetMinutes = -420,
        IsDaylightSavingTime = true
    };

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

    private static async Task MarkAgentStateAsync(string connectionString, string staleAgentId, string disabledAgentId)
    {
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        await using var command = dataSource.CreateCommand("""
            update agents
            set last_seen = now() - interval '2 hours', updated_at = now()
            where agent_id = @stale_agent_id;

            update agents
            set status = 'disabled', last_seen = now() - interval '2 hours', updated_at = now()
            where agent_id = @disabled_agent_id;
            """);
        command.Parameters.AddWithValue("stale_agent_id", staleAgentId);
        command.Parameters.AddWithValue("disabled_agent_id", disabledAgentId);
        await command.ExecuteNonQueryAsync();
    }

    private static string AssertAgentInventoryRedirect(
        HttpResponseMessage response,
        string expectedAgentId,
        string expectedHealth,
        string expectedStatus,
        string expectedPage)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location?.OriginalString ?? throw new InvalidOperationException("Cleanup did not return a redirect location.");
        Assert.Contains("/agents", location, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"agent_id={Uri.EscapeDataString(expectedAgentId)}", location, StringComparison.Ordinal);
        Assert.Contains($"health={Uri.EscapeDataString(expectedHealth)}", location, StringComparison.Ordinal);
        Assert.Contains($"status={Uri.EscapeDataString(expectedStatus)}", location, StringComparison.Ordinal);
        Assert.Contains($"page={Uri.EscapeDataString(expectedPage)}", location, StringComparison.Ordinal);
        return location;
    }

    private static async Task LoginAsync(HttpClient client, string username = "synthetic-web-admin", string password = OperatorPassword)
    {
        var login = await GetHtmlAsync(client, "/login");
        var token = ExtractAntiforgeryToken(login);
        using var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Username"] = username,
            ["Password"] = password,
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

    private static Guid ExtractSessionId(string location)
    {
        var match = Regex.Match(location, "[?&]session_id=(?<session_id>[0-9a-fA-F-]{36})", RegexOptions.CultureInvariant);
        Assert.True(match.Success, "soc-agent redirect should include a session_id query value.");
        return Guid.Parse(match.Groups["session_id"].Value);
    }

    private static void AssertHtmlUrlsDoNotContain(string html, string forbiddenValue)
    {
        foreach (Match match in Regex.Matches(html, "(?:href|action)=\"(?<url>[^\"]*)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var url = WebUtility.HtmlDecode(match.Groups["url"].Value);
            Assert.DoesNotContain(forbiddenValue, url, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Uri.EscapeDataString(forbiddenValue), url, StringComparison.OrdinalIgnoreCase);
        }
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
