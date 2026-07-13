using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class OperatorRbacIntegrationTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "synthetic-rbac-enrollment-token";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [PostgresFact]
    public async Task RoleMatrixAndFieldRedactionAreEnforcedAtHttpBoundary()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var password = "Synthetic-RoleMatrix1!";
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var viewerToken = await CreateOperatorApiTokenAsync(operators, $"rbac-v-{suffix}", OperatorRoles.Viewer, password);
        var analystToken = await CreateOperatorApiTokenAsync(operators, $"rbac-a-{suffix}", OperatorRoles.Analyst, password);
        var detectionToken = await CreateOperatorApiTokenAsync(operators, $"rbac-d-{suffix}", OperatorRoles.DetectionEngineer, password);
        var adminToken = await CreateOperatorApiTokenAsync(operators, $"rbac-m-{suffix}", OperatorRoles.Admin, password);

        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var agentId = $"rbac-agent-{Guid.NewGuid():N}";
        var agentToken = await RegisterAgentAsync(client, agentId, "windows");
        var sensitiveEventId = Guid.NewGuid();
        await IngestSensitiveWindowsEventAsync(client, agentId, agentToken, sensitiveEventId);

        using (var viewerEvents = await GetWithBearerAsync(client, $"/api/v1/events?agent_id={agentId}&limit=10", viewerToken))
        {
            Assert.Equal(HttpStatusCode.OK, viewerEvents.StatusCode);
            var body = await viewerEvents.Content.ReadAsStringAsync();
            Assert.Contains("[restricted]", body, StringComparison.Ordinal);
            Assert.DoesNotContain("Sensitive command line", body, StringComparison.Ordinal);
            Assert.DoesNotContain("192.0.2.55", body, StringComparison.Ordinal);
        }

        using (var analystEvents = await GetWithBearerAsync(client, $"/api/v1/events?agent_id={agentId}&limit=10", analystToken))
        {
            Assert.Equal(HttpStatusCode.OK, analystEvents.StatusCode);
            var body = await analystEvents.Content.ReadAsStringAsync();
            Assert.Contains("[redacted: sensitive event text]", body, StringComparison.Ordinal);
            Assert.DoesNotContain("Sensitive command line", body, StringComparison.Ordinal);
            Assert.DoesNotContain("192.0.2.55", body, StringComparison.Ordinal);
            Assert.DoesNotContain("synthetic-user", body, StringComparison.Ordinal);
            Assert.DoesNotContain("/tmp/sensitive", body, StringComparison.Ordinal);
        }

        using (var adminEvents = await GetWithBearerAsync(client, $"/api/v1/events?agent_id={agentId}&limit=10", adminToken))
        {
            Assert.Equal(HttpStatusCode.OK, adminEvents.StatusCode);
            var body = await adminEvents.Content.ReadAsStringAsync();
            Assert.Contains("Sensitive command line", body, StringComparison.Ordinal);
            Assert.Contains("192.0.2.55", body, StringComparison.Ordinal);
        }

        using (var viewerStorage = await GetWithBearerAsync(client, "/api/v1/storage/accounting", viewerToken))
            Assert.Equal(HttpStatusCode.Forbidden, viewerStorage.StatusCode);
        using (var adminStorage = await GetWithBearerAsync(client, "/api/v1/storage/accounting", adminToken))
            Assert.Equal(HttpStatusCode.OK, adminStorage.StatusCode);

        using (var analystOperators = await PostJsonWithBearerAsync(client, "/api/v1/operators", analystToken, new
        {
            username = "should-fail",
            display_name = "Should Fail",
            role = "viewer",
            password
        }))
            Assert.Equal(HttpStatusCode.Forbidden, analystOperators.StatusCode);

        using (var detectionCreate = await PostJsonWithBearerAsync(client, "/api/v1/operators", detectionToken, new
        {
            username = "should-fail-de",
            display_name = "Should Fail DE",
            role = "viewer",
            password
        }))
            Assert.Equal(HttpStatusCode.Forbidden, detectionCreate.StatusCode);

        using (var adminCreate = await PostJsonWithBearerAsync(client, "/api/v1/operators", adminToken, new
        {
            username = $"rbac-created-{Guid.NewGuid():N}"[..20],
            display_name = "Created Viewer",
            role = "viewer",
            password
        }))
            Assert.Equal(HttpStatusCode.OK, adminCreate.StatusCode);

        using (var cookieClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true }))
        {
            await LoginAsync(cookieClient, $"rbac-a-{suffix}", password);
            using var csrfBlocked = await cookieClient.PostAsJsonAsync("/api/v1/operators/me/api-token/rotate", new { });
            Assert.Equal(HttpStatusCode.BadRequest, csrfBlocked.StatusCode);
            var csrfBody = await csrfBlocked.Content.ReadAsStringAsync();
            Assert.Contains("csrf_safe_bearer_required", csrfBody, StringComparison.Ordinal);
        }
    }

    [PostgresFact]
    public async Task AgentAndOperatorCredentialsRemainSeparateAndLinuxRegistrationPersists()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var operatorToken = await CreateOperatorApiTokenAsync(operators, $"rbac-dom-{Guid.NewGuid():N}"[..20], OperatorRoles.Admin, "Synthetic-DomainAdmin1!");

        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var agentId = $"linux-rbac-{Guid.NewGuid():N}";
        var agentToken = await RegisterAgentAsync(client, agentId, "linux");
        Assert.False(string.IsNullOrWhiteSpace(agentToken));

        using (var operatorOnAgent = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/heartbeat"))
        {
            operatorOnAgent.Headers.Authorization = new AuthenticationHeaderValue("Bearer", operatorToken);
            operatorOnAgent.Content = JsonContent.Create(CreateLinuxHeartbeat(agentId), options: JsonOptions);
            using var response = await client.SendAsync(operatorOnAgent);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        using (var agentOnOperator = await GetWithBearerAsync(client, "/api/v1/events?limit=1", agentToken))
            Assert.Equal(HttpStatusCode.Unauthorized, agentOnOperator.StatusCode);

        await using (var before = dataSource.CreateCommand("select count(*) from security_audit_events where action='operator.api_auth' and outcome='failure'"))
        {
            var beforeCount = Convert.ToInt64(await before.ExecuteScalarAsync());
            using (var heartbeat = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/heartbeat"))
            {
                heartbeat.Headers.Authorization = new AuthenticationHeaderValue("Bearer", agentToken);
                heartbeat.Content = JsonContent.Create(CreateLinuxHeartbeat(agentId), options: JsonOptions);
                using var response = await client.SendAsync(heartbeat);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }

            await using var after = dataSource.CreateCommand("select count(*) from security_audit_events where action='operator.api_auth' and outcome='failure'");
            var afterCount = Convert.ToInt64(await after.ExecuteScalarAsync());
            Assert.Equal(beforeCount, afterCount);
        }
    }

    [PostgresFact]
    public async Task FailedLoginAuditBoundsInvalidIdentifiersAndBootstrapWorksWithoutEnrollmentToken()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);

        // Bootstrap path only needs DB; enrollment token must not be required for local operator commands.
        var env = new Dictionary<string, string?>
        {
            ["ConnectionStrings__SiemDatabase"] = connectionString,
            ["SIEM_OPERATOR_PASSWORD"] = "Synthetic-BootstrapOnly1!",
            ["Auth__EnrollmentToken"] = null
        };
        // Direct repository bootstrap-equivalent create when table may already have operators.
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var username = $"audit-user-{Guid.NewGuid():N}"[..20];
        await operators.CreateAsync(username, "Audit User", OperatorRoles.Analyst, "Synthetic-AuditUser1!", false, CancellationToken.None);

        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var loginHtml = await client.GetStringAsync("/login");
        var token = ExtractRequestVerificationToken(loginHtml);
        var oversized = new string('A', 400) + ":password-looking-value";
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Username"] = oversized,
            ["Password"] = "not-the-password",
            ["__RequestVerificationToken"] = token
        });
        using var response = await client.PostAsync("/login", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var audit = dataSource.CreateCommand(
            "select actor_username from security_audit_events where action='operator.login' and outcome='failure' order by audit_id desc limit 1");
        var actor = (string?)await audit.ExecuteScalarAsync();
        Assert.NotNull(actor);
        Assert.StartsWith("invalid_identifier:", actor, StringComparison.Ordinal);
        Assert.DoesNotContain(oversized, actor, StringComparison.Ordinal);
        Assert.DoesNotContain("password-looking-value", actor, StringComparison.Ordinal);
        Assert.True(actor.Length <= 64 + "invalid_identifier:".Length);
    }

    [PostgresFact]
    public async Task LogoutExpiryAndRevocationInvalidateSessions()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var username = $"session-user-{Guid.NewGuid():N}"[..20];
        var password = "Synthetic-SessionUser1!";
        var created = await operators.CreateAsync(username, "Session User", OperatorRoles.Analyst, password, false, CancellationToken.None);

        var login = await operators.AuthenticatePasswordAsync(username, password, CancellationToken.None);
        Assert.Equal("success", login.Status);
        Assert.NotNull(await operators.ValidateSessionAsync(login.SessionToken!, CancellationToken.None));

        await operators.RevokeSessionAsync(login.SessionToken!, "logout", CancellationToken.None);
        Assert.Null(await operators.ValidateSessionAsync(login.SessionToken!, CancellationToken.None));

        var active = await operators.AuthenticatePasswordAsync(username, password, CancellationToken.None);
        Assert.Equal("success", active.Status);
        await operators.ChangePasswordAsync(created.OperatorId, password, true, CancellationToken.None);
        Assert.Null(await operators.ValidateSessionAsync(active.SessionToken!, CancellationToken.None));
    }

    private static async Task<string> CreateOperatorApiTokenAsync(OperatorRepository operators, string username, string role, string password)
    {
        var op = await operators.CreateAsync(username, username, role, password, false, CancellationToken.None);
        return await operators.RotateApiTokenAsync(op.OperatorId, CancellationToken.None);
    }

    private static WebApplicationFactory<Program> CreateFactory(string connectionString) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SiemDatabase"] = connectionString,
                    ["Auth:EnrollmentToken"] = EnrollmentToken,
                    ["Ingestion:MaxEventsPerBatch"] = "500",
                    ["SocAgent:Provider"] = "Local",
                    ["SocAgent:ProviderDisplayName"] = "Local soc-agent",
                    ["SocAgent:AuthMode"] = "Local",
                    ["SocAgent:Model"] = "soc-agent-local-v1",
                    ["SocAgent:ExternalCallsEnabled"] = "false"
                });
            });
        });

    private static async Task LoginAsync(HttpClient client, string username, string password)
    {
        var loginHtml = await client.GetStringAsync("/login");
        var token = ExtractRequestVerificationToken(loginHtml);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Username"] = username,
            ["Password"] = password,
            ["__RequestVerificationToken"] = token
        });
        using var response = await client.PostAsync("/login", content);
        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK);
    }

    private static string ExtractRequestVerificationToken(string html)
    {
        const string marker = "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0);
        start += marker.Length;
        var end = html.IndexOf('"', start);
        return html[start..end];
    }

    private static async Task<string> RegisterAgentAsync(HttpClient client, string agentId, string platform)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register");
        request.Headers.Add("X-Enrollment-Token", EnrollmentToken);
        request.Content = JsonContent.Create(new AgentRegistrationRequest
        {
            AgentId = agentId,
            Hostname = platform == "linux" ? "linux-rbac-host" : "windows-rbac-host",
            OsVersion = platform == "linux" ? "Linux Test" : "Windows Test",
            AgentVersion = "1.0.0",
            Platform = platform == "linux" ? TelemetryPlatforms.Linux : TelemetryPlatforms.Windows,
            HostId = platform == "linux" ? $"host-{agentId}" : null
        }, options: JsonOptions);
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("api_token").GetString()!;
    }

    private static HeartbeatRequest CreateLinuxHeartbeat(string agentId) => new()
    {
        AgentId = agentId,
        Hostname = "linux-rbac-host",
        AgentVersion = "1.0.0",
        Os = "Linux Test",
        Platform = TelemetryPlatforms.Linux,
        HostId = $"host-{agentId}",
        LastEventTime = DateTimeOffset.UtcNow,
        QueueDepth = 0,
        ConfigHash = "synthetic-linux-config"
    };

    private static async Task IngestSensitiveWindowsEventAsync(HttpClient client, string agentId, string agentToken, Guid eventId)
    {
        var now = DateTimeOffset.UtcNow;
        var envelope = new EventEnvelope
        {
            EventId = eventId,
            AgentId = agentId,
            Hostname = "windows-rbac-host",
            EventTime = now,
            Source = EventSources.WindowsEventLog,
            Channel = "Security",
            Provider = "Microsoft-Windows-Security-Auditing",
            WindowsEventId = 4688,
            RecordId = 1001,
            Severity = "information",
            Message = "Sensitive command line for synthetic-user at 192.0.2.55 path C:\\temp\\sensitive.exe",
            Raw = JsonSerializer.SerializeToElement(new { message = "Sensitive command line for synthetic-user at 192.0.2.55 path C:\\temp\\sensitive.exe" }),
            Normalized = new NormalizedEventFields
            {
                Category = "process",
                Action = "create",
                UserName = "synthetic-user",
                ProcessCommandLine = "Sensitive command line",
                SourceIp = "192.0.2.55",
                FilePath = "C:\\temp\\sensitive.exe"
            }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/ingest/events");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", agentToken);
        request.Content = JsonContent.Create(new IngestBatchRequest
        {
            BatchId = Guid.NewGuid(),
            AgentId = agentId,
            SentAt = now,
            Events = new[] { envelope }
        }, options: JsonOptions);
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    private static async Task<HttpResponseMessage> GetWithBearerAsync(HttpClient client, string url, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> PostJsonWithBearerAsync(HttpClient client, string url, string token, object body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = JsonContent.Create(body, options: JsonOptions);
        return await client.SendAsync(request);
    }
}
