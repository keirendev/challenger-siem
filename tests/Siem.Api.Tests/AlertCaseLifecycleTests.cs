using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
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
public sealed class AlertCaseLifecycleTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "synthetic-alert-case-enrollment-token";

    [Fact]
    public void AlertAndCaseValidatorsBoundLifecycleInputs()
    {
        Assert.Equal("investigating", AlertRepository.NormalizeAlertStatus("Investigating"));
        Assert.Throws<ArgumentException>(() => AlertRepository.NormalizeAlertStatus("deleted"));
        Assert.Equal("false_positive", AlertRepository.NormalizeDisposition("FALSE_POSITIVE", required: true));
        Assert.Throws<ArgumentException>(() => AlertRepository.BoundRequired("short", 8, 100, "reason"));
        Assert.Throws<ArgumentException>(() => AlertRepository.ValidateIdempotency(new string('x', 129)));
        Assert.Equal("urgent", CaseRepository.NormalizePriority("Urgent"));
        Assert.Throws<ArgumentException>(() => CaseRepository.NormalizeStatus("closed", allowClosed: false));
    }

    [PostgresFact]
    public async Task AlertAndCaseLifecycleIsConcurrentIdempotentAndEvidenceStateExplicit()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var (agentId, alertId, retainedEventId, removedEventId, missingEventId) = await SeedAlertWithEvidenceAsync(dataSource);
        var alerts = new AlertRepository(dataSource);
        var cases = new CaseRepository(dataSource);

        var loaded = await alerts.GetAlertAsync(alertId, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(1, loaded!.Version);
        Assert.Contains(loaded.Evidence, item => item.EventId == retainedEventId && item.TelemetryRetentionState == "telemetry_retained");
        Assert.Contains(loaded.Evidence, item => item.EventId == removedEventId && item.TelemetryRetentionState == "telemetry_removed_by_retention");
        Assert.Contains(loaded.Evidence, item => item.EventId == missingEventId && item.TelemetryRetentionState == "underlying_telemetry_missing");

        var acknowledged = await alerts.AcknowledgeAsync(alertId, new AlertMutationRequest { ExpectedVersion = loaded.Version, IdempotencyKey = "ack-key-0001" }, "synthetic-analyst", CancellationToken.None);
        Assert.NotNull(acknowledged);
        Assert.Equal("acknowledged", acknowledged!.Status);
        Assert.Equal(2, acknowledged.Version);

        var stale = await alerts.CloseAsync(alertId, new AlertMutationRequest { ExpectedVersion = 1, Disposition = "false_positive", Summary = "Synthetic stale close attempt." }, "synthetic-analyst", CancellationToken.None);
        Assert.Null(stale);

        var idempotent = await alerts.AcknowledgeAsync(alertId, new AlertMutationRequest { ExpectedVersion = loaded.Version, IdempotencyKey = "ack-key-0001" }, "synthetic-analyst", CancellationToken.None);
        Assert.Equal(acknowledged.Version, idempotent!.Version);

        var created = await cases.CreateAsync(new CaseCreateRequest { Title = "Synthetic alert lifecycle case", Owner = "synthetic-analyst", Severity = "high", Priority = "urgent", AlertIds = new[] { alertId }, IdempotencyKey = "case-create-0001" }, "synthetic-analyst", CancellationToken.None);
        Assert.Single(created.Alerts);
        await cases.LinkEvidenceAsync(created.CaseId, new CaseEvidenceRequest { AlertId = alertId, AgentId = agentId, EventId = retainedEventId, IdempotencyKey = "case-ev-retained" }, "synthetic-analyst", CancellationToken.None);
        await cases.LinkEvidenceAsync(created.CaseId, new CaseEvidenceRequest { AlertId = alertId, AgentId = agentId, EventId = removedEventId, IdempotencyKey = "case-ev-removed" }, "synthetic-analyst", CancellationToken.None);
        var withMissing = await cases.LinkEvidenceAsync(created.CaseId, new CaseEvidenceRequest { AlertId = alertId, AgentId = agentId, EventId = missingEventId, Summary = "Synthetic missing telemetry identity.", IdempotencyKey = "case-ev-missing" }, "synthetic-analyst", CancellationToken.None);
        Assert.NotNull(withMissing);
        Assert.Contains(withMissing!.Evidence, item => item.EventId == retainedEventId && item.TelemetryRetentionState == "telemetry_retained");
        Assert.Contains(withMissing.Evidence, item => item.EventId == removedEventId && item.TelemetryRetentionState == "telemetry_removed_by_retention");
        Assert.Contains(withMissing.Evidence, item => item.EventId == missingEventId && item.TelemetryRetentionState == "underlying_telemetry_missing");

        var closed = await cases.CloseAsync(withMissing.CaseId, new CaseMutationRequest { ExpectedVersion = withMissing.Version, Disposition = "false_positive", ClosureSummary = "Synthetic signal generated during approved test.", CoverageGapAcknowledged = true, Confirm = true, IdempotencyKey = "case-close-0001" }, "synthetic-analyst", CancellationToken.None);
        Assert.NotNull(closed);
        Assert.Equal("closed", closed!.Status);
        Assert.True(closed.CoverageGapAcknowledged);
        Assert.NotEmpty(closed.Activity);

        var reopened = await cases.ReopenAsync(closed.CaseId, new CaseMutationRequest { ExpectedVersion = closed.Version, IdempotencyKey = "case-reopen-0001" }, "synthetic-analyst", CancellationToken.None);
        Assert.Equal("investigating", reopened!.Status);
    }

    [PostgresFact]
    public async Task RazorSignalToClosureWorkflowCompletesWithSyntheticData()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var (_, alertId, _, _, _) = await SeedAlertWithEvidenceAsync(dataSource);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var username = $"web-case-{Guid.NewGuid():N}"[..20];
        var password = "Synthetic-WebCase1!";
        await operators.CreateAsync(username, username, OperatorRoles.Analyst, password, false, CancellationToken.None);

        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        await LoginAsync(client, username, password);

        var alertHtml = await client.GetStringAsync($"/alerts/detail?alert_id={alertId}");
        var token = ExtractRequestVerificationToken(alertHtml);
        using (var ack = await client.PostAsync("/alerts/detail?handler=Acknowledge", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["AlertId"] = alertId.ToString(), ["ExpectedVersion"] = "1", ["__RequestVerificationToken"] = token
        })))
        {
            Assert.Equal(HttpStatusCode.Redirect, ack.StatusCode);
            Assert.NotNull(ack.Headers.Location);
            var acknowledgementRedirect = new Uri(new Uri("https://siem.invalid"), ack.Headers.Location!);
            var redirectedAlertId = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(acknowledgementRedirect.Query)["alert_id"].FirstOrDefault();
            Assert.True(Guid.TryParse(redirectedAlertId, out var parsedAlertId));
            Assert.Equal(alertId, parsedAlertId);
        }

        var acknowledged = await new AlertRepository(dataSource).GetAlertAsync(alertId, CancellationToken.None);
        Assert.Equal("acknowledged", acknowledged!.Status);

        alertHtml = await client.GetStringAsync($"/alerts/detail?alert_id={alertId}");
        token = ExtractRequestVerificationToken(alertHtml);
        using var createCase = await client.PostAsync($"/alerts/detail?handler=CreateCase&alert_id={alertId}", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["AlertId"] = alertId.ToString(), ["CaseTitle"] = "Synthetic browser lifecycle case", ["CasePriority"] = "normal", ["__RequestVerificationToken"] = token
        }));
        Assert.Equal(HttpStatusCode.Redirect, createCase.StatusCode);
        Assert.NotNull(createCase.Headers.Location);
        var absoluteRedirect = new Uri(new Uri("https://siem.invalid"), createCase.Headers.Location!);
        var caseIdText = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(absoluteRedirect.Query)["case_id"].FirstOrDefault();
        Assert.True(Guid.TryParse(caseIdText, out var caseId));

        var detail = await new CaseRepository(dataSource).GetAsync(caseId, CancellationToken.None);
        Assert.NotNull(detail);
        var caseHtml = await client.GetStringAsync($"/cases/detail?case_id={caseId}");
        token = ExtractRequestVerificationToken(caseHtml);
        using (var close = await client.PostAsync($"/cases/detail?handler=Close&case_id={caseId}", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["ExpectedVersion"] = detail!.Version.ToString(),
            ["Disposition"] = "false_positive",
            ["ClosureSummary"] = "Synthetic browser lifecycle closure.",
            ["CoverageGapAcknowledged"] = "true",
            ["ConfirmClose"] = "true",
            ["__RequestVerificationToken"] = token
        })))
            Assert.Equal(HttpStatusCode.Redirect, close.StatusCode);

        var closed = await new CaseRepository(dataSource).GetAsync(caseId, CancellationToken.None);
        Assert.Equal("closed", closed!.Status);
        Assert.Equal("false_positive", closed.Disposition);
    }

    [PostgresFact]
    public async Task AlertCaseApisEnforceRbacBearerCsrfAndAudit()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var (_, alertId, _, _, _) = await SeedAlertWithEvidenceAsync(dataSource);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var viewerToken = await CreateOperatorApiTokenAsync(operators, $"case-v-{suffix}", OperatorRoles.Viewer);
        var analystToken = await CreateOperatorApiTokenAsync(operators, $"case-a-{suffix}", OperatorRoles.Analyst);

        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var viewerDenied = await PostJsonWithBearerAsync(client, $"/api/v1/alerts/{alertId}/acknowledge", viewerToken, new { expected_version = 1, idempotency_key = "viewer-denied-1" }))
            Assert.Equal(HttpStatusCode.Forbidden, viewerDenied.StatusCode);

        using (var unauthenticatedClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false }))
        {
            using var unauthenticated = await unauthenticatedClient.PostAsJsonAsync($"/api/v1/alerts/{alertId}/acknowledge", new { expected_version = 1, idempotency_key = "unauthenticated-1" });
            Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        }

        using (var cookieClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true }))
        {
            await LoginAsync(cookieClient, $"case-a-{suffix}", "Synthetic-CaseUser1!");
            using var csrfBlocked = await cookieClient.PostAsJsonAsync($"/api/v1/alerts/{alertId}/acknowledge", new { expected_version = 1, idempotency_key = "cookie-block-1" });
            Assert.Equal(HttpStatusCode.BadRequest, csrfBlocked.StatusCode);
        }

        using (var ok = await PostJsonWithBearerAsync(client, $"/api/v1/alerts/{alertId}/acknowledge", analystToken, new { expected_version = 1, idempotency_key = "analyst-ack-1" }))
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        using (var stale = await PostJsonWithBearerAsync(client, $"/api/v1/alerts/{alertId}/close", analystToken, new { expected_version = 1, disposition = "false_positive", summary = "Synthetic stale closure." }))
            Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);

        await using var audit = dataSource.CreateCommand("select count(*) from security_audit_events where action in ('alert.acknowledge','alert.close') and target_id=@target;");
        audit.Parameters.AddWithValue("target", alertId.ToString());
        Assert.True(Convert.ToInt64(await audit.ExecuteScalarAsync()) >= 2);
    }

    private static async Task<(string AgentId, Guid AlertId, Guid RetainedEventId, Guid RemovedEventId, Guid MissingEventId)> SeedAlertWithEvidenceAsync(NpgsqlDataSource dataSource)
    {
        var agentId = $"case-agent-{Guid.NewGuid():N}"[..30];
        var alertId = Guid.NewGuid();
        var retainedEventId = Guid.NewGuid();
        var removedEventId = Guid.NewGuid();
        var missingEventId = Guid.NewGuid();
        await using var command = dataSource.CreateCommand("""
            insert into agents(agent_id, hostname, machine_guid, os_version, agent_version, api_token_hash) values(@agent_id, @hostname, @machine_guid, 'Windows 11', '1.4.0', 'synthetic-hash');
            insert into events(event_id, agent_id, hostname, source, channel, provider, windows_event_id, record_id, event_time, severity, message, raw_json, event_category, event_action, normalized_json)
            values(@retained_event_id, @agent_id, @hostname, 'windows_event_log', 'Security', 'Synthetic', 4625, 1, now(), 'information', 'Synthetic retained event', '{}'::jsonb, 'authentication', 'logon', '{}'::jsonb);
            insert into managed_retention_removed_events(agent_id, event_id, event_time, category, removed_at, run_id)
            values(@agent_id, @removed_event_id, now() - interval '40 days', 'retention_test', now(), null) on conflict do nothing;
            insert into alerts(alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary, affected_entities)
            values(@alert_id, 'auth.synthetic.case', 7, 'Synthetic case alert', 'high', 'medium', 'new', @agent_id, @hostname, 'Synthetic alert summary', '[]'::jsonb);
            insert into alert_evidence(alert_id, agent_id, event_id, event_time, channel, windows_event_id, summary)
            values(@alert_id, @agent_id, @retained_event_id, now(), 'Security', 4625, 'retained evidence'),
                  (@alert_id, @agent_id, @removed_event_id, now() - interval '40 days', 'Security', 4625, 'removed evidence'),
                  (@alert_id, @agent_id, @missing_event_id, now() - interval '1 day', 'Security', 4625, 'missing evidence');
            """);
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("hostname", "DEMO-WIN11");
        command.Parameters.AddWithValue("machine_guid", Guid.NewGuid().ToString());
        command.Parameters.AddWithValue("alert_id", alertId);
        command.Parameters.AddWithValue("retained_event_id", retainedEventId);
        command.Parameters.AddWithValue("removed_event_id", removedEventId);
        command.Parameters.AddWithValue("missing_event_id", missingEventId);
        await command.ExecuteNonQueryAsync();
        return (agentId, alertId, retainedEventId, removedEventId, missingEventId);
    }

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
        var index = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(index >= 0, "Antiforgery token was not rendered.");
        var start = index + marker.Length;
        var end = html.IndexOf('"', start);
        Assert.True(end > start);
        return WebUtility.HtmlDecode(html[start..end]);
    }

    private static async Task<string> CreateOperatorApiTokenAsync(OperatorRepository operators, string username, string role)
    {
        var op = await operators.CreateAsync(username, username, role, "Synthetic-CaseUser1!", false, CancellationToken.None);
        return await operators.RotateApiTokenAsync(op.OperatorId, CancellationToken.None);
    }

    private static async Task<HttpResponseMessage> PostJsonWithBearerAsync(HttpClient client, string path, string token, object payload)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web)) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
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
                    ["SocAgent:Provider"] = "Local",
                    ["SocAgent:ProviderDisplayName"] = "Local soc-agent",
                    ["SocAgent:AuthMode"] = "Local",
                    ["SocAgent:Model"] = "soc-agent-local-v1",
                    ["SocAgent:ExternalCallsEnabled"] = "false"
                });
            });
        });
}
