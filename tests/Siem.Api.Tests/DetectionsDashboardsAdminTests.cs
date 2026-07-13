using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Challenger.Siem.Api.Tests;

[Collection(PostgresIntegrationCollection.Name)]
public sealed class DetectionsDashboardsAdminTests(IntegrationTestDatabase database)
{
    private const string EnrollmentToken = "synthetic-206-enrollment-token";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [PostgresFact]
    public async Task DetectionDashboardAndAdminApisEnforceRolesValidationConcurrencyAndAudit()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var password = "Synthetic-Issue206!";
        var viewerToken = await CreateTokenAsync(operators, $"i206-v-{suffix}", OperatorRoles.Viewer, password);
        var analystToken = await CreateTokenAsync(operators, $"i206-a-{suffix}", OperatorRoles.Analyst, password);
        var detectionToken = await CreateTokenAsync(operators, $"i206-d-{suffix}", OperatorRoles.DetectionEngineer, password);
        var adminToken = await CreateTokenAsync(operators, $"i206-m-{suffix}", OperatorRoles.Admin, password);

        using var factory = CreateFactory(connectionString);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using (var viewerRules = await SendWithBearerAsync(client, HttpMethod.Get, "/api/v1/detections/rules", viewerToken))
        {
            Assert.Equal(HttpStatusCode.OK, viewerRules.StatusCode);
            var body = await viewerRules.Content.ReadAsStringAsync();
            Assert.Contains("managed_rules", body, StringComparison.Ordinal);
            Assert.Contains("response_guidance", body, StringComparison.Ordinal);
            Assert.DoesNotContain("api_token", body, StringComparison.OrdinalIgnoreCase);
        }

        var updateBody = new
        {
            expected_version = 1,
            enabled = false,
            lifecycle_state = "disabled",
            validation_status = "synthetic_passed",
            tuning_notes = "Synthetic tuning note for issue 206.",
            suppression_notes = "Suppress only with approved maintenance evidence.",
            confirm_impact = "CONFIRM DETECTION SERVER CHANGE"
        };

        using (var analystDenied = await SendWithBearerAsync(client, HttpMethod.Put, "/api/v1/detections/rules/auth.bruteforce.linux/1/settings", analystToken, updateBody))
            Assert.Equal(HttpStatusCode.Forbidden, analystDenied.StatusCode);

        using (var invalidCode = await SendWithBearerAsync(client, HttpMethod.Put, "/api/v1/detections/rules/auth.bruteforce.linux/1/settings", detectionToken, new
        {
            expected_version = 1,
            enabled = true,
            lifecycle_state = "active",
            validation_status = "synthetic_passed",
            tuning_notes = "eval(alert)",
            suppression_notes = "none",
            confirm_impact = "CONFIRM DETECTION SERVER CHANGE"
        }))
            Assert.Equal(HttpStatusCode.BadRequest, invalidCode.StatusCode);

        using (var validUpdate = await SendWithBearerAsync(client, HttpMethod.Put, "/api/v1/detections/rules/auth.bruteforce.linux/1/settings", detectionToken, updateBody))
        {
            Assert.Equal(HttpStatusCode.OK, validUpdate.StatusCode);
            var body = await validUpdate.Content.ReadAsStringAsync();
            Assert.Contains("Synthetic tuning note", body, StringComparison.Ordinal);
            Assert.Contains("settings_version", body, StringComparison.Ordinal);
        }

        using (var staleUpdate = await SendWithBearerAsync(client, HttpMethod.Put, "/api/v1/detections/rules/auth.bruteforce.linux/1/settings", detectionToken, updateBody))
            Assert.Equal(HttpStatusCode.Conflict, staleUpdate.StatusCode);

        using (var summary = await SendWithBearerAsync(client, HttpMethod.Get, "/api/v1/dashboards/summary?time_range_hours=999", viewerToken))
        {
            Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
            var body = await summary.Content.ReadAsStringAsync();
            Assert.Contains("time_range_hours", body, StringComparison.Ordinal);
            Assert.Contains("event_buckets", body, StringComparison.Ordinal);
            Assert.DoesNotContain("raw", body, StringComparison.OrdinalIgnoreCase);
        }

        using (var viewerLayout = await SendWithBearerAsync(client, HttpMethod.Post, "/api/v1/dashboards/layouts", viewerToken, LayoutBody("private")))
            Assert.Equal(HttpStatusCode.Forbidden, viewerLayout.StatusCode);

        using (var analystShared = await SendWithBearerAsync(client, HttpMethod.Post, "/api/v1/dashboards/layouts", analystToken, LayoutBody("shared")))
            Assert.Equal(HttpStatusCode.BadRequest, analystShared.StatusCode);

        using (var analystPrivate = await SendWithBearerAsync(client, HttpMethod.Post, "/api/v1/dashboards/layouts", analystToken, LayoutBody("private")))
        {
            Assert.Equal(HttpStatusCode.OK, analystPrivate.StatusCode);
            var body = await analystPrivate.Content.ReadAsStringAsync();
            Assert.Contains("Synthetic SOC view", body, StringComparison.Ordinal);
            Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
        }

        using (var viewerAdmin = await SendWithBearerAsync(client, HttpMethod.Get, "/api/v1/admin/overview", viewerToken))
            Assert.Equal(HttpStatusCode.Forbidden, viewerAdmin.StatusCode);

        using (var missingConfirm = await SendWithBearerAsync(client, HttpMethod.Put, "/api/v1/admin/settings", adminToken, new
        {
            key = "retention.target_days",
            value = "14",
            expected_version = 1,
            confirm_impact = ""
        }))
            Assert.Equal(HttpStatusCode.BadRequest, missingConfirm.StatusCode);

        using (var validSetting = await SendWithBearerAsync(client, HttpMethod.Put, "/api/v1/admin/settings", adminToken, new
        {
            key = "retention.target_days",
            value = "14",
            expected_version = 1,
            confirm_impact = "CONFIRM SERVER CONFIG CHANGE"
        }))
        {
            Assert.Equal(HttpStatusCode.OK, validSetting.StatusCode);
            var body = await validSetting.Content.ReadAsStringAsync();
            Assert.Contains("Managed telemetry older than 14", body, StringComparison.Ordinal);
            Assert.DoesNotContain("api_token", body, StringComparison.OrdinalIgnoreCase);
        }

        await using var audit = dataSource.CreateCommand("select count(*) from security_audit_events where action in ('detection_rule.settings.update','dashboard_layout.create','admin.config.update')");
        var count = Convert.ToInt64(await audit.ExecuteScalarAsync());
        Assert.True(count >= 3);
    }

    [PostgresFact]
    public async Task NewRazorPagesRenderAccessibleBoundedStatesAndProtectAdminRoute()
    {
        var connectionString = database.RequireConnectionString();
        await using var dataSource = NpgsqlDataSource.Create(connectionString);
        var operators = new OperatorRepository(dataSource, new OperatorPasswordHasher());
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var password = "Synthetic-Web206!";
        await operators.CreateAsync($"i206-web-a-{suffix}", "Issue 206 Analyst", OperatorRoles.Analyst, password, false, CancellationToken.None);
        await operators.CreateAsync($"i206-web-m-{suffix}", "Issue 206 Admin", OperatorRoles.Admin, password, false, CancellationToken.None);

        using var factory = CreateFactory(connectionString);
        using var analystClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        await LoginAsync(analystClient, $"i206-web-a-{suffix}", password);

        var detections = await analystClient.GetStringAsync("/detections");
        Assert.Contains("Detection rules", detections, StringComparison.Ordinal);
        Assert.Contains("Rule catalog", detections, StringComparison.Ordinal);
        Assert.Contains("arbitrary code", detections, StringComparison.OrdinalIgnoreCase);

        var dashboards = await analystClient.GetStringAsync("/dashboards");
        Assert.Contains("Event volume by hour", dashboards, StringComparison.Ordinal);
        Assert.Contains("<meter", dashboards, StringComparison.Ordinal);
        Assert.Contains("Event count per UTC hour", dashboards, StringComparison.Ordinal);
        Assert.Contains("Saved layouts", dashboards, StringComparison.Ordinal);

        using var deniedAdmin = await analystClient.GetAsync("/administration");
        Assert.Equal(HttpStatusCode.Redirect, deniedAdmin.StatusCode);
        Assert.Contains("/forbidden", deniedAdmin.Headers.Location?.OriginalString ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        using var adminClient = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        await LoginAsync(adminClient, $"i206-web-m-{suffix}", password);
        var adminPage = await adminClient.GetStringAsync("/administration");
        Assert.Contains("Effective retention and capacity settings", adminPage, StringComparison.Ordinal);
        Assert.Contains("Security audit history", adminPage, StringComparison.Ordinal);
        Assert.DoesNotContain("api_token", adminPage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password_hash", adminPage, StringComparison.OrdinalIgnoreCase);
    }

    private static object LayoutBody(string visibility) => new
    {
        name = "Synthetic SOC view",
        visibility,
        time_range_hours = 24,
        refresh_minutes = 15,
        layout = new { widgets = new[] { "event_volume", "source_health" }, density = "comfortable" }
    };

    private static async Task<string> CreateTokenAsync(OperatorRepository operators, string username, string role, string password)
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
                    ["SocAgent:Provider"] = "Local",
                    ["SocAgent:ExternalCallsEnabled"] = "false"
                });
            });
        });

    private static async Task<HttpResponseMessage> SendWithBearerAsync(HttpClient client, HttpMethod method, string url, string token, object? body = null)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        return await client.SendAsync(request);
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
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0);
        start += marker.Length;
        var end = html.IndexOf('"', start);
        return html[start..end];
    }
}
