using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;
using Npgsql;
using Xunit;
using Xunit.Abstractions;

namespace Challenger.Siem.ReleaseGates;

public sealed class ReleaseGateSuite(ITestOutputHelper output)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = false };
    private static readonly object ReportLock = new();

    [Fact]
    public async Task BrowserAuthenticationAuthorizationAndNavigationAreReleaseReady()
    {
        var config = GateConfig.Load(output);
        if (!config.Enabled) return;

        await using var browser = await LaunchBrowserAsync(config);
        await using var anonymous = await NewContextAsync(browser, config);
        var page = await anonymous.NewPageAsync();

        var response = await page.GotoAsync(config.Url("/events"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        Assert.NotNull(response);
        Assert.Contains("/login", page.Url, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Operator login", await page.Locator("body").InnerTextAsync());

        await page.GetByLabel("Username").FillAsync(config.AdminUser);
        await page.GetByLabel("Password").FillAsync("Synthetic-Wrong1!");
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign in" }).ClickAsync();
        await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        var failedBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains("Login failed", failedBody);
        Assert.DoesNotContain("Synthetic-Wrong1!", await page.ContentAsync(), StringComparison.Ordinal);
        Record(config, "auth.login_failure", "passed", details: "invalid password rejected without echoing secret input");

        foreach (var role in new[] { "viewer", "analyst", "detection-engineer", "admin" })
        {
            await using var context = await NewContextAsync(browser, config);
            var rolePage = await LoginAsync(context, config, role);
            await ExpectHeadingAsync(rolePage, "Overview");
            var body = await rolePage.Locator("body").InnerTextAsync();
            Assert.Contains(role, body, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Overview", body);
            Assert.Contains("Search", body);
            Assert.Contains("Assets", body);
            Assert.Contains("Alerts", body);
            Assert.Contains("Detections", body);
            Assert.Contains("Dashboards", body);

            if (role == "viewer")
            {
                Assert.DoesNotContain("Cases", body, StringComparison.Ordinal);
                Assert.DoesNotContain("Administration", body, StringComparison.Ordinal);
                Assert.DoesNotContain("soc-agent", body, StringComparison.OrdinalIgnoreCase);
                await rolePage.GotoAsync(config.Url("/cases"), new() { WaitUntil = WaitUntilState.NetworkIdle });
                Assert.True(rolePage.Url.Contains("/forbidden", StringComparison.OrdinalIgnoreCase) || (await rolePage.Locator("body").InnerTextAsync()).Contains("Forbidden", StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                Assert.Contains("Cases", body, StringComparison.Ordinal);
                Assert.Contains("soc-agent", body, StringComparison.OrdinalIgnoreCase);
            }

            await rolePage.GotoAsync(config.Url("/administration"), new() { WaitUntil = WaitUntilState.NetworkIdle });
            var adminBody = await rolePage.Locator("body").InnerTextAsync();
            if (role == "admin")
            {
                Assert.Contains("Administration", adminBody);
                Assert.Contains("Operators", adminBody, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                Assert.True(rolePage.Url.Contains("/forbidden", StringComparison.OrdinalIgnoreCase) || adminBody.Contains("Forbidden", StringComparison.OrdinalIgnoreCase));
            }

            await rolePage.GotoAsync(config.Url("/detections"), new() { WaitUntil = WaitUntilState.NetworkIdle });
            var detectionBody = await rolePage.Locator("body").InnerTextAsync();
            if (role is "detection-engineer" or "admin")
            {
                Assert.Contains("CONFIRM DETECTION SERVER CHANGE", detectionBody, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                Assert.DoesNotContain("Save rule metadata", detectionBody, StringComparison.OrdinalIgnoreCase);
            }

            await rolePage.GetByRole(AriaRole.Button, new() { Name = "Logout" }).ClickAsync();
            await rolePage.WaitForLoadStateAsync(LoadState.NetworkIdle);
            await rolePage.GotoAsync(config.Url("/"), new() { WaitUntil = WaitUntilState.NetworkIdle });
            Assert.Contains("/login", rolePage.Url, StringComparison.OrdinalIgnoreCase);
            Record(config, $"auth.role_matrix.{role}", "passed", details: "navigation, forbidden state, logout/session revocation verified");
        }
    }

    [Fact]
    public async Task BrowserWorkflowsExerciseSearchAssetsAlertsCasesDetectionsDashboardsAndAdmin()
    {
        var config = GateConfig.Load(output);
        if (!config.Enabled) return;

        await using var browser = await LaunchBrowserAsync(config);
        await using var context = await NewContextAsync(browser, config);
        var page = await LoginAsync(context, config, "admin");

        await page.GotoAsync(config.Url($"/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&keyword={WebUtility.UrlEncode(config.RunId)}&limit=25&bucket_seconds=3600"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        await ExpectHeadingAsync(page, "Event search");
        var searchBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains(config.AgentId, searchBody);
        Assert.Contains("Timeline buckets", searchBody);
        Assert.Contains("Saved searches", searchBody);
        Assert.Contains("Open", searchBody);
        Assert.Contains("Asset", searchBody);
        Assert.DoesNotContain("syntheticSecret", await page.ContentAsync(), StringComparison.OrdinalIgnoreCase);
        Assert.True(await page.Locator("table >> text=Open").CountAsync() > 0);
        Assert.True(await page.Locator("table tbody tr").CountAsync() <= 500);

        await page.GetByLabel("Name", new() { Exact = true }).FillAsync($"Synthetic saved search {config.RunId}");
        await page.GetByLabel("Description").FillAsync("Synthetic release-gate saved search metadata only.");
        await page.GetByRole(AriaRole.Button, new() { Name = "Save current filters" }).ClickAsync();
        await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.Contains("Synthetic saved search", await page.Locator("body").InnerTextAsync());

        await page.GotoAsync(config.Url($"/agents/detail?agent_id={WebUtility.UrlEncode(config.AgentId)}"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        await ExpectHeadingContainsAsync(page, "Host coverage");
        var assetBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains("healthy", assetBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("degraded", assetBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("permission", assetBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("queue", assetBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("capacity", assetBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("gap/drop", assetBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("2/1", assetBody, StringComparison.OrdinalIgnoreCase);

        await page.GotoAsync(config.Url("/alerts"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        await ExpectHeadingAsync(page, "Alerts");
        Assert.Contains("Synthetic release gate alert", await page.Locator("body").InnerTextAsync());
        await page.GotoAsync(config.Url($"/alerts/detail?alert_id={config.AlertId}"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        Assert.Contains("Evidence", await page.Locator("body").InnerTextAsync());

        await page.GotoAsync(config.Url("/cases"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        await ExpectHeadingAsync(page, "Cases");
        Assert.Contains("Synthetic release gate case", await page.Locator("body").InnerTextAsync());
        await page.GotoAsync(config.Url($"/cases/detail?case_id={config.CaseId}"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        var caseBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains("Closure", caseBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Coverage", caseBody, StringComparison.OrdinalIgnoreCase);

        await page.GotoAsync(config.Url("/detections"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        var detectionsBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains("Detections", detectionsBody);
        Assert.Contains("source prerequisites", detectionsBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("tuning", detectionsBody, StringComparison.OrdinalIgnoreCase);

        await page.GotoAsync(config.Url("/dashboards"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        var dashboardsBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains("Dashboards", dashboardsBody);
        Assert.Contains("freshness", dashboardsBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Synthetic release gate layout", dashboardsBody);

        await page.GotoAsync(config.Url("/administration"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        var adminBody = await page.Locator("body").InnerTextAsync();
        Assert.Contains("Administration", adminBody);
        Assert.Contains("Audit", adminBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(config.AdminPassword, adminBody, StringComparison.Ordinal);
        Assert.DoesNotContain(config.AdminToken, adminBody, StringComparison.Ordinal);
        Record(config, "browser.workflows", "passed", details: "real Razor pages covered search/assets/alerts/cases/detections/dashboards/admin with synthetic seeded state");
    }

    [Fact]
    public async Task AccessibilityResponsiveAndKeyboardGatesPassForCorePages()
    {
        var config = GateConfig.Load(output);
        if (!config.Enabled) return;

        await using var browser = await LaunchBrowserAsync(config);
        await using var context = await NewContextAsync(browser, config, reducedMotion: true);
        var page = await LoginAsync(context, config, "analyst");
        var paths = new[]
        {
            "/",
            $"/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=10",
            "/agents",
            $"/agents/detail?agent_id={WebUtility.UrlEncode(config.AgentId)}",
            "/alerts",
            "/cases",
            "/detections",
            "/dashboards",
            "/about"
        };

        foreach (var viewport in new[] { (1440, 1000), (800, 900), (390, 844) })
        {
            await page.SetViewportSizeAsync(viewport.Item1, viewport.Item2);
            foreach (var path in paths)
            {
                var started = Stopwatch.StartNew();
                await page.GotoAsync(config.Url(path), new() { WaitUntil = WaitUntilState.NetworkIdle });
                started.Stop();
                var issues = await PageAccessibilityIssuesAsync(page);
                Assert.True(issues.Count == 0, $"Accessibility issues on {path} at {viewport.Item1}px: {string.Join("; ", issues)}");
                var scrollWidth = await page.EvaluateAsync<int>("() => document.scrollingElement.scrollWidth");
                var innerWidth = await page.EvaluateAsync<int>("() => window.innerWidth");
                Assert.True(scrollWidth <= innerWidth + 24, $"Page {path} has document-level horizontal overflow: {scrollWidth}>{innerWidth}");
                Assert.True(started.ElapsedMilliseconds < config.BrowserLoadBudgetMs, $"Page {path} exceeded browser load budget: {started.ElapsedMilliseconds}ms");
            }
        }

        await page.GotoAsync(config.Url("/events"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        await page.Locator(".skip-link").FocusAsync();
        Assert.True(await page.Locator(".skip-link").EvaluateAsync<bool>("el => getComputedStyle(el).position === 'absolute' && (getComputedStyle(el).outlineStyle !== 'none' || getComputedStyle(el).boxShadow !== 'none')"));
        for (var i = 0; i < 12; i++) await page.Keyboard.PressAsync("Tab");
        var focusVisible = await page.EvaluateAsync<bool>("() => { const el = document.activeElement; if (!el) return false; const s = getComputedStyle(el); return s.outlineStyle !== 'none' || s.boxShadow !== 'none'; }");
        Assert.True(focusVisible, "Keyboard focus indicator must remain visible.");
        Assert.True(await page.EvaluateAsync<bool>("() => matchMedia('(prefers-reduced-motion: reduce)').matches"));
        Record(config, "a11y.responsive.keyboard", "passed", details: "semantic WCAG checks, keyboard focus, reduced motion, and 1440/800/390px reflow passed");
    }

    [Fact]
    public async Task SecurityProtectedFieldAndExportGatesPass()
    {
        var config = GateConfig.Load(output);
        if (!config.Enabled) return;

        using var client = config.CreateHttpClient();
        using (var response = await client.GetAsync("/login"))
        {
            Assert.True(response.IsSuccessStatusCode);
            Assert.Contains("default-src 'self'", Header(response, "Content-Security-Policy"));
            Assert.Contains("nosniff", Header(response, "X-Content-Type-Options"));
            Assert.Contains("same-origin", Header(response, "Referrer-Policy"));
        }

        await using var browser = await LaunchBrowserAsync(config);
        await using var context = await NewContextAsync(browser, config);
        var page = await LoginAsync(context, config, "admin");
        var cookies = await context.CookiesAsync(new[] { config.BaseUrl });
        var sessionCookie = cookies.Single(cookie => cookie.Name == ".ChallengerSiem.Operator");
        Assert.True(sessionCookie.HttpOnly);
        Assert.Equal("Strict", sessionCookie.SameSite.ToString());
        Assert.True(sessionCookie.Expires > DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "session cookie must carry an expiry");
        Assert.True(sessionCookie.Expires <= DateTimeOffset.UtcNow.AddHours(8.1).ToUnixTimeSeconds(), "session expiry must remain bounded to the documented eight-hour absolute lifetime");
        if (config.BaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) Assert.True(sessionCookie.Secure);

        await page.GotoAsync(config.Url("/login?ReturnUrl=https%3A%2F%2Fexample.invalid%2Fsteal"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        Assert.Equal(config.BaseUrl, page.Url.TrimEnd('/'));

        var csrfStatus = await page.EvaluateAsync<int>(
            "async () => (await fetch('/api/v1/alerts/" + config.AlertId + "/acknowledge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ expected_version: 1, idempotency_key: 'cookie-only-blocked' }) })).status");
        Assert.Equal(400, csrfStatus);

        await page.GotoAsync(config.Url($"/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&keyword={WebUtility.UrlEncode(config.RunId)}&limit=50"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        var content = await page.ContentAsync();
        Assert.False(await page.EvaluateAsync<bool>("""
            () => Array.from(document.querySelectorAll('script')).some(script => (script.textContent || '').includes('alert('))
              || Array.from(document.querySelectorAll('*')).some(element => Array.from(element.attributes).some(attribute => attribute.name.toLowerCase().startsWith('on')))
            """), "Seeded XSS markers must remain escaped text and must not create executable script or event-handler attributes.");
        Assert.DoesNotContain("syntheticSecret", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(config.AdminToken, content, StringComparison.Ordinal);
        Assert.DoesNotContain("api_token", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", content, StringComparison.OrdinalIgnoreCase);

        using (var viewer = await SendBearerAsync(client, HttpMethod.Get, $"/api/v1/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=1", config.ViewerToken))
        {
            var text = await viewer.Content.ReadAsStringAsync();
            Assert.True(viewer.IsSuccessStatusCode, text);
            Assert.Contains("\"raw\":{}", text.Replace(" ", string.Empty), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("syntheticSecret", text, StringComparison.OrdinalIgnoreCase);
        }

        using (var admin = await SendBearerAsync(client, HttpMethod.Get, $"/api/v1/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=1", config.AdminToken))
        {
            var text = await admin.Content.ReadAsStringAsync();
            Assert.True(admin.IsSuccessStatusCode, text);
            Assert.Contains("raw", text, StringComparison.OrdinalIgnoreCase);
        }

        using (var missingConfirmExport = await SendBearerAsync(client, HttpMethod.Post, $"/api/v1/events/export?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=100", config.AdminToken, new StringContent(string.Empty)))
        {
            var text = await missingConfirmExport.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.BadRequest, missingConfirmExport.StatusCode);
            Assert.Contains("confirm_export", text, StringComparison.OrdinalIgnoreCase);
        }

        using (var viewerExport = await SendBearerAsync(client, HttpMethod.Post, $"/api/v1/events/export?confirm_export=EXPORT&agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=100", config.ViewerToken, new StringContent(string.Empty)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, viewerExport.StatusCode);
        }

        using (var export = await SendBearerAsync(client, HttpMethod.Post, $"/api/v1/events/export?confirm_export=EXPORT&agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=100", config.AdminToken, new StringContent(string.Empty)))
        {
            var csv = await export.Content.ReadAsStringAsync();
            Assert.True(export.IsSuccessStatusCode, csv);
            Assert.Contains("attachment", string.Join(';', export.Content.Headers.ContentDisposition?.DispositionType, export.Content.Headers.ContentDisposition?.FileNameStar, export.Content.Headers.ContentDisposition?.FileName));
            Assert.DoesNotContain("\r\nContent-", string.Join(';', export.Headers.Select(header => header.Key + string.Join(',', header.Value))), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("'=cmd|", csv, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("\n=cmd|", csv, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("syntheticSecret", csv, StringComparison.OrdinalIgnoreCase);
        }
        Record(config, "security.protected_fields", "passed", details: "CSP/cookie/CSRF/open-redirect/XSS/export guards/redaction checks passed");
    }

    [Fact]
    public async Task PerformanceBudgetsAndBoundedRenderingPass()
    {
        var config = GateConfig.Load(output);
        if (!config.Enabled) return;
        using var client = config.CreateHttpClient();

        var eventSearch = await TimedAsync(async () => await SendBearerAsync(client, HttpMethod.Get, $"/api/v1/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=100&bucket_seconds=3600", config.AdminToken));
        Assert.True(eventSearch.Response.IsSuccessStatusCode, await eventSearch.Response.Content.ReadAsStringAsync());
        Assert.True(eventSearch.ElapsedMs <= config.ApiSearchBudgetMs, $"event search took {eventSearch.ElapsedMs}ms");
        var eventPayload = await eventSearch.Response.Content.ReadAsStringAsync();
        Assert.True(JsonDocument.Parse(eventPayload).RootElement.GetProperty("events").GetArrayLength() <= 100);
        eventSearch.Response.Dispose();

        var timeline = await TimedAsync(async () => await SendBearerAsync(client, HttpMethod.Get, $"/api/v1/events/timeline?agent_id={WebUtility.UrlEncode(config.AgentId)}&bucket_seconds=3600", config.AdminToken));
        Assert.True(timeline.Response.IsSuccessStatusCode, await timeline.Response.Content.ReadAsStringAsync());
        Assert.True(timeline.ElapsedMs <= config.ApiTimelineBudgetMs, $"timeline took {timeline.ElapsedMs}ms");
        timeline.Response.Dispose();

        await using (var dataSource = NpgsqlDataSource.Create(config.DatabaseConnectionString))
        {
            await using var indexCommand = dataSource.CreateCommand("select to_regclass('public.idx_events_agent_id') is not null and to_regclass('public.idx_events_event_time') is not null and to_regclass('public.idx_events_source_time') is not null;");
            Assert.True((bool)(await indexCommand.ExecuteScalarAsync() ?? false), "required event search/timeline indexes must exist");
            await using var countCommand = dataSource.CreateCommand("select count(*) from events where agent_id = $1 and event_time > now() - interval '7 days';");
            countCommand.Parameters.AddWithValue(config.AgentId);
            var dbStarted = Stopwatch.StartNew();
            var count = Convert.ToInt64(await countCommand.ExecuteScalarAsync());
            dbStarted.Stop();
            Assert.True(count > 0, "synthetic performance dataset must contain indexed event rows");
            Assert.True(dbStarted.ElapsedMilliseconds <= config.ApiSearchBudgetMs, $"indexed database count took {dbStarted.ElapsedMilliseconds}ms");
        }

        using (var css = await client.GetAsync("/css/site.css"))
        {
            Assert.True(css.IsSuccessStatusCode);
            var bytes = (await css.Content.ReadAsByteArrayAsync()).Length;
            Assert.True(bytes <= config.CssBudgetBytes, $"site.css size {bytes} exceeded budget {config.CssBudgetBytes}");
        }
        using (var js = await client.GetAsync("/js/design-system.js"))
        {
            Assert.True(js.IsSuccessStatusCode);
            var bytes = (await js.Content.ReadAsByteArrayAsync()).Length;
            Assert.True(bytes <= config.JsBudgetBytes, $"design-system.js size {bytes} exceeded budget {config.JsBudgetBytes}");
        }

        await using var browser = await LaunchBrowserAsync(config);
        await using var context = await NewContextAsync(browser, config);
        var page = await LoginAsync(context, config, "admin");
        var started = Stopwatch.StartNew();
        await page.GotoAsync(config.Url($"/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=100"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        started.Stop();
        Assert.True(started.ElapsedMilliseconds <= config.BrowserLoadBudgetMs, $"browser event page took {started.ElapsedMilliseconds}ms");
        var renderedRows = await page.Locator("section:has(#event-results-title) tbody tr").CountAsync();
        Assert.True(renderedRows <= 100, $"event page rendered unbounded rows: {renderedRows}");

        var cancelled = false;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1));
        try { await SendBearerAsync(client, HttpMethod.Get, $"/api/v1/events?agent_id={WebUtility.UrlEncode(config.AgentId)}&limit=500", config.AdminToken, cancellationToken: cts.Token); }
        catch (OperationCanceledException) { cancelled = true; }
        Assert.True(cancelled, "HTTP client cancellation must be observable by the release gate harness.");
        Record(config, "performance.budgets", "passed", eventSearch.ElapsedMs + timeline.ElapsedMs + started.ElapsedMilliseconds, "API search/timeline, page load, asset-size, cancellation, and row-bound budgets passed");
    }

    private static async Task<(HttpResponseMessage Response, long ElapsedMs)> TimedAsync(Func<Task<HttpResponseMessage>> action)
    {
        var sw = Stopwatch.StartNew();
        var response = await action();
        sw.Stop();
        return (response, sw.ElapsedMilliseconds);
    }

    private static async Task<HttpResponseMessage> SendBearerAsync(HttpClient client, HttpMethod method, string path, string bearer, HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await client.SendAsync(request, cancellationToken);
    }

    private static string Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? string.Join(";", values) : string.Empty;

    private static async Task<IBrowser> LaunchBrowserAsync(GateConfig config)
    {
        var playwright = await Playwright.CreateAsync();
        try
        {
            var options = new BrowserTypeLaunchOptions
            {
                Headless = true,
                Timeout = config.BrowserOperationTimeoutMs
            };
            if (!string.IsNullOrWhiteSpace(config.BrowserExecutablePath))
            {
                options.ExecutablePath = config.BrowserExecutablePath;
            }
            return await playwright.Chromium.LaunchAsync(options);
        }
        catch
        {
            playwright.Dispose();
            throw;
        }
    }

    private static async Task<IBrowserContext> NewContextAsync(IBrowser browser, GateConfig config, bool reducedMotion = false) =>
        await browser.NewContextAsync(new()
        {
            BaseURL = config.BaseUrl,
            IgnoreHTTPSErrors = false,
            ReducedMotion = reducedMotion ? ReducedMotion.Reduce : ReducedMotion.NoPreference,
            ViewportSize = new ViewportSize { Width = 1440, Height = 1000 }
        });

    private static async Task<IPage> LoginAsync(IBrowserContext context, GateConfig config, string role)
    {
        var (username, password) = config.Credentials(role);
        var page = await context.NewPageAsync();
        await page.GotoAsync(config.Url("/login"), new() { WaitUntil = WaitUntilState.NetworkIdle });
        await page.GetByLabel("Username").FillAsync(username);
        await page.GetByLabel("Password").FillAsync(password);
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign in" }).ClickAsync();
        await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.DoesNotContain("/login", page.Url, StringComparison.OrdinalIgnoreCase);
        return page;
    }

    private static async Task ExpectHeadingAsync(IPage page, string heading)
    {
        await Assertions.Expect(page.GetByRole(AriaRole.Heading, new() { Name = heading, Exact = false })).ToBeVisibleAsync();
    }

    private static async Task ExpectHeadingContainsAsync(IPage page, string heading)
    {
        var h1 = await page.Locator("main h1").First.InnerTextAsync();
        Assert.Contains(heading, h1, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<IReadOnlyList<string>> PageAccessibilityIssuesAsync(IPage page)
    {
        var issues = await page.EvaluateAsync<string[]>("""
            () => {
              const issues = [];
              const main = document.querySelector('main#main-content');
              if (!main) issues.push('missing main#main-content landmark');
              if (!document.querySelector('nav[aria-label="Primary"]')) issues.push('missing primary nav label');
              if (!document.querySelector('.skip-link[href="#main-content"]')) issues.push('missing skip link');
              const h1 = Array.from(document.querySelectorAll('main h1'));
              if (h1.length !== 1) issues.push(`expected one h1 in main, found ${h1.length}`);
              const controls = Array.from(document.querySelectorAll('input:not([type="hidden"]), select, textarea'));
              for (const control of controls) {
                const id = control.getAttribute('id');
                const hasLabel = (id && document.querySelector(`label[for="${CSS.escape(id)}"]`)) || control.closest('label') || control.getAttribute('aria-label') || control.getAttribute('aria-labelledby');
                if (!hasLabel) issues.push(`unlabelled control ${control.name || control.id || control.tagName}`);
                const describedBy = control.getAttribute('aria-describedby');
                if (describedBy) {
                  for (const token of describedBy.split(/\s+/).filter(Boolean)) if (!document.getElementById(token)) issues.push(`aria-describedby target missing: ${token}`);
                }
              }
              for (const element of Array.from(document.querySelectorAll('button, a[href]'))) {
                const name = (element.getAttribute('aria-label') || element.textContent || '').trim();
                if (!name) issues.push(`${element.tagName.toLowerCase()} missing accessible name`);
              }
              for (const table of Array.from(document.querySelectorAll('table'))) {
                if (!table.querySelector('caption') && !table.getAttribute('aria-label') && !table.getAttribute('aria-labelledby')) issues.push('table missing caption or label');
                if (!table.querySelector('th')) issues.push('data table missing header cells');
              }
              for (const badge of Array.from(document.querySelectorAll('.badge, .pill'))) {
                if (!(badge.textContent || '').trim()) issues.push('state badge has no text');
              }
              return issues;
            }
            """);
        return issues;
    }

    private static void Record(GateConfig config, string gate, string status, long? elapsedMs = null, string? details = null)
    {
        var entry = JsonSerializer.Serialize(new
        {
            gate,
            status,
            elapsed_ms = elapsedMs,
            details,
            measured_at_utc = DateTimeOffset.UtcNow
        }, JsonOptions);
        lock (ReportLock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(config.ReportPath)!);
            File.AppendAllText(config.ReportPath, entry + Environment.NewLine);
        }
    }

    private sealed class GateConfig
    {
        public bool Enabled { get; private init; }
        public string BaseUrl { get; private init; } = string.Empty;
        public string ArtifactDir { get; private init; } = string.Empty;
        public string ReportPath { get; private init; } = string.Empty;
        public string RunId { get; private init; } = string.Empty;
        public string AgentId { get; private init; } = string.Empty;
        public string AlertId { get; private init; } = string.Empty;
        public string CaseId { get; private init; } = string.Empty;
        public string AdminUser { get; private init; } = string.Empty;
        public string AdminPassword { get; private init; } = string.Empty;
        public string ViewerUser { get; private init; } = string.Empty;
        public string ViewerPassword { get; private init; } = string.Empty;
        public string AnalystUser { get; private init; } = string.Empty;
        public string AnalystPassword { get; private init; } = string.Empty;
        public string DetectionEngineerUser { get; private init; } = string.Empty;
        public string DetectionEngineerPassword { get; private init; } = string.Empty;
        public string AdminToken { get; private init; } = string.Empty;
        public string ViewerToken { get; private init; } = string.Empty;
        public string DatabaseConnectionString { get; private init; } = string.Empty;
        public long ApiSearchBudgetMs { get; private init; }
        public long ApiTimelineBudgetMs { get; private init; }
        public long BrowserLoadBudgetMs { get; private init; }
        public int CssBudgetBytes { get; private init; }
        public int JsBudgetBytes { get; private init; }
        public float BrowserOperationTimeoutMs { get; private init; }
        public string? BrowserExecutablePath { get; private init; }

        public static GateConfig Load(ITestOutputHelper output)
        {
            var enabled = string.Equals(Environment.GetEnvironmentVariable("SIEM_RELEASE_GATE_ENABLED"), "1", StringComparison.Ordinal);
            if (!enabled)
            {
                output.WriteLine("release gates not run: set SIEM_RELEASE_GATE_ENABLED=1 or use ./scripts/release-gates.sh run");
                return new GateConfig { Enabled = false };
            }

            var artifactDir = Required("SIEM_RELEASE_GATE_ARTIFACT_DIR");
            Directory.CreateDirectory(artifactDir);
            var config = new GateConfig
            {
                Enabled = true,
                BaseUrl = Required("SIEM_RELEASE_GATE_BASE_URL").TrimEnd('/'),
                ArtifactDir = artifactDir,
                ReportPath = Environment.GetEnvironmentVariable("SIEM_RELEASE_GATE_REPORT") ?? Path.Combine(artifactDir, "release-gates-report.jsonl"),
                RunId = Required("SIEM_RELEASE_GATE_RUN_ID"),
                AgentId = Required("SIEM_RELEASE_GATE_AGENT_ID"),
                AlertId = Required("SIEM_RELEASE_GATE_ALERT_ID"),
                CaseId = Required("SIEM_RELEASE_GATE_CASE_ID"),
                AdminUser = Required("SIEM_RELEASE_GATE_ADMIN_USERNAME"),
                AdminPassword = Required("SIEM_RELEASE_GATE_ADMIN_PASSWORD"),
                ViewerUser = Required("SIEM_RELEASE_GATE_VIEWER_USERNAME"),
                ViewerPassword = Required("SIEM_RELEASE_GATE_VIEWER_PASSWORD"),
                AnalystUser = Required("SIEM_RELEASE_GATE_ANALYST_USERNAME"),
                AnalystPassword = Required("SIEM_RELEASE_GATE_ANALYST_PASSWORD"),
                DetectionEngineerUser = Required("SIEM_RELEASE_GATE_DETECTION_ENGINEER_USERNAME"),
                DetectionEngineerPassword = Required("SIEM_RELEASE_GATE_DETECTION_ENGINEER_PASSWORD"),
                AdminToken = Required("SIEM_RELEASE_GATE_ADMIN_API_TOKEN"),
                ViewerToken = Required("SIEM_RELEASE_GATE_VIEWER_API_TOKEN"),
                DatabaseConnectionString = Required("ConnectionStrings__SiemDatabase"),
                ApiSearchBudgetMs = Long("SIEM_RELEASE_GATE_API_SEARCH_BUDGET_MS", 3_000),
                ApiTimelineBudgetMs = Long("SIEM_RELEASE_GATE_API_TIMELINE_BUDGET_MS", 3_000),
                BrowserLoadBudgetMs = Long("SIEM_RELEASE_GATE_BROWSER_LOAD_BUDGET_MS", 8_000),
                CssBudgetBytes = (int)Long("SIEM_RELEASE_GATE_CSS_BUDGET_BYTES", 300_000),
                JsBudgetBytes = (int)Long("SIEM_RELEASE_GATE_JS_BUDGET_BYTES", 120_000),
                BrowserOperationTimeoutMs = Long("SIEM_RELEASE_GATE_BROWSER_OPERATION_TIMEOUT_MS", 30_000),
                BrowserExecutablePath = Environment.GetEnvironmentVariable("SIEM_RELEASE_GATE_BROWSER_EXECUTABLE_PATH")
            };
            output.WriteLine($"release gate artifacts: {config.ArtifactDir}");
            output.WriteLine($"release gate report: {config.ReportPath}");
            if (!string.IsNullOrWhiteSpace(config.BrowserExecutablePath)) output.WriteLine("release gate browser executable: configured by SIEM_RELEASE_GATE_BROWSER_EXECUTABLE_PATH");
            return config;
        }

        public string Url(string path) => path.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? path : BaseUrl + (path.StartsWith('/') ? path : "/" + path);

        public HttpClient CreateHttpClient() => new() { BaseAddress = new Uri(BaseUrl), Timeout = TimeSpan.FromSeconds(30) };

        public (string Username, string Password) Credentials(string role) => role switch
        {
            "viewer" => (ViewerUser, ViewerPassword),
            "analyst" => (AnalystUser, AnalystPassword),
            "detection-engineer" => (DetectionEngineerUser, DetectionEngineerPassword),
            "admin" => (AdminUser, AdminPassword),
            _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Unknown role")
        };

        private static string Required(string name) =>
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))
                ? throw new InvalidOperationException($"Required release-gate environment variable is missing: {name}")
                : Environment.GetEnvironmentVariable(name)!;

        private static long Long(string name, long fallback) =>
            long.TryParse(Environment.GetEnvironmentVariable(name), out var value) && value > 0 ? value : fallback;
    }
}
