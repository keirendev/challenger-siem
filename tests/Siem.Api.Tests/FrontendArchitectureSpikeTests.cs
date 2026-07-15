using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class FrontendArchitectureSpikeTests
{
    [Fact]
    public void SelectedRazorPathKeepsPaginationCancellationAndAuthorizationInServerCode()
    {
        var root = RepositoryRoot();
        var indexModel = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Index.cshtml.cs"));
        var eventRepository = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Database/EventRepository.cs"));
        var program = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Program.cs"));

        Assert.Contains("OnGetAsync(CancellationToken cancellationToken)", indexModel, StringComparison.Ordinal);
        Assert.Contains("Limit = NormalizedLimit", indexModel, StringComparison.Ordinal);
        Assert.Contains("SearchEventsPageForOperatorAsync", indexModel, StringComparison.Ordinal);
        Assert.Contains("PageInfo", indexModel, StringComparison.Ordinal);

        Assert.Contains("Math.Clamp(query.Limit, 1, maxLimit)", eventRepository, StringComparison.Ordinal);
        Assert.Contains("limit @limit offset @offset", eventRepository, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("OperatorAuthorization.HasPermission(role, OperatorPermission.ReviewSensitive)", eventRepository, StringComparison.Ordinal);
        Assert.Contains("EventFieldPolicy.Apply(item, role)", eventRepository, StringComparison.Ordinal);

        Assert.Contains("EventSearchQuery.FromQuery(context.Request.Query)", program, StringComparison.Ordinal);
        Assert.Contains("SearchEventsPageForOperatorAsync(query, OperatorAuthorization.Role(context.User)!", program, StringComparison.Ordinal);
        Assert.Contains("csrf_safe_bearer_required", program, StringComparison.Ordinal);
    }

    [Fact]
    public void RazorMarkupKeepsAccessibilityResponsiveAndLifecycleSurfacesForSearchWorkflow()
    {
        var root = RepositoryRoot();
        var layout = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Shared/_Layout.cshtml"));
        var indexModel = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Index.cshtml.cs"));
        var events = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Index.cshtml"));
        var detail = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Detail.cshtml"));
        var css = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/css/site.css"));

        Assert.Contains("Skip to main content", layout, StringComparison.Ordinal);
        Assert.Contains("<main id=\"main-content\"", layout, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Primary\"", layout, StringComparison.Ordinal);
        Assert.Contains("Global search", layout, StringComparison.Ordinal);
        Assert.Contains("Overview", layout, StringComparison.Ordinal);
        Assert.Contains("Search", layout, StringComparison.Ordinal);
        Assert.Contains("Assets", layout, StringComparison.Ordinal);
        Assert.Contains("Alerts", layout, StringComparison.Ordinal);
        Assert.Contains("Cases", layout, StringComparison.Ordinal);
        Assert.Contains("Detections", layout, StringComparison.Ordinal);
        Assert.Contains("Dashboards", layout, StringComparison.Ordinal);
        Assert.Contains("Health", layout, StringComparison.Ordinal);
        Assert.Contains("Administration", layout, StringComparison.Ordinal);
        Assert.Contains("asp-page=\"/Logout\"", layout, StringComparison.Ordinal);

        Assert.Contains("aria-label=\"Event search filters\"", events, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Active event filters\"", events, StringComparison.Ordinal);
        Assert.Contains("OnPostGlobalSearchAsync", indexModel, StringComparison.Ordinal);
        Assert.Contains("Search validation failed", events, StringComparison.Ordinal);
        Assert.Contains("class=\"empty\"", events, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Event result pages\"", events, StringComparison.Ordinal);
        Assert.Contains("table-scroll", events, StringComparison.Ordinal);
        Assert.Contains("raw JSON only on role-filtered detail pages", events, StringComparison.Ordinal);
        Assert.Contains("Timeline buckets", events, StringComparison.Ordinal);
        Assert.Contains("Saved searches", events, StringComparison.Ordinal);

        Assert.Contains("Raw JSON", detail, StringComparison.Ordinal);
        Assert.Contains("Keep it out of public issues, docs, screenshots, logs, and exports", detail, StringComparison.Ordinal);

        Assert.Contains("a:focus-visible", css, StringComparison.Ordinal);
        Assert.Contains("outline: 3px", css, StringComparison.Ordinal);
        Assert.Contains(".table-scroll", css, StringComparison.Ordinal);
        Assert.Contains("overflow-x: auto", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 900px)", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 640px)", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 480px)", css, StringComparison.Ordinal);
        Assert.Contains("@media (prefers-reduced-motion: reduce)", css, StringComparison.Ordinal);
    }

    [Fact]
    public void DesignSystemUsesOwnedAssetsCspAndBundleBudgetsWithoutInlineHandlers()
    {
        var root = RepositoryRoot();
        var layout = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Shared/_Layout.cshtml"));
        var eventDetail = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Detail.cshtml"));
        var socAgent = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/SocAgent.cshtml"));
        var program = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Program.cs"));
        var css = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/css/site.css"));
        var designSystemJs = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/js/design-system.js"));
        var socAgentJs = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/js/soc-agent.js"));

        Assert.Contains("Content-Security-Policy", program, StringComparison.Ordinal);
        Assert.Contains("script-src 'self'", program, StringComparison.Ordinal);
        Assert.Contains("~/js/design-system.js", layout, StringComparison.Ordinal);
        Assert.Contains("~/js/soc-agent.js", socAgent, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>\n(() =>", socAgent, StringComparison.Ordinal);
        Assert.DoesNotContain("onclick=", eventDetail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("innerHTML", designSystemJs, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("innerHTML", socAgentJs, StringComparison.OrdinalIgnoreCase);
        Assert.InRange(System.Text.Encoding.UTF8.GetByteCount(css), 1, 42000);
        Assert.InRange(System.Text.Encoding.UTF8.GetByteCount(designSystemJs), 1, 6000);
        Assert.InRange(System.Text.Encoding.UTF8.GetByteCount(socAgentJs), 1, 45000);
    }

    [Fact]
    public void ChallengerOverviewUsesOwnedResponsiveRailAndBoundedRepositoryData()
    {
        var root = RepositoryRoot();
        var layout = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Shared/_Layout.cshtml"));
        var overview = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Index.cshtml"));
        var overviewModel = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Index.cshtml.cs"));
        var css = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/css/site.css"));

        Assert.Contains("class=\"app-frame\"", layout, StringComparison.Ordinal);
        Assert.Contains("class=\"app-shell\"", layout, StringComparison.Ordinal);
        Assert.Contains("class=\"command-bar\"", layout, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"soc-agent\"", layout, StringComparison.Ordinal);
        Assert.Contains("asp-page-handler=\"GlobalSearch\"", layout, StringComparison.Ordinal);
        Assert.DoesNotContain("http://", layout, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", layout, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("DashboardRepository dashboardRepository", overviewModel, StringComparison.Ordinal);
        Assert.Contains("AlertRepository alertRepository", overviewModel, StringComparison.Ordinal);
        Assert.Contains("AlertFieldPolicy.Apply", overviewModel, StringComparison.Ordinal);
        Assert.Contains("GetAggregationsAsync", overviewModel, StringComparison.Ordinal);
        Assert.Contains("SearchAlertsAsync", overviewModel, StringComparison.Ordinal);

        Assert.Contains("Security overview", overview, StringComparison.Ordinal);
        Assert.Contains("Recent alerts", overview, StringComparison.Ordinal);
        Assert.Contains("Events by UTC hour", overview, StringComparison.Ordinal);
        Assert.Contains("<meter", overview, StringComparison.Ordinal);
        Assert.Contains("Review cases", overview, StringComparison.Ordinal);
        Assert.DoesNotContain("incident", overview, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("--bg: #0e1522", css, StringComparison.Ordinal);
        Assert.Contains("--brand: #8fa0f8", css, StringComparison.Ordinal);
        Assert.Contains(".app-frame", css, StringComparison.Ordinal);
        Assert.Contains(".overview-grid", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 600px)", css, StringComparison.Ordinal);
    }

    [Fact]
    public void AlertDetailPostsBindTheRenderedHiddenAlertIdentifier()
    {
        var root = RepositoryRoot();
        var alertDetail = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Alerts/Detail.cshtml"));
        var css = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/css/site.css"));
        var property = typeof(Challenger.Siem.Api.Pages.Alerts.DetailModel)
            .GetProperty(nameof(Challenger.Siem.Api.Pages.Alerts.DetailModel.AlertId));
        var binding = Assert.Single(property!.GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.BindPropertyAttribute), inherit: true))
            as Microsoft.AspNetCore.Mvc.BindPropertyAttribute;

        Assert.NotNull(binding);
        Assert.Null(binding!.Name);
        Assert.False(binding.SupportsGet);
        Assert.DoesNotContain("type=\"hidden\" asp-for=\"AlertId\"", alertDetail, StringComparison.Ordinal);
        Assert.DoesNotContain("type=\"hidden\" asp-for=\"ExpectedVersion\"", alertDetail, StringComparison.Ordinal);
        Assert.Contains("type=\"hidden\" name=\"AlertId\" value=\"@Model.AlertId\"", alertDetail, StringComparison.Ordinal);
        Assert.Contains("type=\"hidden\" name=\"ExpectedVersion\" value=\"@Model.ExpectedVersion\"", alertDetail, StringComparison.Ordinal);
        Assert.Contains(
            "input[type=\"checkbox\"],\ninput[type=\"radio\"] {\n    width: auto;\n    flex: none;\n}",
            css,
            StringComparison.Ordinal);
    }

    [Fact]
    public void FrontendArchitectureAdrRecordsScoringMeasurementsAndCleanupDecision()
    {
        var root = RepositoryRoot();
        var adr = File.ReadAllText(Path.Combine(root, "docs/frontend-architecture-adr.md"));
        var dependencies = File.ReadAllText(Path.Combine(root, "docs/dependencies.md"));
        var development = File.ReadAllText(Path.Combine(root, "docs/development.md"));

        Assert.Contains("Continue with an enhanced ASP.NET Core/Razor Pages frontend", adr, StringComparison.Ordinal);
        Assert.Contains("**89**", adr, StringComparison.Ordinal);
        Assert.Contains("**57**", adr, StringComparison.Ordinal);
        Assert.Contains("DOMContentLoaded 12 ms; load 73 ms", adr, StringComparison.Ordinal);
        Assert.Contains("500", adr, StringComparison.Ordinal);
        Assert.Contains("then deleted", adr, StringComparison.Ordinal);
        Assert.Contains("non-production test harness", adr, StringComparison.Ordinal);
        Assert.Contains("Deletion criteria for superseded UI code", adr, StringComparison.Ordinal);
        Assert.Contains("Do not add a separate TypeScript frontend", adr, StringComparison.Ordinal);

        Assert.Contains("No TypeScript frontend, npm package manager, lockfile, bundler", dependencies, StringComparison.Ordinal);
        Assert.Contains("Temporary browser traces, screenshots, generated prototypes", development, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(root, "package.json")), "The spike must not leave a JavaScript package manifest.");
        Assert.False(File.Exists(Path.Combine(root, "package-lock.json")), "The spike must not leave an npm lockfile.");
        Assert.False(File.Exists(Path.Combine(root, "pnpm-lock.yaml")), "The spike must not leave a pnpm lockfile.");
        Assert.False(File.Exists(Path.Combine(root, "yarn.lock")), "The spike must not leave a Yarn lockfile.");
    }

    [Fact]
    public async Task RetainedPrototypeHarnessDemonstratesHighDensitySearchTimelineAndLifecycleStates()
    {
        var result = await FrontendArchitecturePrototypeHarness.RenderAsync(
            new FrontendPrototypeOptions(2, 50, "DEMO", "", ""),
            operatorRole: "viewer",
            CancellationToken.None);

        Assert.Equal(500, result.TotalRows);
        Assert.Equal(50, result.RenderedRows);
        Assert.True(result.HasNextPage);
        Assert.InRange(result.TimelineBuckets, 1, 12);
        Assert.Contains("Host: DEMO", result.ActiveFilters);
        Assert.Contains("<main id=\"main-content\">", result.Html, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Primary\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Synthetic search filters\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("<caption>Synthetic high-density event rows</caption>", result.Html, StringComparison.Ordinal);
        Assert.Contains("id=\"timeline\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("a:focus-visible", result.Html, StringComparison.Ordinal);
        Assert.Contains("@media(max-width:900px)", result.Html, StringComparison.Ordinal);
        Assert.Contains("@media(max-width:480px)", result.Html, StringComparison.Ordinal);
        Assert.Contains("data-state=\"loading\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("data-state=\"empty\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("data-state=\"error\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("data-state=\"unauthorized\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("data-state=\"stale\"", result.Html, StringComparison.Ordinal);
        Assert.Contains("data-state=\"degraded\"", result.Html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RetainedPrototypeHarnessExercisesCancellationAndProtectedFieldEnforcement()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => FrontendArchitecturePrototypeHarness.RenderAsync(
            new FrontendPrototypeOptions(1, 500, "", "", ""),
            operatorRole: "viewer",
            cancelled.Token));

        var viewer = await FrontendArchitecturePrototypeHarness.RenderAsync(
            new FrontendPrototypeOptions(1, 25, "DEMO-WIN11", "Security", "high"),
            operatorRole: "viewer",
            CancellationToken.None);
        var admin = await FrontendArchitecturePrototypeHarness.RenderAsync(
            new FrontendPrototypeOptions(1, 25, "DEMO-WIN11", "Security", "high"),
            operatorRole: "admin",
            CancellationToken.None);

        Assert.DoesNotContain("synthetic-user-", viewer.Html, StringComparison.Ordinal);
        Assert.DoesNotContain("/opt/challenger-demo/bin/tool", viewer.Html, StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2.", viewer.Html, StringComparison.Ordinal);
        Assert.Contains("[redacted: protected event fields]", viewer.Html, StringComparison.Ordinal);
        Assert.Contains("omitted before render", viewer.Html, StringComparison.Ordinal);

        Assert.Contains("synthetic-user-", admin.Html, StringComparison.Ordinal);
        Assert.Contains("/opt/challenger-demo/bin/tool", admin.Html, StringComparison.Ordinal);
        Assert.Contains("192.0.2.", admin.Html, StringComparison.Ordinal);
        Assert.Contains("shown to admin", admin.Html, StringComparison.Ordinal);
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        current = new DirectoryInfo(Environment.CurrentDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate Challenger.Siem.sln from the test process.");
    }
}
