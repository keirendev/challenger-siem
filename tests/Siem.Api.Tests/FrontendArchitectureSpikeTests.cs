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
        Assert.Contains("(PageNumber - 1) * NormalizedLimit", indexModel, StringComparison.Ordinal);
        Assert.Contains("SearchEventsForOperatorAsync(fetchQuery, OperatorAuthorization.Role(User)!", indexModel, StringComparison.Ordinal);

        Assert.Contains("Math.Clamp(query.Limit, 1, 500)", eventRepository, StringComparison.Ordinal);
        Assert.Contains("limit @limit offset @offset", eventRepository, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("OperatorAuthorization.HasPermission(role, OperatorPermission.ReviewSensitive)", eventRepository, StringComparison.Ordinal);
        Assert.Contains("EventFieldPolicy.Apply(item, role)", eventRepository, StringComparison.Ordinal);

        Assert.Contains("EventSearchQuery.FromQuery(context.Request.Query)", program, StringComparison.Ordinal);
        Assert.Contains("SearchEventsForOperatorAsync(query, OperatorAuthorization.Role(context.User)!", program, StringComparison.Ordinal);
        Assert.Contains("csrf_safe_bearer_required", program, StringComparison.Ordinal);
    }

    [Fact]
    public void RazorMarkupKeepsAccessibilityResponsiveAndLifecycleSurfacesForSearchWorkflow()
    {
        var root = RepositoryRoot();
        var layout = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Shared/_Layout.cshtml"));
        var events = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Index.cshtml"));
        var detail = File.ReadAllText(Path.Combine(root, "server/Siem.Api/Pages/Events/Detail.cshtml"));
        var css = File.ReadAllText(Path.Combine(root, "server/Siem.Api/wwwroot/css/site.css"));

        Assert.Contains("Skip to main content", layout, StringComparison.Ordinal);
        Assert.Contains("<main id=\"main-content\"", layout, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Primary\"", layout, StringComparison.Ordinal);
        Assert.Contains("asp-page=\"/Logout\"", layout, StringComparison.Ordinal);

        Assert.Contains("aria-label=\"Event search filters\"", events, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Active event filters\"", events, StringComparison.Ordinal);
        Assert.Contains("role=\"alert\"", events, StringComparison.Ordinal);
        Assert.Contains("class=\"empty\"", events, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Event result pages\"", events, StringComparison.Ordinal);
        Assert.Contains("table-scroll", events, StringComparison.Ordinal);
        Assert.Contains("raw JSON available only on detail pages", events, StringComparison.Ordinal);

        Assert.Contains("Raw JSON", detail, StringComparison.Ordinal);
        Assert.Contains("do not copy into public issues, docs, or logs", detail, StringComparison.Ordinal);

        Assert.Contains("a:focus-visible", css, StringComparison.Ordinal);
        Assert.Contains("outline: 3px", css, StringComparison.Ordinal);
        Assert.Contains(".table-scroll", css, StringComparison.Ordinal);
        Assert.Contains("overflow-x: auto", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 900px)", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 640px)", css, StringComparison.Ordinal);
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
        Assert.Contains("Deletion criteria for superseded UI code", adr, StringComparison.Ordinal);
        Assert.Contains("Do not add a separate TypeScript frontend", adr, StringComparison.Ordinal);

        Assert.Contains("No TypeScript frontend, npm package manager, lockfile, bundler", dependencies, StringComparison.Ordinal);
        Assert.Contains("Temporary browser traces, screenshots, generated prototypes", development, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(root, "package.json")), "The spike must not leave a JavaScript package manifest.");
        Assert.False(File.Exists(Path.Combine(root, "package-lock.json")), "The spike must not leave an npm lockfile.");
        Assert.False(File.Exists(Path.Combine(root, "pnpm-lock.yaml")), "The spike must not leave a pnpm lockfile.");
        Assert.False(File.Exists(Path.Combine(root, "yarn.lock")), "The spike must not leave a Yarn lockfile.");
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
