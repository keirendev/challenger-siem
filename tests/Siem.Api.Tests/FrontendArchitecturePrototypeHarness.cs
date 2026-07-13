using System.Net;
using System.Text;

namespace Challenger.Siem.Api.Tests;

internal sealed record FrontendPrototypeOptions(
    int Page,
    int Limit,
    string HostFilter,
    string SourceFilter,
    string SeverityFilter,
    bool IncludeEmptyState = true,
    bool IncludeErrorState = true,
    bool IncludeUnauthorizedState = true,
    bool IncludeStaleState = true,
    bool IncludeDegradedState = true);

internal sealed record FrontendPrototypeResult(
    string Html,
    int TotalRows,
    int RenderedRows,
    int TimelineBuckets,
    bool HasNextPage,
    IReadOnlyList<string> ActiveFilters);

/// <summary>
/// Non-production issue #201 harness that renders a synthetic Razor-shaped
/// high-density search/timeline slice for repeatable architecture tests. It is
/// deliberately not routed, not referenced by the web app, and uses no runtime
/// dependencies or external assets.
/// </summary>
internal static class FrontendArchitecturePrototypeHarness
{
    public static Task<FrontendPrototypeResult> RenderAsync(
        FrontendPrototypeOptions options,
        string operatorRole,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var normalizedLimit = Math.Clamp(options.Limit, 1, 100);
        var page = Math.Max(1, options.Page);
        var rows = SyntheticRows().Where(row =>
            row.Host.Contains(options.HostFilter, StringComparison.OrdinalIgnoreCase)
            && row.Source.Contains(options.SourceFilter, StringComparison.OrdinalIgnoreCase)
            && row.Severity.Contains(options.SeverityFilter, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        cancellationToken.ThrowIfCancellationRequested();

        var renderedRows = rows
            .Skip((page - 1) * normalizedLimit)
            .Take(normalizedLimit + 1)
            .ToArray();
        var visibleRows = renderedRows.Take(normalizedLimit).ToArray();
        var buckets = rows
            .GroupBy(row => new SyntheticTimelineBucket(row.EventTime.UtcDateTime.ToString("yyyy-MM-dd HH:00'Z'"), row.Source, row.Status))
            .OrderBy(group => group.Key.Bucket)
            .ThenBy(group => group.Key.Source)
            .ThenBy(group => group.Key.Status)
            .Take(12)
            .ToArray();

        var activeFilters = new[]
            {
                (Label: "Host", Value: options.HostFilter),
                (Label: "Source", Value: options.SourceFilter),
                (Label: "Severity", Value: options.SeverityFilter),
                (Label: "Limit", Value: normalizedLimit.ToString())
            }
            .Where(item => !string.IsNullOrWhiteSpace(item.Value))
            .Select(item => $"{item.Label}: {item.Value}")
            .ToArray();

        var html = RenderHtml(options, operatorRole, normalizedLimit, page, rows.Length, visibleRows, buckets, activeFilters);
        return Task.FromResult(new FrontendPrototypeResult(
            html,
            rows.Length,
            visibleRows.Length,
            buckets.Length,
            renderedRows.Length > normalizedLimit,
            activeFilters));
    }

    private static string RenderHtml(
        FrontendPrototypeOptions options,
        string operatorRole,
        int normalizedLimit,
        int page,
        int totalRows,
        IReadOnlyList<SyntheticPrototypeRow> visibleRows,
        IReadOnlyList<IGrouping<SyntheticTimelineBucket, SyntheticPrototypeRow>> buckets,
        IReadOnlyList<string> activeFilters)
    {
        var canViewProtected = string.Equals(operatorRole, "admin", StringComparison.Ordinal);
        var html = new StringBuilder();
        html.AppendLine("<!doctype html><html lang=\"en\"><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
        html.AppendLine("<title>Prototype high-density search</title><style>");
        html.AppendLine("a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid #4f8cff;outline-offset:2px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem}.table-scroll{overflow-x:auto}.timeline{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.5rem}@media(max-width:900px){.grid,.timeline{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){.grid,.timeline{grid-template-columns:1fr}table{min-width:760px}}");
        html.AppendLine("</style></head><body><a href=\"#main-content\">Skip to main content</a><nav aria-label=\"Primary\"><a href=\"#results\">Search</a><a href=\"#timeline\">Timeline</a></nav><main id=\"main-content\">");
        html.AppendLine("<h1>High-density search and timeline prototype</h1>");
        html.AppendLine("<form aria-label=\"Synthetic search filters\" class=\"grid\"><label>Host <input name=\"host\" value=\"" + Encode(options.HostFilter) + "\" /></label><label>Source <input name=\"source\" value=\"" + Encode(options.SourceFilter) + "\" /></label><label>Severity <input name=\"severity\" value=\"" + Encode(options.SeverityFilter) + "\" /></label><label>Limit <input name=\"limit\" type=\"number\" min=\"1\" max=\"100\" value=\"" + normalizedLimit + "\" /></label><button type=\"submit\">Apply filters</button></form>");
        html.AppendLine("<section aria-label=\"Active result scope\"><h2>Active filters</h2><ul>");
        foreach (var filter in activeFilters) html.AppendLine("<li>" + Encode(filter) + "</li>");
        html.AppendLine("</ul><p>Page " + page + ", " + visibleRows.Count + " rendered of " + totalRows + " matching synthetic rows. Pagination is capped to " + normalizedLimit + " rows and request cancellation is checked before filtering and after filtering.</p></section>");
        RenderLifecycleStates(html, options);
        html.AppendLine("<section id=\"results\" aria-labelledby=\"results-heading\"><h2 id=\"results-heading\">Results</h2><div class=\"table-scroll\"><table><caption>Synthetic high-density event rows</caption><thead><tr><th scope=\"col\">Time</th><th scope=\"col\">Host</th><th scope=\"col\">Source</th><th scope=\"col\">Severity</th><th scope=\"col\">Summary</th><th scope=\"col\">Protected field state</th><th scope=\"col\">Action</th></tr></thead><tbody>");
        foreach (var row in visibleRows)
        {
            var summary = canViewProtected ? row.ProtectedSummary : "[redacted: protected event fields]";
            var protectedState = canViewProtected ? "shown to admin" : "omitted before render";
            html.AppendLine("<tr><td>" + Encode(row.EventTime.ToString("O")) + "</td><td>" + Encode(row.Host) + "</td><td>" + Encode(row.Source) + "</td><td>" + Encode(row.Severity) + "</td><td>" + Encode(summary) + "</td><td>" + protectedState + "</td><td><a href=\"#event-" + row.Index + "\">Open event " + row.Index + "</a></td></tr>");
        }
        html.AppendLine("</tbody></table></div></section>");
        html.AppendLine("<section id=\"timeline\" aria-labelledby=\"timeline-heading\"><h2 id=\"timeline-heading\">Timeline aggregation</h2><ol class=\"timeline\">");
        foreach (var bucket in buckets)
        {
            html.AppendLine("<li><strong>" + Encode(bucket.Key.Bucket) + "</strong><br />" + Encode(bucket.Key.Source) + " / " + Encode(bucket.Key.Status) + ": " + bucket.Count() + " events</li>");
        }
        html.AppendLine("</ol></section></main></body></html>");
        return html.ToString();
    }

    private static void RenderLifecycleStates(StringBuilder html, FrontendPrototypeOptions options)
    {
        html.AppendLine("<section aria-label=\"Lifecycle states\"><h2>Lifecycle states</h2>");
        if (options.IncludeEmptyState) html.AppendLine("<p data-state=\"empty\">Empty: no synthetic events match the active filters.</p>");
        if (options.IncludeErrorState) html.AppendLine("<p role=\"alert\" data-state=\"error\">Error: query failed; retry without exposing database details.</p>");
        if (options.IncludeUnauthorizedState) html.AppendLine("<p data-state=\"unauthorized\">Unauthorized: sign in or request access for this workflow.</p>");
        if (options.IncludeStaleState) html.AppendLine("<p data-state=\"stale\">Stale: selected source has not reported within the expected window.</p>");
        if (options.IncludeDegradedState) html.AppendLine("<p data-state=\"degraded\">Degraded: partial source coverage; timeline confidence is reduced.</p>");
        html.AppendLine("<p data-state=\"loading\" aria-busy=\"true\">Loading: retaining headings and active filter scope.</p></section>");
    }

    private static IReadOnlyList<SyntheticPrototypeRow> SyntheticRows()
    {
        var start = DateTimeOffset.Parse("2026-07-14T00:00:00Z");
        return Enumerable.Range(0, 500)
            .Select(index => new SyntheticPrototypeRow(
                index,
                start.AddMinutes(index * 3),
                index % 2 == 0 ? "DEMO-WIN11" : "DEMO-LNX-02",
                index % 3 == 0 ? "Security" : index % 3 == 1 ? "PowerShell" : "linux-ssh",
                index % 5 == 0 ? "high" : "medium",
                index % 7 == 0 ? "degraded" : "healthy",
                $"synthetic-user-{index % 9} ran /opt/challenger-demo/bin/tool --demo-ip 192.0.2.{index % 200}"))
            .ToArray();
    }

    private static string Encode(string value) => WebUtility.HtmlEncode(value);

    private sealed record SyntheticTimelineBucket(string Bucket, string Source, string Status);

    private sealed record SyntheticPrototypeRow(
        int Index,
        DateTimeOffset EventTime,
        string Host,
        string Source,
        string Severity,
        string Status,
        string ProtectedSummary);
}
