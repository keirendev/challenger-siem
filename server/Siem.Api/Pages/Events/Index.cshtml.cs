using System.Globalization;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages.Events;

public sealed class IndexModel(
    EventRepository eventRepository,
    SecurityAuditRepository auditRepository,
    IOptions<ReviewOptions> reviewOptions,
    ILogger<IndexModel> logger) : PageModel
{
    public EventSearchQuery Query { get; private set; } = EventSearchQuery.Empty;

    [BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    [BindProperty(SupportsGet = true, Name = "saved_search_id")]
    public Guid? SavedSearchId { get; set; }

    public IReadOnlyList<EventEnvelope> Events { get; private set; } = Array.Empty<EventEnvelope>();
    public IReadOnlyList<EventTimelineBucket> TimelineBuckets { get; private set; } = Array.Empty<EventTimelineBucket>();
    public IReadOnlyList<SavedEventSearchRecord> SavedSearches { get; private set; } = Array.Empty<SavedEventSearchRecord>();
    public EventSearchPageInfo? PageInfo { get; private set; }

    public bool HasPreviousPage => PageNumber > 1;
    public bool HasNextPage => PageInfo?.HasNext == true;
    public int FirstResultNumber => Events.Count == 0 ? 0 : ((PageNumber - 1) * NormalizedLimit) + 1;
    public int LastResultNumber => ((PageNumber - 1) * NormalizedLimit) + Events.Count;
    public int NormalizedLimit => Math.Clamp(Query.Limit, 1, EventSearchQuery.MaxLimit);
    public string ResultScope { get; private set; } = "No search run yet.";
    public string RedactionNotice { get; private set; } = "server_role_policy_applied";
    public string? ErrorMessage { get; private set; }
    public string? StatusMessage { get; private set; }
    public bool CanExport => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(User), OperatorPermission.ManageOperators);
    public bool CanShareSavedSearch => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(User), OperatorPermission.ReviewSensitive);

    [BindProperty]
    public string? GlobalSearch { get; set; }

    [BindProperty]
    public string? SavedSearchName { get; set; }

    [BindProperty]
    public string? SavedSearchDescription { get; set; }

    [BindProperty]
    public string SavedSearchVisibility { get; set; } = SavedEventSearchVisibility.Private;

    [BindProperty]
    public string? ConfirmExport { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);
        Query = EventSearchQuery.FromQuery(Request.Query);
        if (!Request.Query.ContainsKey("limit")) Query = Query with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        await LoadSavedSearchesAsync(cancellationToken);
        await ApplySavedSearchIfRequestedAsync(cancellationToken);
        await LoadEventsAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostGlobalSearchAsync(CancellationToken cancellationToken)
    {
        PageNumber = 1;
        var searchText = string.IsNullOrWhiteSpace(GlobalSearch) ? null : GlobalSearch.Trim();
        if (searchText?.Length > 160) searchText = searchText[..160];
        Query = EventSearchQuery.Empty with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        if (searchText is null)
        {
            StatusMessage = "Enter a host, agent, event code, source, or authorized keyword to search the bounded event index.";
            await LoadSavedSearchesAsync(cancellationToken);
            return Page();
        }

        await LoadSavedSearchesAsync(cancellationToken);
        await LoadGlobalSearchAsync(searchText, cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostSaveSearchAsync(CancellationToken cancellationToken)
    {
        Query = EventSearchQuery.FromQuery(Request.Query);
        if (!Request.Query.ContainsKey("limit")) Query = Query with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        var operatorId = OperatorAuthentication.OperatorId(User);
        if (!operatorId.HasValue) return Unauthorized();
        try
        {
            var saved = await eventRepository.SaveSearchAsync(new SavedEventSearchRequest
            {
                Name = SavedSearchName ?? string.Empty,
                Description = SavedSearchDescription,
                Visibility = SavedSearchVisibility,
                Query = Query.ToSavedQueryDictionary(),
                Columns = Query.Columns
            }, operatorId.Value, User.Identity?.Name ?? "operator", CanShareSavedSearch, cancellationToken);
            await auditRepository.RecordAsync(operatorId, User.Identity?.Name, "event_search.saved.create", "success", "saved_event_search", saved.SavedSearchId.ToString(), HttpContext, new Dictionary<string, object?> { ["visibility"] = saved.Visibility, ["version"] = saved.Version }, cancellationToken);
            StatusMessage = $"Saved search '{saved.Name}' created at version {saved.Version}.";
        }
        catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
        }
        await LoadSavedSearchesAsync(cancellationToken);
        await LoadEventsAsync(cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostDeleteSavedSearchAsync(Guid savedSearchId, CancellationToken cancellationToken)
    {
        var operatorId = OperatorAuthentication.OperatorId(User);
        if (!operatorId.HasValue) return Unauthorized();
        var deleted = await eventRepository.DeleteSavedSearchAsync(savedSearchId, operatorId.Value, cancellationToken);
        await auditRepository.RecordAsync(operatorId, User.Identity?.Name, "event_search.saved.delete", deleted ? "success" : "denied", "saved_event_search", savedSearchId.ToString(), HttpContext, null, cancellationToken);
        StatusMessage = deleted ? "Saved search deleted." : "Saved search was not found or is not owned by this operator.";
        Query = EventSearchQuery.FromQuery(Request.Query);
        await LoadSavedSearchesAsync(cancellationToken);
        await LoadEventsAsync(cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostExportAsync(CancellationToken cancellationToken)
    {
        if (!CanExport) return Forbid();
        if (!string.Equals(ConfirmExport, "EXPORT", StringComparison.Ordinal))
        {
            ErrorMessage = "Type EXPORT to confirm this bounded audited event export.";
            Query = EventSearchQuery.FromQuery(Request.Query);
            await LoadSavedSearchesAsync(cancellationToken);
            await LoadEventsAsync(cancellationToken);
            return Page();
        }

        Query = EventSearchQuery.FromQuery(Request.Query);
        if (Query.ValidationErrors.Count > 0)
        {
            ErrorMessage = "Fix search validation errors before exporting.";
            await LoadSavedSearchesAsync(cancellationToken);
            await LoadEventsAsync(cancellationToken);
            return Page();
        }

        var role = OperatorAuthorization.Role(User)!;
        var export = await eventRepository.ExportCsvForOperatorAsync(Query, role, cancellationToken);
        await auditRepository.RecordAsync(OperatorAuthentication.OperatorId(User), User.Identity?.Name, "event_search.export", "success", "events", null, HttpContext, new Dictionary<string, object?> { ["rows"] = export.Rows, ["limit"] = export.BoundedLimit, ["format"] = "csv" }, cancellationToken);
        return File(export.Content, "text/csv; charset=utf-8", export.FileName);
    }

    private async Task ApplySavedSearchIfRequestedAsync(CancellationToken cancellationToken)
    {
        if (!SavedSearchId.HasValue) return;
        var operatorId = OperatorAuthentication.OperatorId(User);
        if (!operatorId.HasValue) return;
        var saved = await eventRepository.GetSavedSearchAsync(
            SavedSearchId.Value,
            operatorId.Value,
            canUseShared: true,
            OperatorAuthorization.Role(User)!,
            cancellationToken);
        if (saved is null)
        {
            ErrorMessage = "Saved search was not found or is not visible to this operator.";
            return;
        }
        Query = EventSearchQuery.FromSavedQuery(saved.Query);
        StatusMessage = $"Loaded saved search '{saved.Name}' version {saved.Version}.";
    }

    private async Task LoadSavedSearchesAsync(CancellationToken cancellationToken)
    {
        var operatorId = OperatorAuthentication.OperatorId(User);
        SavedSearches = operatorId.HasValue
            ? await eventRepository.ListSavedSearchesAsync(operatorId.Value, OperatorAuthorization.Role(User)!, cancellationToken)
            : Array.Empty<SavedEventSearchRecord>();
    }

    private async Task LoadEventsAsync(CancellationToken cancellationToken)
    {
        Query = Query with { Limit = NormalizedLimit };
        if (Query.ValidationErrors.Count > 0)
        {
            Events = Array.Empty<EventEnvelope>();
            TimelineBuckets = Array.Empty<EventTimelineBucket>();
            ResultScope = "Search validation failed; no query was executed.";
            return;
        }

        try
        {
            var pageQuery = PageNumber > 1 ? Query with { Cursor = null } : Query;
            var loaded = await eventRepository.SearchEventsPageForOperatorAsync(pageQuery, OperatorAuthorization.Role(User)!, cancellationToken);
            PageInfo = loaded.Page;
            Events = loaded.Events;
            ResultScope = loaded.ResultScope;
            RedactionNotice = loaded.RedactionNotice;
            var timeline = await eventRepository.GetTimelineAsync(Query, OperatorAuthorization.Role(User)!, cancellationToken);
            TimelineBuckets = timeline.Buckets;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Event search could not be loaded.");
            ErrorMessage = "Event search is currently unavailable.";
        }
    }

    private async Task LoadGlobalSearchAsync(string searchText, CancellationToken cancellationToken)
    {
        var role = OperatorAuthorization.Role(User) ?? OperatorRoles.Viewer;
        var limit = Math.Clamp(reviewOptions.Value.NormalizedDefaultEventLimit, 1, EventSearchQuery.MaxLimit);

        try
        {
            Events = await eventRepository.SearchGlobalEventsForOperatorAsync(searchText, limit, role, cancellationToken);
            PageInfo = new EventSearchPageInfo
            {
                Limit = limit,
                Returned = Events.Count,
                HasNext = false
            };
            TimelineBuckets = Array.Empty<EventTimelineBucket>();
            ResultScope = $"Global search scope: permitted metadata and role-authorized content; newest first; limit {limit}; role {role}.";
            RedactionNotice = OperatorAuthorization.HasPermission(role, OperatorPermission.ReviewSensitive)
                ? "raw_omitted_sensitive_fields_redacted"
                : "metadata_only_sensitive_filters_removed";
            StatusMessage = Events.Count == 0
                ? "No matching permitted event metadata or authorized content was found. The search term is not repeated in the URL or page links."
                : "Global search is scoped to permitted event metadata and role-authorized content. The search term is not repeated in the URL or page links.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Bounded global event search could not be loaded.");
            Events = Array.Empty<EventEnvelope>();
            TimelineBuckets = Array.Empty<EventTimelineBucket>();
            ResultScope = "Global search scope could not be loaded; no broad fallback query was executed.";
            ErrorMessage = "Global event search is currently unavailable.";
        }
    }

    public string FormatDateTimeInput(DateTimeOffset? value) => TimeDisplay.FormatUtcInput(value);

    public IReadOnlyList<EventSearchFilterSummary> ActiveFilters() => Query.ActiveFilterSummaries();

    public string Preview(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return "—";
        var singleLine = message.ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 140 ? singleLine : string.Concat(singleLine.AsSpan(0, 140), "…");
    }

    public string BuildCurrentQueryString(string? cursor = null, int? page = null)
    {
        var query = Query.ToSavedQueryDictionary().ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(cursor)) query["cursor"] = cursor;
        if (page.HasValue) query["page"] = page.Value.ToString(CultureInfo.InvariantCulture);
        return string.Join('&', query.Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value)}"));
    }
}
