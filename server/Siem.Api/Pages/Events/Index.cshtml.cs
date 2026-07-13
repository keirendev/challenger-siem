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
    IOptions<ReviewOptions> reviewOptions,
    ILogger<IndexModel> logger) : PageModel
{
    public EventSearchQuery Query { get; private set; } = new(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 100);

    [Microsoft.AspNetCore.Mvc.BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    public IReadOnlyList<EventEnvelope> Events { get; private set; } = Array.Empty<EventEnvelope>();

    public bool HasPreviousPage => PageNumber > 1;

    public bool HasNextPage { get; private set; }

    public int FirstResultNumber => Events.Count == 0 ? 0 : ((PageNumber - 1) * NormalizedLimit) + 1;

    public int LastResultNumber => ((PageNumber - 1) * NormalizedLimit) + Events.Count;

    public int NormalizedLimit => Math.Clamp(Query.Limit, 1, 500);

    public string? ErrorMessage { get; private set; }

    public string? GlobalSearchMessage { get; private set; }

    [BindProperty]
    public string? GlobalSearch { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);
        Query = EventSearchQuery.FromQuery(Request.Query);
        if (!Request.Query.ContainsKey("limit"))
        {
            Query = Query with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        }

        await LoadEventsAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostGlobalSearchAsync(CancellationToken cancellationToken)
    {
        PageNumber = 1;
        Query = Query with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        var searchText = string.IsNullOrWhiteSpace(GlobalSearch) ? null : GlobalSearch.Trim();
        if (searchText?.Length > 160)
        {
            searchText = searchText[..160];
            GlobalSearchMessage = "Global search input was shortened to the 160-character event-search limit. The submitted term is not repeated in page links.";
        }
        else
        {
            GlobalSearchMessage = "Global search is currently scoped to bounded event metadata for every role, with sensitive keyword matching only for authorized analysts. Unified event, alert, case, and entity search is planned. The submitted term is not repeated in page links.";
        }

        if (searchText is null)
        {
            GlobalSearchMessage = "Enter a host, agent, event code, source, or authorized keyword to search the current bounded event index.";
            Events = Array.Empty<EventEnvelope>();
            HasNextPage = false;
            return Page();
        }

        await LoadGlobalEventsAsync(searchText, cancellationToken);
        return Page();
    }

    private async Task LoadGlobalEventsAsync(string searchText, CancellationToken cancellationToken)
    {
        Query = Query with { Limit = NormalizedLimit };
        var fetchLimit = Math.Min(NormalizedLimit + 1, 500);

        try
        {
            var loadedEvents = await eventRepository.SearchGlobalEventsForOperatorAsync(searchText, fetchLimit, OperatorAuthorization.Role(User)!, cancellationToken);
            HasNextPage = loadedEvents.Count > NormalizedLimit;
            Events = loadedEvents.Take(NormalizedLimit).ToArray();
            if (Events.Count == 0)
            {
                GlobalSearchMessage = string.Concat(GlobalSearchMessage, " No matching permitted event metadata was found for the current role.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Global event search could not be loaded.");
            ErrorMessage = "Global event search is currently unavailable.";
        }
    }

    private async Task LoadEventsAsync(CancellationToken cancellationToken)
    {
        Query = Query with { Limit = NormalizedLimit };
        var fetchLimit = Math.Min(NormalizedLimit + 1, 500);
        var fetchQuery = Query with { Limit = fetchLimit };

        try
        {
            var loadedEvents = await eventRepository.SearchEventsForOperatorAsync(fetchQuery, OperatorAuthorization.Role(User)!, cancellationToken, (PageNumber - 1) * NormalizedLimit);
            HasNextPage = loadedEvents.Count > NormalizedLimit;
            Events = loadedEvents.Take(NormalizedLimit).ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Event search could not be loaded.");
            ErrorMessage = "Event search is currently unavailable.";
        }
    }

    public string FormatDateTimeInput(DateTimeOffset? value)
    {
        return TimeDisplay.FormatUtcInput(value);
    }

    public IReadOnlyList<string> ActiveFilters()
    {
        var filters = new List<string>();
        AddFilter(filters, "Host", Query.Hostname);
        AddFilter(filters, "Agent", Query.AgentId);
        AddFilter(filters, "Source kind", Query.Source);
        AddFilter(filters, "Platform", Query.Platform);
        AddFilter(filters, "Source ID", Query.SourceId);
        AddFilter(filters, "Event code", Query.EventCode);
        AddFilter(filters, "Package", Query.PackageName);
        AddFilter(filters, "Channel", Query.Channel);
        AddFilter(filters, "Event ID", Query.WindowsEventId?.ToString(CultureInfo.InvariantCulture));
        AddFilter(filters, "Keyword", Query.Keyword);
        AddFilter(filters, "Category", Query.Category);
        AddFilter(filters, "Action", Query.Action);
        AddFilter(filters, "User", Query.UserName);
        AddFilter(filters, "Process", Query.ProcessImage);
        AddFilter(filters, "Destination", Query.DestinationIp);
        if (Query.From.HasValue) AddFilter(filters, "From UTC", TimeDisplay.FormatUtc(Query.From, "yyyy-MM-dd HH:mm"));
        if (Query.To.HasValue) AddFilter(filters, "To UTC", TimeDisplay.FormatUtc(Query.To, "yyyy-MM-dd HH:mm"));
        return filters;
    }

    public string Preview(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "—";
        }

        var singleLine = message.ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 140 ? singleLine : string.Concat(singleLine.AsSpan(0, 140), "…");
    }

    private static void AddFilter(List<string> filters, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            filters.Add($"{label}: {value.Trim()}");
        }
    }
}
