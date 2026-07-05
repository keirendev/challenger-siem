using System.Globalization;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages.Events;

public sealed class IndexModel(
    EventRepository eventRepository,
    IOptions<ReviewOptions> reviewOptions,
    ILogger<IndexModel> logger) : PageModel
{
    public EventSearchQuery Query { get; private set; } = new(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 100);

    [Microsoft.AspNetCore.Mvc.BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    public IReadOnlyList<EventEnvelope> Events { get; private set; } = Array.Empty<EventEnvelope>();

    public bool HasPreviousPage => PageNumber > 1;

    public bool HasNextPage { get; private set; }

    public int FirstResultNumber => Events.Count == 0 ? 0 : ((PageNumber - 1) * NormalizedLimit) + 1;

    public int LastResultNumber => ((PageNumber - 1) * NormalizedLimit) + Events.Count;

    public int NormalizedLimit => Math.Clamp(Query.Limit, 1, 500);

    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);
        Query = EventSearchQuery.FromQuery(Request.Query);
        if (!Request.Query.ContainsKey("limit"))
        {
            Query = Query with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        }

        Query = Query with { Limit = NormalizedLimit };
        var fetchLimit = Math.Min(NormalizedLimit + 1, 500);
        var fetchQuery = Query with { Limit = fetchLimit };

        try
        {
            var loadedEvents = await eventRepository.SearchEventsAsync(fetchQuery, cancellationToken, (PageNumber - 1) * NormalizedLimit);
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
        return value?.ToLocalTime().ToString("yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture) ?? string.Empty;
    }

    public IReadOnlyList<string> ActiveFilters()
    {
        var filters = new List<string>();
        AddFilter(filters, "Host", Query.Hostname);
        AddFilter(filters, "Agent", Query.AgentId);
        AddFilter(filters, "Channel", Query.Channel);
        AddFilter(filters, "Event ID", Query.WindowsEventId?.ToString(CultureInfo.InvariantCulture));
        AddFilter(filters, "Keyword", Query.Keyword);
        AddFilter(filters, "Category", Query.Category);
        AddFilter(filters, "Action", Query.Action);
        AddFilter(filters, "User", Query.UserName);
        AddFilter(filters, "Process", Query.ProcessImage);
        AddFilter(filters, "Destination", Query.DestinationIp);
        if (Query.From.HasValue) AddFilter(filters, "From", Query.From.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
        if (Query.To.HasValue) AddFilter(filters, "To", Query.To.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
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
