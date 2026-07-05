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

    public IReadOnlyList<EventEnvelope> Events { get; private set; } = Array.Empty<EventEnvelope>();

    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Query = EventSearchQuery.FromQuery(Request.Query);
        if (!Request.Query.ContainsKey("limit"))
        {
            Query = Query with { Limit = reviewOptions.Value.NormalizedDefaultEventLimit };
        }

        try
        {
            Events = await eventRepository.SearchEventsAsync(Query, cancellationToken);
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

    public string Preview(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "—";
        }

        var singleLine = message.ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 140 ? singleLine : string.Concat(singleLine.AsSpan(0, 140), "…");
    }
}
