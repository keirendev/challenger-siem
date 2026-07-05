using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Alerts;

public sealed class IndexModel(AlertRepository alerts) : PageModel
{
    public const int PageSize = 50;

    [BindProperty(SupportsGet = true, Name = "status")]
    public string? Status { get; set; }

    [BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    public IReadOnlyList<AlertRecord> Alerts { get; private set; } = Array.Empty<AlertRecord>();
    public bool HasPreviousPage => PageNumber > 1;
    public bool HasNextPage { get; private set; }
    public int FirstResultNumber => Alerts.Count == 0 ? 0 : ((PageNumber - 1) * PageSize) + 1;
    public int LastResultNumber => ((PageNumber - 1) * PageSize) + Alerts.Count;
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);
        try
        {
            var loadedAlerts = await alerts.SearchAlertsAsync(Status, cancellationToken, PageSize + 1, (PageNumber - 1) * PageSize);
            HasNextPage = loadedAlerts.Count > PageSize;
            Alerts = loadedAlerts.Take(PageSize).ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Alerts could not be loaded. Confirm the alert schema has been applied.";
        }
    }
}
