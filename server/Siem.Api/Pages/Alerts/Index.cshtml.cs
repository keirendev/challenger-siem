using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Alerts;

public sealed class IndexModel(AlertRepository alerts) : PageModel
{
    public string? Status { get; private set; }
    public IReadOnlyList<AlertRecord> Alerts { get; private set; } = Array.Empty<AlertRecord>();
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(string? status, CancellationToken cancellationToken)
    {
        Status = status;
        try
        {
            Alerts = await alerts.SearchAlertsAsync(status, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Alerts could not be loaded. Confirm the alert schema has been applied.";
        }
    }
}
