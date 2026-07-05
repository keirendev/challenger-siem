using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Alerts;

public sealed class DetailModel(AlertRepository alerts) : PageModel
{
    public AlertRecord? Alert { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "alert_id")] Guid? alertId, CancellationToken cancellationToken)
    {
        if (!alertId.HasValue || alertId.Value == Guid.Empty)
        {
            ErrorMessage = "An alert_id query value is required.";
            return Page();
        }

        try
        {
            Alert = await alerts.GetAlertAsync(alertId.Value, cancellationToken);
            if (Alert is null)
            {
                ErrorMessage = "Alert was not found.";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Alert detail could not be loaded.";
        }

        return Page();
    }
}
