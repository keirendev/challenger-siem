using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;

namespace Challenger.Siem.Api.Pages.Dashboards;

public sealed class IndexModel(DashboardRepository dashboards, SecurityAuditRepository audit, ILogger<IndexModel> logger) : PageModel
{
    public DashboardAggregationResponse? Summary { get; private set; }
    public IReadOnlyList<DashboardLayoutRecord> Layouts { get; private set; } = Array.Empty<DashboardLayoutRecord>();
    public string? ErrorMessage { get; private set; }
    public string? SuccessMessage { get; private set; }
    public int TimeRangeHours { get; private set; } = 24;
    public bool CanSave => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(User), OperatorPermission.ManageInvestigations);

    [BindProperty] public string Name { get; set; } = string.Empty;
    [BindProperty] public string Visibility { get; set; } = "private";
    [BindProperty] public int LayoutTimeRangeHours { get; set; } = 24;
    [BindProperty] public int RefreshMinutes { get; set; } = 15;
    [BindProperty] public string? LayoutJson { get; set; }

    public async Task OnGetAsync(int? time_range_hours, CancellationToken cancellationToken)
    {
        TimeRangeHours = Math.Clamp(time_range_hours ?? 24, 1, 168);
        await LoadAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostSaveAsync(CancellationToken cancellationToken)
    {
        if (!CanSave) return Forbid();
        TimeRangeHours = Math.Clamp(LayoutTimeRangeHours, 1, 168);
        try
        {
            var operatorId = OperatorAuthentication.OperatorId(User) ?? throw new InvalidOperationException("Operator session is missing an identifier.");
            var layout = string.IsNullOrWhiteSpace(LayoutJson) ? JsonDocument.Parse("{}").RootElement : JsonDocument.Parse(LayoutJson).RootElement.Clone();
            var saved = await dashboards.SaveLayoutAsync(operatorId, User.Identity?.Name ?? "operator", OperatorAuthorization.Role(User)!, new DashboardLayoutRequest(Name, Visibility, LayoutTimeRangeHours, RefreshMinutes, layout, null), HttpContext, audit, cancellationToken);
            SuccessMessage = $"Saved dashboard layout {saved.Name}.";
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Dashboard layout save failed.");
            ErrorMessage = "Dashboard layout could not be saved.";
        }

        await LoadAsync(cancellationToken);
        return Page();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            Summary = await dashboards.GetAggregationsAsync(TimeRangeHours, cancellationToken);
            var operatorId = OperatorAuthentication.OperatorId(User);
            Layouts = operatorId.HasValue ? await dashboards.ListLayoutsAsync(operatorId.Value, cancellationToken) : Array.Empty<DashboardLayoutRecord>();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Dashboard data could not be loaded.");
            ErrorMessage ??= "Dashboard data is currently unavailable.";
        }
    }
}
