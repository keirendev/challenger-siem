using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Alerts;

public sealed class DetailModel(AlertRepository alerts, CaseRepository cases) : PageModel
{
    [BindProperty]
    public Guid AlertId { get; set; }

    [BindProperty]
    public int ExpectedVersion { get; set; }
    [BindProperty]
    public string? Owner { get; set; }
    [BindProperty]
    public string? Status { get; set; }
    [BindProperty]
    public string? SuppressionReason { get; set; }
    [BindProperty]
    public DateTimeOffset? SuppressedUntil { get; set; }
    [BindProperty]
    public string? Disposition { get; set; }
    [BindProperty]
    public string? ClosureSummary { get; set; }
    [BindProperty]
    public bool ConfirmSuppress { get; set; }
    [BindProperty]
    public bool ConfirmClose { get; set; }
    [BindProperty]
    public string? CaseTitle { get; set; }
    [BindProperty]
    public string CasePriority { get; set; } = CasePriorities.Normal;

    [TempData]
    public string? Message { get; set; }
    [TempData]
    public string? ErrorMessage { get; set; }

    public AlertRecord? Alert { get; private set; }

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "alert_id")] Guid? alertId, CancellationToken cancellationToken)
    {
        if (!alertId.HasValue || alertId.Value == Guid.Empty)
        {
            ErrorMessage = "An alert_id query value is required.";
            return Page();
        }

        try
        {
            var loaded = await alerts.GetAlertAsync(alertId.Value, cancellationToken);
            Alert = loaded is null ? null : AlertFieldPolicy.Apply(loaded, OperatorAuthorization.Role(User)!);
            if (loaded is not null)
            {
                AlertId = loaded.AlertId;
                ExpectedVersion = loaded.Version;
                Owner = loaded.Owner;
                Status = loaded.Status;
                SuppressionReason = loaded.SuppressionReason;
                SuppressedUntil = loaded.SuppressedUntil;
                Disposition = loaded.Disposition;
                ClosureSummary = loaded.ClosureSummary;
                CaseTitle = loaded.Title;
            }
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

    public async Task<IActionResult> OnPostAssignAsync(CancellationToken cancellationToken) => await MutateAsync(() => alerts.AssignAsync(AlertId, new AlertMutationRequest { ExpectedVersion = ExpectedVersion, Owner = Owner, IdempotencyKey = NewKey("assign") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert assigned.", cancellationToken);
    public async Task<IActionResult> OnPostAcknowledgeAsync(CancellationToken cancellationToken) => await MutateAsync(() => alerts.AcknowledgeAsync(AlertId, new AlertMutationRequest { ExpectedVersion = ExpectedVersion, IdempotencyKey = NewKey("ack") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert acknowledged.", cancellationToken);
    public async Task<IActionResult> OnPostStatusAsync(CancellationToken cancellationToken) => await MutateAsync(() => alerts.SetStatusAsync(AlertId, new AlertMutationRequest { ExpectedVersion = ExpectedVersion, Status = Status, IdempotencyKey = NewKey("status") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert status updated.", cancellationToken);
    public async Task<IActionResult> OnPostSuppressAsync(CancellationToken cancellationToken)
    {
        if (!ConfirmSuppress) { ErrorMessage = "Suppression requires explicit confirmation."; return RedirectToPage(new { alert_id = AlertId }); }
        return await MutateAsync(() => alerts.SuppressAsync(AlertId, new AlertMutationRequest { ExpectedVersion = ExpectedVersion, Reason = SuppressionReason, SuppressedUntil = SuppressedUntil, IdempotencyKey = NewKey("suppress") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert suppressed.", cancellationToken);
    }
    public async Task<IActionResult> OnPostCloseAsync(CancellationToken cancellationToken)
    {
        if (!ConfirmClose) { ErrorMessage = "Closure requires explicit confirmation."; return RedirectToPage(new { alert_id = AlertId }); }
        return await MutateAsync(() => alerts.CloseAsync(AlertId, new AlertMutationRequest { ExpectedVersion = ExpectedVersion, Disposition = Disposition, Summary = ClosureSummary, IdempotencyKey = NewKey("close") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert closed.", cancellationToken);
    }
    public async Task<IActionResult> OnPostReopenAsync(CancellationToken cancellationToken) => await MutateAsync(() => alerts.ReopenAsync(AlertId, new AlertMutationRequest { ExpectedVersion = ExpectedVersion, IdempotencyKey = NewKey("reopen") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert reopened.", cancellationToken);

    public async Task<IActionResult> OnPostCreateCaseAsync(CancellationToken cancellationToken)
    {
        if (!OperatorAuthorization.HasPermission(OperatorAuthorization.Role(User), OperatorPermission.ManageInvestigations)) return Forbid();
        try
        {
            var created = await cases.CreateAsync(new CaseCreateRequest { Title = string.IsNullOrWhiteSpace(CaseTitle) ? "Case from alert" : CaseTitle, Owner = User.Identity?.Name, Severity = Alert?.Severity ?? DetectionSeverities.Medium, Priority = CasePriority, AlertIds = new[] { AlertId }, IdempotencyKey = NewKey("case") }, User.Identity?.Name ?? "operator", cancellationToken);
            Message = $"Case {created.CaseKey} created.";
            return RedirectToPage("/Cases/Detail", new { case_id = created.CaseId });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
            return RedirectToPage(new { alert_id = AlertId });
        }
    }

    private async Task<IActionResult> MutateAsync(Func<Task<AlertRecord?>> action, string success, CancellationToken cancellationToken)
    {
        if (!OperatorAuthorization.HasPermission(OperatorAuthorization.Role(User), OperatorPermission.ManageInvestigations)) return Forbid();
        try
        {
            var result = await action();
            ErrorMessage = result is null ? "Alert changed in another request or was not found; reload and try again." : null;
            Message = result is null ? null : success;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
        }
        return RedirectToPage(new { alert_id = AlertId });
    }

    private static string NewKey(string prefix) => $"web-alert-{prefix}-{Guid.NewGuid():N}";
}
