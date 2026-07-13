using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Detections;

public sealed class IndexModel(
    AlertRepository alerts,
    DetectionManagementRepository detections,
    SecurityAuditRepository audit,
    ILogger<IndexModel> logger) : PageModel
{
    public IReadOnlyList<DetectionRuleManagementRecord> Rules { get; private set; } = Array.Empty<DetectionRuleManagementRecord>();
    public string? ErrorMessage { get; private set; }
    public string? SuccessMessage { get; private set; }
    public bool CanManage => OperatorAuthorization.HasPermission(OperatorAuthorization.Role(User), OperatorPermission.ManageDetections);

    [BindProperty] public string RuleId { get; set; } = string.Empty;
    [BindProperty] public int RuleVersion { get; set; }
    [BindProperty] public int ExpectedVersion { get; set; }
    [BindProperty] public bool Enabled { get; set; }
    [BindProperty] public string LifecycleState { get; set; } = "active";
    [BindProperty] public string ValidationStatus { get; set; } = "synthetic_passed";
    [BindProperty] public string? TuningNotes { get; set; }
    [BindProperty] public string? SuppressionNotes { get; set; }
    [BindProperty] public string ConfirmImpact { get; set; } = string.Empty;

    public async Task OnGetAsync(CancellationToken cancellationToken) => await LoadAsync(cancellationToken);

    public async Task<IActionResult> OnPostSettingsAsync(CancellationToken cancellationToken)
    {
        if (!CanManage)
        {
            return Forbid();
        }

        try
        {
            var rules = await alerts.GetRulesAsync(cancellationToken);
            var updated = await detections.UpdateSettingsAsync(rules, RuleId, RuleVersion, new DetectionRuleSettingsRequest(
                ExpectedVersion,
                Enabled,
                LifecycleState,
                ValidationStatus,
                TuningNotes,
                SuppressionNotes,
                ConfirmImpact), User.Identity?.Name ?? "operator", HttpContext, audit, cancellationToken);
            if (updated is null)
            {
                ErrorMessage = "Detection rule settings changed in another session. Reload and retry with the current version.";
            }
            else
            {
                SuccessMessage = $"Updated {updated.Rule.RuleId} version {updated.Rule.Version}.";
            }
        }
        catch (Exception ex) when (ex is ArgumentException or KeyNotFoundException)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Detection settings update failed.");
            ErrorMessage = "Detection settings could not be updated safely.";
        }

        await LoadAsync(cancellationToken);
        return Page();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var rules = await alerts.GetRulesAsync(cancellationToken);
            Rules = await detections.ListAsync(rules, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Detection catalog could not be loaded.");
            ErrorMessage ??= "Detection catalog is currently unavailable.";
        }
    }
}
