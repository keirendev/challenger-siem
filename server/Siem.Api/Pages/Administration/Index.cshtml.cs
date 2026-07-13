using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages.Administration;

[Authorize(Policy = "admin")]
public sealed class IndexModel(AdminRepository admin, SecurityAuditRepository audit, IOptions<ManagedRetentionOptions> retentionOptions, ILogger<IndexModel> logger) : PageModel
{
    public AdminOverviewResponse? Overview { get; private set; }
    public string? ErrorMessage { get; private set; }
    public string? SuccessMessage { get; private set; }

    [BindProperty] public string SettingKey { get; set; } = string.Empty;
    [BindProperty] public string SettingValue { get; set; } = string.Empty;
    [BindProperty] public int ExpectedVersion { get; set; }
    [BindProperty] public string ConfirmImpact { get; set; } = string.Empty;

    [BindProperty] public string SourceId { get; set; } = string.Empty;
    [BindProperty] public string DisplayName { get; set; } = string.Empty;
    [BindProperty] public string? ReviewNote { get; set; }
    [BindProperty] public DateTimeOffset? MutedUntil { get; set; }
    [BindProperty] public int SourceExpectedVersion { get; set; }
    [BindProperty] public string SourceConfirmImpact { get; set; } = string.Empty;

    public async Task OnGetAsync(CancellationToken cancellationToken) => await LoadAsync(cancellationToken);

    public async Task<IActionResult> OnPostSettingAsync(CancellationToken cancellationToken)
    {
        try
        {
            var updated = await admin.UpdateSettingAsync(new AdminConfigSettingRequest(SettingKey, SettingValue, ExpectedVersion, ConfirmImpact), User.Identity?.Name ?? "operator", HttpContext, audit, retentionOptions.Value, cancellationToken);
            SuccessMessage = updated is null ? null : $"Updated {updated.Key}.";
            ErrorMessage = updated is null ? "Configuration setting changed in another session. Reload and retry." : null;
        }
        catch (Exception ex) when (ex is ArgumentException)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Admin setting update failed.");
            ErrorMessage = "Server configuration setting could not be updated safely.";
        }
        await LoadAsync(cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostSourceAsync(CancellationToken cancellationToken)
    {
        try
        {
            var updated = await admin.UpdateSourceSettingAsync(new AdminSourceSettingRequest(SourceId, DisplayName, ReviewNote, MutedUntil, SourceExpectedVersion, SourceConfirmImpact), User.Identity?.Name ?? "operator", HttpContext, audit, cancellationToken);
            SuccessMessage = updated is null ? null : $"Updated review note for {updated.SourceId}.";
            ErrorMessage = updated is null ? "Source review setting changed in another session. Reload and retry." : null;
        }
        catch (Exception ex) when (ex is ArgumentException)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Source review setting update failed.");
            ErrorMessage = "Source review setting could not be updated safely.";
        }
        await LoadAsync(cancellationToken);
        return Page();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            Overview = await admin.GetOverviewAsync(retentionOptions.Value, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Administration overview could not be loaded.");
            ErrorMessage ??= "Administration data is currently unavailable.";
        }
    }
}
