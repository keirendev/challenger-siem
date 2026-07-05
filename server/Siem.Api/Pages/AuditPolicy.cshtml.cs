using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

public sealed class AuditPolicyModel(AssetInventoryRepository inventory) : PageModel
{
    public IReadOnlyList<AssetInventorySnapshot> Snapshots { get; private set; } = Array.Empty<AssetInventorySnapshot>();
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(string? agent_id, CancellationToken cancellationToken)
    {
        try
        {
            Snapshots = await inventory.SearchAsync(agent_id, "audit_policy", cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Audit-policy snapshots could not be loaded. Confirm the inventory schema has been applied.";
        }
    }
}
