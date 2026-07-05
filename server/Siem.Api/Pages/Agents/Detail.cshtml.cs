using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Agents;

public sealed class DetailModel(SourceHealthRepository sourceHealth) : PageModel
{
    public string? AgentId { get; private set; }
    public CoverageSummary? Summary { get; private set; }
    public IReadOnlyList<SourceHealthReport> Sources { get; private set; } = Array.Empty<SourceHealthReport>();
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "agent_id")] string? agentId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(agentId))
        {
            ErrorMessage = "An agent_id query value is required.";
            return Page();
        }

        AgentId = agentId;
        try
        {
            var response = await sourceHealth.SearchAsync(agentId, cancellationToken);
            Summary = response.Summaries.FirstOrDefault();
            Sources = response.Sources;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Source health could not be loaded. Confirm the database schema has been applied.";
        }

        return Page();
    }
}
