using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Agents;

public sealed class DetailModel(SourceHealthRepository sourceHealth, TelemetryCoverageRepository telemetryCoverage) : PageModel
{
    public string? AgentId { get; private set; }
    public CoverageSummary? Summary { get; private set; }
    public AgentTelemetryCoverage? Coverage { get; private set; }
    public IReadOnlyList<SourceTelemetryCoverage> Sources { get; private set; } = Array.Empty<SourceTelemetryCoverage>();
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
            var coverageResponse = await telemetryCoverage.AssessAsync(agentId, WindowsCoverageLevel.L2, 24, cancellationToken);
            Coverage = coverageResponse.Agents.FirstOrDefault();
            Sources = Coverage?.Sources ?? response.Sources.Select(source => new SourceTelemetryCoverage
            {
                SourceId = source.SourceId,
                DisplayName = source.DisplayName,
                Channel = source.Channel,
                CoverageLevel = source.CoverageLevel,
                Required = source.Required,
                Enabled = source.Enabled,
                Status = source.Status,
                LastEventTime = source.LastEventTime,
                Reason = source.ErrorMessage ?? source.ErrorCode ?? string.Empty
            }).ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Source health could not be loaded. Confirm the database schema has been applied.";
        }

        return Page();
    }
}
