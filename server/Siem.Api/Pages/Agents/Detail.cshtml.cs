using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Agents;

public sealed class DetailModel(SourceHealthRepository sourceHealth, TelemetryCoverageRepository telemetryCoverage) : PageModel
{
    public string? AgentId { get; private set; }
    public WindowsCoverageLevel TargetLevel { get; private set; } = WindowsCoverageLevel.L3;
    public IReadOnlyList<WindowsCoverageLevel> TargetLevels { get; } = new[] { WindowsCoverageLevel.L1, WindowsCoverageLevel.L2, WindowsCoverageLevel.L3, WindowsCoverageLevel.L4 };
    public CoverageSummary? Summary { get; private set; }
    public AgentTelemetryCoverage? Coverage { get; private set; }
    public IReadOnlyList<SourceTelemetryCoverage> Sources { get; private set; } = Array.Empty<SourceTelemetryCoverage>();
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(
        [FromQuery(Name = "agent_id")] string? agentId,
        [FromQuery(Name = "target_level")] string? targetLevel,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(agentId))
        {
            ErrorMessage = "An agent_id query value is required.";
            return Page();
        }

        AgentId = agentId;
        TargetLevel = ParseTargetLevel(targetLevel);
        try
        {
            var response = await sourceHealth.SearchAsync(agentId, TargetLevel, cancellationToken);
            Summary = response.Summaries.FirstOrDefault();
            var coverageResponse = await telemetryCoverage.AssessAsync(agentId, TargetLevel, 24, cancellationToken);
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
                HostTimezone = source.HostTimezone ?? Summary?.HostTimezone,
                SourceVersion = source.SourceVersion,
                ConfigHash = source.ConfigHash,
                Details = source.Details,
                Reason = source.ErrorMessage ?? source.ErrorCode ?? string.Empty
            }).ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "Source health could not be loaded. Confirm the database schema has been applied.";
        }

        return Page();
    }

    private static WindowsCoverageLevel ParseTargetLevel(string? targetLevel)
    {
        return Enum.TryParse<WindowsCoverageLevel>(targetLevel, ignoreCase: true, out var parsed) && parsed is >= WindowsCoverageLevel.L1 and <= WindowsCoverageLevel.L4
            ? parsed
            : WindowsCoverageLevel.L3;
    }
}
