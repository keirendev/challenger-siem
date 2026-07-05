using Challenger.Siem.Api.Review;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages.Agents;

public sealed class IndexModel(
    ReviewRepository reviewRepository,
    IOptions<ReviewOptions> reviewOptions,
    ILogger<IndexModel> logger) : PageModel
{
    private const int CleanupSampleLimit = 10;
    public const int PageSize = 50;

    [BindProperty(SupportsGet = true, Name = "hostname")]
    public string? Hostname { get; set; }

    [BindProperty(SupportsGet = true, Name = "agent_id")]
    public string? AgentId { get; set; }

    [BindProperty(SupportsGet = true, Name = "health")]
    public string? Health { get; set; }

    [BindProperty(SupportsGet = true, Name = "status")]
    public string? Status { get; set; } = "active";

    [BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    [BindProperty]
    public bool ConfirmCleanup { get; set; }

    [TempData]
    public string? CleanupMessage { get; set; }

    [TempData]
    public string? CleanupErrorMessage { get; set; }

    public IReadOnlyList<AgentInventoryItem> Agents { get; private set; } = Array.Empty<AgentInventoryItem>();

    public bool HasPreviousPage => PageNumber > 1;

    public bool HasNextPage { get; private set; }

    public int FirstResultNumber => Agents.Count == 0 ? 0 : ((PageNumber - 1) * PageSize) + 1;

    public int LastResultNumber => ((PageNumber - 1) * PageSize) + Agents.Count;

    public StaleAgentCleanupPreview CleanupPreview { get; private set; } = StaleAgentCleanupPreview.Empty;

    public string? ErrorMessage { get; private set; }

    public int StaleAgentMinutes => Math.Clamp(reviewOptions.Value.StaleAgentMinutes, 1, 24 * 60);

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Status = NormalizeStatus(Status);
        PageNumber = Math.Max(1, PageNumber);
        await LoadPageDataAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostCleanupStaleAsync(CancellationToken cancellationToken)
    {
        Status = NormalizeStatus(Status);
        PageNumber = Math.Max(1, PageNumber);
        if (!ConfirmCleanup)
        {
            CleanupErrorMessage = "Confirm the non-destructive stale-agent cleanup before retiring agents.";
            return RedirectToPage(new { hostname = Hostname, agent_id = AgentId, health = Health, status = Status, page = PageNumber });
        }

        try
        {
            var summary = await reviewRepository.DisableStaleAgentsAsync(
                reviewOptions.Value.StaleAgentAfter,
                CleanupSampleLimit,
                cancellationToken);

            CleanupMessage = summary.DisabledCount == 0
                ? "No stale active agents matched the cleanup cutoff."
                : $"Retired {summary.DisabledCount} stale active agent(s); {summary.SkippedRecentCount} recent active agent(s) were left active.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Stale-agent cleanup could not be completed.");
            CleanupErrorMessage = "Stale-agent cleanup could not be completed.";
        }

        return RedirectToPage(new { hostname = Hostname, agent_id = AgentId, health = Health, status = Status, page = PageNumber });
    }

    private async Task LoadPageDataAsync(CancellationToken cancellationToken)
    {
        try
        {
            var options = reviewOptions.Value;
            CleanupPreview = await reviewRepository.GetStaleAgentCleanupPreviewAsync(
                options.StaleAgentAfter,
                CleanupSampleLimit,
                cancellationToken);
            var loadedAgents = await reviewRepository.SearchAgentsAsync(
                new AgentInventoryQuery(Hostname, AgentId, Health, Status),
                options.StaleAgentAfter,
                cancellationToken,
                PageSize + 1,
                (PageNumber - 1) * PageSize);
            HasNextPage = loadedAgents.Count > PageSize;
            Agents = loadedAgents.Take(PageSize).ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Agent inventory could not be loaded.");
            ErrorMessage = "Agent inventory is currently unavailable.";
        }
    }

    private static string NormalizeStatus(string? status)
    {
        return status?.Trim().ToLowerInvariant() switch
        {
            "all" => "all",
            "disabled" => "disabled",
            _ => "active"
        };
    }
}
