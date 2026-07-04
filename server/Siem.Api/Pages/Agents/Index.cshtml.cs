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
    [BindProperty(SupportsGet = true, Name = "hostname")]
    public string? Hostname { get; set; }

    [BindProperty(SupportsGet = true, Name = "agent_id")]
    public string? AgentId { get; set; }

    [BindProperty(SupportsGet = true, Name = "health")]
    public string? Health { get; set; }

    public IReadOnlyList<AgentInventoryItem> Agents { get; private set; } = Array.Empty<AgentInventoryItem>();

    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        try
        {
            Agents = await reviewRepository.SearchAgentsAsync(
                new AgentInventoryQuery(Hostname, AgentId, Health),
                reviewOptions.Value.StaleAgentAfter,
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Agent inventory could not be loaded.");
            ErrorMessage = "Agent inventory is currently unavailable.";
        }
    }
}
