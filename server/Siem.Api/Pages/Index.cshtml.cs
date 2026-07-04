using Challenger.Siem.Api.Review;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages;

public sealed class IndexModel(
    ReviewRepository reviewRepository,
    IOptions<ReviewOptions> reviewOptions,
    ILogger<IndexModel> logger) : PageModel
{
    private readonly ReviewOptions options = reviewOptions.Value;

    public DashboardSummary Summary { get; private set; } = DashboardSummary.Empty;

    public string? ErrorMessage { get; private set; }

    public int StaleAgentMinutes => Math.Clamp(options.StaleAgentMinutes, 1, 24 * 60);

    public int RecentEventWindowHours => Math.Clamp(options.RecentEventHours, 1, 24 * 30);

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        try
        {
            Summary = await reviewRepository.GetDashboardSummaryAsync(
                options.StaleAgentAfter,
                options.RecentEventWindow,
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Dashboard summary could not be loaded.");
            ErrorMessage = "Dashboard data is currently unavailable.";
        }
    }
}
