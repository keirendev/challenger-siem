using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Pages;

public sealed class IndexModel(
    ReviewRepository reviewRepository,
    EventRepository eventRepository,
    DashboardRepository dashboardRepository,
    AlertRepository alertRepository,
    IOptions<ReviewOptions> reviewOptions,
    IOptions<ManagedRetentionOptions> retentionOptions,
    ILogger<IndexModel> logger) : PageModel
{
    private readonly ReviewOptions options = reviewOptions.Value;

    public DashboardSummary Summary { get; private set; } = DashboardSummary.Empty;

    public ManagedStorageAccounting? StorageAccounting { get; private set; }

    public DashboardAggregationResponse? Operations { get; private set; }

    public IReadOnlyList<AlertRecord> RecentAlerts { get; private set; } = Array.Empty<AlertRecord>();

    public string? ErrorMessage { get; private set; }

    public int StaleAgentMinutes => Math.Clamp(options.StaleAgentMinutes, 1, 24 * 60);

    public int RecentEventWindowHours => Math.Clamp(options.RecentEventHours, 1, 24 * 30);

    public int DashboardWindowHours => Math.Clamp(RecentEventWindowHours, 1, 168);

    public long RecentAlertCount => Operations?.AlertStatuses.Sum(item => item.Count) ?? 0;

    public bool CanUseCases => OperatorAuthorization.HasPermission(
        OperatorAuthorization.Role(User),
        OperatorPermission.ManageInvestigations);

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        try
        {
            Summary = await reviewRepository.GetDashboardSummaryAsync(
                options.StaleAgentAfter,
                options.RecentEventWindow,
                cancellationToken);
            StorageAccounting = await eventRepository.GetManagedStorageAccountingAsync(
                retentionOptions.Value.ManagedCapacityBytes,
                cancellationToken,
                retentionOptions.Value.TargetRetentionDays);
            Operations = await dashboardRepository.GetAggregationsAsync(DashboardWindowHours, cancellationToken);
            var role = OperatorAuthorization.Role(User) ?? OperatorRoles.Viewer;
            RecentAlerts = (await alertRepository.SearchAlertsAsync(null, cancellationToken, 6))
                .Select(alert => AlertFieldPolicy.Apply(alert, role))
                .ToArray();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Dashboard summary could not be loaded.");
            ErrorMessage = "Dashboard data is currently unavailable.";
        }
    }
}
