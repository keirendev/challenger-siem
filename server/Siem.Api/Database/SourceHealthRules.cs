using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Database;

public static class SourceHealthRules
{
    public static readonly TimeSpan DefaultStaleAfter = TimeSpan.FromHours(24);

    public static string EffectiveStatus(SourceHealthReport report, DateTimeOffset now)
    {
        if (!string.Equals(report.Status, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase))
        {
            return report.Status;
        }

        if (report.Required && report.LastEventTime.HasValue && now - report.LastEventTime.Value.ToUniversalTime() > DefaultStaleAfter)
        {
            return SourceHealthStatuses.Stale;
        }

        if (report.GapDetected || report.ClearedDetected || report.BookmarkGapDetected)
        {
            return SourceHealthStatuses.Error;
        }

        return report.Status;
    }
}
