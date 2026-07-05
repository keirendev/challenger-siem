using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Coverage;

public sealed record EventLogBaselineResult(string SourceId, bool MeetsBaseline, string Reason);

public static class EventLogBaselineRules
{
    public const long DefaultMinimumLogSizeBytes = 64L * 1024L * 1024L;
    public const int DefaultMinimumRetentionDays = 7;

    public static EventLogBaselineResult Evaluate(SourceHealthReport report)
    {
        if (report.LogSizeBytes.HasValue && report.LogSizeBytes.Value < DefaultMinimumLogSizeBytes)
        {
            return new EventLogBaselineResult(report.SourceId, false, "log size below L2 baseline");
        }

        if (report.RetentionDays.HasValue && report.RetentionDays.Value < DefaultMinimumRetentionDays)
        {
            return new EventLogBaselineResult(report.SourceId, false, "retention below L2 baseline");
        }

        return new EventLogBaselineResult(report.SourceId, true, "baseline met or not enough data");
    }
}
