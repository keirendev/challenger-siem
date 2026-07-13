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

        if (report.PrerequisiteStatuses?.Values.Any(value => value == SourceEvidenceStatuses.PermissionDenied) == true)
        {
            return SourceHealthStatuses.PermissionDenied;
        }
        if (report.PrerequisiteStatuses?.Values.Any(value => value == SourceEvidenceStatuses.Unsupported) == true)
        {
            return SourceHealthStatuses.Unsupported;
        }
        if (report.PrerequisiteStatuses?.Values.Any(value => value is SourceEvidenceStatuses.Missing or SourceEvidenceStatuses.Degraded) == true)
        {
            return SourceHealthStatuses.Degraded;
        }
        if (report.EventFamilyStatuses?.Values.Any(value => value == SourceEvidenceStatuses.Stale) == true)
        {
            return SourceHealthStatuses.Stale;
        }

        var mandatory = report.Requirement switch
        {
            SourceRequirementKinds.Mandatory => true,
            SourceRequirementKinds.RoleSpecific => report.Applicability == SourceApplicabilityStatuses.Applicable,
            SourceRequirementKinds.Optional => false,
            _ => report.Required
        };
        if (mandatory
            && report.CoverageLevel >= WindowsCoverageLevel.L2
            && report.EventFamilyStatuses is { Count: > 0 }
            && report.EventFamilyStatuses.Values.All(value => value == SourceEvidenceStatuses.NotObserved))
        {
            return SourceHealthStatuses.Degraded;
        }
        if (mandatory && report.LastEventTime.HasValue && now - report.LastEventTime.Value.ToUniversalTime() > DefaultStaleAfter)
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
