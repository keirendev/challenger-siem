using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Database;

public static class SourceHealthRules
{
    public static readonly TimeSpan DefaultStaleAfter = TimeSpan.FromHours(24);
    public static readonly TimeSpan PassivePollingStaleAfter = TimeSpan.FromHours(2);
    public static readonly TimeSpan PerformanceSloStaleAfter = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaximumFutureObservationSkew = TimeSpan.FromMinutes(5);

    private static readonly IReadOnlySet<string> LinuxPassivePollingSourceIds = LinuxTelemetrySourceCatalog.L3Passive
        .Select(source => source.SourceId)
        .Append(LinuxTelemetrySourceIds.PolicyPostureDrift)
        .Concat(LinuxTelemetrySourceCatalog.All
            .Where(source => source.CoverageLevel == WindowsCoverageLevel.L4
                && source.Requirement == SourceRequirementKinds.RoleSpecific)
            .Select(source => source.SourceId))
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlySet<string> TwoHourPollingSourceIds { get; } = LinuxPassivePollingSourceIds
        .Concat(LinuxTelemetrySourceCatalog.SuccessfulJournalObservationSourceIds)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlySet<string> PerformanceSloSourceIds { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { LinuxTelemetrySourceIds.AgentPerformanceSlo };

    private static readonly IReadOnlySet<string> SuccessfulDetectionObservationSourceIds =
        LinuxPassivePollingSourceIds
            .Append(LinuxTelemetrySourceIds.AgentLogTamper)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static bool IsSuccessfulPollingSource(string sourceId) =>
        SuccessfulDetectionObservationSourceIds.Contains(sourceId)
        || PerformanceSloSourceIds.Contains(sourceId);

    public static bool UsesSuccessfulObservationFreshness(string sourceId) =>
        TwoHourPollingSourceIds.Contains(sourceId)
        || PerformanceSloSourceIds.Contains(sourceId);

    public static TimeSpan? PollingStaleAfter(string sourceId)
    {
        if (PerformanceSloSourceIds.Contains(sourceId))
        {
            return PerformanceSloStaleAfter;
        }

        return TwoHourPollingSourceIds.Contains(sourceId) ? PassivePollingStaleAfter : null;
    }

    public static string EffectiveStatus(SourceHealthReport report, DateTimeOffset now)
    {
        if (TelemetrySourceKinds.UsesPortableIdentity(report.SourceKind)
            && string.Equals(report.Status, SourceHealthStatuses.Excepted, StringComparison.Ordinal))
        {
            // Coverage exceptions are server-owned. This defensive downgrade prevents a row
            // accepted before the current validation rule from satisfying coverage by itself.
            return SourceHealthStatuses.Degraded;
        }

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
        if (report.GapDetected || report.ClearedDetected || report.BookmarkGapDetected)
        {
            return SourceHealthStatuses.Error;
        }
        if (report.PrerequisiteStatuses?.Values.Any(value => value is SourceEvidenceStatuses.Missing or SourceEvidenceStatuses.Degraded) == true)
        {
            return SourceHealthStatuses.Degraded;
        }
        if (report.EventFamilyStatuses?.Values.Any(value => value == SourceEvidenceStatuses.Stale) == true)
        {
            return SourceHealthStatuses.Stale;
        }

        if (LinuxTelemetrySourceCatalog.JournalObservationRequiresProducerEvidenceSourceIds.Contains(report.SourceId)
            && !HasJournalProducerEvidence(report))
        {
            return SourceHealthStatuses.Degraded;
        }

        // Snapshot-diff, metrics, and quiet event-driven journal sources can be observed
        // successfully without emitting a new event. Their agent-reported source observation,
        // rather than production activity, is the freshness signal.
        var pollingStaleAfter = PollingStaleAfter(report.SourceId);
        if (pollingStaleAfter.HasValue
            && report.ObservedAt.HasValue
            && report.ObservedAt.Value.ToUniversalTime() > now.ToUniversalTime() + MaximumFutureObservationSkew)
        {
            return SourceHealthStatuses.Degraded;
        }
        if (pollingStaleAfter.HasValue
            && (!report.ObservedAt.HasValue
                || now - report.ObservedAt.Value.ToUniversalTime() > pollingStaleAfter.Value))
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
            && !UsesSuccessfulObservationFreshness(report.SourceId)
            && report.CoverageLevel >= WindowsCoverageLevel.L2
            && report.EventFamilyStatuses is { Count: > 0 }
            && report.EventFamilyStatuses.Values.All(value => value == SourceEvidenceStatuses.NotObserved))
        {
            return SourceHealthStatuses.Degraded;
        }
        if (mandatory
            && !UsesSuccessfulObservationFreshness(report.SourceId)
            && report.LastEventTime.HasValue
            && now - report.LastEventTime.Value.ToUniversalTime() > DefaultStaleAfter)
        {
            return SourceHealthStatuses.Stale;
        }

        return report.Status;
    }

    private static bool HasJournalProducerEvidence(SourceHealthReport report)
    {
        if (report.EventFamilyStatuses?.Values.Any(value => value == SourceEvidenceStatuses.Observed) == true)
        {
            return true;
        }

        return report.SourceId switch
        {
            LinuxTelemetrySourceIds.Firewall => report.PrerequisiteStatuses?.GetValueOrDefault("firewall_logging_already_enabled")
                == SourceEvidenceStatuses.Satisfied,
            LinuxTelemetrySourceIds.Ssh => report.PrerequisiteStatuses?.GetValueOrDefault("sshd_journal_visibility")
                == SourceEvidenceStatuses.Satisfied,
            _ => false
        };
    }
}
