using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Contracts.V1;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class TelemetryCoverageEvaluatorTests
{
    [Fact]
    public void PassivePollingObservationSatisfiesRecencyWithoutAnEmittedEvent()
    {
        var rule = Rule("synthetic.passive-poll", LinuxTelemetrySourceIds.ProcessSnapshotDiff);
        var source = Source(
            LinuxTelemetrySourceIds.ProcessSnapshotDiff,
            TelemetrySourceKinds.InventoryDiff,
            recentEventCount: 0,
            observedAt: DateTimeOffset.Parse("2026-07-16T01:00:00Z"));

        var result = Assert.Single(TelemetryCoverageEvaluator.EvaluateDetectionPrerequisites(
            [rule],
            [source],
            new Dictionary<string, InventoryTelemetryStatus>(StringComparer.OrdinalIgnoreCase),
            WindowsCoverageLevel.L3));

        Assert.Equal(TelemetryCoverageEvaluator.StatusSatisfied, result.Status);
        Assert.Contains(LinuxTelemetrySourceIds.ProcessSnapshotDiff, result.RecentEventSources);
    }

    [Fact]
    public void NonPassiveObservationDoesNotReplaceRecentEventEvidence()
    {
        var rule = Rule("synthetic.journal", LinuxTelemetrySourceIds.JournalL1);
        var source = Source(
            LinuxTelemetrySourceIds.JournalL1,
            TelemetrySourceKinds.LinuxJournal,
            recentEventCount: 0,
            observedAt: DateTimeOffset.Parse("2026-07-16T01:00:00Z"),
            coverageLevel: WindowsCoverageLevel.L1);

        var result = Assert.Single(TelemetryCoverageEvaluator.EvaluateDetectionPrerequisites(
            [rule],
            [source],
            new Dictionary<string, InventoryTelemetryStatus>(StringComparer.OrdinalIgnoreCase),
            WindowsCoverageLevel.L1));

        Assert.Equal(TelemetryCoverageEvaluator.StatusUnknown, result.Status);
        Assert.Empty(result.RecentEventSources);
    }

    [Fact]
    public void HealthyAnyOfAlternativeDoesNotReportSiblingAlternativesAsMissing()
    {
        var rule = Rule(
            "synthetic.any-of-without-events",
            LinuxTelemetrySourceIds.JournalL1,
            LinuxTelemetrySourceIds.AgentLogTamper);
        var source = Source(
            LinuxTelemetrySourceIds.JournalL1,
            TelemetrySourceKinds.LinuxJournal,
            recentEventCount: 0,
            coverageLevel: WindowsCoverageLevel.L1);

        var result = Assert.Single(TelemetryCoverageEvaluator.EvaluateDetectionPrerequisites(
            [rule],
            [source],
            new Dictionary<string, InventoryTelemetryStatus>(StringComparer.OrdinalIgnoreCase),
            WindowsCoverageLevel.L2));

        Assert.Equal(TelemetryCoverageEvaluator.StatusUnknown, result.Status);
        Assert.Contains(LinuxTelemetrySourceIds.JournalL1, result.HealthySources);
        Assert.Empty(result.MissingSources);
        Assert.Empty(result.StaleSources);
    }

    [Theory]
    [InlineData("inventory-diff", LinuxTelemetrySourceIds.ProcessSnapshotDiff, TelemetrySourceKinds.InventoryDiff)]
    [InlineData("agent-health", LinuxTelemetrySourceIds.HostBehaviourMetrics, TelemetrySourceKinds.AgentHealth)]
    public void GenericSourceKindAliasSatisfiesAnyOfPrerequisite(
        string alias,
        string concreteSourceId,
        string concreteSourceKind)
    {
        var rule = Rule(
            "synthetic.any-of",
            LinuxTelemetrySourceIds.AgentLogTamper,
            alias);
        var source = Source(concreteSourceId, concreteSourceKind, recentEventCount: 1);

        var result = Assert.Single(TelemetryCoverageEvaluator.EvaluateDetectionPrerequisites(
            [rule],
            [source],
            new Dictionary<string, InventoryTelemetryStatus>(StringComparer.OrdinalIgnoreCase),
            WindowsCoverageLevel.L3));

        Assert.Equal(TelemetryCoverageEvaluator.StatusSatisfied, result.Status);
        Assert.Contains(alias, result.HealthySources);
        Assert.Contains(alias, result.RecentEventSources);
        Assert.Empty(result.MissingSources);
        Assert.Empty(result.StaleSources);
    }

    [Fact]
    public void RelevantMandatoryLinuxL3SourceCannotBeCoveredAsNotApplicable()
    {
        var blockedSource = LinuxTelemetrySourceCatalog.L3Passive.Single(entry =>
            entry.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
        Assert.Equal(SourceRequirementKinds.Mandatory, blockedSource.Requirement);

        var sources = LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L3)
            .Select(entry =>
            {
                var blocked = entry.SourceId == blockedSource.SourceId;
                var mandatory = entry.Requirement == SourceRequirementKinds.Mandatory;
                var applicable = mandatory && !blocked;
                return new SourceHealthReport
                {
                    SourceId = entry.SourceId,
                    Platform = entry.Platform,
                    SourceKind = entry.SourceKind,
                    DisplayName = entry.DisplayName,
                    CoverageLevel = entry.CoverageLevel,
                    Requirement = entry.Requirement,
                    Required = entry.Required,
                    Applicability = applicable
                        ? SourceApplicabilityStatuses.Applicable
                        : SourceApplicabilityStatuses.NotApplicable,
                    Status = applicable
                        ? SourceHealthStatuses.Healthy
                        : SourceHealthStatuses.NotApplicable,
                    Enabled = applicable
                };
            })
            .ToArray();

        var level = TelemetryCoverageEvaluator.CalculateCurrentLevel(
            sources,
            WindowsCoverageLevel.L3,
            TelemetryPlatforms.Linux);

        Assert.Equal(WindowsCoverageLevel.L2, level);
    }

    private static DetectionRuleMetadata Rule(string ruleId, params string[] requiredSources) => new()
    {
        RuleId = ruleId,
        Name = ruleId,
        Category = "synthetic",
        RequiredSources = requiredSources,
        Enabled = true
    };

    private static SourceTelemetryCoverage Source(
        string sourceId,
        string sourceKind,
        int recentEventCount,
        DateTimeOffset? observedAt = null,
        WindowsCoverageLevel coverageLevel = WindowsCoverageLevel.L3) => new()
        {
            SourceId = sourceId,
            Platform = TelemetryPlatforms.Linux,
            SourceKind = sourceKind,
            CoverageLevel = coverageLevel,
            Applicability = SourceApplicabilityStatuses.Applicable,
            Status = SourceHealthStatuses.Healthy,
            Enabled = true,
            Reported = true,
            ObservedAt = observedAt,
            RecentEventCount = recentEventCount
        };
}
