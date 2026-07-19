using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Api.Pages.Agents;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class LinuxL2CoverageTests
{
    [Fact]
    public void LinuxCatalogOverlayDistinguishesRequirementApplicabilityAndUnsupportedStates()
    {
        var merged = TelemetryCoverageEvaluator.MergeExpectedSources(
            Array.Empty<SourceHealthReport>(),
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            DateTimeOffset.Parse("2026-07-13T12:00:00Z"),
            TelemetryPlatforms.Linux);

        var login = Assert.Single(merged, source => source.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceRequirementKinds.Mandatory, login.Requirement);
        Assert.Equal(SourceHealthStatuses.Missing, login.Status);
        var ssh = Assert.Single(merged, source => source.SourceId == LinuxTelemetrySourceIds.Ssh);
        Assert.Equal(SourceRequirementKinds.RoleSpecific, ssh.Requirement);
        Assert.Equal(SourceApplicabilityStatuses.Unknown, ssh.Applicability);
        Assert.Equal(SourceHealthStatuses.Degraded, ssh.Status);
        var firewall = Assert.Single(merged, source => source.SourceId == LinuxTelemetrySourceIds.Firewall);
        Assert.Equal(SourceRequirementKinds.Optional, firewall.Requirement);
        Assert.Equal(SourceApplicabilityStatuses.Unknown, firewall.Applicability);
        Assert.Equal(SourceHealthStatuses.Degraded, firewall.Status);
        var audit = Assert.Single(merged, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        Assert.Equal(SourceApplicabilityStatuses.Unsupported, audit.Applicability);
        Assert.Equal(SourceHealthStatuses.Unsupported, audit.Status);
        Assert.All(audit.PrerequisiteStatuses!.Values, state => Assert.Equal(SourceEvidenceStatuses.Unsupported, state));

        var incorrectlyReportedAudit = Report(LinuxTelemetrySourceCatalog.UnsupportedAuditFramework, DateTimeOffset.Parse("2026-07-13T12:00:00Z")) with
        {
            Applicability = SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = null,
            Status = SourceHealthStatuses.Healthy,
            Enabled = true,
            PrerequisiteStatuses = new Dictionary<string, string> { ["linux_audit_collector"] = SourceEvidenceStatuses.Satisfied },
            EventFamilyStatuses = new Dictionary<string, string> { ["audit"] = SourceEvidenceStatuses.Observed }
        };
        var canonical = TelemetryCoverageEvaluator.MergeExpectedSources(
            [incorrectlyReportedAudit],
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { LinuxTelemetrySourceIds.AuditFramework },
            DateTimeOffset.Parse("2026-07-13T12:00:00Z"),
            TelemetryPlatforms.Linux);
        var canonicalAudit = Assert.Single(canonical, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        Assert.Equal(SourceApplicabilityStatuses.Unsupported, canonicalAudit.Applicability);
        Assert.Equal(SourceHealthStatuses.Unsupported, canonicalAudit.Status);
        Assert.False(canonicalAudit.Enabled);
        Assert.All(canonicalAudit.EventFamilyStatuses!.Values, state => Assert.Equal(SourceEvidenceStatuses.Unsupported, state));

        var loginManifest = LinuxTelemetrySourceCatalog.L2Security.Single(entry => entry.SourceId == LinuxTelemetrySourceIds.LoginSession);
        var incorrectlyInapplicableLogin = Report(loginManifest, DateTimeOffset.Parse("2026-07-13T12:00:00Z")) with
        {
            Applicability = SourceApplicabilityStatuses.NotApplicable,
            ApplicabilityReason = "synthetic_invalid_override",
            Status = SourceHealthStatuses.NotApplicable,
            Enabled = false,
            PrerequisiteStatuses = loginManifest.Prerequisites.ToDictionary(item => item, _ => SourceEvidenceStatuses.NotApplicable, StringComparer.Ordinal),
            EventFamilyStatuses = loginManifest.EventFamilies.ToDictionary(item => item, _ => SourceEvidenceStatuses.NotApplicable, StringComparer.Ordinal)
        };
        var requiredCanonical = TelemetryCoverageEvaluator.MergeExpectedSources(
            [incorrectlyInapplicableLogin],
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            DateTimeOffset.Parse("2026-07-13T12:00:00Z"),
            TelemetryPlatforms.Linux);
        var canonicalLogin = Assert.Single(requiredCanonical, source => source.SourceId == LinuxTelemetrySourceIds.LoginSession);
        Assert.Equal(SourceApplicabilityStatuses.Applicable, canonicalLogin.Applicability);
        Assert.Equal(SourceHealthStatuses.Degraded, canonicalLogin.Status);
        Assert.All(canonicalLogin.PrerequisiteStatuses!.Values, state => Assert.Equal(SourceEvidenceStatuses.Degraded, state));
    }

    [Theory]
    [InlineData(SourceHealthStatuses.Degraded)]
    [InlineData(SourceHealthStatuses.PermissionDenied)]
    [InlineData(SourceHealthStatuses.Stale)]
    [InlineData(SourceHealthStatuses.Error)]
    public void OptionalUnknownFirewallRemainsVisibleWithoutDegradingAggregateHealth(string rowStatus)
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var l1 = Report(LinuxTelemetrySourceCatalog.L1.Single(), now);
        var firewallManifest = LinuxTelemetrySourceCatalog.L2Security.Single(entry =>
            entry.SourceId == LinuxTelemetrySourceIds.Firewall);
        var unresolved = Report(firewallManifest, now) with { Status = rowStatus };

        Assert.Equal(SourceRequirementKinds.Optional, unresolved.Requirement);
        Assert.Equal(SourceApplicabilityStatuses.Unknown, unresolved.Applicability);
        Assert.Equal(rowStatus, unresolved.Status);
        Assert.Equal(SourceHealthStatuses.Healthy,
            TelemetryCoverageEvaluator.CalculateOverallStatus([l1, unresolved]));
        Assert.Equal(rowStatus,
            TelemetryCoverageEvaluator.CalculateOverallStatus(
            [
                l1,
                unresolved with
                {
                    Applicability = SourceApplicabilityStatuses.Applicable,
                    ApplicabilityReason = null
                }
            ]));
        Assert.Equal(rowStatus,
            TelemetryCoverageEvaluator.CalculateOverallStatus(
            [
                l1,
                unresolved with
                {
                    Applicability = null,
                    ApplicabilityReason = null
                }
            ]));
    }

    [Fact]
    public void FirewallApiAndWebGuidanceUsesBoundedStatesWithoutPolicyMutation()
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var manifest = LinuxTelemetrySourceCatalog.L2Security.Single(entry =>
            entry.SourceId == LinuxTelemetrySourceIds.Firewall);
        var quiet = Report(manifest, now) with
        {
            Applicability = SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = null,
            Status = SourceHealthStatuses.Healthy,
            Enabled = true,
            LastEventTime = null,
            ObservedAt = now,
            PrerequisiteStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["systemd_journal_readable"] = SourceEvidenceStatuses.Satisfied,
                ["firewall_logging_already_enabled"] = SourceEvidenceStatuses.Satisfied
            },
            EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                family => family,
                _ => SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal),
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["firewall_inventory_state"] = "logging_enabled",
                ["firewall_producer"] = "nftables",
                ["firewall_inventory_reason"] = "firewall_logging_enabled"
            }
        };

        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(quiet, now));
        var quietCoverage = TelemetryCoverageRepository.ToSourceCoverage(
            "synthetic-firewall-agent",
            quiet,
            now.AddHours(-24),
            new Dictionary<string, int>(StringComparer.Ordinal),
            null);
        Assert.Contains("current journal observation was quiet", quietCoverage.StateGuidance, StringComparison.Ordinal);
        Assert.Contains("no raw rules or records", quietCoverage.StateGuidance, StringComparison.Ordinal);
        Assert.Contains("never enables or reconfigures logging", DetailModel.SourceStateGuidance(quietCoverage with
        {
            Status = SourceHealthStatuses.Disabled,
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["firewall_inventory_state"] = "logging_disabled"
            }
        }), StringComparison.Ordinal);

        var unhealthyEnabledCoverage = TelemetryCoverageRepository.ToSourceCoverage(
            "synthetic-firewall-agent",
            quiet with { Status = SourceHealthStatuses.Stale },
            now.AddHours(-24),
            new Dictionary<string, int>(StringComparer.Ordinal),
            null);
        Assert.Contains("current source health is not healthy", unhealthyEnabledCoverage.StateGuidance, StringComparison.Ordinal);
        Assert.DoesNotContain("current journal observation was quiet", unhealthyEnabledCoverage.StateGuidance, StringComparison.Ordinal);
        Assert.Contains("current source health is not healthy", DetailModel.SourceStateGuidance(unhealthyEnabledCoverage), StringComparison.Ordinal);

        var directEvidenceCoverage = TelemetryCoverageRepository.ToSourceCoverage(
            "synthetic-firewall-agent",
            quiet with
            {
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["firewall_inventory_state"] = "logging_disabled",
                    ["firewall_producer"] = "ufw",
                    ["firewall_journal_visibility"] = "observed"
                }
            },
            now.AddHours(-24),
            new Dictionary<string, int>(StringComparer.Ordinal),
            null);
        Assert.Contains("newer than the last inventory observation", directEvidenceCoverage.StateGuidance, StringComparison.Ordinal);
        Assert.Contains("newer than the last inventory observation", DetailModel.SourceStateGuidance(directEvidenceCoverage), StringComparison.Ordinal);
        Assert.DoesNotContain("SYNTHETIC_PRIVATE_FIREWALL_RECORD", directEvidenceCoverage.StateGuidance, StringComparison.Ordinal);
        Assert.Contains(
            "current source health is not healthy",
            DetailModel.SourceStateGuidance(directEvidenceCoverage with { Status = SourceHealthStatuses.PermissionDenied }),
            StringComparison.Ordinal);

        foreach (var (state, status, applicability, expected) in new[]
        {
            ("absent", SourceHealthStatuses.NotApplicable, SourceApplicabilityStatuses.NotApplicable, "Do not install or enable"),
            ("logging_disabled", SourceHealthStatuses.Disabled, SourceApplicabilityStatuses.Applicable, "separately approved firewall change runbook"),
            ("unsupported", SourceHealthStatuses.Unsupported, SourceApplicabilityStatuses.Unsupported, "do not replace or reconfigure"),
            ("permission_denied", SourceHealthStatuses.PermissionDenied, SourceApplicabilityStatuses.Unknown, "does not elevate or mutate host policy")
        })
        {
            var source = quiet with
            {
                Status = status,
                Applicability = applicability,
                Enabled = applicability == SourceApplicabilityStatuses.Applicable,
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["firewall_inventory_state"] = state,
                    ["firewall_producer"] = state == "unsupported" ? "iptables" : "unknown"
                }
            };
            var coverage = TelemetryCoverageRepository.ToSourceCoverage(
                "synthetic-firewall-agent",
                source,
                now.AddHours(-24),
                new Dictionary<string, int>(StringComparer.Ordinal),
                null);
            Assert.Contains(expected, coverage.StateGuidance, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SYNTHETIC_PRIVATE_FIREWALL_RECORD", coverage.StateGuidance, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void PackageManagementRetainsInventoryResolvedApplicability()
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var manifest = LinuxTelemetrySourceCatalog.L2Security.Single(entry =>
            entry.SourceId == LinuxTelemetrySourceIds.PackageManagement);
        var unsupported = Report(manifest, now) with
        {
            Applicability = SourceApplicabilityStatuses.Unsupported,
            ApplicabilityReason = "package_manager_producer_out_of_scope",
            Status = SourceHealthStatuses.Unsupported,
            Enabled = false,
            PrerequisiteStatuses = manifest.Prerequisites.ToDictionary(
                item => item,
                _ => SourceEvidenceStatuses.Unsupported,
                StringComparer.Ordinal),
            EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                item => item,
                _ => SourceEvidenceStatuses.Unsupported,
                StringComparer.Ordinal)
        };

        var merged = TelemetryCoverageEvaluator.MergeExpectedSources(
            [unsupported],
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);

        var package = Assert.Single(merged, source => source.SourceId == LinuxTelemetrySourceIds.PackageManagement);
        Assert.Equal(SourceApplicabilityStatuses.Unsupported, package.Applicability);
        Assert.Equal(SourceHealthStatuses.Unsupported, package.Status);
        Assert.All(package.EventFamilyStatuses!.Values,
            state => Assert.Equal(SourceEvidenceStatuses.Unsupported, state));
    }

    [Fact]
    public void LinuxL1TargetExcludesDisabledAndUnsupportedL2RowsFromSummary()
    {
        var now = DateTimeOffset.Parse("2026-07-13T12:00:00Z");
        var reports = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
                WindowsCoverageLevel.L1,
                Array.Empty<string>(),
                new HashSet<string>(StringComparer.Ordinal))
            .Select(entry => entry.CoverageLevel > WindowsCoverageLevel.L1 && entry.Applicability != SourceApplicabilityStatuses.Unsupported
                ? Report(entry, now) with { Status = SourceHealthStatuses.Disabled, Enabled = false }
                : Report(entry, now))
            .ToArray();

        var merged = TelemetryCoverageEvaluator.MergeExpectedSources(
            reports,
            WindowsCoverageLevel.L1,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);
        var l1 = Assert.Single(merged);
        Assert.Equal(LinuxTelemetrySourceIds.JournalL1, l1.SourceId);
        var summary = TelemetryCoverageEvaluator.CreateSummary("linux-synthetic", "SYNTHETIC-LINUX-01", 0, now, merged, WindowsCoverageLevel.L1);
        Assert.Equal(WindowsCoverageLevel.L1, summary.CurrentLevel);
        Assert.Equal(SourceHealthStatuses.Healthy, summary.OverallStatus);
        Assert.Equal(0, summary.MissingMandatorySources);
        Assert.Equal(0, summary.UnsupportedSources);
    }

    [Fact]
    public void OptionalUnsupportedAuditRemainsCapabilityOnlyForAggregateHealthAndWebPresentation()
    {
        var now = DateTimeOffset.Parse("2026-07-13T12:00:00Z");
        var manifest = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
                WindowsCoverageLevel.L2,
                ["general_server"],
                new HashSet<string>(StringComparer.Ordinal) { LinuxTelemetrySourceIds.Firewall })
            .Where(entry => entry.CoverageLevel <= WindowsCoverageLevel.L2)
            .ToArray();
        var merged = TelemetryCoverageEvaluator.MergeExpectedSources(
            manifest.Select(entry => Report(entry, now)).ToArray(),
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);

        var summary = TelemetryCoverageEvaluator.CreateSummary(
            "linux-synthetic",
            "SYNTHETIC-LINUX-01",
            0,
            now,
            merged,
            WindowsCoverageLevel.L2);
        Assert.Equal(WindowsCoverageLevel.L2, summary.CurrentLevel);
        Assert.Equal(SourceHealthStatuses.Healthy, summary.OverallStatus);
        Assert.Equal(1, summary.UnsupportedSources);
        Assert.Equal(0, summary.MissingMandatorySources);

        var audit = Assert.Single(merged, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        var auditCoverage = new SourceTelemetryCoverage
        {
            SourceId = audit.SourceId,
            Status = audit.Status,
            Required = audit.Required,
            Requirement = audit.Requirement,
            Applicability = audit.Applicability
        };
        Assert.Equal("informational", DetailModel.SourceStatusBadgeClass(auditCoverage));
        Assert.Contains("does not degrade aggregate health", DetailModel.SourceStateGuidance(auditCoverage), StringComparison.Ordinal);

        var mandatoryUnsupported = auditCoverage with
        {
            Required = true,
            Requirement = SourceRequirementKinds.Mandatory,
            Applicability = SourceApplicabilityStatuses.Applicable
        };
        Assert.Equal("danger", DetailModel.SourceStatusBadgeClass(mandatoryUnsupported));
        Assert.Contains("visibility gap", DetailModel.SourceStateGuidance(mandatoryUnsupported), StringComparison.Ordinal);
        Assert.Equal(SourceHealthStatuses.Unsupported, TelemetryCoverageEvaluator.CalculateOverallStatus(
        [
            audit with
            {
                Required = true,
                Requirement = SourceRequirementKinds.Mandatory,
                Applicability = SourceApplicabilityStatuses.Applicable
            }
        ]));
    }

    [Fact]
    public void LinuxCoverageLevelCountsMandatoryOptionalRoleAndExceptionStatesAccurately()
    {
        var now = DateTimeOffset.Parse("2026-07-13T12:00:00Z");
        var manifest = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
            WindowsCoverageLevel.L2,
            ["general_server"],
            new HashSet<string>(StringComparer.Ordinal));
        var reports = manifest.Select(entry => Report(entry, now)).ToArray();

        var baseline = TelemetryCoverageEvaluator.MergeExpectedSources(
            reports,
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);
        var summary = TelemetryCoverageEvaluator.CreateSummary("linux-synthetic", "SYNTHETIC-LINUX-01", 0, now, baseline, WindowsCoverageLevel.L2);
        Assert.Equal(WindowsCoverageLevel.L2, summary.CurrentLevel);
        Assert.Equal(SourceHealthStatuses.Healthy, summary.OverallStatus);
        Assert.Equal(1, summary.DegradedSources);
        Assert.Equal(1, summary.UnsupportedSources);
        Assert.Equal(1, summary.NotApplicableSources);
        Assert.Equal(0, summary.MissingMandatorySources);

        var deniedReports = reports.Select(report => report.SourceId == LinuxTelemetrySourceIds.LoginSession
            ? report with
            {
                Status = SourceHealthStatuses.PermissionDenied,
                PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(pair => pair.Key, _ => SourceEvidenceStatuses.PermissionDenied, StringComparer.Ordinal)
            }
            : report).ToArray();
        var denied = TelemetryCoverageEvaluator.MergeExpectedSources(
            deniedReports,
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);
        var deniedSummary = TelemetryCoverageEvaluator.CreateSummary("linux-synthetic", "SYNTHETIC-LINUX-01", 0, now, denied, WindowsCoverageLevel.L2);
        Assert.Equal(WindowsCoverageLevel.L1, deniedSummary.CurrentLevel);
        Assert.Equal(SourceHealthStatuses.PermissionDenied, deniedSummary.OverallStatus);
        Assert.Equal(1, deniedSummary.PermissionDeniedSources);

        var staleReports = reports.Select(report => report.SourceId == LinuxTelemetrySourceIds.ServiceChange
            ? report with { Status = SourceHealthStatuses.Stale }
            : report).ToArray();
        var stale = TelemetryCoverageEvaluator.MergeExpectedSources(
            staleReports,
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);
        var staleSummary = TelemetryCoverageEvaluator.CreateSummary("linux-synthetic", "SYNTHETIC-LINUX-01", 0, now, stale, WindowsCoverageLevel.L2);
        Assert.Equal(WindowsCoverageLevel.L1, staleSummary.CurrentLevel);
        Assert.Equal(SourceHealthStatuses.Stale, staleSummary.OverallStatus);
        Assert.Equal(1, staleSummary.StaleSources);

        var selfExceptedReports = reports.Select(report => report.SourceId == LinuxTelemetrySourceIds.PackageManagement
            ? report with { Status = SourceHealthStatuses.Excepted }
            : report).ToArray();
        var selfExcepted = TelemetryCoverageEvaluator.MergeExpectedSources(
            selfExceptedReports,
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);
        Assert.Equal(SourceHealthStatuses.Degraded,
            Assert.Single(selfExcepted, source => source.SourceId == LinuxTelemetrySourceIds.PackageManagement).Status);
        Assert.Equal(WindowsCoverageLevel.L1,
            TelemetryCoverageEvaluator.CreateSummary("linux-synthetic", "SYNTHETIC-LINUX-01", 0, now, selfExcepted, WindowsCoverageLevel.L2).CurrentLevel);

        var missingPackage = reports.Select(report => report.SourceId == LinuxTelemetrySourceIds.PackageManagement
            ? report with { Status = SourceHealthStatuses.Missing }
            : report).ToArray();
        var excepted = TelemetryCoverageEvaluator.MergeExpectedSources(
            missingPackage,
            WindowsCoverageLevel.L2,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { LinuxTelemetrySourceIds.PackageManagement },
            now,
            TelemetryPlatforms.Linux);
        Assert.Equal(SourceHealthStatuses.Excepted,
            Assert.Single(excepted, source => source.SourceId == LinuxTelemetrySourceIds.PackageManagement).Status);
        Assert.Equal(WindowsCoverageLevel.L2,
            TelemetryCoverageEvaluator.CreateSummary("linux-synthetic", "SYNTHETIC-LINUX-01", 0, now, excepted, WindowsCoverageLevel.L2).CurrentLevel);
    }

    [Fact]
    public void LinuxCoverageAdvancesToL3OnlyWithApplicableHealthyL3Evidence()
    {
        var now = DateTimeOffset.Parse("2026-07-13T12:00:00Z");
        var reports = LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L3)
            .Select(entry => Report(entry, now))
            .ToArray();
        var unavailableL3 = reports
            .Select(report => report.CoverageLevel == WindowsCoverageLevel.L3
                ? report with
                {
                    Applicability = SourceApplicabilityStatuses.Unknown,
                    Status = SourceHealthStatuses.Disabled,
                    Enabled = false,
                    LastEventTime = null
                }
                : report)
            .ToArray();

        Assert.Equal(
            WindowsCoverageLevel.L2,
            TelemetryCoverageEvaluator.CalculateCurrentLevel(
                unavailableL3,
                WindowsCoverageLevel.L3,
                TelemetryPlatforms.Linux));

        var healthyL3 = reports
            .Select(report => report.CoverageLevel == WindowsCoverageLevel.L3
                ? report with
                {
                    Applicability = SourceApplicabilityStatuses.Applicable,
                    ApplicabilityReason = null,
                    Status = SourceHealthStatuses.Healthy,
                    Enabled = true,
                    LastEventTime = now
                }
                : report)
            .ToArray();

        Assert.Equal(
            WindowsCoverageLevel.L3,
            TelemetryCoverageEvaluator.CalculateCurrentLevel(
                healthyL3,
                WindowsCoverageLevel.L3,
                TelemetryPlatforms.Linux));
        Assert.Equal(
            WindowsCoverageLevel.L3,
            TelemetryCoverageEvaluator.CalculateCurrentLevel(
                healthyL3,
                WindowsCoverageLevel.L4,
                TelemetryPlatforms.Linux));
    }

    [Fact]
    public void AgentCoverageReviewExplainsLinuxL3AndPlatformApplicableDetections()
    {
        var markup = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Pages", "Agents", "Detail.cshtml"));
        Assert.Contains("explicit-opt-in L3 sources", markup, StringComparison.Ordinal);
        Assert.Contains("healthy applicable evidence exists at that level", markup, StringComparison.Ordinal);
        Assert.Contains("Windows or Linux built-in detection rules", markup, StringComparison.Ordinal);
        Assert.DoesNotContain("Executable built-ins remain Windows-focused", markup, StringComparison.Ordinal);
    }

    [Fact]
    public void PassivePollingFreshnessUsesRecentObservedScanAfterAnEstablishedBaseline()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");

        foreach (var entry in LinuxTelemetrySourceCatalog.L3Passive)
        {
            var report = HealthyPassiveReport(entry, now) with
            {
                LastEventTime = now.Subtract(TimeSpan.FromDays(2)),
                ObservedAt = now.Subtract(TimeSpan.FromMinutes(5)),
                EventFamilyStatuses = entry.EventFamilies
                    .Select((family, index) => new
                    {
                        Family = family,
                        Status = index == 0
                            ? SourceEvidenceStatuses.Observed
                            : SourceEvidenceStatuses.NotObserved
                    })
                    .ToDictionary(item => item.Family, item => item.Status, StringComparer.Ordinal)
            };

            Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(report, now));
        }
    }

    [Fact]
    public void PassivePollingFreshnessRequiresARecentAgentReportedObservation()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");

        foreach (var entry in LinuxTelemetrySourceCatalog.L3Passive)
        {
            var report = HealthyPassiveReport(entry, now) with
            {
                LastEventTime = now,
                ObservedAt = now.Subtract(TimeSpan.FromDays(2))
            };
            Assert.Equal(SourceHealthStatuses.Stale, SourceHealthRules.EffectiveStatus(report, now));
            Assert.Equal(SourceHealthStatuses.Stale, SourceHealthRules.EffectiveStatus(report with { ObservedAt = null }, now));
            Assert.Equal(
                SourceHealthStatuses.Stale,
                SourceHealthRules.EffectiveStatus(report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1) }, now));
            Assert.Equal(
                SourceHealthStatuses.Healthy,
                SourceHealthRules.EffectiveStatus(report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter) }, now));
        }
    }

    [Fact]
    public void PassivePollingFreshnessRejectsFutureObservationsAndHonorsIdentityCaseDefensively()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L3Passive.First();
        var report = HealthyPassiveReport(entry, now) with
        {
            SourceId = entry.SourceId.ToUpperInvariant(),
            ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew).AddSeconds(1)
        };

        Assert.Equal(SourceHealthStatuses.Degraded, SourceHealthRules.EffectiveStatus(report, now));
        Assert.Equal(
            SourceHealthStatuses.Healthy,
            SourceHealthRules.EffectiveStatus(report with { ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew) }, now));
    }

    [Fact]
    public void PassivePollingSuccessfulEmptyScanAndRecoveredHistoricalGapRemainHealthy()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");

        foreach (var entry in LinuxTelemetrySourceCatalog.L3Passive)
        {
            var report = HealthyPassiveReport(entry, now) with
            {
                LastEventTime = null,
                ObservedAt = now.Subtract(TimeSpan.FromMinutes(5)),
                GapCount = 3,
                GapDetected = false,
                BookmarkGapDetected = false,
                EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                    family => family,
                    _ => SourceEvidenceStatuses.NotObserved,
                    StringComparer.Ordinal)
            };

            Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(report, now));
            Assert.Equal(
                SourceHealthStatuses.Error,
                SourceHealthRules.EffectiveStatus(report with { GapDetected = true }, now));
        }
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("old")]
    [InlineData("recent")]
    public void AgentLogTamperFreshnessUsesCurrentJournalObservationDuringQuietPeriods(string eventAge)
    {
        var now = DateTimeOffset.Parse("2026-07-18T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.AgentLogTamper);
        var lastEventTime = eventAge switch
        {
            "old" => now.Subtract(TimeSpan.FromDays(2)),
            "recent" => now.Subtract(TimeSpan.FromMinutes(5)),
            _ => (DateTimeOffset?)null
        };
        var familyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["agent_tamper"] = eventAge == "absent"
                ? SourceEvidenceStatuses.NotObserved
                : SourceEvidenceStatuses.Observed,
            ["log_tamper"] = SourceEvidenceStatuses.NotObserved
        };
        var report = Report(entry, now) with
        {
            LastEventTime = lastEventTime,
            ObservedAt = now.Subtract(TimeSpan.FromMinutes(5)),
            EventFamilyStatuses = familyStatuses
        };

        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(report, now));
        Assert.Equal(
            eventAge == "absent" ? SourceEvidenceStatuses.NotObserved : SourceEvidenceStatuses.Observed,
            report.EventFamilyStatuses!["agent_tamper"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, report.EventFamilyStatuses["log_tamper"]);
    }

    [Fact]
    public void AgentLogTamperObservationExpiryAndVisibilityFailuresRemainExplicit()
    {
        var now = DateTimeOffset.Parse("2026-07-18T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.AgentLogTamper);
        var report = Report(entry, now) with
        {
            LastEventTime = null,
            ObservedAt = now,
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                family => family,
                _ => SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal)
        };

        Assert.Equal(
            SourceHealthStatuses.Stale,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew).AddSeconds(1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Key == "systemd_journal_readable"
                            ? SourceEvidenceStatuses.Degraded
                            : pair.Value,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.PermissionDenied,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.PermissionDenied,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Error,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1),
                    GapDetected = true
                },
                now));
    }

    [Theory]
    [InlineData("quiet")]
    [InlineData("partial_old")]
    [InlineData("partial_recent")]
    public void KernelSecurityFreshnessUsesCurrentJournalObservationDuringQuietPeriods(string evidenceState)
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.KernelSecurity);
        var hasKernelModuleEvidence = evidenceState != "quiet";
        var lastEventTime = evidenceState switch
        {
            "partial_old" => now.Subtract(TimeSpan.FromDays(2)),
            "partial_recent" => now.Subtract(TimeSpan.FromMinutes(5)),
            _ => (DateTimeOffset?)null
        };
        var report = Report(entry, now) with
        {
            LastEventTime = lastEventTime,
            ObservedAt = now.Subtract(TimeSpan.FromMinutes(5)),
            EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["kernel_security"] = SourceEvidenceStatuses.NotObserved,
                ["security_module"] = SourceEvidenceStatuses.NotObserved,
                ["kernel_module"] = hasKernelModuleEvidence
                    ? SourceEvidenceStatuses.Observed
                    : SourceEvidenceStatuses.NotObserved
            }
        };

        Assert.Equal(SourceApplicabilityStatuses.Applicable, report.Applicability);
        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(report, now));
        Assert.Equal(
            hasKernelModuleEvidence ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
            report.EventFamilyStatuses!["kernel_module"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, report.EventFamilyStatuses["kernel_security"]);
        Assert.Equal(SourceEvidenceStatuses.NotObserved, report.EventFamilyStatuses["security_module"]);
    }

    [Fact]
    public void KernelSecurityObservationExpiryAndVisibilityFailuresRemainFailClosed()
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.KernelSecurity);
        var report = Report(entry, now) with
        {
            LastEventTime = null,
            ObservedAt = now,
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                family => family,
                _ => SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal)
        };

        Assert.Equal(
            SourceHealthStatuses.Stale,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew).AddSeconds(1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Missing,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    Status = SourceHealthStatuses.Missing,
                    ErrorCode = "kernel_journal_unavailable",
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.Missing,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Key == "kernel_journal_visibility"
                            ? SourceEvidenceStatuses.Degraded
                            : pair.Value,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.PermissionDenied,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.PermissionDenied,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Error,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1),
                    GapDetected = true
                },
                now));
    }

    [Theory]
    [InlineData("quiet")]
    [InlineData("recent")]
    [InlineData("partial_family")]
    public void LoginSessionFreshnessUsesCurrentJournalObservationDuringQuietPeriods(string evidenceState)
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        var lastEventTime = evidenceState switch
        {
            "recent" => now.Subtract(TimeSpan.FromMinutes(5)),
            "partial_family" => now.Subtract(TimeSpan.FromDays(2)),
            _ => (DateTimeOffset?)null
        };
        var report = Report(entry, now) with
        {
            LastEventTime = lastEventTime,
            ObservedAt = now.Subtract(TimeSpan.FromMinutes(5)),
            EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["login"] = evidenceState == "quiet"
                    ? SourceEvidenceStatuses.NotObserved
                    : SourceEvidenceStatuses.Observed,
                ["session"] = evidenceState == "recent"
                    ? SourceEvidenceStatuses.Observed
                    : SourceEvidenceStatuses.NotObserved
            }
        };

        Assert.Equal(SourceApplicabilityStatuses.Applicable, report.Applicability);
        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(report, now));
        Assert.Equal(
            evidenceState == "quiet" ? SourceEvidenceStatuses.NotObserved : SourceEvidenceStatuses.Observed,
            report.EventFamilyStatuses!["login"]);
        Assert.Equal(
            evidenceState == "recent" ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
            report.EventFamilyStatuses["session"]);
    }

    [Fact]
    public void LoginSessionObservationExpiryAndVisibilityFailuresRemainFailClosed()
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.LoginSession);
        var report = Report(entry, now) with
        {
            LastEventTime = null,
            ObservedAt = now,
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                family => family,
                _ => SourceEvidenceStatuses.NotObserved,
                StringComparer.Ordinal)
        };

        Assert.Equal(
            SourceHealthStatuses.Stale,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew).AddSeconds(1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Missing,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    Status = SourceHealthStatuses.Missing,
                    ErrorCode = "login_session_journal_unavailable",
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.Missing,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Key == "pam_or_logind_journal_visibility"
                            ? SourceEvidenceStatuses.Degraded
                            : pair.Value,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.PermissionDenied,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.PermissionDenied,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Error,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1),
                    GapDetected = true
                },
                now));
    }

    [Theory]
    [InlineData("no_evidence", SourceHealthStatuses.Degraded)]
    [InlineData("cron_only", SourceHealthStatuses.Healthy)]
    [InlineData("timer_only", SourceHealthStatuses.Healthy)]
    [InlineData("mixed", SourceHealthStatuses.Healthy)]
    public void SchedulerFreshnessUsesCurrentJournalObservationAfterProducerEvidence(
        string evidenceState,
        string expectedStatus)
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.Scheduler);
        var cronObserved = evidenceState is "cron_only" or "mixed";
        var timerObserved = evidenceState is "timer_only" or "mixed";
        var report = Report(entry, now) with
        {
            LastEventTime = cronObserved || timerObserved ? now.Subtract(TimeSpan.FromDays(2)) : null,
            ObservedAt = now.Subtract(TimeSpan.FromMinutes(5)),
            EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["cron"] = cronObserved ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
                ["systemd_timer"] = timerObserved ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved
            }
        };

        Assert.Equal(SourceApplicabilityStatuses.Applicable, report.Applicability);
        Assert.Equal(expectedStatus, SourceHealthRules.EffectiveStatus(report, now));
        Assert.Equal(cronObserved ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
            report.EventFamilyStatuses!["cron"]);
        Assert.Equal(timerObserved ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
            report.EventFamilyStatuses["systemd_timer"]);
    }

    [Fact]
    public void SchedulerObservationExpiryAndVisibilityFailuresRemainFailClosed()
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var entry = LinuxTelemetrySourceCatalog.L2Security.Single(
            item => item.SourceId == LinuxTelemetrySourceIds.Scheduler);
        var report = Report(entry, now) with
        {
            LastEventTime = now.Subtract(TimeSpan.FromDays(2)),
            ObservedAt = now,
            EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["cron"] = SourceEvidenceStatuses.Observed,
                ["systemd_timer"] = SourceEvidenceStatuses.NotObserved
            }
        };

        Assert.Equal(
            SourceHealthStatuses.Healthy,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Stale,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with { ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew).AddSeconds(1) },
                now));
        Assert.Equal(
            SourceHealthStatuses.Missing,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    Status = SourceHealthStatuses.Missing,
                    ErrorCode = "scheduler_journal_unavailable",
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.Missing,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Key == "cron_or_systemd_timer_visibility"
                            ? SourceEvidenceStatuses.Degraded
                            : pair.Value,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.PermissionDenied,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                        pair => pair.Key,
                        _ => SourceEvidenceStatuses.PermissionDenied,
                        StringComparer.Ordinal)
                },
                now));
        Assert.Equal(
            SourceHealthStatuses.Error,
            SourceHealthRules.EffectiveStatus(
                report with
                {
                    ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1),
                    GapDetected = true
                },
                now));
    }

    [Fact]
    public void UnrelatedSourceRetainsLastEventFreshnessSemantics()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");
        var windows = new SourceHealthReport
        {
            SourceId = "security",
            Platform = TelemetryPlatforms.Windows,
            SourceKind = TelemetrySourceKinds.WindowsEventLog,
            DisplayName = "Windows Security",
            Channel = "Security",
            CoverageLevel = WindowsCoverageLevel.L2,
            Status = SourceHealthStatuses.Healthy,
            Required = true,
            Requirement = SourceRequirementKinds.Mandatory,
            Enabled = true,
            LastEventTime = now.Subtract(TimeSpan.FromDays(2)),
            ObservedAt = now
        };

        Assert.Equal(SourceHealthStatuses.Stale, SourceHealthRules.EffectiveStatus(windows, now));

        var linuxJournal = Report(LinuxTelemetrySourceCatalog.L1.Single(), now) with
        {
            LastEventTime = now.Subtract(TimeSpan.FromDays(2)),
            ObservedAt = now
        };
        Assert.Equal(SourceHealthStatuses.Stale, SourceHealthRules.EffectiveStatus(linuxJournal, now));
    }

    [Fact]
    public void SqlCoverageSummariesRequireTheCanonicalLinuxL3PassiveSet()
    {
        var sourceHealth = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "SourceHealthRepository.cs"));
        var review = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Review", "ReviewRepository.cs"));
        foreach (var implementation in new[] { sourceHealth, review })
        {
            Assert.Contains("LinuxTelemetrySourceCatalog.L3Passive", implementation, StringComparison.Ordinal);
            Assert.Contains("linux_l3_required_source_ids", implementation, StringComparison.Ordinal);
            Assert.Contains("linux_l3_required_source_count", implementation, StringComparison.Ordinal);
            Assert.Contains("count(distinct lower(source_id))", implementation, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("coalesce(applicability, '') = 'unknown'", implementation, StringComparison.Ordinal);
            foreach (var aggregate in new[]
            {
                "aggregate_error_sources",
                "aggregate_stale_sources",
                "aggregate_permission_denied_sources",
                "aggregate_degraded_sources"
            })
            {
                Assert.Contains(aggregate, implementation, StringComparison.Ordinal);
            }
        }
        Assert.Contains("l3_canonical_covered_sources", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("l3_canonical_present_sources", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("l3_canonical_attempted_sources", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("health_with_expected", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("@linux_l3_required_source_count - l3_canonical_present_sources", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("target_scoped_health", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("@target_level = 'L2' and sh.coverage_level in ('L1', 'L2')", sourceHealth, StringComparison.Ordinal);
        Assert.Contains("linux_l3_canonical_covered_sources", review, StringComparison.Ordinal);
        Assert.Contains("in_coverage_status_scope", review, StringComparison.Ordinal);
        Assert.Contains("from source_health attempted_l3", review, StringComparison.Ordinal);
        Assert.Contains("attempted_l3.enabled or attempted_l3.applicability = 'applicable'", review, StringComparison.Ordinal);
        Assert.Contains("@linux_l3_required_source_count", review, StringComparison.Ordinal);
        Assert.Contains("count(distinct lower(source_id))", review, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("greatest(", review, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SqlCoverageOverallStatusPrecedenceMatchesTheInMemoryEvaluator()
    {
        foreach (var implementation in new[]
        {
            File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "SourceHealthRepository.cs")),
            File.ReadAllText(RepositoryFile("server", "Siem.Api", "Review", "ReviewRepository.cs"))
        })
        {
            var statusCaseStart = implementation.IndexOf(
                "when coalesce(h.aggregate_error_sources",
                StringComparison.Ordinal);
            if (statusCaseStart < 0)
            {
                statusCaseStart = implementation.IndexOf(
                    "when coalesce(sh.aggregate_error_sources",
                    StringComparison.Ordinal);
            }
            Assert.True(statusCaseStart >= 0, "Coverage status CASE expression was not found.");
            var statusCase = implementation[statusCaseStart..];
            var prior = -1;
            foreach (var aggregate in new[]
            {
                "aggregate_error_sources",
                "mandatory_permission_denied_sources",
                "mandatory_unsupported_sources",
                "missing_mandatory_sources",
                "aggregate_stale_sources",
                "aggregate_permission_denied_sources",
                "aggregate_degraded_sources"
            })
            {
                var current = statusCase.IndexOf(aggregate, prior + 1, StringComparison.Ordinal);
                Assert.True(current > prior, $"{aggregate} is missing or out of precedence order.");
                prior = current;
            }
        }
    }

    [Fact]
    public void PortableRequirementAndEvidenceMetadataValidateAdditively()
    {
        var now = DateTimeOffset.Parse("2026-07-13T12:00:00Z");
        var manifest = LinuxTelemetrySourceCatalog.L2Security.Single(entry => entry.SourceId == LinuxTelemetrySourceIds.LoginSession);
        var health = Report(manifest, now);
        var heartbeat = new HeartbeatRequest
        {
            AgentId = "linux-l2-synthetic",
            Hostname = "SYNTHETIC-LINUX-01",
            AgentVersion = "1.1.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = "synthetic-host-id",
            QueueDepth = 0,
            SourceManifest = [manifest],
            SourceHealth = [health]
        };

        Assert.Empty(RequestValidation.ValidateHeartbeat(heartbeat));

        var invalidRequirement = heartbeat with
        {
            SourceHealth = [health with { Requirement = SourceRequirementKinds.Optional }]
        };
        Assert.Contains("source_health[0].requirement", RequestValidation.ValidateHeartbeat(invalidRequirement).Keys);

        var invalidEvidence = heartbeat with
        {
            SourceHealth =
            [
                health with
                {
                    EventFamilyStatuses = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["unexpected_family"] = SourceEvidenceStatuses.Observed
                    }
                }
            ]
        };
        Assert.Contains("source_health[0].event_family_statuses", RequestValidation.ValidateHeartbeat(invalidEvidence).Keys);

        var invalidState = heartbeat with
        {
            SourceHealth =
            [
                health with
                {
                    PrerequisiteStatuses = health.PrerequisiteStatuses!.ToDictionary(pair => pair.Key, _ => "invented", StringComparer.Ordinal)
                }
            ]
        };
        Assert.Contains(RequestValidation.ValidateHeartbeat(invalidState).Keys,
            key => key.StartsWith("source_health[0].prerequisite_statuses.", StringComparison.Ordinal));
    }

    [Fact]
    public void LinuxL2MigrationAndSchemaValidatorRemainAdditive()
    {
        var migration = File.ReadAllText(RepositoryFile("server", "Siem.Api", "Database", "005_linux_l2_source_coverage.sql"));
        var validator = File.ReadAllText(RepositoryFile("scripts", "validate-schema.sh"));
        foreach (var fragment in new[]
        {
            "agents add column if not exists platform",
            "agents add column if not exists host_id",
            "source_health add column if not exists requirement_kind",
            "source_health add column if not exists applicable_roles",
            "source_health add column if not exists prerequisite_statuses",
            "source_health add column if not exists event_family_statuses",
            "idx_events_package_name",
            "idx_source_health_requirement",
            "idx_agents_platform"
        })
        {
            Assert.Contains(fragment, migration, StringComparison.OrdinalIgnoreCase);
        }
        Assert.DoesNotContain("drop table", migration, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("drop column", migration, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("truncate ", migration, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("idx_events_package_name", validator, StringComparison.Ordinal);
        Assert.Contains("requirement_kind", validator, StringComparison.Ordinal);
        Assert.Contains("event_family_statuses", validator, StringComparison.Ordinal);
    }

    [Fact]
    public void PortablePackageSearchFilterIsParsedAdditively()
    {
        var query = EventSearchQuery.FromQuery(new QueryCollection(new Dictionary<string, StringValues>
        {
            ["source"] = EventSources.LinuxJournal,
            ["platform"] = TelemetryPlatforms.Linux,
            ["source_id"] = LinuxTelemetrySourceIds.PackageManagement,
            ["package_name"] = "synthetic-package"
        }));
        Assert.Equal(EventSources.LinuxJournal, query.Source);
        Assert.Equal(TelemetryPlatforms.Linux, query.Platform);
        Assert.Equal(LinuxTelemetrySourceIds.PackageManagement, query.SourceId);
        Assert.Equal("synthetic-package", query.PackageName);

        var restricted = EventFieldPolicy.Apply(new EventEnvelope
        {
            Normalized = new NormalizedEventFields { PackageName = "synthetic-package" }
        }, OperatorRoles.Viewer);
        Assert.Null(restricted.Normalized?.PackageName);
    }

    [Fact]
    public void CoverageContractsSerializeNewMetadataWithoutChangingWindowsDefaults()
    {
        var source = new SourceTelemetryCoverage
        {
            SourceId = LinuxTelemetrySourceIds.Ssh,
            DisplayName = "Linux SSH activity",
            Platform = TelemetryPlatforms.Linux,
            SourceKind = TelemetrySourceKinds.LinuxJournal,
            SourceNamespace = "systemd.journal",
            Applicability = SourceApplicabilityStatuses.NotApplicable,
            ApplicabilityReason = "declared_roles_do_not_require_source",
            Requirement = SourceRequirementKinds.RoleSpecific,
            ApplicableRoles = ["ssh_server", "bastion"],
            PrerequisiteStatuses = new Dictionary<string, string> { ["sshd_journal_visibility"] = SourceEvidenceStatuses.NotApplicable },
            EventFamilyStatuses = new Dictionary<string, string> { ["ssh_authentication"] = SourceEvidenceStatuses.NotApplicable },
            CoverageLevel = WindowsCoverageLevel.L2,
            Status = SourceHealthStatuses.NotApplicable,
            Reason = "synthetic",
            EventSearchUrl = "/events?source_id=linux-ssh",
            SourceHealthUrl = "/agents/detail"
        };
        var json = JsonSerializer.Serialize(source, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("requirement", json, StringComparison.Ordinal);
        Assert.Contains("prerequisite_statuses", json, StringComparison.Ordinal);
        Assert.Contains("event_family_statuses", json, StringComparison.Ordinal);

        var windows = new SourceHealthReport
        {
            SourceId = "system",
            DisplayName = "Windows System",
            Channel = "System",
            Status = SourceHealthStatuses.Healthy,
            Required = true,
            Enabled = true
        };
        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(windows, DateTimeOffset.UtcNow));
        Assert.Null(windows.Requirement);
        Assert.Null(windows.PrerequisiteStatuses);
    }

    private static string RepositoryFile(params string[] parts)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(new[] { current.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate))
            {
                return candidate;
            }
            current = current.Parent;
        }
        throw new FileNotFoundException($"Could not locate repository file: {string.Join('/', parts)}");
    }

    private static SourceHealthReport Report(SourceManifestEntry entry, DateTimeOffset now)
    {
        var status = entry.Applicability switch
        {
            SourceApplicabilityStatuses.Unsupported => SourceHealthStatuses.Unsupported,
            SourceApplicabilityStatuses.NotApplicable => SourceHealthStatuses.NotApplicable,
            SourceApplicabilityStatuses.Unknown => SourceHealthStatuses.Degraded,
            _ => SourceHealthStatuses.Healthy
        };
        var evidence = status switch
        {
            SourceHealthStatuses.Unsupported => SourceEvidenceStatuses.Unsupported,
            SourceHealthStatuses.NotApplicable => SourceEvidenceStatuses.NotApplicable,
            SourceHealthStatuses.Degraded => SourceEvidenceStatuses.Unknown,
            _ => SourceEvidenceStatuses.Satisfied
        };
        var familyEvidence = status == SourceHealthStatuses.Healthy ? SourceEvidenceStatuses.Observed : evidence;
        return new SourceHealthReport
        {
            SourceId = entry.SourceId,
            Platform = entry.Platform,
            SourceKind = entry.SourceKind,
            DisplayName = entry.DisplayName,
            SourceNamespace = entry.SourceNamespace,
            Applicability = entry.Applicability,
            ApplicabilityReason = entry.ApplicabilityReason,
            CoverageLevel = entry.CoverageLevel,
            Status = status,
            Required = entry.Required,
            Requirement = entry.Requirement,
            ApplicableRoles = entry.ApplicableRoles,
            Enabled = status is not SourceHealthStatuses.Unsupported and not SourceHealthStatuses.NotApplicable,
            LastEventTime = status == SourceHealthStatuses.Healthy ? now : null,
            ObservedAt = status == SourceHealthStatuses.Healthy ? now : null,
            CollectedCheckpoint = entry.SourceKind == TelemetrySourceKinds.LinuxJournal
                ? new SourceCheckpoint { Cursor = "s=synthetic;i=coverage", RecordedAt = now }
                : null,
            AcknowledgedCheckpoint = entry.SourceKind == TelemetrySourceKinds.LinuxJournal
                ? new SourceCheckpoint { Cursor = "s=synthetic;i=coverage", RecordedAt = now }
                : null,
            PrerequisiteStatuses = entry.Prerequisites.ToDictionary(item => item, _ => evidence, StringComparer.Ordinal),
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(item => item, _ => familyEvidence, StringComparer.Ordinal),
            Details = new Dictionary<string, string>()
        };
    }

    private static SourceHealthReport HealthyPassiveReport(SourceManifestEntry entry, DateTimeOffset now) =>
        Report(entry, now) with
        {
            Applicability = SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = null,
            Status = SourceHealthStatuses.Healthy,
            Enabled = true,
            LastEventTime = now,
            ObservedAt = now,
            PrerequisiteStatuses = entry.Prerequisites.ToDictionary(
                item => item,
                _ => SourceEvidenceStatuses.Satisfied,
                StringComparer.Ordinal),
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(
                item => item,
                _ => SourceEvidenceStatuses.Observed,
                StringComparer.Ordinal)
        };
}
