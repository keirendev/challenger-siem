using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Ingestion;
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
        Assert.Equal(SourceHealthStatuses.Degraded, summary.OverallStatus);
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
}
