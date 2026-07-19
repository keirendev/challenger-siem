using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V1;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class LinuxL4CoverageTests
{
    private const string PolicySourceId = "linux-policy-posture-drift";
    private const string PerformanceSourceId = "linux-agent-performance-slo";

    private static readonly string[] RoleSourceIds =
    [
        "linux-role-web",
        "linux-role-database",
        "linux-role-dns",
        "linux-role-file-server",
        "linux-role-container",
        "linux-role-identity"
    ];

    [Fact]
    public void CanonicalLinuxL4CatalogHasExactMandatoryAndRoleSources()
    {
        var l4 = LinuxTelemetrySourceCatalog.All
            .Where(entry => entry.CoverageLevel == WindowsCoverageLevel.L4)
            .ToArray();

        Assert.Equal(
            new[] { PolicySourceId, PerformanceSourceId }.Order(StringComparer.Ordinal),
            l4.Where(entry => entry.Requirement == SourceRequirementKinds.Mandatory)
                .Select(entry => entry.SourceId)
                .Order(StringComparer.Ordinal));
        Assert.Equal(
            RoleSourceIds.Order(StringComparer.Ordinal),
            l4.Where(entry => entry.Requirement == SourceRequirementKinds.RoleSpecific)
                .Select(entry => entry.SourceId)
                .Order(StringComparer.Ordinal));
        Assert.All(l4.Where(entry => entry.Requirement == SourceRequirementKinds.RoleSpecific), entry =>
        {
            Assert.False(entry.Required);
            Assert.NotEmpty(entry.ApplicableRoles!);
        });
    }

    [Fact]
    public void LinuxL4RequiresExactHealthyLowerMandatoryAndCanonicalL4Evidence()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");
        var healthy = Merged(Reports(now), now);
        Assert.Equal(WindowsCoverageLevel.L4, Current(healthy));

        var exceptedLowerId = LinuxTelemetrySourceCatalog.L2Security
            .First(entry => entry.Requirement == SourceRequirementKinds.Mandatory)
            .SourceId;
        var withLowerGap = Reports(now)
            .Select(report => report.SourceId == exceptedLowerId
                ? report with { Status = SourceHealthStatuses.Missing }
                : report)
            .ToArray();
        var excepted = TelemetryCoverageEvaluator.MergeExpectedSources(
            withLowerGap,
            WindowsCoverageLevel.L4,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { exceptedLowerId },
            now,
            TelemetryPlatforms.Linux);
        Assert.Equal(WindowsCoverageLevel.L3, Current(excepted));

        foreach (var sourceId in new[] { PolicySourceId, PerformanceSourceId })
        {
            var missing = Merged(Reports(now).Where(report => report.SourceId != sourceId).ToArray(), now);
            Assert.Equal(WindowsCoverageLevel.L3, Current(missing));

            var unhealthy = Merged(Reports(now).Select(report => report.SourceId == sourceId
                ? report with { Status = SourceHealthStatuses.Degraded }
                : report).ToArray(), now);
            Assert.Equal(WindowsCoverageLevel.L3, Current(unhealthy));
        }
    }

    [Fact]
    public void LinuxL4RequiresResolvedRolesAndHealthyApplicableRolePacks()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");
        var roleId = RoleSourceIds[0];

        var unknown = Merged(Reports(now).Select(report => report.SourceId == roleId
            ? report with
            {
                Applicability = SourceApplicabilityStatuses.Unknown,
                ApplicabilityReason = "host_role_not_declared",
                Status = SourceHealthStatuses.Disabled,
                Enabled = false
            }
            : report).ToArray(), now);
        Assert.Equal(WindowsCoverageLevel.L3, Current(unknown));

        var applicableHealthy = Merged(Reports(now).Select(report => report.SourceId == roleId
            ? report with
            {
                Applicability = SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = null,
                Status = SourceHealthStatuses.Healthy,
                Enabled = true,
                ObservedAt = now
            }
            : report).ToArray(), now);
        Assert.Equal(WindowsCoverageLevel.L4, Current(applicableHealthy));

        var applicableStale = Merged(Reports(now).Select(report => report.SourceId == roleId
            ? report with
            {
                Applicability = SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = null,
                Status = SourceHealthStatuses.Healthy,
                Enabled = true,
                ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1)
            }
            : report).ToArray(), now);
        Assert.Equal(WindowsCoverageLevel.L3, Current(applicableStale));
    }

    [Fact]
    public void LinuxL4RequiresResolvedSshApplicabilityAndAcceptsCurrentQuietProducerEvidence()
    {
        var now = DateTimeOffset.Parse("2026-07-19T12:00:00Z");
        var sshId = LinuxTelemetrySourceIds.Ssh;

        var unknown = Merged(Reports(now).Select(report => report.SourceId == sshId
            ? report with
            {
                Applicability = SourceApplicabilityStatuses.Unknown,
                ApplicabilityReason = "host_role_not_declared",
                Status = SourceHealthStatuses.Degraded,
                Enabled = true,
                ObservedAt = now
            }
            : report).ToArray(), now);
        Assert.Equal(WindowsCoverageLevel.L3, Current(unknown));

        var unsupported = Merged(Reports(now).Select(report => report.SourceId == sshId
            ? report with
            {
                Applicability = SourceApplicabilityStatuses.Unsupported,
                ApplicabilityReason = "ssh_producer_not_present",
                Status = SourceHealthStatuses.Unsupported,
                Enabled = false,
                ObservedAt = now,
                PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                    pair => pair.Key,
                    _ => SourceEvidenceStatuses.Unsupported,
                    StringComparer.Ordinal),
                EventFamilyStatuses = report.EventFamilyStatuses!.ToDictionary(
                    pair => pair.Key,
                    _ => SourceEvidenceStatuses.Unsupported,
                    StringComparer.Ordinal)
            }
            : report).ToArray(), now);
        Assert.Equal(WindowsCoverageLevel.L3, Current(unsupported));

        var quietApplicable = Merged(Reports(now).Select(report => report.SourceId == sshId
            ? report with
            {
                Applicability = SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = null,
                Status = SourceHealthStatuses.Healthy,
                Enabled = true,
                LastEventTime = null,
                ObservedAt = now,
                PrerequisiteStatuses = report.PrerequisiteStatuses!.ToDictionary(
                    pair => pair.Key,
                    _ => SourceEvidenceStatuses.Satisfied,
                    StringComparer.Ordinal),
                EventFamilyStatuses = report.EventFamilyStatuses!.ToDictionary(
                    pair => pair.Key,
                    _ => SourceEvidenceStatuses.NotObserved,
                    StringComparer.Ordinal)
            }
            : report).ToArray(), now);
        var quietSsh = Assert.Single(quietApplicable, report => report.SourceId == sshId);
        Assert.Equal(SourceHealthStatuses.Healthy, quietSsh.Status);
        Assert.True(SourceHealthRules.UsesSuccessfulObservationFreshness(sshId));
        Assert.False(SourceHealthRules.IsSuccessfulPollingSource(sshId));
        Assert.Equal(WindowsCoverageLevel.L4, Current(quietApplicable));

        var stale = Merged(quietApplicable.Select(report => report.SourceId == sshId
            ? report with
            {
                Status = SourceHealthStatuses.Healthy,
                ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1)
            }
            : report).ToArray(), now);
        Assert.Equal(SourceHealthStatuses.Stale, Assert.Single(stale, report => report.SourceId == sshId).Status);
        Assert.Equal(WindowsCoverageLevel.L1, Current(stale));
    }

    [Fact]
    public void LinuxL4PollingFreshnessUsesSuccessfulObservationWithoutAnEvent()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");
        var policy = Report(Find(PolicySourceId), now) with { LastEventTime = null };
        var performance = Report(Find(PerformanceSourceId), now) with { LastEventTime = null };
        var role = Report(Find(RoleSourceIds[0]), now) with
        {
            Applicability = SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = null,
            Status = SourceHealthStatuses.Healthy,
            Enabled = true,
            LastEventTime = null,
            ObservedAt = now
        };

        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(policy, now));
        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(role, now));
        Assert.Equal(SourceHealthStatuses.Healthy, SourceHealthRules.EffectiveStatus(performance, now));
        Assert.Equal(SourceHealthStatuses.Stale, SourceHealthRules.EffectiveStatus(
            policy with { ObservedAt = now.Subtract(SourceHealthRules.PassivePollingStaleAfter).AddSeconds(-1) }, now));
        Assert.Equal(SourceHealthStatuses.Stale, SourceHealthRules.EffectiveStatus(
            performance with { ObservedAt = now.Subtract(SourceHealthRules.PerformanceSloStaleAfter).AddSeconds(-1) }, now));
        Assert.Equal(SourceHealthStatuses.Degraded, SourceHealthRules.EffectiveStatus(
            role with { ObservedAt = now.Add(SourceHealthRules.MaximumFutureObservationSkew).AddSeconds(1) }, now));
    }

    [Fact]
    public void CustomHealthyL4RowCannotReplaceCanonicalEvidence()
    {
        var now = DateTimeOffset.Parse("2026-07-16T12:00:00Z");
        var reports = Reports(now)
            .Where(report => report.SourceId != PolicySourceId)
            .Append(new SourceHealthReport
            {
                SourceId = "synthetic-custom-l4",
                Platform = TelemetryPlatforms.Linux,
                SourceKind = TelemetrySourceKinds.AgentHealth,
                SourceNamespace = "synthetic.custom",
                DisplayName = "Synthetic custom L4",
                CoverageLevel = WindowsCoverageLevel.L4,
                Requirement = SourceRequirementKinds.Mandatory,
                Required = true,
                Applicability = SourceApplicabilityStatuses.Applicable,
                Status = SourceHealthStatuses.Healthy,
                Enabled = true,
                ObservedAt = now
            })
            .ToArray();

        Assert.Equal(WindowsCoverageLevel.L3, Current(Merged(reports, now)));
    }

    [Fact]
    public void KnownLinuxL4CatalogMetadataCannotBeSpoofedInHeartbeat()
    {
        var now = DateTimeOffset.UtcNow;
        var canonical = Find(PolicySourceId) with
        {
            Applicability = SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = null
        };
        var health = Report(canonical, now);
        var request = new HeartbeatRequest
        {
            AgentId = "synthetic-linux-l4",
            Hostname = "SYNTHETIC-LINUX-L4",
            AgentVersion = "1.8.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = "synthetic-linux-l4-host",
            QueueDepth = 0,
            SourceManifest = [canonical],
            SourceHealth = [health]
        };

        Assert.Empty(RequestValidation.ValidateHeartbeat(request, now));

        var spoofedManifest = canonical with
        {
            CoverageLevel = WindowsCoverageLevel.L3,
            Requirement = SourceRequirementKinds.Optional,
            Required = false,
            ParserId = "synthetic-parser"
        };
        var spoofedHealth = health with
        {
            CoverageLevel = WindowsCoverageLevel.L3,
            Requirement = SourceRequirementKinds.Optional,
            Required = false
        };
        var errors = RequestValidation.ValidateHeartbeat(request with
        {
            SourceManifest = [spoofedManifest],
            SourceHealth = [spoofedHealth]
        }, now);

        Assert.Contains("source_manifest[0].coverage_level", errors.Keys);
        Assert.Contains("source_manifest[0].requirement", errors.Keys);
        Assert.Contains("source_manifest[0].parser_id", errors.Keys);
        Assert.Contains("source_health[0].coverage_level", errors.Keys);
        Assert.Contains("source_health[0].requirement", errors.Keys);
    }

    [Fact]
    public void PolicyPostureDetectionAlertsOnlyOnExactDriftEvidence()
    {
        var engine = new DetectionEngine();
        var health = new Dictionary<string, SourceHealthReport>(StringComparer.OrdinalIgnoreCase)
        {
            [PolicySourceId] = new SourceHealthReport
            {
                SourceId = PolicySourceId,
                Status = SourceHealthStatuses.Healthy,
                ObservedAt = DateTimeOffset.UtcNow,
                PrerequisiteStatuses = new Dictionary<string, string> { ["policy_scan"] = SourceEvidenceStatuses.Satisfied },
                EventFamilyStatuses = new Dictionary<string, string> { ["policy_drift"] = SourceEvidenceStatuses.Observed },
                Details = new Dictionary<string, string>()
            }
        };

        var drift = PolicyEvent("policy_drift", "drift");
        var matched = Assert.Single(engine.EvaluateLinux(drift, health), result => result.Rule.RuleId == "policy.security-posture-drift.linux");
        Assert.True(matched.PrerequisitesMet);
        Assert.True(matched.Matched);

        foreach (var (eventCode, action) in new[]
        {
            ("policy_baseline", "baseline"),
            ("policy_sample", "sample"),
            ("policy_gap", "gap"),
            ("policy_restored", "restored"),
            ("policy_drift", "sample")
        })
        {
            var result = Assert.Single(engine.EvaluateLinux(PolicyEvent(eventCode, action), health), item => item.Rule.RuleId == "policy.security-posture-drift.linux");
            Assert.False(result.Matched);
        }
    }

    [Fact]
    public void ServerSqlAndWebSurfacesContainStrictLinuxL4Gate()
    {
        var sourceHealth = Read("server", "Siem.Api", "Database", "SourceHealthRepository.cs");
        var review = Read("server", "Siem.Api", "Review", "ReviewRepository.cs");
        foreach (var implementation in new[] { sourceHealth, review })
        {
            Assert.Contains("linux_l2_role_source_count", implementation, StringComparison.Ordinal);
            Assert.Contains("l2_role_resolved_sources", implementation, StringComparison.Ordinal);
            Assert.Contains("linux_l4_mandatory_source_ids", implementation, StringComparison.Ordinal);
            Assert.Contains("linux_l4_role_source_ids", implementation, StringComparison.Ordinal);
            Assert.Contains("l4_role_resolved", implementation, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("effective_status = 'healthy'", implementation, StringComparison.Ordinal);
            Assert.Contains("then 'L4'", implementation, StringComparison.Ordinal);
            Assert.Contains("performance_source_health_stale_cutoff", implementation, StringComparison.Ordinal);
        }

        var detailModel = Read("server", "Siem.Api", "Pages", "Agents", "Detail.cshtml.cs");
        var detail = Read("server", "Siem.Api", "Pages", "Agents", "Detail.cshtml");
        var index = Read("server", "Siem.Api", "Pages", "Agents", "Index.cshtml");
        Assert.Contains("WindowsCoverageLevel.L4", detailModel, StringComparison.Ordinal);
        Assert.Contains("Coverage exceptions never satisfy this strict L4 gate", detail, StringComparison.Ordinal);
        Assert.Contains("asp-route-target_level=\"L4\"", index, StringComparison.Ordinal);
        Assert.Contains("approval_state' = 'missing_or_mismatched'", review, StringComparison.Ordinal);
    }

    private static IReadOnlyList<SourceHealthReport> Reports(DateTimeOffset now) =>
        LinuxTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L4)
            .Select(entry => Report(entry, now))
            .ToArray();

    private static SourceHealthReport Report(SourceManifestEntry entry, DateTimeOffset now)
    {
        var unsupported = entry.Applicability == SourceApplicabilityStatuses.Unsupported;
        var roleSpecific = entry.Requirement == SourceRequirementKinds.RoleSpecific;
        var status = unsupported
            ? SourceHealthStatuses.Unsupported
            : roleSpecific
                ? SourceHealthStatuses.NotApplicable
                : SourceHealthStatuses.Healthy;
        var applicability = unsupported
            ? SourceApplicabilityStatuses.Unsupported
            : roleSpecific
                ? SourceApplicabilityStatuses.NotApplicable
                : SourceApplicabilityStatuses.Applicable;
        var evidence = status == SourceHealthStatuses.Healthy
            ? SourceEvidenceStatuses.Satisfied
            : status == SourceHealthStatuses.Unsupported
                ? SourceEvidenceStatuses.Unsupported
                : SourceEvidenceStatuses.NotApplicable;
        var eventEvidence = status == SourceHealthStatuses.Healthy
            ? SourceHealthRules.IsSuccessfulPollingSource(entry.SourceId)
                ? SourceEvidenceStatuses.NotObserved
                : SourceEvidenceStatuses.Observed
            : evidence;
        var sequence = entry.CheckpointKind == SourceCheckpointKinds.Sequence ? 1L : (long?)null;
        var cursor = entry.CheckpointKind == SourceCheckpointKinds.Cursor ? "synthetic-cursor" : null;

        return new SourceHealthReport
        {
            SourceId = entry.SourceId,
            Platform = entry.Platform,
            SourceKind = entry.SourceKind,
            DisplayName = entry.DisplayName,
            SourceNamespace = entry.SourceNamespace,
            Facility = entry.Facility,
            Unit = entry.Unit,
            Applicability = applicability,
            ApplicabilityReason = unsupported || roleSpecific ? "synthetic_not_applicable" : null,
            CoverageLevel = entry.CoverageLevel,
            Status = status,
            Required = entry.Required,
            Requirement = entry.Requirement,
            ApplicableRoles = entry.ApplicableRoles,
            Enabled = !unsupported && !roleSpecific,
            LastEventTime = status == SourceHealthStatuses.Healthy ? now : null,
            ObservedAt = status == SourceHealthStatuses.Healthy ? now : null,
            CollectedCheckpoint = status == SourceHealthStatuses.Healthy ? new SourceCheckpoint { Cursor = cursor, Sequence = sequence, RecordedAt = now } : null,
            AcknowledgedCheckpoint = status == SourceHealthStatuses.Healthy ? new SourceCheckpoint { Cursor = cursor, Sequence = sequence, RecordedAt = now } : null,
            PrerequisiteStatuses = entry.Prerequisites.ToDictionary(item => item, _ => evidence, StringComparer.Ordinal),
            EventFamilyStatuses = entry.EventFamilies.ToDictionary(item => item, _ => eventEvidence, StringComparer.Ordinal),
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
        };
    }

    private static IReadOnlyList<SourceHealthReport> Merged(IReadOnlyList<SourceHealthReport> reports, DateTimeOffset now) =>
        TelemetryCoverageEvaluator.MergeExpectedSources(
            reports,
            WindowsCoverageLevel.L4,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            now,
            TelemetryPlatforms.Linux);

    private static WindowsCoverageLevel Current(IReadOnlyList<SourceHealthReport> reports) =>
        TelemetryCoverageEvaluator.CalculateCurrentLevel(reports, WindowsCoverageLevel.L4, TelemetryPlatforms.Linux);

    private static SourceManifestEntry Find(string sourceId) =>
        LinuxTelemetrySourceCatalog.All.Single(entry => entry.SourceId == sourceId);

    private static EventEnvelope PolicyEvent(string eventCode, string action) => new()
    {
        EventId = Guid.NewGuid(),
        AgentId = "synthetic-linux-l4",
        Hostname = "SYNTHETIC-LINUX-L4",
        Platform = TelemetryPlatforms.Linux,
        Source = EventSources.InventoryDiff,
        SourceId = PolicySourceId,
        EventCode = eventCode,
        EventTime = DateTimeOffset.UtcNow,
        Severity = "warning",
        Message = "Synthetic bounded policy-posture evidence.",
        Normalized = new NormalizedEventFields
        {
            Category = "policy_posture",
            Action = action,
            Outcome = "success"
        }
    };

    private static string Read(params string[] segments) => File.ReadAllText(RepositoryFile(segments));

    private static string RepositoryFile(params string[] segments) =>
        Path.Combine(FindRepositoryRoot(), Path.Combine(segments));

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
