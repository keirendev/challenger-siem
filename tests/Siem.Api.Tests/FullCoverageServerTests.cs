using System.Text.Json;
using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class FullCoverageServerTests
{
    [Fact]
    public void HeartbeatValidationAcceptsSourceHealthAndQueueMetrics()
    {
        var request = new HeartbeatRequest
        {
            AgentId = "agent-coverage-test",
            Hostname = "HOST-COVERAGE",
            AgentVersion = "0.4.0-test",
            Os = "Windows Test",
            QueueDepth = 2,
            HostTimezone = SyntheticPacificTimezone(),
            ConfigHash = "abc123",
            QueueMetrics = new QueueSloMetrics
            {
                QueueDepth = 2,
                PoisonDepth = 1,
                MaxSizeMb = 512,
                WarningSizePercent = 80
            },
            SourceHealth = new[]
            {
                new SourceHealthReport
                {
                    SourceId = "security",
                    DisplayName = "Windows Security",
                    Channel = "Security",
                    CoverageLevel = WindowsCoverageLevel.L2,
                    Status = SourceHealthStatuses.Healthy,
                    Required = true,
                    Enabled = true,
                    NewestRecordId = 100,
                    HostTimezone = SyntheticPacificTimezone()
                }
            }
        };

        Assert.Empty(RequestValidation.ValidateHeartbeat(request));
    }

    [Fact]
    public void HostTimezoneValidationRejectsOutOfRangeOffsets()
    {
        var request = new HeartbeatRequest
        {
            AgentId = "agent-coverage-test",
            Hostname = "HOST-COVERAGE",
            AgentVersion = "0.4.0-test",
            Os = "Windows Test",
            QueueDepth = 0,
            HostTimezone = SyntheticPacificTimezone() with { UtcOffsetMinutes = 1000 }
        };

        var errors = RequestValidation.ValidateHeartbeat(request);

        Assert.Contains("host_timezone.utc_offset_minutes", errors.Keys);
    }

    [Fact]
    public void EventSearchDateTimeLocalFiltersAreInterpretedAsUtc()
    {
        var query = EventSearchQuery.FromQuery(new QueryCollection(new Dictionary<string, StringValues>
        {
            ["from"] = "2026-07-04T12:00",
            ["to"] = "2026-07-04T13:30"
        }));

        Assert.Equal(new DateTimeOffset(2026, 7, 4, 12, 0, 0, TimeSpan.Zero), query.From);
        Assert.Equal(new DateTimeOffset(2026, 7, 4, 13, 30, 0, TimeSpan.Zero), query.To);
    }

    [Fact]
    public void TimeDisplayUsesHostOffsetWhenAvailableAndUtcFallbackWhenMissing()
    {
        var utc = new DateTimeOffset(2026, 7, 4, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal("2026-07-04 05:00:00 UTC-07:00", TimeDisplay.FormatHostTime(utc, SyntheticPacificTimezone()));
        Assert.Equal("2026-07-04 12:00:00 UTC", TimeDisplay.FormatHostTime(utc, null));
        Assert.Contains("Pacific Standard Time", TimeDisplay.HostTimezoneLabel(SyntheticPacificTimezone()), StringComparison.Ordinal);
    }

    [Fact]
    public void HeartbeatValidationRejectsUnknownSourceStatus()
    {
        var request = new HeartbeatRequest
        {
            AgentId = "agent-coverage-test",
            Hostname = "HOST-COVERAGE",
            AgentVersion = "0.4.0-test",
            Os = "Windows Test",
            QueueDepth = 0,
            SourceHealth = new[]
            {
                new SourceHealthReport
                {
                    SourceId = "security",
                    DisplayName = "Windows Security",
                    Channel = "Security",
                    Status = "surprised",
                    Required = true,
                    Enabled = true
                }
            }
        };

        var errors = RequestValidation.ValidateHeartbeat(request);
        Assert.Contains("source_health[0].status", errors.Keys);
    }

    [Fact]
    public void SourceHealthRulesMarkOldRequiredSourcesStale()
    {
        var status = Challenger.Siem.Api.Database.SourceHealthRules.EffectiveStatus(new SourceHealthReport
        {
            SourceId = "security",
            DisplayName = "Windows Security",
            Channel = "Security",
            Status = SourceHealthStatuses.Healthy,
            Required = true,
            Enabled = true,
            LastEventTime = DateTimeOffset.UtcNow.AddDays(-2)
        }, DateTimeOffset.UtcNow);

        Assert.Equal(SourceHealthStatuses.Stale, status);
    }

    [Fact]
    public void WindowsTelemetrySourceCatalogIncludesL2ValidationSources()
    {
        var sources = WindowsTelemetrySourceCatalog.ExpectedFor(WindowsCoverageLevel.L2);

        Assert.Contains(sources, source => source.SourceId == "security" && source.Required);
        Assert.Contains(sources, source => source.SourceId == "rdp-corets" && source.Required);
        Assert.Contains(sources, source => source.SourceId == "applocker-msi-script" && !source.Required);
        Assert.DoesNotContain(sources, source => source.SourceId == "sysmon-operational");
    }

    [Fact]
    public void TelemetryCoverageEvaluatorAddsMissingExpectedSources()
    {
        var sources = TelemetryCoverageEvaluator.MergeExpectedSources(new[]
        {
            new SourceHealthReport
            {
                SourceId = "system",
                DisplayName = "Windows System",
                Channel = "System",
                CoverageLevel = WindowsCoverageLevel.L1,
                Status = SourceHealthStatuses.Healthy,
                Required = true,
                Enabled = true,
                LastEventTime = DateTimeOffset.UtcNow
            }
        }, WindowsCoverageLevel.L2, new HashSet<string>(StringComparer.OrdinalIgnoreCase), DateTimeOffset.UtcNow);

        Assert.Contains(sources, source => source.SourceId == "system" && source.Details["reported_by_agent"] == "true");
        Assert.Contains(sources, source => source.SourceId == "security" && source.Status == SourceHealthStatuses.Missing && source.Details["reported_by_agent"] == "false");
        var summary = TelemetryCoverageEvaluator.CreateSummary("agent", "HOST", 0, DateTimeOffset.UtcNow, sources, WindowsCoverageLevel.L2);
        Assert.Equal(WindowsCoverageLevel.L0, summary.CurrentLevel);
        Assert.True(summary.MissingMandatorySources > 0);
        Assert.Equal(SourceHealthStatuses.Missing, summary.OverallStatus);
    }

    [Fact]
    public void TelemetryCoverageEvaluatorDoesNotCountOptionalL3SourcesAsMandatoryForL2()
    {
        var manifest = WindowsTelemetrySourceCatalog.BuildManifest(
            new[] { "Security", "System", "Application" },
            new[] { "Microsoft-Windows-Sysmon/Operational" });
        var sysmon = Assert.Single(manifest, source => source.SourceId == "sysmon-operational");

        Assert.False(sysmon.Required);
    }

    [Fact]
    public void DetectionCatalogCoversRequiredDetectionFamilies()
    {
        var categories = DetectionRuleCatalog.BuiltInRules.Select(rule => rule.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var required in new[] { "authentication", "account", "powershell", "credential_access", "persistence", "tamper", "malware", "network", "impact", "coverage" })
        {
            Assert.Contains(required, categories);
        }
    }

    [Fact]
    public void TelemetryCoverageSourcesExposeSourceVersionAndConfigHashAdditively()
    {
        var source = new SourceTelemetryCoverage
        {
            SourceId = "sysmon-operational",
            DisplayName = "Sysmon Operational",
            Channel = "Microsoft-Windows-Sysmon/Operational",
            CoverageLevel = WindowsCoverageLevel.L3,
            Required = true,
            Enabled = true,
            Reported = true,
            Status = SourceHealthStatuses.Healthy,
            SourceVersion = "challenger-siem-l3-2026.07.06",
            ConfigHash = "abcdef123456",
            Details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["source_pack"] = "windows-l3-sysmon"
            },
            RecentEventCount = 10,
            Reason = "healthy",
            EventSearchUrl = "/events",
            SourceHealthUrl = "/agents/detail"
        };

        var json = JsonSerializer.Serialize(source, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("source_version", json, StringComparison.Ordinal);
        Assert.Contains("config_hash", json, StringComparison.Ordinal);
        Assert.Contains("details", json, StringComparison.Ordinal);
    }

    [Fact]
    public void TelemetryCoverageMappingExposesPersistedSourceObservability()
    {
        var observedAt = DateTimeOffset.Parse("2026-07-14T00:00:00Z");
        var deniedSince = observedAt.AddMinutes(-5);
        var recoveredAt = observedAt.AddMinutes(-1);
        var source = new SourceHealthReport
        {
            SourceId = LinuxTelemetrySourceIds.JournalL1,
            DisplayName = "Linux journal L1",
            Platform = TelemetryPlatforms.Linux,
            SourceKind = TelemetrySourceKinds.LinuxJournal,
            SourceNamespace = "linux.journal",
            Applicability = SourceApplicabilityStatuses.Applicable,
            CoverageLevel = WindowsCoverageLevel.L1,
            Status = SourceHealthStatuses.Degraded,
            Required = true,
            Enabled = true,
            ObservedAt = observedAt,
            LastEventTime = observedAt.AddSeconds(-20),
            LagSeconds = 20,
            SilenceSeconds = 20,
            EventRatePerMinute = 3.5m,
            CollectedCheckpoint = new SourceCheckpoint { Cursor = "cursor-collected", EventTime = observedAt.AddSeconds(-20), RecordedAt = observedAt },
            AcknowledgedCheckpoint = new SourceCheckpoint { Cursor = "cursor-acked", EventTime = observedAt.AddSeconds(-30), RecordedAt = observedAt.AddSeconds(-10) },
            GapCount = 2,
            PermissionDeniedSince = deniedSince,
            RecoveredAt = recoveredAt,
            TransitionState = HealthTransitionStates.Recovering,
            TransitionedAt = observedAt,
            DroppedEvents = 4,
            PoisonEvents = 1,
            Details = new Dictionary<string, string>(StringComparer.Ordinal) { ["gap_state"] = "rotation" }
        };

        var coverage = TelemetryCoverageRepository.ToSourceCoverage(
            "synthetic-agent",
            source,
            observedAt.AddHours(-1),
            new Dictionary<string, int>(StringComparer.Ordinal) { [LinuxTelemetrySourceIds.JournalL1] = 7 },
            null);

        Assert.Equal(20, coverage.LagSeconds);
        Assert.Equal("cursor-collected", coverage.CollectedCheckpoint!.Cursor);
        Assert.Equal("cursor-acked", coverage.AcknowledgedCheckpoint!.Cursor);
        Assert.Equal(deniedSince, coverage.PermissionDeniedSince);
        Assert.Equal(recoveredAt, coverage.RecoveredAt);
        Assert.Equal(4, coverage.DroppedEvents);
        Assert.Equal(1, coverage.PoisonEvents);
        Assert.Equal(7, coverage.RecentEventCount);
        Assert.True(coverage.HasCheckpointGap);
        Assert.Contains("partial", coverage.StateGuidance, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TelemetryCoverageContractsExposePressureGapCapacityAndGuidanceAdditively()
    {
        var source = new SourceTelemetryCoverage
        {
            SourceId = LinuxTelemetrySourceIds.JournalL1,
            DisplayName = "Synthetic Linux journal",
            Platform = TelemetryPlatforms.Linux,
            CoverageLevel = WindowsCoverageLevel.L1,
            Required = true,
            Enabled = true,
            Reported = true,
            Status = SourceHealthStatuses.Degraded,
            RecentEventCount = 0,
            HasCheckpointGap = true,
            IsThrottled = true,
            StateGuidance = "Source is degraded or throttled; review pressure and backlog before assuming complete coverage.",
            Reason = "synthetic degraded state",
            EventSearchUrl = "/events?source_id=linux-journal-l1",
            SourceHealthUrl = "/agents/detail"
        };
        var agent = new AgentTelemetryCoverage
        {
            AgentId = "synthetic-agent",
            Hostname = "SYNTHETIC-LINUX-01",
            AgentStatus = "active",
            Platform = TelemetryPlatforms.Linux,
            PressureState = QueuePressureStates.Throttled,
            CapacityState = "critical_95",
            HasGap = true,
            IsThrottled = true,
            Sources = [source]
        };

        var json = JsonSerializer.Serialize(agent, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("pressure_state", json, StringComparison.Ordinal);
        Assert.Contains("capacity_state", json, StringComparison.Ordinal);
        Assert.Contains("has_gap", json, StringComparison.Ordinal);
        Assert.Contains("state_guidance", json, StringComparison.Ordinal);
    }

    [Fact]
    public void DetectionEngineReportsCoveragePrerequisiteFailures()
    {
        var engine = new DetectionEngine();
        var envelope = new EventEnvelope
        {
            EventId = Guid.NewGuid(),
            AgentId = "agent",
            Hostname = "host",
            Channel = "Security",
            Provider = "Microsoft-Windows-Security-Auditing",
            WindowsEventId = 4625,
            RecordId = 1,
            EventTime = DateTimeOffset.UtcNow,
            Severity = "audit_failure",
            Message = "failure",
            Normalized = new NormalizedEventFields { Category = "authentication", Action = "logon", Outcome = "failure" },
            Raw = JsonSerializer.SerializeToElement(new { synthetic = true })
        };

        var results = engine.Evaluate(envelope, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        Assert.Contains(results, result => result.Rule.RuleId == "auth.bruteforce.windows" && !result.PrerequisitesMet);
    }

    [Fact]
    public void SocAgentContractsSerializeToolRunsAndCitations()
    {
        var response = new SocAgentAskResponse
        {
            Answer = "Synthetic answer",
            ToolRuns = new[] { new SocAgentToolRunSummary { ToolName = "event_search", RowCount = 1, Summary = "one event" } },
            Citations = new[] { new SocAgentCitation { Kind = "event_detail", Label = "Event", Url = "/events/detail" } }
        };

        var json = JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("tool_runs", json, StringComparison.Ordinal);
        Assert.Contains("citations", json, StringComparison.Ordinal);
    }

    private static HostTimezoneMetadata SyntheticPacificTimezone() => new()
    {
        Id = "Pacific Standard Time",
        DisplayName = "(UTC-08:00) Pacific Time (US & Canada)",
        StandardName = "Pacific Standard Time",
        DaylightName = "Pacific Daylight Time",
        BaseUtcOffsetMinutes = -480,
        UtcOffsetMinutes = -420,
        IsDaylightSavingTime = true
    };

    [Fact]
    public void AlertAndDetectionContractsSerializeWithSnakeCaseFields()
    {
        var alert = new AlertRecord
        {
            AlertId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            RuleId = "unit.rule",
            RuleVersion = 2,
            Title = "Unit alert",
            Severity = DetectionSeverities.High,
            Confidence = "high",
            Status = AlertStatuses.New,
            CreatedAt = DateTimeOffset.UnixEpoch,
            Summary = "Synthetic alert",
            Evidence = new[] { new AlertEvidenceRecord { AgentId = "agent", EventId = Guid.Parse("11111111-2222-3333-4444-555555555555"), Summary = "evidence" } }
        };

        var json = JsonSerializer.Serialize(alert, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("alert_id", json, StringComparison.Ordinal);
        Assert.Contains("rule_version", json, StringComparison.Ordinal);
        Assert.Contains("evidence", json, StringComparison.Ordinal);
    }
}
