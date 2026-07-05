using System.Text.Json;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V1;
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
                    NewestRecordId = 100
                }
            }
        };

        Assert.Empty(RequestValidation.ValidateHeartbeat(request));
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
    public void DetectionCatalogCoversRequiredDetectionFamilies()
    {
        var categories = DetectionRuleCatalog.BuiltInRules.Select(rule => rule.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var required in new[] { "authentication", "account", "powershell", "credential_access", "persistence", "tamper", "malware", "network", "impact", "coverage" })
        {
            Assert.Contains(required, categories);
        }
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
