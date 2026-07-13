using System.Text.Json;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V1;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class RequestValidationTests
{
    [Theory]
    [InlineData(69, "normal")]
    [InlineData(70, "warning_70")]
    [InlineData(85, "warning_85")]
    [InlineData(95, "critical_95")]
    [InlineData(100, "over_capacity")]
    public void StorageAccountingWarningStateUsesConfiguredCapacityThresholds(int usedPercent, string expected)
    {
        const long capacity = 100L * 1024 * 1024 * 1024;
        var used = capacity * usedPercent / 100;

        Assert.Equal(expected, EventRepository.CalculateStorageWarningState(used, capacity));
    }

    [Fact]
    public void StorageAccountingThresholdsExposeHardCapacityCeiling()
    {
        var thresholds = EventRepository.BuildStorageThresholds(ManagedRetentionOptions.HardManagedCapacityBytes);

        Assert.Contains(thresholds, item => item.Percent == 70 && item.State == "warning_70");
        Assert.Contains(thresholds, item => item.Percent == 85 && item.State == "warning_85");
        Assert.Contains(thresholds, item => item.Percent == 95 && item.State == "critical_95");
        Assert.Contains(thresholds, item => item.Percent == 100 && item.State == "over_capacity" && item.Bytes == ManagedRetentionOptions.HardManagedCapacityBytes);
    }

    [Fact]
    public void ManagedRetentionOptionsValidatorRejectsUnboundedCleanupConfiguration()
    {
        var validator = new ManagedRetentionOptionsValidator();
        var invalid = new ManagedRetentionOptions
        {
            TargetRetentionDays = 0,
            ManagedCapacityBytes = ManagedRetentionOptions.HardManagedCapacityBytes + 1,
            CleanupBatchSize = 0,
            MaxBatchesPerRun = 0,
            EmergencyTargetPercent = 100,
            HostedServiceIntervalMinutes = 1,
            AdvisoryLockKey = 0
        };

        var result = validator.Validate(null, invalid);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, item => item.Contains("TargetRetentionDays", StringComparison.Ordinal));
        Assert.Contains(result.Failures, item => item.Contains("ManagedCapacityBytes", StringComparison.Ordinal));
        Assert.Contains(result.Failures, item => item.Contains("100 GiB", StringComparison.Ordinal));
        Assert.Contains(result.Failures, item => item.Contains("CleanupBatchSize", StringComparison.Ordinal));

        var tooSmall = validator.Validate(null, new ManagedRetentionOptions { ManagedCapacityBytes = 1 });
        Assert.True(tooSmall.Failed);
        Assert.Contains(tooSmall.Failures, item => item.Contains("ManagedCapacityBytes", StringComparison.Ordinal));
    }

    [Fact]
    public void ValidateBatchAcceptsValidWindowsEventBatch()
    {
        var batch = CreateValidBatch();

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 500);

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateBatchRejectsMismatchedEventAgentId()
    {
        var valid = CreateValidBatch();
        var invalidEvent = valid.Events[0] with { AgentId = "other-agent" };
        var batch = valid with { Events = new[] { invalidEvent } };

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 500);

        Assert.Contains("events[0].agent_id", errors.Keys);
    }

    [Fact]
    public void ValidateBatchRejectsOversizedBatch()
    {
        var valid = CreateValidBatch();
        var events = Enumerable.Range(0, 2)
            .Select(index => valid.Events[0] with { EventId = Guid.NewGuid(), RecordId = index + 1 })
            .ToArray();
        var batch = valid with { Events = events };

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 1);

        Assert.Contains(nameof(IngestBatchRequest.Events), errors.Keys);
    }

    [Fact]
    public void ValidateHeartbeatAcceptsBoundedObservabilityAndPreservesUnknownVsZero()
    {
        var heartbeat = CreateLinuxHeartbeat() with
        {
            CpuPercent = null,
            MemoryMb = null,
            ResourceMetrics = new AgentResourceMetrics
            {
                ObservedAt = DateTimeOffset.Parse("2026-07-11T12:00:00Z"),
                CpuPercent = null,
                RssBytes = 0,
                ManagedMemoryBytes = 0,
                Status = "partial"
            },
            QueueMetrics = new QueueSloMetrics
            {
                QueueDepth = 0,
                PoisonDepth = 0,
                OldestQueuedAgeSeconds = null,
                QueueSizeBytes = 0,
                MaxSizeBytes = 1024,
                UsedPercent = 0,
                PressureState = QueuePressureStates.Normal,
                SendState = QueueSendStates.Idle,
                BackoffSeconds = null,
                LastSuccessfulSendTime = null,
                PoisonEventsTotal = 0,
                DroppedEventsTotal = 0,
                MaxSizeMb = 1,
                WarningSizePercent = 70
            }
        };

        var errors = RequestValidation.ValidateHeartbeat(heartbeat);

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateHeartbeatRejectsUnboundedObservabilityValues()
    {
        var valid = CreateLinuxHeartbeat();
        var invalid = valid with
        {
            ResourceMetrics = new AgentResourceMetrics
            {
                ObservedAt = DateTimeOffset.UtcNow,
                CpuPercent = 101,
                RssBytes = -1,
                ManagedMemoryBytes = -1,
                Status = "secret-dump"
            },
            QueueMetrics = valid.QueueMetrics! with
            {
                PressureState = "credentialed-host-path",
                SendState = "raw-error-body",
                UsedPercent = 1001,
                BackoffSeconds = 86_401
            },
            SourceHealth = new[]
            {
                valid.SourceHealth[0] with
                {
                    EventRatePerMinute = 1_000_001,
                    LagSeconds = -1,
                    SilenceSeconds = -1,
                    GapCount = -1,
                    TransitionState = "full-log-body",
                    DroppedEvents = -1,
                    PoisonEvents = -1
                }
            }
        };

        var errors = RequestValidation.ValidateHeartbeat(invalid);

        Assert.Contains("resource_metrics.cpu_percent", errors.Keys);
        Assert.Contains("queue_metrics.pressure_state", errors.Keys);
        Assert.Contains("source_health[0].lag_seconds", errors.Keys);
        Assert.Contains("source_health[0].transition_state", errors.Keys);
    }

    [Fact]
    public void ValidateRegistrationRequiresAgentIdentity()
    {
        var request = new AgentRegistrationRequest
        {
            AgentId = "",
            Hostname = "WIN11-TEST",
            MachineGuid = "machine-guid",
            OsVersion = "Windows 11",
            AgentVersion = "0.1.0"
        };

        var errors = RequestValidation.ValidateRegistration(request);

        Assert.Contains(nameof(AgentRegistrationRequest.AgentId), errors.Keys);
    }

    private static HeartbeatRequest CreateLinuxHeartbeat()
    {
        var manifest = new SourceManifestEntry
        {
            SourceId = "linux-journal-l1",
            Platform = TelemetryPlatforms.Linux,
            SourceKind = EventSources.LinuxJournal,
            SourceNamespace = "systemd",
            Applicability = SourceApplicabilityStatuses.Applicable,
            CheckpointKind = SourceCheckpointKinds.Cursor,
            DisplayName = "Linux journal",
            CoverageLevel = WindowsCoverageLevel.L1,
            Required = true,
            Requirement = SourceRequirementKinds.Mandatory,
            Prerequisites = new[] { "systemd_journal_available" },
            EventFamilies = new[] { "system" },
            ValidationScenarios = new[] { "synthetic_journal" }
        };
        return new HeartbeatRequest
        {
            AgentId = "linux-synthetic-001",
            Hostname = "linux-synthetic",
            AgentVersion = "1.2.0",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = "synthetic-host-id",
            LastEventTime = DateTimeOffset.Parse("2026-07-11T12:00:00Z"),
            QueueDepth = 0,
            QueueMetrics = new QueueSloMetrics
            {
                QueueDepth = 0,
                PoisonDepth = 0,
                MaxSizeMb = 1,
                WarningSizePercent = 70
            },
            SourceManifest = new[] { manifest },
            SourceHealth = new[]
            {
                new SourceHealthReport
                {
                    SourceId = manifest.SourceId,
                    Platform = manifest.Platform,
                    SourceKind = manifest.SourceKind,
                    SourceNamespace = manifest.SourceNamespace,
                    Applicability = manifest.Applicability,
                    DisplayName = manifest.DisplayName,
                    CoverageLevel = manifest.CoverageLevel,
                    Status = SourceHealthStatuses.Healthy,
                    Required = manifest.Required,
                    Requirement = manifest.Requirement,
                    Enabled = true,
                    LastEventTime = DateTimeOffset.Parse("2026-07-11T12:00:00Z"),
                    ObservedAt = DateTimeOffset.Parse("2026-07-11T12:00:01Z"),
                    CollectedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic;i=1" },
                    AcknowledgedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic;i=1" },
                    PrerequisiteStatuses = new Dictionary<string,string> { ["systemd_journal_available"] = SourceEvidenceStatuses.Satisfied },
                    EventFamilyStatuses = new Dictionary<string,string> { ["system"] = SourceEvidenceStatuses.Observed },
                    SilenceSeconds = 0,
                    EventRatePerMinute = 0,
                    GapCount = 0,
                    TransitionState = HealthTransitionStates.Healthy,
                    TransitionedAt = DateTimeOffset.Parse("2026-07-11T12:00:01Z"),
                    DroppedEvents = 0,
                    PoisonEvents = 0
                }
            }
        };
    }

    private static IngestBatchRequest CreateValidBatch()
    {
        return new IngestBatchRequest
        {
            AgentId = "win11-test-001",
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                new EventEnvelope
                {
                    EventId = Guid.NewGuid(),
                    AgentId = "win11-test-001",
                    Hostname = "WIN11-TEST",
                    Source = EventSources.WindowsEventLog,
                    Channel = "Security",
                    Provider = "Microsoft-Windows-Security-Auditing",
                    WindowsEventId = 4625,
                    RecordId = 123456,
                    EventTime = DateTimeOffset.UtcNow,
                    IngestTime = null,
                    Severity = "audit_failure",
                    Message = "An account failed to log on.",
                    Raw = JsonSerializer.SerializeToElement(new { event_data = new { target_user_name = "alice" } })
                }
            }
        };
    }
}
