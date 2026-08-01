using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class RequestValidationTests
{
    [Theory]
    [InlineData("/api/v2/agents/register", true)]
    [InlineData("/api/v2/agents/heartbeat", true)]
    [InlineData("/API/V2/INGEST/EVENTS", true)]
    [InlineData("/api/v2/agents-not-a-route", false)]
    [InlineData("/api/v2/events", false)]
    [InlineData("/mcp", false)]
    public void ServiceAuthenticationDoesNotMisclassifyAgentCredentialRoutes(string path, bool expected)
    {
        Assert.Equal(expected, ServiceAuthentication.UsesAgentCredential(new PathString(path)));
    }

    [Fact]
    public void ManualRetentionExecutionRequiresExactConfirmationWhileDryRunDoesNot()
    {
        Assert.True(new RetentionRunRequest().HasRequiredManualConfirmation());
        Assert.False(new RetentionRunRequest(DryRun: false).HasRequiredManualConfirmation());
        Assert.False(new RetentionRunRequest(DryRun: false, ConfirmImpact: "confirm retention delete").HasRequiredManualConfirmation());
        Assert.True(new RetentionRunRequest(
            DryRun: false,
            ConfirmImpact: RetentionRunRequest.ExecutionConfirmation).HasRequiredManualConfirmation());
    }

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
            .Select(_ => valid.Events[0] with { EventId = Guid.NewGuid() })
            .ToArray();
        var batch = valid with { Events = events };

        var errors = RequestValidation.ValidateBatch(batch, maxEventsPerBatch: 1);

        Assert.Contains(nameof(IngestBatchRequest.Events), errors.Keys);
    }

    [Fact]
    public void InventoryPagingContractAcceptsCompleteMetadataAndRejectsLossyClaims()
    {
        var snapshot = new AssetInventorySnapshot
        {
            AgentId = "synthetic-agent",
            Hostname = "SYNTHETIC-LINUX-01",
            SnapshotType = "linux_packages",
            CollectedAt = DateTimeOffset.Parse("2026-08-01T12:00:00Z"),
            Items = [new InventoryItem { Kind = "package", Name = "synthetic-package", Status = "installed" }],
            Summary = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["generation_id"] = "synthetic-generation",
                ["page_index"] = "1",
                ["page_count"] = "2",
                ["page_item_count"] = "1",
                ["total_item_count"] = "2",
                ["source_complete"] = "true",
                ["source_truncated"] = "false"
            }
        };
        var request = new AssetInventoryBatchRequest
        {
            AgentId = snapshot.AgentId,
            SentAt = snapshot.CollectedAt,
            Snapshots = [snapshot]
        };

        Assert.Empty(RequestValidation.ValidateInventoryBatch(request));
        var invalid = request with
        {
            Snapshots = [snapshot with { Summary = snapshot.Summary.ToDictionary(pair => pair.Key, pair => pair.Key == "page_item_count" ? "2" : pair.Value) }]
        };
        Assert.Contains("snapshots[0].summary.page_item_count", RequestValidation.ValidateInventoryBatch(invalid).Keys);
    }

    [Fact]
    public void InventoryGenerationCompletenessIsDerivedFromEveryReceivedPage()
    {
        static AssetInventorySnapshot Page(int index) => new()
        {
            AgentId = "synthetic-agent",
            Hostname = "SYNTHETIC-LINUX-01",
            SnapshotType = "linux_timers",
            CollectedAt = DateTimeOffset.Parse("2026-08-01T12:00:00Z"),
            Items = [new InventoryItem { Kind = "timer", Name = $"synthetic-{index}.timer", Status = "enabled" }],
            Summary = new Dictionary<string, string>
            {
                ["generation_id"] = "synthetic-generation",
                ["page_index"] = index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["page_count"] = "3",
                ["page_item_count"] = "1",
                ["total_item_count"] = "3",
                ["source_complete"] = "true",
                ["source_truncated"] = "false"
            }
        };

        Assert.False(AssetInventoryPaging.Status([Page(1), Page(3)]).Complete);
        var complete = AssetInventoryPaging.Status([Page(3), Page(1), Page(2)]);
        Assert.True(complete.Complete);
        Assert.Equal(3, complete.ReceivedPageCount);
        Assert.Equal(3, AssetInventoryPaging.Reassemble([Page(2), Page(1), Page(3)]).Items.Count);
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
    public async Task ValidateHeartbeatAcceptsUnobservedLinuxSourcesWithNullLastEventTime()
    {
        var temporaryRoot = Path.Combine(Path.GetTempPath(), "challenger-heartbeat-validation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporaryRoot);
        try
        {
            var statePath = Path.Combine(temporaryRoot, "state.json");
            var options = new LinuxAgentOptions
            {
                AgentId = "linux-synthetic-validation-001",
                ApiToken = "fake-test-token",
                ServerBaseUrl = new Uri("https://siem.synthetic"),
                Journal = new JournalOptions
                {
                    TargetCoverageLevel = CoverageLevel.L2,
                    DeclaredRoles = ["ssh_server"]
                },
                Queue = new QueueOptions { Path = Path.Combine(temporaryRoot, "queue.sqlite") },
                State = new StateOptions { Path = statePath }
            };
            var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(statePath), TimeProvider.System);
            await runtime.InitializeAsync("1.6.0-test", "synthetic-config", default);
            var snapshot = runtime.Snapshot();
            var ssh = Assert.Single(snapshot.Health, item => item.SourceId == LinuxTelemetrySourceIds.Ssh);
            Assert.Null(ssh.LastEventTime);

            var heartbeat = new HeartbeatRequest
            {
                AgentId = options.AgentId,
                Hostname = "linux-synthetic",
                AgentVersion = "1.6.0-test",
                Os = "Synthetic Linux",
                Platform = TelemetryPlatforms.Linux,
                HostId = "synthetic-host-id",
                LastEventTime = null,
                QueueDepth = 0,
                QueueMetrics = new QueueSloMetrics
                {
                    QueueDepth = 0,
                    PoisonDepth = 0,
                    MaxSizeMb = 1,
                    WarningSizePercent = 70
                },
                SourceManifest = snapshot.Manifest,
                SourceHealth = snapshot.Health
            };

            var errors = RequestValidation.ValidateHeartbeat(heartbeat);

            Assert.Empty(errors);
        }
        finally
        {
            Directory.Delete(temporaryRoot, recursive: true);
        }
    }

    [Fact]
    public void ValidateHeartbeatAcceptsInventoryResolvedUnsupportedPackageProducer()
    {
        var manifest = LinuxTelemetrySourceCatalog.L2Security.Single(entry =>
            entry.SourceId == LinuxTelemetrySourceIds.PackageManagement) with
        {
            Applicability = SourceApplicabilityStatuses.Unsupported,
            ApplicabilityReason = "package_manager_producer_out_of_scope"
        };
        var heartbeat = CreateLinuxHeartbeat() with
        {
            SourceManifest = [manifest],
            SourceHealth =
            [
                new SourceHealthReport
                {
                    SourceId = manifest.SourceId,
                    Platform = manifest.Platform,
                    SourceKind = manifest.SourceKind,
                    SourceNamespace = manifest.SourceNamespace,
                    Applicability = manifest.Applicability,
                    ApplicabilityReason = manifest.ApplicabilityReason,
                    DisplayName = manifest.DisplayName,
                    CoverageLevel = manifest.CoverageLevel,
                    Status = SourceHealthStatuses.Unsupported,
                    Required = manifest.Required,
                    Requirement = manifest.Requirement,
                    ApplicableRoles = manifest.ApplicableRoles,
                    Enabled = false,
                    ObservedAt = DateTimeOffset.Parse("2026-07-11T12:00:01Z"),
                    PrerequisiteStatuses = manifest.Prerequisites.ToDictionary(
                        item => item,
                        _ => SourceEvidenceStatuses.Unsupported,
                        StringComparer.Ordinal),
                    EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                        item => item,
                        _ => SourceEvidenceStatuses.Unsupported,
                        StringComparer.Ordinal),
                    EventRatePerMinute = 0,
                    GapCount = 0,
                    TransitionState = HealthTransitionStates.Degraded,
                    TransitionedAt = DateTimeOffset.Parse("2026-07-11T12:00:01Z"),
                    DroppedEvents = 0,
                    PoisonEvents = 0
                }
            ]
        };

        var errors = RequestValidation.ValidateHeartbeat(heartbeat);

        Assert.Empty(errors);

        var notApplicableManifest = manifest with
        {
            Applicability = SourceApplicabilityStatuses.NotApplicable,
            ApplicabilityReason = "synthetic_not_applicable"
        };
        var notApplicableHealth = heartbeat.SourceHealth.Single() with
        {
            Applicability = notApplicableManifest.Applicability,
            ApplicabilityReason = notApplicableManifest.ApplicabilityReason,
            Status = SourceHealthStatuses.NotApplicable,
            PrerequisiteStatuses = notApplicableManifest.Prerequisites.ToDictionary(
                item => item,
                _ => SourceEvidenceStatuses.NotApplicable,
                StringComparer.Ordinal),
            EventFamilyStatuses = notApplicableManifest.EventFamilies.ToDictionary(
                item => item,
                _ => SourceEvidenceStatuses.NotApplicable,
                StringComparer.Ordinal)
        };
        var invalid = heartbeat with
        {
            SourceManifest = [notApplicableManifest],
            SourceHealth = [notApplicableHealth]
        };

        var invalidErrors = RequestValidation.ValidateHeartbeat(invalid);

        Assert.Contains("source_health[0].applicability", invalidErrors.Keys);
    }

    [Fact]
    public void ValidateRegistrationRequiresAgentIdentity()
    {
        var request = new AgentRegistrationRequest
        {
            AgentId = "",
            Hostname = "linux-test",
            OsVersion = "Linux Test",
            AgentVersion = "2.0.0",
            Platform = TelemetryPlatforms.Linux,
            HostId = "synthetic-host-id"
        };

        var errors = RequestValidation.ValidateRegistration(request);

        Assert.Contains(nameof(AgentRegistrationRequest.AgentId), errors.Keys);
    }

    private static HeartbeatRequest CreateLinuxHeartbeat()
    {
        var manifest = LinuxTelemetrySourceCatalog.L1.Single();
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
                    ApplicableRoles = manifest.ApplicableRoles,
                    Enabled = true,
                    LastEventTime = DateTimeOffset.Parse("2026-07-11T12:00:00Z"),
                    ObservedAt = DateTimeOffset.Parse("2026-07-11T12:00:01Z"),
                    CollectedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic;i=1" },
                    AcknowledgedCheckpoint = new SourceCheckpoint { Cursor = "s=synthetic;i=1" },
                    PrerequisiteStatuses = manifest.Prerequisites.ToDictionary(item => item, _ => SourceEvidenceStatuses.Satisfied, StringComparer.Ordinal),
                    EventFamilyStatuses = manifest.EventFamilies.ToDictionary(item => item, _ => SourceEvidenceStatuses.Observed, StringComparer.Ordinal),
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
            AgentId = "linux-test-001",
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = new[]
            {
                new EventEnvelope
                {
                    EventId = Guid.NewGuid(),
                    AgentId = "linux-test-001",
                    Hostname = "linux-test",
                    Platform = TelemetryPlatforms.Linux,
                    Source = EventSources.LinuxJournal,
                    SourceId = LinuxTelemetrySourceIds.JournalL1,
                    EventCode = "ssh.login.failure",
                    Facility = "authpriv",
                    Unit = "sshd.service",
                    Checkpoint = new SourceCheckpoint { Sequence = 123456 },
                    Deduplication = new EventDeduplicationMetadata
                    {
                        Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode]
                    },
                    DataHandling = new DataHandlingMetadata
                    {
                        RawSizeBytes = 2,
                        RedactedFields = [],
                        TruncatedFields = []
                    },
                    EventTime = DateTimeOffset.UtcNow,
                    IngestTime = null,
                    Severity = "audit_failure",
                    Message = "An account failed to log on.",
                    Raw = JsonSerializer.SerializeToElement(new { synthetic = true })
                }
            }
        };
    }
}
