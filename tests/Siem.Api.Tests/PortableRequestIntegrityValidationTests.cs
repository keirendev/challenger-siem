using System.Text.Json;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Passive;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class PortableRequestIntegrityValidationTests
{
    private static readonly DateTimeOffset ReceivedAt = DateTimeOffset.Parse("2026-07-16T12:00:00Z");

    [Fact]
    public void PortableEventsAcceptEquivalentScalarAndNestedRepresentations()
    {
        var sha256 = new string('a', 64);
        var normalized = new NormalizedEventFields
        {
            ProcessId = "4242",
            ParentProcessId = "41",
            ProcessImage = "/usr/bin/synthetic-worker",
            ProcessCommandLine = "/usr/bin/synthetic-worker --observe",
            UserName = "synthetic-user",
            UserSid = "1001",
            SourceIp = "2001:0db8:0000:0000:0000:0000:0000:0010",
            SourcePort = "00443",
            DestinationIp = "198.51.100.20",
            DestinationPort = "00053",
            Protocol = "TCP",
            FilePath = "/opt/synthetic/synthetic.conf",
            Hash = $"SHA256:{sha256.ToUpperInvariant()}",
            Process = new ProcessTelemetryConcept
            {
                Pid = "4242",
                ParentPid = "41",
                Executable = "/usr/bin/synthetic-worker",
                CommandLine = "/usr/bin/synthetic-worker --observe"
            },
            User = new UserTelemetryConcept { Name = "synthetic-user", Id = "1001" },
            Network = new NetworkTelemetryConcept
            {
                SourceIp = "2001:db8::10",
                SourcePort = 443,
                DestinationIp = "198.51.100.20",
                DestinationPort = 53,
                Protocol = "tcp"
            },
            File = new FileTelemetryConcept
            {
                Path = "/opt/synthetic/synthetic.conf",
                Sha256 = sha256
            }
        };

        var errors = RequestValidation.ValidateBatch(
            CreateBatch(CreatePortableEvent(normalized: normalized)),
            maxEventsPerBatch: 500,
            receivedAt: ReceivedAt);

        Assert.Empty(errors);
    }

    [Fact]
    public void PortableEventsRejectEveryConflictingScalarAndNestedRepresentation()
    {
        var normalized = new NormalizedEventFields
        {
            ProcessId = "4242",
            ParentProcessId = "41",
            ProcessImage = "/usr/bin/synthetic-a",
            ProcessCommandLine = "/usr/bin/synthetic-a --observe",
            UserName = "synthetic-user-a",
            UserSid = "1001",
            SourceIp = "192.0.2.10",
            SourcePort = "443",
            DestinationIp = "198.51.100.20",
            DestinationPort = "53",
            Protocol = "tcp",
            FilePath = "/opt/synthetic/a.conf",
            Hash = new string('a', 64),
            Process = new ProcessTelemetryConcept
            {
                Pid = "4243",
                ParentPid = "42",
                Executable = "/usr/bin/synthetic-b",
                CommandLine = "/usr/bin/synthetic-b --observe"
            },
            User = new UserTelemetryConcept { Name = "synthetic-user-b", Id = "1002" },
            Network = new NetworkTelemetryConcept
            {
                SourceIp = "192.0.2.11",
                SourcePort = 444,
                DestinationIp = "198.51.100.21",
                DestinationPort = 54,
                Protocol = "udp"
            },
            File = new FileTelemetryConcept
            {
                Path = "/opt/synthetic/b.conf",
                Sha256 = new string('b', 64)
            }
        };

        var errors = RequestValidation.ValidateBatch(
            CreateBatch(CreatePortableEvent(normalized: normalized)),
            maxEventsPerBatch: 500,
            receivedAt: ReceivedAt);

        var expectedKeys = new[]
        {
            "events[0].normalized.process.pid",
            "events[0].normalized.process.parent_pid",
            "events[0].normalized.process.executable",
            "events[0].normalized.process.command_line",
            "events[0].normalized.user.name",
            "events[0].normalized.user.id",
            "events[0].normalized.network.source_ip",
            "events[0].normalized.network.source_port",
            "events[0].normalized.network.destination_ip",
            "events[0].normalized.network.destination_port",
            "events[0].normalized.network.protocol",
            "events[0].normalized.file.path",
            "events[0].normalized.file.sha256"
        };
        Assert.All(expectedKeys, key => Assert.Contains(key, errors.Keys));
        Assert.Equal(expectedKeys.Length, errors.Count);
    }

    [Fact]
    public void LegacyWindowsEventsRetainConflictingDuplicateRepresentationCompatibility()
    {
        var normalized = new NormalizedEventFields
        {
            ProcessId = "4242",
            ProcessImage = "C:\\Synthetic\\a.exe",
            SourceIp = "192.0.2.10",
            SourcePort = "443",
            FilePath = "C:\\Synthetic\\a.conf",
            Hash = new string('a', 64),
            Process = new ProcessTelemetryConcept { Pid = "4243", Executable = "C:\\Synthetic\\b.exe" },
            Network = new NetworkTelemetryConcept { SourceIp = "192.0.2.11", SourcePort = 444 },
            File = new FileTelemetryConcept { Path = "C:\\Synthetic\\b.conf", Sha256 = new string('b', 64) }
        };
        var windowsEvent = CreateWindowsEvent(normalized);

        var errors = RequestValidation.ValidateBatch(
            CreateBatch(windowsEvent),
            maxEventsPerBatch: 500,
            receivedAt: ReceivedAt);

        Assert.Empty(errors);
    }

    [Fact]
    public void DuplicateEventIdsAreAlsoRejectedForLegacyWindowsBatches()
    {
        var windowsEvent = CreateWindowsEvent();

        var errors = RequestValidation.ValidateBatch(
            CreateBatch(windowsEvent, windowsEvent),
            maxEventsPerBatch: 500,
            receivedAt: ReceivedAt);

        Assert.Contains("events[0].event_id", errors.Keys);
        Assert.Contains("events[1].event_id", errors.Keys);
    }

    [Fact]
    public void DuplicatePortableEventIdsAreRejectedBeforeDetectionCanRun()
    {
        var envelope = CreatePortableEvent();

        var errors = RequestValidation.ValidateBatch(
            CreateBatch(envelope, envelope),
            maxEventsPerBatch: 500,
            receivedAt: ReceivedAt);

        Assert.Contains("events[0].event_id", errors.Keys);
        Assert.Contains("events[1].event_id", errors.Keys);
        Assert.All(errors.Where(error => error.Key.EndsWith(".event_id", StringComparison.Ordinal)),
            error => Assert.Contains("unique within an ingest batch", error.Value.Single(), StringComparison.Ordinal));
    }

    [Fact]
    public void KnownLinuxEventIdentityRequiresCanonicalCatalogCasingKindAndPlatform()
    {
        var canonical = LinuxTelemetrySourceCatalog.L3Passive.First();
        var valid = CreatePortableEvent(source: canonical.SourceKind!, sourceId: canonical.SourceId);
        Assert.Empty(RequestValidation.ValidateBatch(CreateBatch(valid), 500, ReceivedAt));

        var caseVariant = WithDeterministicId(valid with { SourceId = canonical.SourceId.ToUpperInvariant() });
        var caseErrors = RequestValidation.ValidateBatch(CreateBatch(caseVariant), 500, ReceivedAt);
        Assert.Contains("events[0].source_id", caseErrors.Keys);

        var wrongKind = WithDeterministicId(valid with { Source = EventSources.AgentHealth });
        var kindErrors = RequestValidation.ValidateBatch(CreateBatch(wrongKind), 500, ReceivedAt);
        Assert.Contains("events[0].source", kindErrors.Keys);

        var wrongPlatform = valid with { Platform = TelemetryPlatforms.Windows };
        var platformErrors = RequestValidation.ValidateBatch(CreateBatch(wrongPlatform), 500, ReceivedAt);
        Assert.Contains("events[0].platform", platformErrors.Keys);

        var wrongCheckpointWithoutId = valid with
        {
            Checkpoint = new SourceCheckpoint { Cursor = "s=synthetic;i=1" },
            Deduplication = valid.Deduplication! with
            {
                Inputs =
                [
                    DeduplicationInputs.AgentId,
                    DeduplicationInputs.SourceId,
                    DeduplicationInputs.CheckpointCursor,
                    DeduplicationInputs.EventCode
                ]
            }
        };
        var wrongCheckpoint = WithDeterministicId(wrongCheckpointWithoutId);
        var checkpointErrors = RequestValidation.ValidateBatch(CreateBatch(wrongCheckpoint), 500, ReceivedAt);
        Assert.Contains("events[0].checkpoint", checkpointErrors.Keys);
    }

    [Fact]
    public void KnownLinuxHeartbeatIdentityRequiresCanonicalCatalogDescriptors()
    {
        var valid = CreateCanonicalHeartbeat(ReceivedAt);
        Assert.Empty(RequestValidation.ValidateHeartbeat(valid, ReceivedAt));

        var canonical = valid.SourceManifest[0];
        var caseVariantId = canonical.SourceId.ToUpperInvariant();
        var caseVariant = valid with
        {
            SourceManifest = [canonical with { SourceId = caseVariantId }],
            SourceHealth = [valid.SourceHealth[0] with { SourceId = caseVariantId }]
        };
        var caseErrors = RequestValidation.ValidateHeartbeat(caseVariant, ReceivedAt);
        Assert.Contains("source_manifest[0].source_id", caseErrors.Keys);
        Assert.Contains("source_health[0].source_id", caseErrors.Keys);

        var wrongNamespace = valid with
        {
            SourceManifest = [canonical with { SourceNamespace = "systemd" }],
            SourceHealth = [valid.SourceHealth[0] with { SourceNamespace = "systemd" }]
        };
        var namespaceErrors = RequestValidation.ValidateHeartbeat(wrongNamespace, ReceivedAt);
        Assert.Contains("source_manifest[0].source_namespace", namespaceErrors.Keys);
        Assert.Contains("source_health[0].source_namespace", namespaceErrors.Keys);

        var wrongKind = valid with
        {
            SourceManifest = [canonical with { SourceKind = EventSources.InventoryDiff }],
            SourceHealth = [valid.SourceHealth[0] with { SourceKind = EventSources.InventoryDiff }]
        };
        var kindErrors = RequestValidation.ValidateHeartbeat(wrongKind, ReceivedAt);
        Assert.Contains("source_manifest[0].source_kind", kindErrors.Keys);
        Assert.Contains("source_health[0].source_kind", kindErrors.Keys);

        var wrongOptionalDescriptors = valid with
        {
            SourceManifest = [canonical with { Facility = "daemon", Unit = "synthetic.service", CheckpointKind = SourceCheckpointKinds.Sequence }],
            SourceHealth = [valid.SourceHealth[0] with { Facility = "daemon", Unit = "synthetic.service" }]
        };
        var descriptorErrors = RequestValidation.ValidateHeartbeat(wrongOptionalDescriptors, ReceivedAt);
        Assert.Contains("source_manifest[0].facility", descriptorErrors.Keys);
        Assert.Contains("source_manifest[0].unit", descriptorErrors.Keys);
        Assert.Contains("source_manifest[0].checkpoint_kind", descriptorErrors.Keys);
        Assert.Contains("source_health[0].facility", descriptorErrors.Keys);
        Assert.Contains("source_health[0].unit", descriptorErrors.Keys);
    }

    [Fact]
    public void PortableEventAndHeartbeatObservationTimesEnforceFiveMinuteReceiveSkew()
    {
        var boundaryEvent = CreatePortableEvent(eventTime: ReceivedAt + RequestValidation.MaximumFutureTimestampSkew);
        Assert.Empty(RequestValidation.ValidateBatch(CreateBatch(boundaryEvent), 500, ReceivedAt));

        var futureEvent = CreatePortableEvent(
            eventTime: ReceivedAt + RequestValidation.MaximumFutureTimestampSkew + TimeSpan.FromSeconds(1));
        var eventErrors = RequestValidation.ValidateBatch(CreateBatch(futureEvent), 500, ReceivedAt);
        Assert.Contains("events[0].event_time", eventErrors.Keys);

        var boundaryHeartbeat = CreateCanonicalHeartbeat(
            ReceivedAt + RequestValidation.MaximumFutureTimestampSkew,
            includeResourceMetrics: true);
        Assert.Empty(RequestValidation.ValidateHeartbeat(boundaryHeartbeat, ReceivedAt));

        var futureObservedAt = ReceivedAt + RequestValidation.MaximumFutureTimestampSkew + TimeSpan.FromSeconds(1);
        var futureHeartbeat = CreateCanonicalHeartbeat(futureObservedAt, includeResourceMetrics: true);
        var heartbeatErrors = RequestValidation.ValidateHeartbeat(futureHeartbeat, ReceivedAt);
        Assert.Contains("source_health[0].observed_at", heartbeatErrors.Keys);
        Assert.Contains("resource_metrics.observed_at", heartbeatErrors.Keys);
    }

    [Fact]
    public void PortableHeartbeatFreshnessAndCheckpointTimesEnforceReceiveSkew()
    {
        var future = ReceivedAt + RequestValidation.MaximumFutureTimestampSkew + TimeSpan.FromSeconds(1);
        var heartbeat = CreateCanonicalHeartbeat(ReceivedAt);
        var futureCheckpoint = heartbeat.SourceHealth[0].CollectedCheckpoint! with
        {
            EventTime = future,
            RecordedAt = future
        };
        var futureHeartbeat = heartbeat with
        {
            LastEventTime = future,
            SourceHealth =
            [
                heartbeat.SourceHealth[0] with
                {
                    LastEventTime = future,
                    CollectedCheckpoint = futureCheckpoint,
                    AcknowledgedCheckpoint = futureCheckpoint
                }
            ]
        };

        var errors = RequestValidation.ValidateHeartbeat(futureHeartbeat, ReceivedAt);
        Assert.Contains("last_event_time", errors.Keys);
        Assert.Contains("source_health[0].last_event_time", errors.Keys);
        Assert.Contains("source_health[0].collected_checkpoint.event_time", errors.Keys);
        Assert.Contains("source_health[0].collected_checkpoint.recorded_at", errors.Keys);
        Assert.Contains("source_health[0].acknowledged_checkpoint.event_time", errors.Keys);
        Assert.Contains("source_health[0].acknowledged_checkpoint.recorded_at", errors.Keys);
    }

    [Fact]
    public async Task PassiveRuntimeHeartbeatCapsMergedDetailsAtPortableContractLimit()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-heartbeat-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var statePath = Path.Combine(root, "passive-state.json");
            var options = new LinuxAgentOptions
            {
                AgentId = "synthetic-agent",
                ServerBaseUrl = new Uri("https://siem.example.invalid"),
                ApiToken = "synthetic-token",
                PassiveTelemetry = new PassiveTelemetryOptions
                {
                    Enabled = true,
                    StatePath = statePath
                }
            };
            var clock = new FixedTimeProvider(ReceivedAt);
            var sources = new EmptyPassiveSources();
            var collector = new LinuxPassiveTelemetryCollector(
                Options.Create(options), sources, sources, sources, clock);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var persistedDetails = Enumerable.Range(0, LinuxPassiveTelemetryLimits.MaximumHealthDetailEntries)
                .ToDictionary(index => $"persisted_{index:00}", _ => "synthetic", StringComparer.Ordinal);
            var state = new LinuxPassiveTelemetryState
            {
                Metrics = new LinuxPassiveMetricsState
                {
                    Progress = new PassiveSourceProgress
                    {
                        NextSequence = 2,
                        CollectedSequence = 1,
                        AcknowledgedSequence = 1,
                        LastScanAt = ReceivedAt,
                        LastEventAt = ReceivedAt,
                        AcknowledgedAt = ReceivedAt,
                        LastHealthStatus = SourceHealthStatuses.Healthy,
                        LastHealthErrorCode = "none",
                        LastHealthDetails = persistedDetails,
                        HealthTransitionState = HealthTransitionStates.Healthy,
                        HealthTransitionedAt = ReceivedAt,
                        FamilyCounts = new Dictionary<string, long>(StringComparer.Ordinal)
                        {
                            ["host_metrics_sample"] = 1
                        }
                    }
                }
            };
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            await store.WriteAsync(state, default);
            var runtime = new LinuxPassiveTelemetryRuntime(
                Options.Create(options), store, collector, clock);
            await runtime.InitializeAsync(default);
            var health = runtime.Health();
            var heartbeat = new HeartbeatRequest
            {
                AgentId = options.AgentId,
                Hostname = "synthetic-linux",
                AgentVersion = "1.8.1-test",
                Os = "Synthetic Linux",
                Platform = TelemetryPlatforms.Linux,
                HostId = "synthetic-host-id",
                LastEventTime = ReceivedAt,
                QueueDepth = 0,
                SourceManifest = runtime.Manifest,
                SourceHealth = health
            };

            var errors = RequestValidation.ValidateHeartbeat(heartbeat, ReceivedAt);

            Assert.Empty(errors);
            Assert.All(health, item => Assert.True(
                item.Details.Count <= LinuxPassiveTelemetryLimits.MaximumHealthDetailEntries));
            var metrics = Assert.Single(
                health,
                item => item.SourceId == LinuxTelemetrySourceIds.HostBehaviourMetrics);
            Assert.Equal(LinuxPassiveTelemetryLimits.MaximumHealthDetailEntries, metrics.Details.Count);
            Assert.Equal("enabled", metrics.Details["collector_state"]);
            Assert.Equal("matched", metrics.Details["approval_state"]);
            Assert.Equal("persisted", metrics.Details["acknowledgement_state"]);
            Assert.Contains("visibility", metrics.Details.Keys);
            Assert.Contains("persisted_00", metrics.Details.Keys);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static IngestBatchRequest CreateBatch(params EventEnvelope[] events) => new()
    {
        AgentId = "synthetic-agent",
        BatchId = Guid.Parse("00000000-0000-4000-8000-000000000040"),
        SentAt = ReceivedAt,
        Events = events
    };

    private static EventEnvelope CreatePortableEvent(
        NormalizedEventFields? normalized = null,
        string source = EventSources.InventoryDiff,
        string sourceId = "synthetic-portable-integrity",
        DateTimeOffset? eventTime = null)
    {
        var timestamp = eventTime ?? ReceivedAt;
        var raw = JsonSerializer.SerializeToElement(new { synthetic = true, sequence = 1 });
        var envelope = new EventEnvelope
        {
            AgentId = "synthetic-agent",
            Hostname = "synthetic-linux",
            Platform = TelemetryPlatforms.Linux,
            Source = source,
            SourceId = sourceId,
            EventCode = "synthetic_integrity_event",
            Checkpoint = new SourceCheckpoint { Sequence = 1, EventTime = timestamp, RecordedAt = timestamp },
            EventTime = timestamp,
            Severity = "information",
            Message = "Synthetic portable request-integrity fixture.",
            Normalized = normalized,
            Raw = raw,
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw).Length,
                RedactedFields = Array.Empty<string>(),
                TruncatedFields = Array.Empty<string>()
            },
            Deduplication = new EventDeduplicationMetadata
            {
                Inputs =
                [
                    DeduplicationInputs.AgentId,
                    DeduplicationInputs.SourceId,
                    DeduplicationInputs.CheckpointSequence,
                    DeduplicationInputs.EventCode
                ]
            }
        };
        return WithDeterministicId(envelope);
    }

    private static EventEnvelope WithDeterministicId(EventEnvelope envelope) =>
        envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };

    private static EventEnvelope CreateWindowsEvent(NormalizedEventFields? normalized = null) => new()
    {
        EventId = Guid.Parse("00000000-0000-4000-8000-000000000050"),
        AgentId = "synthetic-agent",
        Hostname = "SYNTHETIC-WINDOWS",
        Source = EventSources.WindowsEventLog,
        Channel = "Security",
        Provider = "Synthetic-Provider",
        WindowsEventId = 4688,
        RecordId = 50,
        EventTime = ReceivedAt,
        Severity = "information",
        Message = "Synthetic legacy request-integrity fixture.",
        Normalized = normalized,
        Raw = JsonSerializer.SerializeToElement(new { synthetic = true })
    };

    private static HeartbeatRequest CreateCanonicalHeartbeat(
        DateTimeOffset observedAt,
        bool includeResourceMetrics = false)
    {
        var manifest = LinuxTelemetrySourceCatalog.L1.Single();
        var checkpoint = new SourceCheckpoint
        {
            Cursor = "s=synthetic;i=1",
            EventTime = ReceivedAt,
            RecordedAt = ReceivedAt
        };
        var health = new SourceHealthReport
        {
            SourceId = manifest.SourceId,
            Platform = manifest.Platform,
            SourceKind = manifest.SourceKind,
            DisplayName = manifest.DisplayName,
            SourceNamespace = manifest.SourceNamespace,
            Facility = manifest.Facility,
            Unit = manifest.Unit,
            Applicability = manifest.Applicability,
            ApplicabilityReason = manifest.ApplicabilityReason,
            CoverageLevel = manifest.CoverageLevel,
            Status = SourceHealthStatuses.Healthy,
            Required = manifest.Required,
            Requirement = manifest.Requirement,
            ApplicableRoles = manifest.ApplicableRoles,
            Enabled = true,
            LastEventTime = ReceivedAt,
            ObservedAt = observedAt,
            CollectedCheckpoint = checkpoint,
            AcknowledgedCheckpoint = checkpoint,
            PrerequisiteStatuses = manifest.Prerequisites.ToDictionary(
                prerequisite => prerequisite,
                _ => SourceEvidenceStatuses.Satisfied,
                StringComparer.Ordinal),
            EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                family => family,
                _ => SourceEvidenceStatuses.Observed,
                StringComparer.Ordinal),
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
        };
        return new HeartbeatRequest
        {
            AgentId = "synthetic-agent",
            Hostname = "synthetic-linux",
            AgentVersion = "1.7.0-test",
            Os = "Synthetic Linux",
            Platform = TelemetryPlatforms.Linux,
            HostId = "synthetic-host-id",
            LastEventTime = ReceivedAt,
            QueueDepth = 0,
            ResourceMetrics = includeResourceMetrics
                ? new AgentResourceMetrics
                {
                    ObservedAt = observedAt,
                    CpuPercent = 1,
                    RssBytes = 1,
                    ManagedMemoryBytes = 1,
                    Status = "observed"
                }
                : null,
            SourceManifest = [manifest],
            SourceHealth = [health]
        };
    }

    private sealed class EmptyPassiveSources :
        ILinuxProcessSnapshotSource,
        ILinuxNetworkSnapshotSource,
        ILinuxHostMetricsSource
    {
        public Task<PassiveReadResult<LinuxProcessObservation>> ReadAsync(
            PassiveTelemetryOptions options,
            CancellationToken cancellationToken) =>
            Task.FromResult(new PassiveReadResult<LinuxProcessObservation>(
                Array.Empty<LinuxProcessObservation>(), PassiveReadStatuses.Missing, "synthetic", false, 0));

        Task<PassiveReadResult<LinuxSocketObservation>> ILinuxNetworkSnapshotSource.ReadAsync(
            PassiveTelemetryOptions options,
            CancellationToken cancellationToken) =>
            Task.FromResult(new PassiveReadResult<LinuxSocketObservation>(
                Array.Empty<LinuxSocketObservation>(), PassiveReadStatuses.Missing, "synthetic", false, 0));

        Task<PassiveReadResult<LinuxHostMetricsObservation>> ILinuxHostMetricsSource.ReadAsync(
            PassiveTelemetryOptions options,
            CancellationToken cancellationToken) =>
            Task.FromResult(new PassiveReadResult<LinuxHostMetricsObservation>(
                Array.Empty<LinuxHostMetricsObservation>(), PassiveReadStatuses.Missing, "synthetic", false, 0));
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }
}
