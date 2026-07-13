using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Challenger.Siem.Api.Ingestion;
using Challenger.Siem.Contracts.V1;
using Json.Schema;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class CrossPlatformContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private static readonly string FixturesRoot = Path.Combine(RepositoryRoot, "tests", "ContractFixtures", "v1");
    private static readonly string SchemasRoot = Path.Combine(RepositoryRoot, "contracts", "v1");

    [Theory]
    [InlineData("windows-registration.legacy.json", "agent-registration.schema.json", typeof(AgentRegistrationRequest))]
    [InlineData("windows-heartbeat.legacy.json", "heartbeat.schema.json", typeof(HeartbeatRequest))]
    [InlineData("windows-ingest.legacy.json", "ingest-batch.schema.json", typeof(IngestBatchRequest))]
    [InlineData("windows-search.legacy.json", "event-search.schema.json", typeof(EventSearchResponse))]
    [InlineData("windows-source-health.legacy.json", "source-health.schema.json", typeof(SourceHealthResponse))]
    [InlineData("linux-registration.synthetic.json", "agent-registration.schema.json", typeof(AgentRegistrationRequest))]
    [InlineData("linux-heartbeat.synthetic.json", "heartbeat.schema.json", typeof(HeartbeatRequest))]
    [InlineData("linux-ingest.synthetic.json", "ingest-batch.schema.json", typeof(IngestBatchRequest))]
    public void GoldenFixturesValidateDeserializeAndRoundTrip(string fixtureName, string schemaName, Type contractType)
    {
        var json = ReadFixture(fixtureName);
        AssertSchemaValid(schemaName, JsonNode.Parse(json)!);

        var contract = JsonSerializer.Deserialize(json, contractType, JsonOptions);
        Assert.NotNull(contract);
        var serialized = JsonSerializer.Serialize(contract, contractType, JsonOptions);
        AssertSchemaValid(schemaName, JsonNode.Parse(serialized)!);

        var reparsed = JsonSerializer.Deserialize(serialized, contractType, JsonOptions);
        Assert.Equal(serialized, JsonSerializer.Serialize(reparsed, contractType, JsonOptions));
    }

    [Fact]
    public async Task LinuxRegistrationIsNotRejectedAsCrossPlatformStoragePending()
    {
        const string enrollmentToken = "synthetic-contract-enrollment-token";
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SiemDatabase"] = "Host=127.0.0.1;Database=unused_contract_test;Username=unused_contract_test",
                    ["Auth:EnrollmentToken"] = enrollmentToken,
                });
            });
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Enrollment-Token", enrollmentToken);

        var registration = DeserializeFixture<AgentRegistrationRequest>("linux-registration.synthetic.json");
        using var response = await client.PostAsJsonAsync("/api/v1/agents/register", registration, JsonOptions);

        // Multi-platform storage is active; the obsolete 422 storage-pending gate must not fire.
        // Without a live database the handler may fail later, but never as cross_platform_storage_pending.
        Assert.NotEqual(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        if (response.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("cross_platform_storage_pending", body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void LegacyWindowsPayloadsRetainWindowsIdentityWithoutNewRequirements()
    {
        var registration = DeserializeFixture<AgentRegistrationRequest>("windows-registration.legacy.json");
        var heartbeat = DeserializeFixture<HeartbeatRequest>("windows-heartbeat.legacy.json");
        var batch = DeserializeFixture<IngestBatchRequest>("windows-ingest.legacy.json");
        var search = DeserializeFixture<EventSearchResponse>("windows-search.legacy.json");
        var health = DeserializeFixture<SourceHealthResponse>("windows-source-health.legacy.json");

        Assert.Null(registration.Platform);
        Assert.Null(registration.HostId);
        Assert.Null(heartbeat.Platform);
        Assert.Null(heartbeat.SourceManifest[0].SourceKind);
        Assert.Equal("Security", batch.Events[0].Channel);
        Assert.Equal(4625, batch.Events[0].WindowsEventId);
        Assert.Equal(4102, batch.Events[0].RecordId);
        Assert.Null(batch.Events[0].Platform);
        Assert.Null(batch.Events[0].Checkpoint);
        Assert.Equal(4625, search.Events[0].WindowsEventId);
        Assert.Equal("Security", health.Sources[0].Channel);

        Assert.Empty(RequestValidation.ValidateRegistration(registration));
        Assert.Empty(RequestValidation.ValidateHeartbeat(heartbeat));
        Assert.Empty(RequestValidation.ValidateBatch(batch, 500));
        var legacyCaseVariantBatch = batch with
        {
            Events = new[] { batch.Events[0] with { Severity = "AUDIT_FAILURE" } }
        };
        Assert.Empty(RequestValidation.ValidateBatch(legacyCaseVariantBatch, 500));
        Assert.False(RequestValidation.RequiresCrossPlatformStorage(registration));
        Assert.False(RequestValidation.RequiresCrossPlatformStorage(heartbeat));
        Assert.False(RequestValidation.RequiresCrossPlatformStorage(batch));
    }

    [Fact]
    public void PreviouslyValidLegacyWindowsBoundariesRemainSchemaAndRuntimeValid()
    {
        var batchNode = JsonNode.Parse(ReadFixture("windows-ingest.legacy.json"))!.AsObject();
        var eventNode = batchNode["events"]!.AsArray()[0]!.AsObject();
        eventNode["raw"] = new JsonObject { ["value"] = new string('r', ContractLimits.RawPayloadMaxUtf8Bytes) };
        eventNode["normalized"]!["entities"] = new JsonArray
        {
            new JsonObject { ["type"] = string.Empty, ["value"] = string.Empty }
        };
        var labels = new JsonObject();
        for (var index = 0; index <= ContractLimits.MaxMetadataEntries; index++)
        {
            labels[index == 0 ? string.Empty : $"legacy-label-{index}"] = new string('v', 2_049);
        }
        eventNode["normalized"]!["labels"] = labels;
        AssertSchemaValid("ingest-batch.schema.json", batchNode);
        var legacyBatch = batchNode.Deserialize<IngestBatchRequest>(JsonOptions)!;
        Assert.Empty(RequestValidation.ValidateBatch(legacyBatch, 500));

        var heartbeatNode = JsonNode.Parse(ReadFixture("windows-heartbeat.legacy.json"))!.AsObject();
        heartbeatNode["last_event_time"] = "0001-01-01T00:00:00Z";
        heartbeatNode["cpu_percent"] = 101;
        heartbeatNode["source_manifest"]!.AsArray()[0]!["prerequisites"] = new JsonArray(string.Empty);
        heartbeatNode["source_health"]!.AsArray()[0]!["last_event_time"] = "0001-01-01T00:00:00Z";
        heartbeatNode["source_health"]!.AsArray()[0]!["details"] = new JsonObject
        {
            [new string('k', 129)] = new string('v', 1_001)
        };
        heartbeatNode["tamper_checks"] = new JsonObject { ["binary_hash"] = new string('h', 129) };
        var legacyQueueMetricShapes = new[]
        {
            new JsonObject(),
            new JsonObject { ["queue_depth"] = 1 },
            new JsonObject { ["max_size_mb"] = 1 },
            new JsonObject { ["warning_size_percent"] = 100 },
            new JsonObject
            {
                ["queue_depth"] = 1,
                ["poison_depth"] = 0,
                ["last_successful_send_time"] = "0001-01-01T00:00:00Z",
                ["max_size_mb"] = 1,
                ["warning_size_percent"] = 100
            }
        };
        foreach (var queueMetrics in legacyQueueMetricShapes)
        {
            var candidateNode = JsonNode.Parse(heartbeatNode.ToJsonString())!.AsObject();
            candidateNode["queue_metrics"] = JsonNode.Parse(queueMetrics.ToJsonString());
            AssertSchemaValid("heartbeat.schema.json", candidateNode);
            var legacyHeartbeat = candidateNode.Deserialize<HeartbeatRequest>(JsonOptions)!;
            Assert.Empty(RequestValidation.ValidateHeartbeat(legacyHeartbeat));
            AssertSchemaValid("heartbeat.schema.json", JsonNode.Parse(JsonSerializer.Serialize(legacyHeartbeat, JsonOptions))!);
        }

        var healthNode = JsonNode.Parse(ReadFixture("windows-source-health.legacy.json"))!.AsObject();
        var summary = healthNode["summaries"]!.AsArray()[0]!.AsObject();
        summary["agent_id"] = new string('a', 129);
        summary["hostname"] = new string('h', 256);
        summary["overall_status"] = "legacy_custom_status";
        var summaries = healthNode["summaries"]!.AsArray();
        var summaryJson = summary.ToJsonString();
        while (summaries.Count <= 500)
        {
            summaries.Add(JsonNode.Parse(summaryJson));
        }
        AssertSchemaValid("source-health.schema.json", healthNode);

        var linuxBoundedResponse = JsonNode.Parse(healthNode.ToJsonString())!.AsObject();
        var linuxHealth = JsonNode.Parse(ReadFixture("linux-heartbeat.synthetic.json"))!["source_health"]!.AsArray()[0]!;
        linuxBoundedResponse["sources"] = new JsonArray(JsonNode.Parse(linuxHealth.ToJsonString()));
        AssertSchemaInvalid("source-health.schema.json", linuxBoundedResponse);

        var windowsNeutralBoundedResponse = JsonNode.Parse(healthNode.ToJsonString())!.AsObject();
        var windowsNeutralHealth = JsonNode.Parse(linuxHealth.ToJsonString())!;
        windowsNeutralHealth["platform"] = TelemetryPlatforms.Windows;
        windowsNeutralHealth["source_kind"] = EventSources.InventoryDiff;
        windowsNeutralBoundedResponse["sources"] = new JsonArray(windowsNeutralHealth);
        AssertSchemaInvalid("source-health.schema.json", windowsNeutralBoundedResponse);
    }

    [Fact]
    public void LinuxGoldensRepresentAllRequiredRecordKindsWithoutWindowsIdentifiers()
    {
        var registration = DeserializeFixture<AgentRegistrationRequest>("linux-registration.synthetic.json");
        var heartbeat = DeserializeFixture<HeartbeatRequest>("linux-heartbeat.synthetic.json");
        var batch = DeserializeFixture<IngestBatchRequest>("linux-ingest.synthetic.json");

        Assert.Equal(
            new[] { EventSources.AgentHealth, EventSources.InventoryDiff, EventSources.LinuxAudit, EventSources.LinuxJournal },
            batch.Events.Select(item => item.Source).Order(StringComparer.Ordinal).ToArray());
        Assert.All(batch.Events, envelope =>
        {
            Assert.Equal(TelemetryPlatforms.Linux, envelope.Platform);
            Assert.False(string.IsNullOrWhiteSpace(envelope.SourceId));
            Assert.Null(envelope.WindowsEventId);
            Assert.Null(envelope.RecordId);
            Assert.Null(envelope.Channel);
            Assert.Null(envelope.Provider);
            Assert.NotNull(envelope.Checkpoint);
            Assert.NotNull(envelope.Deduplication);
            Assert.NotNull(envelope.DataHandling);
            Assert.Equal(envelope.EventId, DeterministicEventIdentity.ComputeSha256Uuid(envelope));
        });
        Assert.Equal("f2f56cd6-0323-55e2-8786-b7e65a5b6eeb", batch.Events[0].EventId.ToString());
        Assert.Equal("01c14b1a-68fb-543a-97b8-1252e083dc06", batch.Events[1].EventId.ToString());
        Assert.Equal("1b51e5a7-079f-5b44-aaea-c65ba22ad0fe", batch.Events[2].EventId.ToString());
        Assert.Equal("6ee656fb-e6d4-52b2-b990-cd6587c70d0e", batch.Events[3].EventId.ToString());
        var eventTimeIdentity = batch.Events[0] with
        {
            Deduplication = batch.Events[0].Deduplication! with
            {
                Inputs = new[] { "agent_id", "source_id", "checkpoint.cursor", "event_time" }
            }
        };
        Assert.Equal(Guid.Parse("62009cd5-a45f-5a46-8a34-3155c4a7a131"), DeterministicEventIdentity.ComputeSha256Uuid(eventTimeIdentity));

        var serialized = JsonSerializer.Serialize(batch, JsonOptions);
        using var document = JsonDocument.Parse(serialized);
        foreach (var element in document.RootElement.GetProperty("events").EnumerateArray())
        {
            Assert.False(element.TryGetProperty("windows_event_id", out _));
            Assert.False(element.TryGetProperty("record_id", out _));
            Assert.False(element.TryGetProperty("channel", out _));
            Assert.False(element.TryGetProperty("provider", out _));
        }

        Assert.Empty(RequestValidation.ValidateRegistration(registration));
        Assert.Empty(RequestValidation.ValidateHeartbeat(heartbeat));
        Assert.Empty(RequestValidation.ValidateBatch(batch, 500));
        Assert.True(RequestValidation.RequiresCrossPlatformStorage(registration));
        Assert.True(RequestValidation.RequiresCrossPlatformStorage(heartbeat));
        Assert.True(RequestValidation.RequiresCrossPlatformStorage(batch));
    }

    [Fact]
    public void PlatformNeutralSourcesAreValidOnWindowsWhileLinuxNativeSourcesRemainLinuxOnly()
    {
        Assert.True(TelemetrySourceKinds.IsLinuxNative(EventSources.LinuxJournal));
        Assert.True(TelemetrySourceKinds.IsLinuxNative(EventSources.LinuxAudit));
        Assert.False(TelemetrySourceKinds.IsLinuxNative(EventSources.InventoryDiff));
        Assert.False(TelemetrySourceKinds.IsLinuxNative(EventSources.AgentHealth));
        Assert.True(TelemetrySourceKinds.IsPlatformNeutral(EventSources.InventoryDiff));
        Assert.True(TelemetrySourceKinds.IsPlatformNeutral(EventSources.AgentHealth));
        Assert.True(TelemetrySourceKinds.IsValidForPlatform(EventSources.InventoryDiff, TelemetryPlatforms.Windows));
        Assert.True(TelemetrySourceKinds.IsValidForPlatform(EventSources.AgentHealth, TelemetryPlatforms.Linux));
        Assert.False(TelemetrySourceKinds.IsValidForPlatform(EventSources.LinuxJournal, TelemetryPlatforms.Windows));
        Assert.False(TelemetrySourceKinds.IsValidForPlatform(EventSources.WindowsEventLog, TelemetryPlatforms.Linux));

        var linuxBatch = DeserializeFixture<IngestBatchRequest>("linux-ingest.synthetic.json");
        var windowsNeutralBatch = linuxBatch with
        {
            Events = linuxBatch.Events
                .Where(item => TelemetrySourceKinds.IsPlatformNeutral(item.Source))
                .Select(item => item with { Platform = TelemetryPlatforms.Windows })
                .ToArray()
        };
        Assert.Equal(new[] { EventSources.InventoryDiff, EventSources.AgentHealth },
            windowsNeutralBatch.Events.Select(item => item.Source).ToArray());
        Assert.Empty(RequestValidation.ValidateBatch(windowsNeutralBatch, 500));
        AssertSchemaValid("ingest-batch.schema.json", JsonSerializer.SerializeToNode(windowsNeutralBatch, JsonOptions)!);
        Assert.True(RequestValidation.RequiresCrossPlatformStorage(windowsNeutralBatch));

        var linuxHeartbeat = DeserializeFixture<HeartbeatRequest>("linux-heartbeat.synthetic.json");
        var windowsNeutralHeartbeat = linuxHeartbeat with
        {
            Platform = TelemetryPlatforms.Windows,
            SourceManifest = linuxHeartbeat.SourceManifest
                .Where(item => TelemetrySourceKinds.IsPlatformNeutral(item.SourceKind))
                .Select(item => item with { Platform = TelemetryPlatforms.Windows })
                .ToArray(),
            SourceHealth = linuxHeartbeat.SourceHealth
                .Where(item => TelemetrySourceKinds.IsPlatformNeutral(item.SourceKind))
                .Select(item => item with { Platform = TelemetryPlatforms.Windows })
                .ToArray()
        };
        Assert.Empty(RequestValidation.ValidateHeartbeat(windowsNeutralHeartbeat));
        AssertSchemaValid("heartbeat.schema.json", JsonSerializer.SerializeToNode(windowsNeutralHeartbeat, JsonOptions)!);
        AssertSchemaValid("source-health.schema.json", new JsonObject
        {
            ["summaries"] = new JsonArray(),
            ["sources"] = JsonSerializer.SerializeToNode(windowsNeutralHeartbeat.SourceHealth, JsonOptions)
        });
        Assert.True(RequestValidation.RequiresCrossPlatformStorage(windowsNeutralHeartbeat));

        var mismatchedPlatform = windowsNeutralHeartbeat with
        {
            SourceManifest = new[]
            {
                windowsNeutralHeartbeat.SourceManifest[0] with { Platform = TelemetryPlatforms.Linux }
            },
            SourceHealth = new[]
            {
                windowsNeutralHeartbeat.SourceHealth[0] with { Platform = TelemetryPlatforms.Linux }
            }
        };
        Assert.Contains("source_manifest[0].platform", RequestValidation.ValidateHeartbeat(mismatchedPlatform).Keys);
        AssertSchemaInvalid("heartbeat.schema.json", JsonSerializer.SerializeToNode(mismatchedPlatform, JsonOptions)!);
    }

    [Fact]
    public void RuntimeValidationRejectsAmbiguousAndUnboundedLinuxEvents()
    {
        var batch = DeserializeFixture<IngestBatchRequest>("linux-ingest.synthetic.json");
        var valid = batch.Events[0];

        AssertInvalidEvent(batch, valid with { SourceId = null }, "events[0].source_id");
        AssertInvalidEvent(batch, valid with { Platform = TelemetryPlatforms.Windows }, "events[0].platform");
        AssertInvalidEvent(batch, batch.Events[2] with { Platform = null }, "events[0].platform");
        AssertInvalidEvent(batch, valid with { Checkpoint = null }, "events[0].checkpoint");
        AssertInvalidEvent(batch, valid with { WindowsEventId = 0 }, "events[0].source");
        AssertInvalidEvent(batch, valid with { EventTime = default }, "events[0].event_time");
        AssertInvalidEvent(batch, valid with { Severity = "ERROR" }, "events[0].severity");
        AssertInvalidEvent(batch, valid with { Message = new string('m', 20_001) }, "events[0].message");
        AssertInvalidEvent(batch, valid with { Raw = JsonSerializer.SerializeToElement(new { value = new string('r', ContractLimits.RawPayloadMaxUtf8Bytes) }) }, "events[0].raw");
        AssertInvalidEvent(batch, valid with { Deduplication = null }, "events[0].deduplication");
        AssertInvalidEvent(batch, valid with { EventId = Guid.Parse("00000000-0000-4000-8000-000000000999") }, "events[0].event_id");
        var rawDigestEventWithoutId = batch.Events[3] with
        {
            Deduplication = batch.Events[3].Deduplication! with
            {
                Inputs = batch.Events[3].Deduplication!.Inputs.Append(DeduplicationInputs.RawSha256).ToArray(),
                RawSha256 = DeterministicEventIdentity.ComputeRawSha256(batch.Events[3].Raw)
            }
        };
        var rawDigestEvent = rawDigestEventWithoutId with
        {
            EventId = DeterministicEventIdentity.ComputeSha256Uuid(rawDigestEventWithoutId)
        };
        Assert.Empty(RequestValidation.ValidateBatch(batch with { Events = new[] { rawDigestEvent } }, 500));
        AssertInvalidEvent(batch, rawDigestEvent with
        {
            Deduplication = rawDigestEvent.Deduplication! with { RawSha256 = new string('0', 64) }
        }, "events[0].deduplication.raw_sha256");
        AssertInvalidEvent(batch, valid with
        {
            DataHandling = valid.DataHandling! with { RawSizeBytes = valid.DataHandling!.RawSizeBytes + 1 }
        }, "events[0].data_handling.raw_size_bytes");
        AssertInvalidEvent(batch, valid with
        {
            DataHandling = valid.DataHandling! with
            {
                TruncationApplied = true,
                TruncatedFields = new[] { "raw.value" },
                OriginalSizeBytes = valid.DataHandling!.RawSizeBytes
            }
        }, "events[0].data_handling.original_size_bytes");
        AssertInvalidEvent(batch, valid with
        {
            Normalized = valid.Normalized! with
            {
                Labels = Enumerable.Range(0, ContractLimits.MaxMetadataEntries + 1)
                    .ToDictionary(index => $"label-{index}", _ => "synthetic", StringComparer.Ordinal)
            }
        }, "events[0].normalized.labels");
    }

    [Fact]
    public void RuntimeValidationEnforcesExactUtf8RawBoundaries()
    {
        var batch = DeserializeFixture<IngestBatchRequest>("linux-ingest.synthetic.json");
        var valid = batch.Events[0];
        var boundaryRaw = CreateRawObjectWithExactUtf8Size(ContractLimits.RawPayloadMaxUtf8Bytes);
        var boundary = valid with
        {
            Raw = boundaryRaw,
            DataHandling = valid.DataHandling! with { RawSizeBytes = ContractLimits.RawPayloadMaxUtf8Bytes }
        };

        Assert.Empty(RequestValidation.ValidateBatch(batch with { Events = new[] { boundary } }, 500));

        var oversizedRaw = CreateRawObjectWithExactUtf8Size(ContractLimits.RawPayloadMaxUtf8Bytes + 1);
        AssertInvalidEvent(batch, boundary with
        {
            Raw = oversizedRaw,
            DataHandling = boundary.DataHandling! with { RawSizeBytes = ContractLimits.RawPayloadMaxUtf8Bytes + 1 }
        }, "events[0].raw");

        var multiByteRaw = JsonSerializer.SerializeToElement(new { value = new string('é', 32_763) });
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(multiByteRaw).Length > ContractLimits.RawPayloadMaxUtf8Bytes);
        AssertInvalidEvent(batch, valid with
        {
            Raw = multiByteRaw,
            DataHandling = valid.DataHandling! with { RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(multiByteRaw).Length }
        }, "events[0].raw");
    }

    [Fact]
    public void RuntimeValidationRejectsInvalidSourceManifestAndHealthMetadata()
    {
        var heartbeat = DeserializeFixture<HeartbeatRequest>("linux-heartbeat.synthetic.json");
        var manifest = heartbeat.SourceManifest[0];
        var health = heartbeat.SourceHealth[0];

        var missingIdentity = heartbeat with { SourceManifest = new[] { manifest with { SourceNamespace = null } } };
        Assert.Contains("source_manifest[0].source_namespace", RequestValidation.ValidateHeartbeat(missingIdentity).Keys);

        var invalidKind = heartbeat with { SourceManifest = new[] { manifest with { SourceKind = "unsupported" } } };
        Assert.Contains("source_manifest[0].source_kind", RequestValidation.ValidateHeartbeat(invalidKind).Keys);

        var missingCheckpoint = heartbeat with { SourceHealth = new[] { health with { AcknowledgedCheckpoint = null } } };
        Assert.Contains("source_health[0].acknowledged_checkpoint", RequestValidation.ValidateHeartbeat(missingCheckpoint).Keys);

        var oversizedDetails = heartbeat with
        {
            SourceHealth = new[]
            {
                health with
                {
                    Details = Enumerable.Range(0, 33).ToDictionary(index => $"detail-{index}", _ => "synthetic", StringComparer.Ordinal)
                }
            }
        };
        Assert.Contains("source_health[0].details", RequestValidation.ValidateHeartbeat(oversizedDetails).Keys);

        var windowsRecordOnLinux = heartbeat with { SourceHealth = new[] { health with { NewestRecordId = 1 } } };
        Assert.Contains("source_health[0].source_kind", RequestValidation.ValidateHeartbeat(windowsRecordOnLinux).Keys);

        var oversizedTamper = heartbeat with
        {
            TamperChecks = new TamperCheckSummary { BinaryHash = new string('h', 129) }
        };
        Assert.Contains("tamper_checks.binary_hash", RequestValidation.ValidateHeartbeat(oversizedTamper).Keys);

        var excessiveCpu = heartbeat with { CpuPercent = 101 };
        Assert.Contains(nameof(HeartbeatRequest.CpuPercent), RequestValidation.ValidateHeartbeat(excessiveCpu).Keys);

        var emptyQueueMetrics = heartbeat with { QueueMetrics = new QueueSloMetrics() };
        var emptyQueueErrors = RequestValidation.ValidateHeartbeat(emptyQueueMetrics);
        Assert.Contains("queue_metrics.max_size_mb", emptyQueueErrors.Keys);
        Assert.Contains("queue_metrics.warning_size_percent", emptyQueueErrors.Keys);

        var missingWarningThreshold = heartbeat with { QueueMetrics = new QueueSloMetrics { MaxSizeMb = 512 } };
        Assert.Contains("queue_metrics.warning_size_percent", RequestValidation.ValidateHeartbeat(missingWarningThreshold).Keys);

        var missingMaximumSize = heartbeat with { QueueMetrics = new QueueSloMetrics { WarningSizePercent = 80 } };
        Assert.Contains("queue_metrics.max_size_mb", RequestValidation.ValidateHeartbeat(missingMaximumSize).Keys);

        var emptyManifestMetadata = heartbeat with
        {
            SourceManifest = new[] { manifest with { Prerequisites = new[] { string.Empty } } }
        };
        Assert.Contains("source_manifest[0].prerequisites[0]", RequestValidation.ValidateHeartbeat(emptyManifestMetadata).Keys);

        var tooManySources = heartbeat with
        {
            SourceManifest = Enumerable.Repeat(manifest, ContractLimits.MaxSourceEntries + 1).ToArray()
        };
        Assert.Contains("source_manifest", RequestValidation.ValidateHeartbeat(tooManySources).Keys);

        var duplicateManifestIdentity = heartbeat with { SourceManifest = new[] { manifest, manifest } };
        Assert.Contains("source_manifest[0].source_id", RequestValidation.ValidateHeartbeat(duplicateManifestIdentity).Keys);

        var duplicateHealthIdentity = heartbeat with { SourceHealth = new[] { health, health } };
        Assert.Contains("source_health[0].source_id", RequestValidation.ValidateHeartbeat(duplicateHealthIdentity).Keys);

        var missingHostPlatform = heartbeat with { Platform = null, HostId = null };
        var missingHostErrors = RequestValidation.ValidateHeartbeat(missingHostPlatform);
        Assert.Contains("platform", missingHostErrors.Keys);
        Assert.Contains("host_id", missingHostErrors.Keys);

        var mismatchedNamespace = heartbeat with
        {
            SourceHealth = new[] { health with { SourceNamespace = "different.synthetic.namespace" } }
        };
        Assert.Contains("source_health[0].source_namespace", RequestValidation.ValidateHeartbeat(mismatchedNamespace).Keys);

        var mismatchedCheckpointKind = heartbeat with
        {
            SourceHealth = new[]
            {
                health with
                {
                    CollectedCheckpoint = new SourceCheckpoint { Sequence = 1 },
                    AcknowledgedCheckpoint = new SourceCheckpoint { Sequence = 1 }
                }
            }
        };
        Assert.Contains("source_health[0].collected_checkpoint", RequestValidation.ValidateHeartbeat(mismatchedCheckpointKind).Keys);

        var acknowledgedAhead = heartbeat with
        {
            SourceManifest = new[] { heartbeat.SourceManifest[1] },
            SourceHealth = new[]
            {
                heartbeat.SourceHealth[1] with
                {
                    CollectedCheckpoint = new SourceCheckpoint { Sequence = 10 },
                    AcknowledgedCheckpoint = new SourceCheckpoint { Sequence = 11 }
                }
            }
        };
        Assert.Contains("source_health[0].acknowledged_checkpoint.sequence", RequestValidation.ValidateHeartbeat(acknowledgedAhead).Keys);
    }

    [Fact]
    public void JsonSchemasRejectConditionalIdentityBoundsEnumsAndDefaultTimestamps()
    {
        var batch = JsonNode.Parse(ReadFixture("linux-ingest.synthetic.json"))!.AsObject();
        var first = batch["events"]!.AsArray()[0]!.AsObject();

        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!.AsObject().Remove("source_id"));
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["platform"] = "windows");
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["windows_event_id"] = 0);
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["event_time"] = "0001-01-01T00:00:00+00:00");
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["severity"] = "unsupported");
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["severity"] = "ERROR");
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["message"] = new string('m', 20_001));
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["raw"] = new JsonObject { ["value"] = new string('r', ContractLimits.RawPayloadMaxUtf8Bytes) });
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["deduplication"]!["inputs"] = new JsonArray("agent_id", "source_id", "unsupported"));
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["event_id"] = "00000000-0000-4000-8000-000000000999");
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
        {
            node["events"]!.AsArray()[3]!["deduplication"]!["inputs"]!.AsArray().Add("raw_sha256");
            node["events"]!.AsArray()[3]!["deduplication"]!["raw_sha256"] = new string('0', 64);
        });
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
            node["events"]!.AsArray()[0]!["data_handling"]!["raw_size_bytes"] = 0);
        AssertSchemaMutationInvalid("ingest-batch.schema.json", batch, node =>
        {
            var handling = node["events"]!.AsArray()[0]!["data_handling"]!;
            handling["truncation_applied"] = true;
            handling["truncated_fields"] = new JsonArray("raw.value");
            handling["original_size_bytes"] = 1;
        });

        var heartbeat = JsonNode.Parse(ReadFixture("linux-heartbeat.synthetic.json"))!.AsObject();
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["source_health"]!.AsArray()[0]!.AsObject().Remove("acknowledged_checkpoint"));
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
        {
            var manifest = node["source_manifest"]!.AsArray();
            var template = manifest[0]!.ToJsonString();
            while (manifest.Count <= ContractLimits.MaxSourceEntries) manifest.Add(JsonNode.Parse(template));
        });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
        {
            var details = new JsonObject();
            for (var index = 0; index < 33; index++) details[$"detail-{index}"] = "synthetic";
            node["source_health"]!.AsArray()[0]!["details"] = details;
        });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["tamper_checks"] = new JsonObject { ["binary_hash"] = new string('h', 129) });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node => node["cpu_percent"] = 101);
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["queue_metrics"] = new JsonObject());
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["queue_metrics"] = new JsonObject { ["max_size_mb"] = 512 });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["queue_metrics"] = new JsonObject { ["warning_size_percent"] = 80 });
        var heartbeatWithValidQueueMetrics = JsonNode.Parse(heartbeat.ToJsonString())!.AsObject();
        heartbeatWithValidQueueMetrics["queue_metrics"] = new JsonObject
        {
            ["max_size_mb"] = 512,
            ["warning_size_percent"] = 80
        };
        AssertSchemaValid("heartbeat.schema.json", heartbeatWithValidQueueMetrics);
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["source_manifest"]!.AsArray()[0]!["prerequisites"] = new JsonArray(string.Empty));
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
        {
            node.Remove("platform");
            node.Remove("host_id");
        });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
        {
            var manifest = node["source_manifest"]!.AsArray();
            manifest.Add(JsonNode.Parse(manifest[0]!.ToJsonString()));
        });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
            node["source_health"]!.AsArray()[0]!["source_namespace"] = "different.synthetic.namespace");
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
        {
            node["source_health"]!.AsArray()[0]!["collected_checkpoint"] = new JsonObject { ["sequence"] = 1 };
            node["source_health"]!.AsArray()[0]!["acknowledged_checkpoint"] = new JsonObject { ["sequence"] = 1 };
        });
        AssertSchemaMutationInvalid("heartbeat.schema.json", heartbeat, node =>
        {
            var manifest = node["source_manifest"]!.AsArray();
            var health = node["source_health"]!.AsArray();
            while (manifest.Count > 1) manifest.RemoveAt(manifest.Count - 1);
            while (health.Count > 1) health.RemoveAt(health.Count - 1);
            manifest[0]!["checkpoint_kind"] = "sequence";
            health[0]!["collected_checkpoint"] = new JsonObject { ["sequence"] = 10 };
            health[0]!["acknowledged_checkpoint"] = new JsonObject { ["sequence"] = 11 };
        });

        Assert.NotNull(first["source_id"]);
    }

    [Fact]
    public void EveryV1SchemaLoadsAndSemanticAnnotationsMatchRuntimeContract()
    {
        var schemas = Directory.GetFiles(SchemasRoot, "*.schema.json").Order(StringComparer.Ordinal).ToArray();
        Assert.NotEmpty(schemas);
        foreach (var schemaPath in schemas)
        {
            var schema = JsonSchema.FromText(File.ReadAllText(schemaPath));
            Assert.NotNull(schema);
        }

        var envelopeSchema = JsonNode.Parse(File.ReadAllText(Path.Combine(SchemasRoot, "event-envelope.schema.json")))!;
        var envelopeProperties = envelopeSchema["properties"]!.AsObject();
        Assert.True(envelopeProperties.ContainsKey("source"));
        Assert.False(envelopeProperties.ContainsKey("source_kind"));
        Assert.False(envelopeSchema["$defs"]!.AsObject().ContainsKey("source_kind"));
        Assert.Null(envelopeProperties["raw"]!["x-maxUtf8Bytes"]);
        Assert.Equal(
            ContractLimits.RawPayloadMaxUtf8Bytes,
            envelopeSchema["allOf"]![1]!["then"]!["properties"]!["raw"]!["x-maxUtf8Bytes"]!.GetValue<int>());
        Assert.Equal("/raw", envelopeProperties["data_handling"]!["x-rawSizeMatches"]!.GetValue<string>());
        Assert.True(envelopeProperties["deduplication"]!["x-deterministicEventId"]!.GetValue<bool>());

        var heartbeatSchema = JsonNode.Parse(File.ReadAllText(Path.Combine(SchemasRoot, "heartbeat.schema.json")))!;
        Assert.True(heartbeatSchema["$defs"]!.AsObject().ContainsKey("source_kind"));
        var linuxQueueRequired = heartbeatSchema["allOf"]![0]!["then"]!["properties"]!["queue_metrics"]!["oneOf"]![1]!["allOf"]![1]!["required"]!.AsArray();
        Assert.Equal(new[] { "max_size_mb", "warning_size_percent" }, linuxQueueRequired.Select(item => item!.GetValue<string>()));
        Assert.Equal("source_id", heartbeatSchema["properties"]!["source_manifest"]!["x-uniquePortableBy"]!.GetValue<string>());
        Assert.Equal("source_id", heartbeatSchema["properties"]!["source_health"]!["x-uniquePortableBy"]!.GetValue<string>());
        Assert.True(heartbeatSchema["x-crossSourceIdentity"]!.GetValue<bool>());
    }

    private static void AssertInvalidEvent(IngestBatchRequest sourceBatch, EventEnvelope invalid, string expectedKey)
    {
        var errors = RequestValidation.ValidateBatch(sourceBatch with { Events = new[] { invalid } }, 500);
        Assert.Contains(expectedKey, errors.Keys);
    }

    private static void AssertSchemaMutationInvalid(string schemaName, JsonObject original, Action<JsonObject> mutation)
    {
        var copy = JsonNode.Parse(original.ToJsonString())!.AsObject();
        mutation(copy);
        AssertSchemaInvalid(schemaName, copy);
    }

    private static T DeserializeFixture<T>(string fixtureName) where T : notnull =>
        JsonSerializer.Deserialize<T>(ReadFixture(fixtureName), JsonOptions)
        ?? throw new InvalidOperationException($"Fixture {fixtureName} deserialized to null.");

    private static string ReadFixture(string name) => File.ReadAllText(Path.Combine(FixturesRoot, name));

    private static void AssertSchemaValid(string schemaName, JsonNode instance)
    {
        var (result, extensionErrors) = EvaluateSchema(schemaName, instance);
        Assert.True(result.IsValid && extensionErrors.Count == 0,
            $"{schemaName} validation failed: {JsonSerializer.Serialize(result)} {string.Join("; ", extensionErrors)}");
    }

    private static void AssertSchemaInvalid(string schemaName, JsonNode instance)
    {
        var (result, extensionErrors) = EvaluateSchema(schemaName, instance);
        Assert.True(!result.IsValid || extensionErrors.Count > 0, $"{schemaName} unexpectedly accepted the mutated payload.");
    }

    private static (EvaluationResults Result, IReadOnlyList<string> ExtensionErrors) EvaluateSchema(string schemaName, JsonNode instance)
    {
        var options = new EvaluationOptions
        {
            OutputFormat = OutputFormat.List,
            RequireFormatValidation = true
        };

        foreach (var path in Directory.GetFiles(SchemasRoot, "*.schema.json"))
        {
            options.SchemaRegistry.Register(JsonSchema.FromText(File.ReadAllText(path)));
        }

        var schema = JsonSchema.FromText(File.ReadAllText(Path.Combine(SchemasRoot, schemaName)));
        var result = schema.Evaluate(instance, options);
        return (result, ValidateExtensions(schemaName, instance));
    }

    private static IReadOnlyList<string> ValidateExtensions(string schemaName, JsonNode instance)
    {
        var errors = new List<string>();
        try
        {
            switch (schemaName)
            {
                case "agent-registration.schema.json":
                    AddValidationErrors(errors, RequestValidation.ValidateRegistration(instance.Deserialize<AgentRegistrationRequest>(JsonOptions)!));
                    break;
                case "heartbeat.schema.json":
                    AddValidationErrors(errors, RequestValidation.ValidateHeartbeat(instance.Deserialize<HeartbeatRequest>(JsonOptions)!));
                    break;
                case "ingest-batch.schema.json":
                    AddValidationErrors(errors, RequestValidation.ValidateBatch(instance.Deserialize<IngestBatchRequest>(JsonOptions)!, 500));
                    break;
                case "event-envelope.schema.json":
                    {
                        var envelope = instance.Deserialize<EventEnvelope>(JsonOptions)!;
                        AddValidationErrors(errors, RequestValidation.ValidateBatch(CreateValidationBatch(new[] { envelope }), 500));
                        break;
                    }
                case "event-search.schema.json":
                    {
                        var response = instance.Deserialize<EventSearchResponse>(JsonOptions)!;
                        foreach (var envelope in response.Events)
                        {
                            AddValidationErrors(errors, RequestValidation.ValidateBatch(CreateValidationBatch(new[] { envelope }), 500));
                        }
                        break;
                    }
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException)
        {
            errors.Add($"semantic extension could not evaluate payload: {exception.GetType().Name}");
        }

        return errors;
    }

    private static IngestBatchRequest CreateValidationBatch(IReadOnlyList<EventEnvelope> events) => new()
    {
        AgentId = events.FirstOrDefault()?.AgentId ?? "synthetic-validation-agent",
        BatchId = Guid.Parse("00000000-0000-4000-8000-000000000001"),
        SentAt = DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
        Events = events
    };

    private static void AddValidationErrors(List<string> destination, IReadOnlyDictionary<string, string[]> validationErrors)
    {
        foreach (var error in validationErrors)
        {
            destination.Add($"{error.Key}: {string.Join(", ", error.Value)}");
        }
    }

    private static JsonElement CreateRawObjectWithExactUtf8Size(int targetBytes)
    {
        var emptySize = JsonSerializer.SerializeToUtf8Bytes(new { value = string.Empty }).Length;
        if (targetBytes < emptySize)
        {
            throw new ArgumentOutOfRangeException(nameof(targetBytes));
        }

        var raw = JsonSerializer.SerializeToElement(new { value = new string('r', targetBytes - emptySize) });
        Assert.Equal(targetBytes, JsonSerializer.SerializeToUtf8Bytes(raw).Length);
        return raw;
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Could not locate the repository root.");
    }
}
