using System.Globalization;
using System.Net;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Ingestion;

public static class RequestValidation
{
    public static readonly TimeSpan MaximumFutureTimestampSkew = TimeSpan.FromMinutes(5);

    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.Ordinal)
    {
        "verbose", "information", "warning", "error", "critical", "audit_success", "audit_failure"
    };

    private static readonly HashSet<string> AllowedSourceStatuses = new(StringComparer.Ordinal)
    {
        SourceHealthStatuses.Healthy,
        SourceHealthStatuses.Missing,
        SourceHealthStatuses.Disabled,
        SourceHealthStatuses.Stale,
        SourceHealthStatuses.Degraded,
        SourceHealthStatuses.PermissionDenied,
        SourceHealthStatuses.Unsupported,
        SourceHealthStatuses.Error,
        SourceHealthStatuses.NotApplicable,
        SourceHealthStatuses.Excepted
    };

    private static readonly HashSet<string> AllowedApplicabilityStatuses = new(StringComparer.Ordinal)
    {
        SourceApplicabilityStatuses.Applicable,
        SourceApplicabilityStatuses.NotApplicable,
        SourceApplicabilityStatuses.Unknown,
        SourceApplicabilityStatuses.Unsupported
    };

    private static readonly HashSet<string> AllowedCheckpointKinds = new(StringComparer.Ordinal)
    {
        SourceCheckpointKinds.Cursor,
        SourceCheckpointKinds.Sequence,
        SourceCheckpointKinds.CursorAndSequence
    };

    private static readonly HashSet<string> AllowedQueuePressureStates = new(StringComparer.Ordinal)
    {
        QueuePressureStates.Unknown,
        QueuePressureStates.Normal,
        QueuePressureStates.Warning,
        QueuePressureStates.High,
        QueuePressureStates.Critical,
        QueuePressureStates.Full,
        QueuePressureStates.Throttled
    };

    private static readonly HashSet<string> AllowedQueueSendStates = new(StringComparer.Ordinal)
    {
        QueueSendStates.Unknown,
        QueueSendStates.Idle,
        QueueSendStates.Sending,
        QueueSendStates.Succeeded,
        QueueSendStates.BackingOff,
        QueueSendStates.Failed,
        QueueSendStates.Recovering
    };

    private static readonly HashSet<string> AllowedHealthTransitionStates = new(StringComparer.Ordinal)
    {
        HealthTransitionStates.Unknown,
        HealthTransitionStates.Healthy,
        HealthTransitionStates.Degraded,
        HealthTransitionStates.Recovering,
        HealthTransitionStates.Recovered
    };

    public static Dictionary<string, string[]> ValidateRegistration(AgentRegistrationRequest request)
    {
        var errors = NewErrorBag();
        RequireLength(errors, nameof(request.AgentId), request.AgentId, 1, 128);
        RequireLength(errors, nameof(request.Hostname), request.Hostname, 1, 255);
        OptionalMaxLength(errors, nameof(request.MachineGuid), request.MachineGuid, 255);
        RequireLength(errors, nameof(request.OsVersion), request.OsVersion, 1, 255);
        RequireLength(errors, nameof(request.AgentVersion), request.AgentVersion, 1, 64);
        ValidatePlatformAndHostId(errors, request.Platform, request.HostId);
        ValidateHostTimezone(errors, "host_timezone", request.HostTimezone);
        return ToValidationProblem(errors);
    }

    public static Dictionary<string, string[]> ValidateHeartbeat(
        HeartbeatRequest request,
        DateTimeOffset? receivedAt = null)
    {
        var errors = NewErrorBag();
        var receivedAtUtc = (receivedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        RequireLength(errors, nameof(request.AgentId), request.AgentId, 1, 128);
        RequireLength(errors, nameof(request.Hostname), request.Hostname, 1, 255);
        RequireLength(errors, nameof(request.AgentVersion), request.AgentVersion, 1, 64);
        RequireLength(errors, nameof(request.Os), request.Os, 1, 255);
        ValidatePlatformAndHostId(errors, request.Platform, request.HostId);
        var linuxHeartbeat = string.Equals(request.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
            || request.SourceManifest?.Any(IsLinuxSource) == true
            || request.SourceHealth?.Any(IsLinuxSource) == true;
        if (linuxHeartbeat)
        {
            RequireLength(errors, "platform", request.Platform, 1, 16);
            RequireLength(errors, "host_id", request.HostId, 1, 255);
            ValidateTimestamp(errors, "last_event_time", request.LastEventTime);
            ValidateNotExcessivelyFuture(errors, "last_event_time", request.LastEventTime, receivedAtUtc);
        }
        ValidateHostTimezone(errors, "host_timezone", request.HostTimezone);
        OptionalMaxLength(errors, "config_hash", request.ConfigHash, 128);

        if (request.QueueDepth < 0)
        {
            Add(errors, nameof(request.QueueDepth), "Queue depth must be greater than or equal to zero.");
        }

        if (request.CpuPercent < 0 || (linuxHeartbeat && request.CpuPercent > 100))
        {
            Add(errors, nameof(request.CpuPercent), linuxHeartbeat
                ? "CPU percent must be between zero and 100."
                : "CPU percent must be greater than or equal to zero.");
        }

        if (request.MemoryMb < 0)
        {
            Add(errors, nameof(request.MemoryMb), "Memory MB must be greater than or equal to zero.");
        }

        ValidateQueueMetrics(errors, request.QueueMetrics, enforceLinuxBounds: linuxHeartbeat);
        ValidateResourceMetrics(
            errors,
            "resource_metrics",
            request.ResourceMetrics,
            enforceLinuxBounds: linuxHeartbeat,
            receivedAtUtc: receivedAtUtc);

        if (request.SourceManifest is null)
        {
            Add(errors, "source_manifest", "Source manifest must be an array when supplied.");
        }
        else
        {
            if (request.SourceManifest.Count > ContractLimits.MaxSourceEntries)
            {
                Add(errors, "source_manifest", $"Source manifest contains more than {ContractLimits.MaxSourceEntries} entries.");
            }
            for (var index = 0; index < request.SourceManifest.Count; index++)
            {
                ValidateSourceManifestEntry(errors, request.SourceManifest[index], index);
            }
        }

        if (request.SourceHealth is null)
        {
            Add(errors, "source_health", "Source health must be an array when supplied.");
        }
        else
        {
            if (request.SourceHealth.Count > ContractLimits.MaxSourceEntries)
            {
                Add(errors, "source_health", $"Source health contains more than {ContractLimits.MaxSourceEntries} entries.");
            }
            for (var index = 0; index < request.SourceHealth.Count; index++)
            {
                ValidateSourceHealth(errors, request.SourceHealth[index], index, receivedAtUtc);
            }
        }

        if (request.SourceManifest is not null && request.SourceHealth is not null)
        {
            ValidateHeartbeatSourceRelationships(errors, request);
        }

        ValidateTamperChecks(errors, request.TamperChecks, enforceLinuxBounds: linuxHeartbeat);
        return ToValidationProblem(errors);
    }

    public static Dictionary<string, string[]> ValidateBatch(
        IngestBatchRequest batch,
        int maxEventsPerBatch,
        DateTimeOffset? receivedAt = null)
    {
        var errors = NewErrorBag();
        var receivedAtUtc = (receivedAt ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var effectiveMaxEventsPerBatch = Math.Clamp(maxEventsPerBatch, 1, ContractLimits.MaxIngestEventsPerBatch);
        RequireLength(errors, nameof(batch.AgentId), batch.AgentId, 1, 128);

        if (batch.BatchId == Guid.Empty)
        {
            Add(errors, nameof(batch.BatchId), "Batch ID must be a non-empty UUID.");
        }

        if (batch.SentAt == default)
        {
            Add(errors, nameof(batch.SentAt), "Sent timestamp is required.");
        }

        if (batch.Events is null || batch.Events.Count == 0)
        {
            Add(errors, nameof(batch.Events), "At least one event is required.");
            return ToValidationProblem(errors);
        }

        if (batch.Events.Count > effectiveMaxEventsPerBatch)
        {
            Add(errors, nameof(batch.Events), $"Batch contains more than {effectiveMaxEventsPerBatch} events.");
        }

        for (var index = 0; index < batch.Events.Count; index++)
        {
            ValidateEvent(errors, batch.AgentId, batch.Events[index], index, receivedAtUtc);
        }

        ValidateUniqueEventIds(errors, batch.Events);

        return ToValidationProblem(errors);
    }

    private static void ValidateUniqueEventIds(
        Dictionary<string, List<string>> errors,
        IReadOnlyList<EventEnvelope> events)
    {
        var duplicateGroups = events
            .Select((envelope, index) => (Envelope: envelope, Index: index))
            .Where(item => item.Envelope is not null && item.Envelope.EventId != Guid.Empty)
            .GroupBy(item => item.Envelope.EventId)
            .Where(group => group.Count() > 1);

        foreach (var group in duplicateGroups)
        {
            foreach (var duplicate in group)
            {
                Add(errors, $"events[{duplicate.Index}].event_id",
                    "Event ID must be unique within an ingest batch.");
            }
        }
    }

    public static Dictionary<string, string[]> ValidateInventoryBatch(AssetInventoryBatchRequest request)
    {
        var errors = NewErrorBag();
        RequireLength(errors, nameof(request.AgentId), request.AgentId, 1, 128);
        if (request.SentAt == default)
        {
            Add(errors, nameof(request.SentAt), "Sent timestamp is required.");
        }

        if (request.Snapshots is null || request.Snapshots.Count == 0)
        {
            Add(errors, nameof(request.Snapshots), "At least one inventory snapshot is required.");
            return ToValidationProblem(errors);
        }

        if (request.Snapshots.Count > 20)
        {
            Add(errors, nameof(request.Snapshots), "Inventory batch contains more than 20 snapshots.");
        }

        for (var index = 0; index < request.Snapshots.Count; index++)
        {
            var snapshot = request.Snapshots[index];
            RequireLength(errors, $"snapshots[{index}].agent_id", snapshot.AgentId, 1, 128);
            if (!string.Equals(snapshot.AgentId, request.AgentId, StringComparison.Ordinal))
            {
                Add(errors, $"snapshots[{index}].agent_id", "Snapshot agent_id must match the batch agent_id.");
            }

            RequireLength(errors, $"snapshots[{index}].hostname", snapshot.Hostname, 1, 255);
            RequireLength(errors, $"snapshots[{index}].snapshot_type", snapshot.SnapshotType, 1, 128);
            if (snapshot.CollectedAt == default)
            {
                Add(errors, $"snapshots[{index}].collected_at", "Collected timestamp is required.");
            }

            if (snapshot.Items.Count > 200)
            {
                Add(errors, $"snapshots[{index}].items", "Snapshot contains more than 200 inventory items.");
            }

            ValidateHostTimezone(errors, $"snapshots[{index}].host_timezone", snapshot.HostTimezone);
        }

        return ToValidationProblem(errors);
    }

    public static bool RequiresCrossPlatformStorage(AgentRegistrationRequest request) =>
        string.Equals(request.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal);

    public static bool RequiresCrossPlatformStorage(HeartbeatRequest request) =>
        string.Equals(request.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
        || request.SourceManifest?.Any(source => source is not null && TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind)) == true
        || request.SourceHealth?.Any(source => source is not null && TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind)) == true;

    public static bool RequiresCrossPlatformStorage(IngestBatchRequest request) =>
        request.Events.Any(envelope => TelemetrySourceKinds.UsesPortableIdentity(envelope.Source)
            || string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal));

    private static void ValidateEvent(
        Dictionary<string, List<string>> errors,
        string batchAgentId,
        EventEnvelope? envelope,
        int index,
        DateTimeOffset receivedAtUtc)
    {
        var prefix = $"events[{index}]";
        if (envelope is null)
        {
            Add(errors, prefix, "Event is required.");
            return;
        }

        if (envelope.EventId == Guid.Empty)
        {
            Add(errors, $"{prefix}.event_id", "Event ID must be a non-empty UUID.");
        }

        RequireLength(errors, $"{prefix}.agent_id", envelope.AgentId, 1, 128);
        if (!string.Equals(envelope.AgentId, batchAgentId, StringComparison.Ordinal))
        {
            Add(errors, $"{prefix}.agent_id", "Event agent_id must match the batch agent_id.");
        }

        RequireLength(errors, $"{prefix}.hostname", envelope.Hostname, 1, 255);
        if (!TelemetrySourceKinds.All.Contains(envelope.Source))
        {
            Add(errors, $"{prefix}.source", "Source kind is not supported by the v1 contract.");
        }
        else if (string.Equals(envelope.Source, EventSources.WindowsEventLog, StringComparison.Ordinal))
        {
            ValidateWindowsEventIdentity(errors, prefix, envelope);
        }
        else
        {
            ValidatePortableEventIdentity(errors, prefix, envelope);
        }
        ValidateKnownLinuxEventIdentity(errors, prefix, envelope);

        OptionalMaxLength(errors, $"{prefix}.event_code", envelope.EventCode, 128);
        OptionalMaxLength(errors, $"{prefix}.facility", envelope.Facility, 128);
        OptionalMaxLength(errors, $"{prefix}.unit", envelope.Unit, 255);

        if (envelope.EventTime == default)
        {
            Add(errors, $"{prefix}.event_time", "Event timestamp is required.");
        }

        var portableEvent = TelemetrySourceKinds.UsesPortableIdentity(envelope.Source);
        if (portableEvent)
        {
            ValidateNotExcessivelyFuture(errors, $"{prefix}.event_time", envelope.EventTime, receivedAtUtc);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.checkpoint.event_time", envelope.Checkpoint?.EventTime, receivedAtUtc);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.checkpoint.recorded_at", envelope.Checkpoint?.RecordedAt, receivedAtUtc);
            ValidateTimestamp(errors, $"{prefix}.ingest_time", envelope.IngestTime);
        }
        ValidateHostTimezone(errors, $"{prefix}.host_timezone", envelope.HostTimezone);

        var supportedSeverity = portableEvent
            ? AllowedSeverities.Contains(envelope.Severity)
            : AllowedSeverities.Any(severity => string.Equals(severity, envelope.Severity, StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrWhiteSpace(envelope.Severity) || !supportedSeverity)
        {
            Add(errors, $"{prefix}.severity", "Severity is not supported.");
        }

        if (envelope.Message is null)
        {
            Add(errors, $"{prefix}.message", "Message is required.");
        }
        else if (envelope.Message.Length > 20_000)
        {
            Add(errors, $"{prefix}.message", "Message is too long.");
        }

        int? rawSizeBytes = null;
        if (envelope.Raw.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null or not JsonValueKind.Object)
        {
            Add(errors, $"{prefix}.raw", "Raw event data must be a JSON object.");
        }
        else
        {
            rawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(envelope.Raw).Length;
            if (portableEvent && rawSizeBytes > ContractLimits.RawPayloadMaxUtf8Bytes)
            {
                Add(errors, $"{prefix}.raw", $"Raw event data exceeds {ContractLimits.RawPayloadMaxUtf8Bytes} UTF-8 bytes.");
            }
        }

        ValidateNormalized(errors, prefix, envelope.Normalized, enforcePortableBounds: portableEvent);
        ValidateDataHandling(errors, prefix, envelope.DataHandling, rawSizeBytes);
    }

    private static void ValidateWindowsEventIdentity(Dictionary<string, List<string>> errors, string prefix, EventEnvelope envelope)
    {
        if (envelope.Platform is not null && !string.Equals(envelope.Platform, TelemetryPlatforms.Windows, StringComparison.Ordinal))
        {
            Add(errors, $"{prefix}.platform", "windows_event_log events may only declare the windows platform.");
        }

        RequireLength(errors, $"{prefix}.channel", envelope.Channel, 1, 255);
        RequireLength(errors, $"{prefix}.provider", envelope.Provider, 1, 255);
        if (envelope.WindowsEventId is < 0 or > 65_535 || !envelope.WindowsEventId.HasValue)
        {
            Add(errors, $"{prefix}.windows_event_id", "Windows event ID must be between 0 and 65535.");
        }

        if (envelope.RecordId < 0 || !envelope.RecordId.HasValue)
        {
            Add(errors, $"{prefix}.record_id", "Record ID must be greater than or equal to zero.");
        }
    }

    private static void ValidatePortableEventIdentity(Dictionary<string, List<string>> errors, string prefix, EventEnvelope envelope)
    {
        if (!TelemetrySourceKinds.IsValidForPlatform(envelope.Source, envelope.Platform))
        {
            Add(errors, $"{prefix}.platform", TelemetrySourceKinds.IsLinuxNative(envelope.Source)
                ? "Linux-native source kinds require platform linux."
                : "Platform-neutral source kinds require platform windows or linux.");
        }

        RequireLength(errors, $"{prefix}.source_id", envelope.SourceId, 1, 128);
        if (envelope.Channel is not null || envelope.Provider is not null
            || envelope.WindowsEventId.HasValue || envelope.RecordId.HasValue)
        {
            Add(errors, $"{prefix}.source", "Portable event sources must omit Windows Event Log identity fields.");
        }

        if (envelope.Source == EventSources.LinuxJournal)
        {
            if (string.IsNullOrWhiteSpace(envelope.EventCode)
                && string.IsNullOrWhiteSpace(envelope.Facility)
                && string.IsNullOrWhiteSpace(envelope.Unit))
            {
                Add(errors, $"{prefix}.event_code", "Journal events require an event code, facility, or unit.");
            }
        }
        else
        {
            RequireLength(errors, $"{prefix}.event_code", envelope.EventCode, 1, 128);
        }

        ValidateCheckpoint(errors, $"{prefix}.checkpoint", envelope.Checkpoint, required: true);
        ValidateDeduplication(errors, prefix, envelope);
        if (envelope.DataHandling is null)
        {
            Add(errors, $"{prefix}.data_handling", "Portable event sources require explicit redaction and truncation metadata.");
        }
    }

    private static void ValidateDeduplication(Dictionary<string, List<string>> errors, string prefix, EventEnvelope envelope)
    {
        var deduplication = envelope.Deduplication;
        if (deduplication is null)
        {
            Add(errors, $"{prefix}.deduplication", "Portable event sources require deterministic deduplication metadata.");
            return;
        }

        if (!string.Equals(deduplication.Algorithm, DeduplicationAlgorithms.Sha256Uuid, StringComparison.Ordinal))
        {
            Add(errors, $"{prefix}.deduplication.algorithm", "Deduplication algorithm is not supported.");
        }

        if (deduplication.Inputs is null
            || deduplication.Inputs.Count is < 3 or > 7
            || deduplication.Inputs.Distinct(StringComparer.Ordinal).Count() != deduplication.Inputs.Count
            || deduplication.Inputs.Any(input => !DeduplicationInputs.All.Contains(input)))
        {
            Add(errors, $"{prefix}.deduplication.inputs", "Deduplication inputs must contain three to seven unique supported field names.");
            return;
        }

        RequireDedupInput(errors, prefix, deduplication.Inputs, DeduplicationInputs.AgentId);
        RequireDedupInput(errors, prefix, deduplication.Inputs, DeduplicationInputs.SourceId);
        var checkpoint = envelope.Checkpoint;
        if (checkpoint?.Cursor is not null)
        {
            RequireDedupInput(errors, prefix, deduplication.Inputs, DeduplicationInputs.CheckpointCursor);
        }
        else if (deduplication.Inputs.Contains(DeduplicationInputs.CheckpointCursor, StringComparer.Ordinal))
        {
            Add(errors, $"{prefix}.deduplication.inputs", "checkpoint.cursor cannot be an input when the cursor is absent.");
        }

        if (checkpoint?.Sequence is not null)
        {
            RequireDedupInput(errors, prefix, deduplication.Inputs, DeduplicationInputs.CheckpointSequence);
        }
        else if (deduplication.Inputs.Contains(DeduplicationInputs.CheckpointSequence, StringComparer.Ordinal))
        {
            Add(errors, $"{prefix}.deduplication.inputs", "checkpoint.sequence cannot be an input when the sequence is absent.");
        }

        if (deduplication.Inputs.Contains(DeduplicationInputs.EventCode, StringComparer.Ordinal) && string.IsNullOrWhiteSpace(envelope.EventCode))
        {
            Add(errors, $"{prefix}.deduplication.inputs", "event_code cannot be an input when the event code is absent.");
        }

        if (deduplication.Inputs.Contains(DeduplicationInputs.RawSha256, StringComparer.Ordinal))
        {
            if (deduplication.RawSha256 is null || !IsLowerHexSha256(deduplication.RawSha256))
            {
                Add(errors, $"{prefix}.deduplication.raw_sha256", "raw_sha256 must be 64 lowercase hexadecimal characters when selected as an input.");
            }
            else if (envelope.Raw.ValueKind == JsonValueKind.Object
                && !string.Equals(deduplication.RawSha256, DeterministicEventIdentity.ComputeRawSha256(envelope.Raw), StringComparison.Ordinal))
            {
                Add(errors, $"{prefix}.deduplication.raw_sha256", "raw_sha256 must match the compact UTF-8 serialization of raw.");
            }
        }
        else if (deduplication.RawSha256 is not null)
        {
            Add(errors, $"{prefix}.deduplication.raw_sha256", "raw_sha256 must be listed in inputs when supplied.");
        }

        try
        {
            var expectedEventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope);
            if (envelope.EventId != expectedEventId)
            {
                Add(errors, $"{prefix}.event_id", "Event ID must match the declared sha256_uuid input recipe.");
            }
        }
        catch (ArgumentException)
        {
            // Specific missing, unsupported, and contradictory input errors are reported above.
        }
    }

    private static void RequireDedupInput(Dictionary<string, List<string>> errors, string prefix, IReadOnlyList<string> inputs, string required)
    {
        if (!inputs.Contains(required, StringComparer.Ordinal))
        {
            Add(errors, $"{prefix}.deduplication.inputs", $"Deduplication inputs must include {required}.");
        }
    }

    private static void ValidateDataHandling(Dictionary<string, List<string>> errors, string prefix, DataHandlingMetadata? handling, int? actualRawSizeBytes)
    {
        if (handling is null)
        {
            return;
        }

        if (handling.RawSizeBytes is < 0 or > ContractLimits.RawPayloadMaxUtf8Bytes)
        {
            Add(errors, $"{prefix}.data_handling.raw_size_bytes", $"Raw size must be between zero and {ContractLimits.RawPayloadMaxUtf8Bytes} bytes.");
        }
        else if (actualRawSizeBytes.HasValue && handling.RawSizeBytes != actualRawSizeBytes.Value)
        {
            Add(errors, $"{prefix}.data_handling.raw_size_bytes", "Raw size must equal the compact UTF-8 serialization size of raw.");
        }

        if (handling.RedactedFields is null || handling.TruncatedFields is null)
        {
            Add(errors, $"{prefix}.data_handling", "Redacted and truncated field lists must be arrays.");
            return;
        }

        ValidateFieldList(errors, $"{prefix}.data_handling.redacted_fields", handling.RedactedFields);
        ValidateFieldList(errors, $"{prefix}.data_handling.truncated_fields", handling.TruncatedFields);
        if (handling.RedactionApplied != (handling.RedactedFields.Count > 0))
        {
            Add(errors, $"{prefix}.data_handling.redacted_fields", "redaction_applied must be true exactly when redacted_fields is non-empty.");
        }

        if (handling.TruncationApplied != (handling.TruncatedFields.Count > 0))
        {
            Add(errors, $"{prefix}.data_handling.truncated_fields", "truncation_applied must be true exactly when truncated_fields is non-empty.");
        }

        if (handling.TruncationApplied && (!handling.OriginalSizeBytes.HasValue || handling.OriginalSizeBytes <= handling.RawSizeBytes))
        {
            Add(errors, $"{prefix}.data_handling.original_size_bytes", "Truncated data requires an original size greater than the retained raw size.");
        }
        else if (!handling.TruncationApplied && handling.OriginalSizeBytes.HasValue)
        {
            Add(errors, $"{prefix}.data_handling.original_size_bytes", "original_size_bytes must be omitted when truncation was not applied.");
        }
    }

    private static void ValidateNormalized(
        Dictionary<string, List<string>> errors,
        string prefix,
        NormalizedEventFields? normalized,
        bool enforcePortableBounds)
    {
        if (normalized is null)
        {
            return;
        }

        var fields = new (string Name, string? Value, int Max)[]
        {
            ("category", normalized.Category, 128), ("action", normalized.Action, 128), ("outcome", normalized.Outcome, 128),
            ("user_name", normalized.UserName, 512), ("user_sid", normalized.UserSid, 512), ("target_user_name", normalized.TargetUserName, 512),
            ("logon_type", normalized.LogonType, 64), ("process_id", normalized.ProcessId, 64), ("parent_process_id", normalized.ParentProcessId, 64),
            ("process_image", normalized.ProcessImage, 2048), ("parent_process_image", normalized.ParentProcessImage, 2048),
            ("process_command_line", normalized.ProcessCommandLine, 4096), ("source_ip", normalized.SourceIp, 128),
            ("source_port", normalized.SourcePort, 64), ("destination_ip", normalized.DestinationIp, 128),
            ("destination_port", normalized.DestinationPort, 64), ("protocol", normalized.Protocol, 64),
            ("service_name", normalized.ServiceName, 512), ("driver_name", normalized.DriverName, 512), ("object_name", normalized.ObjectName, 2048),
            ("registry_key", normalized.RegistryKey, 2048), ("file_path", normalized.FilePath, 2048), ("hash", normalized.Hash, 512),
            ("rule_name", normalized.RuleName, 512), ("threat_name", normalized.ThreatName, 512), ("task_name", normalized.TaskName, 512),
            ("package_name", normalized.PackageName, 512)
        };
        foreach (var field in fields)
        {
            OptionalMaxLength(errors, $"{prefix}.normalized.{field.Name}", field.Value, field.Max);
        }

        if (normalized.Entities is null || normalized.Labels is null)
        {
            Add(errors, $"{prefix}.normalized", "Entities and labels must use array and object values.");
            return;
        }

        if (normalized.Entities.Count > 100)
        {
            Add(errors, $"{prefix}.normalized.entities", "Normalized event contains more than 100 entities.");
        }

        for (var index = 0; index < normalized.Entities.Count; index++)
        {
            var entity = normalized.Entities[index];
            if (entity is null)
            {
                Add(errors, $"{prefix}.normalized.entities[{index}]", "Entity must be an object.");
                continue;
            }
            if (enforcePortableBounds)
            {
                RequireLength(errors, $"{prefix}.normalized.entities[{index}].type", entity.Type, 1, 64);
                RequireLength(errors, $"{prefix}.normalized.entities[{index}].value", entity.Value, 1, 2048);
            }
            else
            {
                OptionalMaxLength(errors, $"{prefix}.normalized.entities[{index}].type", entity.Type, 64);
                OptionalMaxLength(errors, $"{prefix}.normalized.entities[{index}].value", entity.Value, 2048);
            }
            OptionalMaxLength(errors, $"{prefix}.normalized.entities[{index}].role", entity.Role, 128);
        }

        if (enforcePortableBounds)
        {
            ValidateMap(errors, $"{prefix}.normalized.labels", normalized.Labels, ContractLimits.MaxMetadataEntries, 128, 2048);
        }
        ValidateProcess(errors, $"{prefix}.normalized.process", normalized.Process);
        ValidateUser(errors, $"{prefix}.normalized.user", normalized.User);
        ValidateNetwork(errors, $"{prefix}.normalized.network", normalized.Network);
        ValidateFile(errors, $"{prefix}.normalized.file", normalized.File);
        if (enforcePortableBounds)
        {
            ValidatePortableNormalizedConsistency(errors, prefix, normalized);
        }
    }

    private static void ValidatePortableNormalizedConsistency(
        Dictionary<string, List<string>> errors,
        string eventPrefix,
        NormalizedEventFields normalized)
    {
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.process.pid", "process_id",
            normalized.ProcessId, normalized.Process?.Pid, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.process.parent_pid", "parent_process_id",
            normalized.ParentProcessId, normalized.Process?.ParentPid, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.process.executable", "process_image",
            normalized.ProcessImage, normalized.Process?.Executable, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.process.command_line", "process_command_line",
            normalized.ProcessCommandLine, normalized.Process?.CommandLine, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.user.name", "user_name",
            normalized.UserName, normalized.User?.Name, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.user.id", "user_sid",
            normalized.UserSid, normalized.User?.Id, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.network.source_ip", "source_ip",
            normalized.SourceIp, normalized.Network?.SourceIp, EquivalentIpAddress);
        ValidateDuplicatePortRepresentation(errors, $"{eventPrefix}.normalized.network.source_port", "source_port",
            normalized.SourcePort, normalized.Network?.SourcePort);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.network.destination_ip", "destination_ip",
            normalized.DestinationIp, normalized.Network?.DestinationIp, EquivalentIpAddress);
        ValidateDuplicatePortRepresentation(errors, $"{eventPrefix}.normalized.network.destination_port", "destination_port",
            normalized.DestinationPort, normalized.Network?.DestinationPort);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.network.protocol", "protocol",
            normalized.Protocol, normalized.Network?.Protocol, EquivalentProtocol);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.file.path", "file_path",
            normalized.FilePath, normalized.File?.Path, EquivalentOrdinal);
        ValidateDuplicateRepresentation(errors, $"{eventPrefix}.normalized.file.sha256", "hash",
            normalized.Hash, normalized.File?.Sha256, EquivalentSha256);
    }

    private static void ValidateDuplicateRepresentation(
        Dictionary<string, List<string>> errors,
        string nestedKey,
        string flattenedField,
        string? flattenedValue,
        string? nestedValue,
        Func<string, string, bool> equivalent)
    {
        if (flattenedValue is null || nestedValue is null || equivalent(flattenedValue, nestedValue))
        {
            return;
        }

        Add(errors, nestedKey,
            $"Value must represent the same concept as normalized.{flattenedField} when both fields are supplied.");
    }

    private static void ValidateDuplicatePortRepresentation(
        Dictionary<string, List<string>> errors,
        string nestedKey,
        string flattenedField,
        string? flattenedValue,
        int? nestedValue)
    {
        if (flattenedValue is null || !nestedValue.HasValue)
        {
            return;
        }

        if (int.TryParse(flattenedValue, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            && parsed == nestedValue.Value)
        {
            return;
        }

        Add(errors, nestedKey,
            $"Value must represent the same numeric port as normalized.{flattenedField} when both fields are supplied.");
    }

    private static bool EquivalentOrdinal(string left, string right) =>
        string.Equals(left, right, StringComparison.Ordinal);

    private static bool EquivalentProtocol(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool EquivalentIpAddress(string left, string right)
    {
        if (string.Equals(left, right, StringComparison.Ordinal))
        {
            return true;
        }

        return IPAddress.TryParse(left, out var leftAddress)
            && IPAddress.TryParse(right, out var rightAddress)
            && leftAddress.Equals(rightAddress);
    }

    private static bool EquivalentSha256(string left, string right)
    {
        var hasAlgorithmPrefix = left.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase)
            || left.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase);
        var candidate = hasAlgorithmPrefix ? left[7..] : left;
        return candidate.Length == 64
            && candidate.All(Uri.IsHexDigit)
            && string.Equals(candidate, right, StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateProcess(Dictionary<string, List<string>> errors, string prefix, ProcessTelemetryConcept? process)
    {
        if (process is null) return;
        OptionalMaxLength(errors, $"{prefix}.pid", process.Pid, 64);
        OptionalMaxLength(errors, $"{prefix}.parent_pid", process.ParentPid, 64);
        OptionalMaxLength(errors, $"{prefix}.executable", process.Executable, 2048);
        OptionalMaxLength(errors, $"{prefix}.command_line", process.CommandLine, 4096);
    }

    private static void ValidateUser(Dictionary<string, List<string>> errors, string prefix, UserTelemetryConcept? user)
    {
        if (user is null) return;
        OptionalMaxLength(errors, $"{prefix}.name", user.Name, 512);
        OptionalMaxLength(errors, $"{prefix}.id", user.Id, 512);
        OptionalMaxLength(errors, $"{prefix}.realm", user.Realm, 255);
    }

    private static void ValidateNetwork(Dictionary<string, List<string>> errors, string prefix, NetworkTelemetryConcept? network)
    {
        if (network is null) return;
        OptionalMaxLength(errors, $"{prefix}.source_ip", network.SourceIp, 128);
        OptionalMaxLength(errors, $"{prefix}.destination_ip", network.DestinationIp, 128);
        OptionalMaxLength(errors, $"{prefix}.protocol", network.Protocol, 64);
        if (network.SourcePort is < 0 or > 65_535) Add(errors, $"{prefix}.source_port", "Port must be between zero and 65535.");
        if (network.DestinationPort is < 0 or > 65_535) Add(errors, $"{prefix}.destination_port", "Port must be between zero and 65535.");
    }

    private static void ValidateFile(Dictionary<string, List<string>> errors, string prefix, FileTelemetryConcept? file)
    {
        if (file is null) return;
        OptionalMaxLength(errors, $"{prefix}.path", file.Path, 4096);
        OptionalMaxLength(errors, $"{prefix}.operation", file.Operation, 128);
        if (file.Sha256 is not null && !IsLowerHexSha256(file.Sha256)) Add(errors, $"{prefix}.sha256", "SHA-256 must be 64 lowercase hexadecimal characters.");
    }

    private static bool IsLinuxSource(SourceManifestEntry? source) => source is not null
        && (string.Equals(source.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
            || TelemetrySourceKinds.IsLinuxNative(source.SourceKind));

    private static bool IsLinuxSource(SourceHealthReport? source) => source is not null
        && (string.Equals(source.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
            || TelemetrySourceKinds.IsLinuxNative(source.SourceKind));

    private static void ValidateHeartbeatSourceRelationships(Dictionary<string, List<string>> errors, HeartbeatRequest request)
    {
        var portableManifest = request.SourceManifest
            .Select((source, index) => (Source: source, Index: index))
            .Where(item => item.Source is not null && TelemetrySourceKinds.UsesPortableIdentity(item.Source.SourceKind))
            .ToArray();
        var portableHealth = request.SourceHealth
            .Select((source, index) => (Source: source, Index: index))
            .Where(item => item.Source is not null && TelemetrySourceKinds.UsesPortableIdentity(item.Source.SourceKind))
            .ToArray();

        if (portableManifest.Length == 0 && portableHealth.Length == 0)
        {
            return;
        }

        RequireLength(errors, "host_id", request.HostId, 1, 255);
        foreach (var item in portableManifest)
        {
            if (!string.Equals(request.Platform, item.Source!.Platform, StringComparison.Ordinal))
            {
                Add(errors, $"source_manifest[{item.Index}].platform", "Portable source platform must match the heartbeat platform.");
            }
        }
        foreach (var item in portableHealth)
        {
            if (!string.Equals(request.Platform, item.Source!.Platform, StringComparison.Ordinal))
            {
                Add(errors, $"source_health[{item.Index}].platform", "Portable source platform must match the heartbeat platform.");
            }
        }

        ValidateUniquePortableSourceIds(errors, portableManifest.Select(item => (item.Source!.SourceId, item.Index)), "source_manifest");
        ValidateUniquePortableSourceIds(errors, portableHealth.Select(item => (item.Source!.SourceId, item.Index)), "source_health");

        foreach (var healthItem in portableHealth)
        {
            var health = healthItem.Source!;
            var manifests = portableManifest
                .Where(item => string.Equals(item.Source!.SourceId, health.SourceId, StringComparison.Ordinal))
                .ToArray();
            if (manifests.Length != 1)
            {
                Add(errors, $"source_health[{healthItem.Index}].source_id", "Each portable health entry must match exactly one manifest source_id.");
                continue;
            }

            var manifest = manifests[0].Source!;
            ValidateMatchingSourceValue(errors, healthItem.Index, "platform", manifest.Platform, health.Platform);
            ValidateMatchingSourceValue(errors, healthItem.Index, "source_kind", manifest.SourceKind, health.SourceKind);
            ValidateMatchingSourceValue(errors, healthItem.Index, "source_namespace", manifest.SourceNamespace, health.SourceNamespace);
            ValidateMatchingSourceValue(errors, healthItem.Index, "facility", manifest.Facility, health.Facility);
            ValidateMatchingSourceValue(errors, healthItem.Index, "unit", manifest.Unit, health.Unit);
            ValidateMatchingSourceValue(errors, healthItem.Index, "applicability", manifest.Applicability, health.Applicability);
            ValidateMatchingSourceValue(errors, healthItem.Index, "applicability_reason", manifest.ApplicabilityReason, health.ApplicabilityReason);
            ValidateMatchingSourceValue(errors, healthItem.Index, "requirement", manifest.Requirement, health.Requirement);
            ValidateMatchingStringList(errors, healthItem.Index, "applicable_roles", manifest.ApplicableRoles, health.ApplicableRoles);
            ValidateEvidenceKeys(errors, healthItem.Index, "prerequisite_statuses", manifest.Prerequisites, health.PrerequisiteStatuses);
            ValidateEvidenceKeys(errors, healthItem.Index, "event_family_statuses", manifest.EventFamilies, health.EventFamilyStatuses);
            ValidateCheckpointKind(errors, healthItem.Index, "collected_checkpoint", manifest.CheckpointKind, health.CollectedCheckpoint);
            ValidateCheckpointKind(errors, healthItem.Index, "acknowledged_checkpoint", manifest.CheckpointKind, health.AcknowledgedCheckpoint);
        }

        foreach (var manifestItem in portableManifest)
        {
            var matchingHealthCount = portableHealth.Count(item =>
                string.Equals(item.Source!.SourceId, manifestItem.Source!.SourceId, StringComparison.Ordinal));
            if (matchingHealthCount != 1)
            {
                Add(errors, $"source_manifest[{manifestItem.Index}].source_id", "Each portable manifest entry must match exactly one health source_id.");
            }
        }
    }

    private static void ValidateUniquePortableSourceIds(
        Dictionary<string, List<string>> errors,
        IEnumerable<(string SourceId, int Index)> sources,
        string collectionName)
    {
        foreach (var duplicate in sources
            .GroupBy(item => item.SourceId, StringComparer.Ordinal)
            .Where(group => !string.IsNullOrWhiteSpace(group.Key) && group.Count() > 1))
        {
            foreach (var item in duplicate)
            {
                Add(errors, $"{collectionName}[{item.Index}].source_id", "Portable source_id values must be unique within this heartbeat array.");
            }
        }
    }

    private static void ValidateMatchingSourceValue(
        Dictionary<string, List<string>> errors,
        int healthIndex,
        string field,
        string? manifestValue,
        string? healthValue)
    {
        if (!string.Equals(manifestValue, healthValue, StringComparison.Ordinal))
        {
            Add(errors, $"source_health[{healthIndex}].{field}", $"Portable source {field} must match its manifest entry.");
        }
    }

    private static void ValidateMatchingStringList(
        Dictionary<string, List<string>> errors,
        int healthIndex,
        string field,
        IReadOnlyList<string>? manifestValues,
        IReadOnlyList<string>? healthValues)
    {
        if (manifestValues is null && healthValues is null)
        {
            return;
        }
        if (manifestValues is null || healthValues is null
            || !manifestValues.SequenceEqual(healthValues, StringComparer.Ordinal))
        {
            Add(errors, $"source_health[{healthIndex}].{field}", $"Portable source {field} must match its manifest entry.");
        }
    }

    private static void ValidateEvidenceKeys(
        Dictionary<string, List<string>> errors,
        int healthIndex,
        string field,
        IReadOnlyList<string> manifestValues,
        IReadOnlyDictionary<string, string>? healthValues)
    {
        if (healthValues is null)
        {
            return;
        }
        if (!manifestValues.ToHashSet(StringComparer.Ordinal).SetEquals(healthValues.Keys))
        {
            Add(errors, $"source_health[{healthIndex}].{field}", $"Portable source {field} keys must exactly match its manifest metadata.");
        }
    }

    private static void ValidateRequirementMetadata(
        Dictionary<string, List<string>> errors,
        string prefix,
        string? requirement,
        IReadOnlyList<string>? applicableRoles,
        bool required,
        bool portableSource)
    {
        if (requirement is null)
        {
            if (applicableRoles is not null)
            {
                Add(errors, $"{prefix}.requirement", "applicable_roles requires a source requirement value.");
            }
            return;
        }
        if (!portableSource || !SourceRequirementKinds.All.Contains(requirement))
        {
            Add(errors, $"{prefix}.requirement", "Source requirement is not supported.");
            return;
        }
        if ((requirement == SourceRequirementKinds.Mandatory) != required)
        {
            Add(errors, $"{prefix}.required", "required must be true exactly for mandatory portable source requirements.");
        }
        if (applicableRoles is not null)
        {
            ValidateStringList(errors, $"{prefix}.applicable_roles", applicableRoles, requireNonEmptyItems: true);
        }
        if (requirement == SourceRequirementKinds.RoleSpecific && (applicableRoles is null || applicableRoles.Count == 0))
        {
            Add(errors, $"{prefix}.applicable_roles", "Role-specific sources require at least one applicable role.");
        }
        if (requirement != SourceRequirementKinds.RoleSpecific && applicableRoles is { Count: > 0 })
        {
            Add(errors, $"{prefix}.applicable_roles", "Only role-specific sources may declare applicable roles.");
        }
    }

    private static void ValidateEvidenceStatuses(
        Dictionary<string, List<string>> errors,
        string key,
        IReadOnlyDictionary<string, string>? values,
        bool portableSource)
    {
        if (values is null)
        {
            return;
        }
        if (!portableSource)
        {
            Add(errors, key, "Evidence status maps are available only to portable sources.");
            return;
        }
        ValidateMap(errors, key, values, ContractLimits.MaxMetadataListItems, 128, 64);
        foreach (var pair in values.Where(pair => !SourceEvidenceStatuses.All.Contains(pair.Value)))
        {
            Add(errors, $"{key}.{pair.Key}", "Evidence status is not supported.");
        }
    }

    private static void ValidateCheckpointKind(
        Dictionary<string, List<string>> errors,
        int healthIndex,
        string field,
        string? checkpointKind,
        SourceCheckpoint? checkpoint)
    {
        if (checkpoint is null || checkpointKind is null)
        {
            return;
        }

        if (!CheckpointMatchesKind(checkpoint, checkpointKind))
        {
            Add(errors, $"source_health[{healthIndex}].{field}", $"Checkpoint fields must match manifest checkpoint_kind {checkpointKind}.");
        }
    }

    private static void ValidateSourceManifestEntry(Dictionary<string, List<string>> errors, SourceManifestEntry? source, int index)
    {
        var prefix = $"source_manifest[{index}]";
        if (source is null)
        {
            Add(errors, prefix, "Source manifest entry must be an object.");
            return;
        }
        RequireLength(errors, $"{prefix}.source_id", source.SourceId, 1, 128);
        RequireLength(errors, $"{prefix}.display_name", source.DisplayName, 1, 255);
        OptionalMaxLength(errors, $"{prefix}.source_pack", source.SourcePack, 128);
        OptionalMaxLength(errors, $"{prefix}.parser_id", source.ParserId, 128);
        OptionalMaxLength(errors, $"{prefix}.privacy", source.Privacy, 128);
        ValidateRequirementMetadata(errors, prefix, source.Requirement, source.ApplicableRoles, source.Required,
            TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind));
        ValidateSourceDescriptor(errors, prefix, source.Platform, source.SourceKind, source.Channel, source.SourceNamespace,
            source.Facility, source.Unit, source.Applicability, source.ApplicabilityReason, source.CheckpointKind);
        ValidateKnownLinuxSourceDescriptor(
            errors,
            prefix,
            source.SourceId,
            source.Platform,
            source.SourceKind,
            source.SourceNamespace,
            source.Facility,
            source.Unit,
            source.CheckpointKind);
        ValidateKnownLinuxManifestMetadata(errors, prefix, source);
        if (TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind) && string.IsNullOrWhiteSpace(source.CheckpointKind))
        {
            Add(errors, $"{prefix}.checkpoint_kind", "Portable source manifests require a checkpoint kind.");
        }
        if (source.Prerequisites is null || source.EventFamilies is null || source.ValidationScenarios is null)
        {
            Add(errors, prefix, "Manifest list fields must use array values.");
        }
        else
        {
            var requireNonEmptyItems = TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind);
            ValidateStringList(errors, $"{prefix}.prerequisites", source.Prerequisites, requireNonEmptyItems);
            ValidateStringList(errors, $"{prefix}.event_families", source.EventFamilies, requireNonEmptyItems);
            ValidateStringList(errors, $"{prefix}.validation_scenarios", source.ValidationScenarios, requireNonEmptyItems);
        }
    }

    private static void ValidateSourceHealth(
        Dictionary<string, List<string>> errors,
        SourceHealthReport? source,
        int index,
        DateTimeOffset receivedAtUtc)
    {
        var prefix = $"source_health[{index}]";
        if (source is null)
        {
            Add(errors, prefix, "Source health entry must be an object.");
            return;
        }
        RequireLength(errors, $"{prefix}.source_id", source.SourceId, 1, 128);
        RequireLength(errors, $"{prefix}.display_name", source.DisplayName, 1, 255);
        ValidateSourceDescriptor(errors, prefix, source.Platform, source.SourceKind, source.Channel, source.SourceNamespace,
            source.Facility, source.Unit, source.Applicability, source.ApplicabilityReason, checkpointKind: null);
        ValidateKnownLinuxSourceDescriptor(
            errors,
            prefix,
            source.SourceId,
            source.Platform,
            source.SourceKind,
            source.SourceNamespace,
            source.Facility,
            source.Unit,
            checkpointKind: null);
        ValidateKnownLinuxHealthMetadata(errors, prefix, source);
        var portableSource = TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind);
        var supportedStatus = portableSource
            ? AllowedSourceStatuses.Contains(source.Status)
            : AllowedSourceStatuses.Any(status => string.Equals(status, source.Status, StringComparison.OrdinalIgnoreCase));
        if (!supportedStatus) Add(errors, $"{prefix}.status", "Source status is not supported.");
        if (portableSource && source.Status == SourceHealthStatuses.Excepted)
        {
            Add(errors, $"{prefix}.status", "Portable agents cannot self-report a server-managed coverage exception.");
        }
        if (source.SourceKind is not null
            && source.Status == SourceHealthStatuses.NotApplicable
            && source.Applicability != SourceApplicabilityStatuses.NotApplicable)
        {
            Add(errors, $"{prefix}.applicability", "not_applicable health requires not_applicable source applicability.");
        }
        if (source.SourceKind is not null
            && source.Applicability == SourceApplicabilityStatuses.NotApplicable
            && source.Status != SourceHealthStatuses.NotApplicable)
        {
            Add(errors, $"{prefix}.status", "A non-applicable source must report not_applicable health.");
        }
        if (source.SourceKind is not null
            && source.Status == SourceHealthStatuses.Unsupported
            && source.Applicability != SourceApplicabilityStatuses.Unsupported)
        {
            Add(errors, $"{prefix}.applicability", "unsupported health requires unsupported source applicability.");
        }
        if (source.SourceKind is not null
            && source.Applicability == SourceApplicabilityStatuses.Unsupported
            && source.Status != SourceHealthStatuses.Unsupported)
        {
            Add(errors, $"{prefix}.status", "An unsupported source must report unsupported health.");
        }
        ValidateRequirementMetadata(errors, prefix, source.Requirement, source.ApplicableRoles, source.Required, portableSource);
        ValidateEvidenceStatuses(errors, $"{prefix}.prerequisite_statuses", source.PrerequisiteStatuses, portableSource);
        ValidateEvidenceStatuses(errors, $"{prefix}.event_family_statuses", source.EventFamilyStatuses, portableSource);
        if (portableSource)
        {
            ValidateTimestamp(errors, $"{prefix}.last_event_time", source.LastEventTime);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.last_event_time", source.LastEventTime, receivedAtUtc);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.observed_at", source.ObservedAt, receivedAtUtc);
        }
        ValidateTimestamp(errors, $"{prefix}.observed_at", source.ObservedAt);
        ValidateHostTimezone(errors, $"{prefix}.host_timezone", source.HostTimezone);
        ValidateNonNegative(errors, $"{prefix}.last_record_id", source.LastRecordId);
        ValidateNonNegative(errors, $"{prefix}.oldest_record_id", source.OldestRecordId);
        ValidateNonNegative(errors, $"{prefix}.newest_record_id", source.NewestRecordId);
        ValidateNonNegative(errors, $"{prefix}.log_size_bytes", source.LogSizeBytes);
        ValidateNonNegative(errors, $"{prefix}.retention_days", source.RetentionDays);
        ValidateNonNegative(errors, $"{prefix}.lag_seconds", source.LagSeconds);
        ValidateNonNegative(errors, $"{prefix}.silence_seconds", source.SilenceSeconds);
        if (source.EventRatePerMinute is < 0 or > 1_000_000) Add(errors, $"{prefix}.event_rate_per_minute", "Event rate must be between zero and 1000000 per minute.");
        OptionalMaxLength(errors, $"{prefix}.error_code", source.ErrorCode, 128);
        OptionalMaxLength(errors, $"{prefix}.error_message", source.ErrorMessage, 1000);
        OptionalMaxLength(errors, $"{prefix}.config_hash", source.ConfigHash, 128);
        OptionalMaxLength(errors, $"{prefix}.source_version", source.SourceVersion, 128);
        ValidateNonNegative(errors, $"{prefix}.gap_count", source.GapCount);
        ValidateTimestamp(errors, $"{prefix}.permission_denied_since", source.PermissionDeniedSince);
        ValidateTimestamp(errors, $"{prefix}.recovered_at", source.RecoveredAt);
        OptionalMaxLength(errors, $"{prefix}.transition_state", source.TransitionState, 64);
        if (source.TransitionState is not null && !AllowedHealthTransitionStates.Contains(source.TransitionState)) Add(errors, $"{prefix}.transition_state", "Health transition state is not supported.");
        ValidateTimestamp(errors, $"{prefix}.transitioned_at", source.TransitionedAt);
        ValidateNonNegative(errors, $"{prefix}.dropped_events", source.DroppedEvents);
        ValidateNonNegative(errors, $"{prefix}.poison_events", source.PoisonEvents);
        if (source.Details is null)
        {
            Add(errors, $"{prefix}.details", "Details must be an object when supplied.");
        }
        else if (portableSource)
        {
            ValidateMap(errors, $"{prefix}.details", source.Details, 32, 128, 1000);
        }

        if (source.CollectedCheckpoint?.Sequence is long collectedSequence
            && source.AcknowledgedCheckpoint?.Sequence is long acknowledgedSequence
            && acknowledgedSequence > collectedSequence)
        {
            Add(errors, $"{prefix}.acknowledged_checkpoint.sequence", "Acknowledged sequence cannot be ahead of the collected sequence.");
        }

        if (portableSource)
        {
            if (source.LastRecordId.HasValue || source.OldestRecordId.HasValue || source.NewestRecordId.HasValue)
            {
                Add(errors, $"{prefix}.source_kind", "Portable source health must use checkpoints instead of Windows record IDs.");
            }

            if (source.Applicability == SourceApplicabilityStatuses.Applicable)
            {
                ValidateCheckpoint(errors, $"{prefix}.collected_checkpoint", source.CollectedCheckpoint, required: true);
                ValidateCheckpoint(errors, $"{prefix}.acknowledged_checkpoint", source.AcknowledgedCheckpoint, required: true);
            }
            ValidateNotExcessivelyFuture(errors, $"{prefix}.collected_checkpoint.event_time", source.CollectedCheckpoint?.EventTime, receivedAtUtc);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.collected_checkpoint.recorded_at", source.CollectedCheckpoint?.RecordedAt, receivedAtUtc);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.acknowledged_checkpoint.event_time", source.AcknowledgedCheckpoint?.EventTime, receivedAtUtc);
            ValidateNotExcessivelyFuture(errors, $"{prefix}.acknowledged_checkpoint.recorded_at", source.AcknowledgedCheckpoint?.RecordedAt, receivedAtUtc);
        }
        else
        {
            ValidateCheckpoint(errors, $"{prefix}.collected_checkpoint", source.CollectedCheckpoint, required: false);
            ValidateCheckpoint(errors, $"{prefix}.acknowledged_checkpoint", source.AcknowledgedCheckpoint, required: false);
        }
    }

    private static void ValidateSourceDescriptor(
        Dictionary<string, List<string>> errors,
        string prefix,
        string? platform,
        string? sourceKind,
        string? channel,
        string? sourceNamespace,
        string? facility,
        string? unit,
        string? applicability,
        string? applicabilityReason,
        string? checkpointKind)
    {
        var legacy = platform is null && sourceKind is null;
        if (legacy)
        {
            RequireLength(errors, $"{prefix}.channel", channel, 1, 255);
            return;
        }

        if (platform is not (TelemetryPlatforms.Windows or TelemetryPlatforms.Linux))
        {
            Add(errors, $"{prefix}.platform", "Platform must be windows or linux.");
        }

        if (sourceKind is null || !TelemetrySourceKinds.All.Contains(sourceKind))
        {
            Add(errors, $"{prefix}.source_kind", "Source kind is not supported.");
            return;
        }

        if (!TelemetrySourceKinds.IsValidForPlatform(sourceKind, platform))
        {
            Add(errors, $"{prefix}.source_kind", "Source kind is not valid for the declared platform.");
        }

        var portable = TelemetrySourceKinds.UsesPortableIdentity(sourceKind);
        if (portable)
        {
            if (channel is not null) Add(errors, $"{prefix}.channel", "Portable sources must omit the Windows channel field.");
            RequireLength(errors, $"{prefix}.source_namespace", sourceNamespace, 1, 128);
            if (applicability is null || !AllowedApplicabilityStatuses.Contains(applicability))
            {
                Add(errors, $"{prefix}.applicability", "Portable sources require a supported applicability value.");
            }
            if (checkpointKind is not null && !AllowedCheckpointKinds.Contains(checkpointKind))
            {
                Add(errors, $"{prefix}.checkpoint_kind", "Checkpoint kind is not supported.");
            }
        }
        else
        {
            RequireLength(errors, $"{prefix}.channel", channel, 1, 255);
        }

        OptionalMaxLength(errors, $"{prefix}.source_namespace", sourceNamespace, 128);
        OptionalMaxLength(errors, $"{prefix}.facility", facility, 128);
        OptionalMaxLength(errors, $"{prefix}.unit", unit, 255);
        OptionalMaxLength(errors, $"{prefix}.applicability_reason", applicabilityReason, 512);
        if (applicability is SourceApplicabilityStatuses.NotApplicable or SourceApplicabilityStatuses.Unknown or SourceApplicabilityStatuses.Unsupported
            && string.IsNullOrWhiteSpace(applicabilityReason))
        {
            Add(errors, $"{prefix}.applicability_reason", "Non-applicable, unknown, or unsupported sources require a reason.");
        }
    }

    private static void ValidateKnownLinuxEventIdentity(
        Dictionary<string, List<string>> errors,
        string prefix,
        EventEnvelope envelope)
    {
        var canonical = FindKnownLinuxSource(envelope.SourceId);
        if (canonical is null)
        {
            return;
        }

        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.source_id", "source_id", canonical.SourceId, envelope.SourceId);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.platform", "platform", canonical.Platform, envelope.Platform);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.source", "source kind", canonical.SourceKind, envelope.Source);
        if (envelope.Checkpoint is not null
            && canonical.CheckpointKind is not null
            && !CheckpointMatchesKind(envelope.Checkpoint, canonical.CheckpointKind))
        {
            Add(errors, $"{prefix}.checkpoint",
                $"Known Linux source checkpoint fields must match canonical checkpoint kind {canonical.CheckpointKind}.");
        }
    }

    private static void ValidateKnownLinuxSourceDescriptor(
        Dictionary<string, List<string>> errors,
        string prefix,
        string? sourceId,
        string? platform,
        string? sourceKind,
        string? sourceNamespace,
        string? facility,
        string? unit,
        string? checkpointKind)
    {
        var canonical = FindKnownLinuxSource(sourceId);
        if (canonical is null)
        {
            return;
        }

        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.source_id", "source_id", canonical.SourceId, sourceId);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.platform", "platform", canonical.Platform, platform);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.source_kind", "source kind", canonical.SourceKind, sourceKind);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.source_namespace", "source namespace", canonical.SourceNamespace, sourceNamespace);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.facility", "facility", canonical.Facility, facility);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.unit", "unit", canonical.Unit, unit);
        if (checkpointKind is not null)
        {
            ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.checkpoint_kind", "checkpoint kind", canonical.CheckpointKind, checkpointKind);
        }
    }

    private static SourceManifestEntry? FindKnownLinuxSource(string? sourceId) =>
        sourceId is null
            ? null
            : LinuxTelemetrySourceCatalog.All.FirstOrDefault(entry =>
                string.Equals(entry.SourceId, sourceId, StringComparison.OrdinalIgnoreCase));

    private static void ValidateKnownLinuxManifestMetadata(
        Dictionary<string, List<string>> errors,
        string prefix,
        SourceManifestEntry submitted)
    {
        var canonical = FindKnownLinuxSource(submitted.SourceId);
        if (canonical is null)
        {
            return;
        }

        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.display_name", "display name", canonical.DisplayName, submitted.DisplayName);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.coverage_level", "coverage level", canonical.CoverageLevel.ToString(), submitted.CoverageLevel.ToString());
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.requirement", "requirement", canonical.Requirement, submitted.Requirement);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.source_pack", "source pack", canonical.SourcePack, submitted.SourcePack);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.parser_id", "parser", canonical.ParserId, submitted.ParserId);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.privacy", "privacy classification", canonical.Privacy, submitted.Privacy);
        if (canonical.Required != submitted.Required)
        {
            Add(errors, $"{prefix}.required", "Known Linux source required flag must exactly match its canonical catalog value.");
        }
        if (canonical.EnabledByDefault != submitted.EnabledByDefault)
        {
            Add(errors, $"{prefix}.enabled_by_default", "Known Linux source enabled-by-default flag must exactly match its canonical catalog value.");
        }
        if (canonical.InstallerManaged != submitted.InstallerManaged)
        {
            Add(errors, $"{prefix}.installer_managed", "Known Linux source installer-managed flag must exactly match its canonical catalog value.");
        }

        ValidateCanonicalLinuxList(errors, $"{prefix}.applicable_roles", "applicable roles", canonical.ApplicableRoles, submitted.ApplicableRoles);
        ValidateCanonicalLinuxList(errors, $"{prefix}.prerequisites", "prerequisites", canonical.Prerequisites, submitted.Prerequisites);
        ValidateCanonicalLinuxList(errors, $"{prefix}.event_families", "event families", canonical.EventFamilies, submitted.EventFamilies);
        ValidateCanonicalLinuxList(errors, $"{prefix}.validation_scenarios", "validation scenarios", canonical.ValidationScenarios, submitted.ValidationScenarios);
    }

    private static void ValidateKnownLinuxHealthMetadata(
        Dictionary<string, List<string>> errors,
        string prefix,
        SourceHealthReport submitted)
    {
        var canonical = FindKnownLinuxSource(submitted.SourceId);
        if (canonical is null)
        {
            return;
        }

        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.display_name", "display name", canonical.DisplayName, submitted.DisplayName);
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.coverage_level", "coverage level", canonical.CoverageLevel.ToString(), submitted.CoverageLevel.ToString());
        ValidateCanonicalLinuxSourceValue(errors, $"{prefix}.requirement", "requirement", canonical.Requirement, submitted.Requirement);
        if (canonical.Required != submitted.Required)
        {
            Add(errors, $"{prefix}.required", "Known Linux source required flag must exactly match its canonical catalog value.");
        }
        ValidateCanonicalLinuxList(errors, $"{prefix}.applicable_roles", "applicable roles", canonical.ApplicableRoles, submitted.ApplicableRoles);

        if (canonical.Applicability == SourceApplicabilityStatuses.Unsupported
            && submitted.Applicability != SourceApplicabilityStatuses.Unsupported)
        {
            Add(errors, $"{prefix}.applicability", "Known unsupported Linux source must retain canonical unsupported applicability.");
        }
        if (canonical.Requirement == SourceRequirementKinds.Mandatory
            && canonical.Applicability == SourceApplicabilityStatuses.Applicable
            && submitted.Applicability != SourceApplicabilityStatuses.Applicable)
        {
            Add(errors, $"{prefix}.applicability", "Known mandatory applicable Linux source cannot report itself as inapplicable.");
        }
    }

    private static void ValidateCanonicalLinuxList(
        Dictionary<string, List<string>> errors,
        string key,
        string fieldName,
        IReadOnlyList<string>? canonical,
        IReadOnlyList<string>? submitted)
    {
        if (canonical is null && submitted is null)
        {
            return;
        }

        if (canonical is null || submitted is null || !canonical.SequenceEqual(submitted, StringComparer.Ordinal))
        {
            Add(errors, key, $"Known Linux source {fieldName} must exactly match its canonical catalog value.");
        }
    }

    private static void ValidateCanonicalLinuxSourceValue(
        Dictionary<string, List<string>> errors,
        string key,
        string fieldName,
        string? canonicalValue,
        string? submittedValue)
    {
        if (!string.Equals(canonicalValue, submittedValue, StringComparison.Ordinal))
        {
            Add(errors, key, $"Known Linux source {fieldName} must exactly match its canonical catalog value.");
        }
    }

    private static bool CheckpointMatchesKind(SourceCheckpoint checkpoint, string checkpointKind) => checkpointKind switch
    {
        SourceCheckpointKinds.Cursor => checkpoint.Cursor is not null && checkpoint.Sequence is null,
        SourceCheckpointKinds.Sequence => checkpoint.Cursor is null && checkpoint.Sequence.HasValue,
        SourceCheckpointKinds.CursorAndSequence => checkpoint.Cursor is not null && checkpoint.Sequence.HasValue,
        _ => false
    };

    private static void ValidateCheckpoint(Dictionary<string, List<string>> errors, string prefix, SourceCheckpoint? checkpoint, bool required)
    {
        if (checkpoint is null)
        {
            if (required) Add(errors, prefix, "Checkpoint metadata is required.");
            return;
        }

        if (checkpoint.Cursor is null && checkpoint.Sequence is null)
        {
            Add(errors, prefix, "A checkpoint requires a cursor, a sequence, or both.");
        }
        OptionalMaxLength(errors, $"{prefix}.cursor", checkpoint.Cursor, 1024);
        ValidateNonNegative(errors, $"{prefix}.sequence", checkpoint.Sequence);
        ValidateTimestamp(errors, $"{prefix}.event_time", checkpoint.EventTime);
        ValidateTimestamp(errors, $"{prefix}.recorded_at", checkpoint.RecordedAt);
    }

    private static void ValidateQueueMetrics(
        Dictionary<string, List<string>> errors,
        QueueSloMetrics? metrics,
        bool enforceLinuxBounds)
    {
        if (metrics is null) return;
        if (metrics.QueueDepth < 0) Add(errors, "queue_metrics.queue_depth", "Queue depth must be greater than or equal to zero.");
        if (metrics.PoisonDepth < 0) Add(errors, "queue_metrics.poison_depth", "Poison depth must be greater than or equal to zero.");
        ValidateNonNegative(errors, "queue_metrics.oldest_queued_age_seconds", metrics.OldestQueuedAgeSeconds);
        ValidateNonNegative(errors, "queue_metrics.queue_size_bytes", metrics.QueueSizeBytes);
        ValidateNonNegative(errors, "queue_metrics.max_size_bytes", metrics.MaxSizeBytes);
        if (metrics.UsedPercent is < 0 or > 1000) Add(errors, "queue_metrics.used_percent", "Used percent must be between zero and 1000.");
        OptionalMaxLength(errors, "queue_metrics.pressure_state", metrics.PressureState, 64);
        if (metrics.PressureState is not null && !AllowedQueuePressureStates.Contains(metrics.PressureState)) Add(errors, "queue_metrics.pressure_state", "Queue pressure state is not supported.");
        OptionalMaxLength(errors, "queue_metrics.send_state", metrics.SendState, 64);
        if (metrics.SendState is not null && !AllowedQueueSendStates.Contains(metrics.SendState)) Add(errors, "queue_metrics.send_state", "Queue send state is not supported.");
        if (metrics.BackoffSeconds is < 0 or > 86_400) Add(errors, "queue_metrics.backoff_seconds", "Backoff seconds must be between zero and 86400.");
        ValidateTimestamp(errors, "queue_metrics.last_attempt_time", metrics.LastAttemptTime);
        ValidateTimestamp(errors, "queue_metrics.last_failed_send_time", metrics.LastFailedSendTime);
        ValidateTimestamp(errors, "queue_metrics.last_recovery_time", metrics.LastRecoveryTime);
        ValidateNonNegative(errors, "queue_metrics.poison_events_total", metrics.PoisonEventsTotal);
        ValidateNonNegative(errors, "queue_metrics.dropped_events_total", metrics.DroppedEventsTotal);
        if (enforceLinuxBounds)
        {
            ValidateTimestamp(errors, "queue_metrics.last_successful_send_time", metrics.LastSuccessfulSendTime);
            if (metrics.MaxSizeMb < 1) Add(errors, "queue_metrics.max_size_mb", "Maximum queue size must be at least one MB.");
            if (metrics.WarningSizePercent is < 1 or > 100) Add(errors, "queue_metrics.warning_size_percent", "Warning percent must be between one and 100.");
        }
    }

    private static void ValidateResourceMetrics(
        Dictionary<string, List<string>> errors,
        string prefix,
        AgentResourceMetrics? metrics,
        bool enforceLinuxBounds,
        DateTimeOffset receivedAtUtc)
    {
        if (metrics is null) return;
        ValidateTimestamp(errors, $"{prefix}.observed_at", metrics.ObservedAt);
        if (enforceLinuxBounds)
        {
            ValidateNotExcessivelyFuture(errors, $"{prefix}.observed_at", metrics.ObservedAt, receivedAtUtc);
        }
        if (metrics.CpuPercent is < 0 || (enforceLinuxBounds && metrics.CpuPercent > 100))
        {
            Add(errors, $"{prefix}.cpu_percent", enforceLinuxBounds
                ? "CPU percent must be between zero and 100."
                : "CPU percent must be greater than or equal to zero.");
        }
        ValidateNonNegative(errors, $"{prefix}.rss_bytes", metrics.RssBytes);
        ValidateNonNegative(errors, $"{prefix}.managed_memory_bytes", metrics.ManagedMemoryBytes);
        if (metrics.Status is not ("observed" or "partial" or "unknown"))
        {
            Add(errors, $"{prefix}.status", "Resource metric status is not supported.");
        }
    }

    private static void ValidateTamperChecks(
        Dictionary<string, List<string>> errors,
        TamperCheckSummary? tamperChecks,
        bool enforceLinuxBounds)
    {
        if (tamperChecks is null || !enforceLinuxBounds) return;
        OptionalMaxLength(errors, "tamper_checks.binary_hash", tamperChecks.BinaryHash, 128);
        OptionalMaxLength(errors, "tamper_checks.config_hash", tamperChecks.ConfigHash, 128);
        OptionalMaxLength(errors, "tamper_checks.signature_status", tamperChecks.SignatureStatus, 128);
        OptionalMaxLength(errors, "tamper_checks.acl_status", tamperChecks.AclStatus, 128);
    }

    private static void ValidatePlatformAndHostId(Dictionary<string, List<string>> errors, string? platform, string? hostId)
    {
        if (platform is not null && platform is not (TelemetryPlatforms.Windows or TelemetryPlatforms.Linux))
        {
            Add(errors, "platform", "Platform must be windows or linux.");
        }
        OptionalMaxLength(errors, "host_id", hostId, 255);
        if (platform == TelemetryPlatforms.Linux) RequireLength(errors, "host_id", hostId, 1, 255);
    }

    private static void ValidateHostTimezone(Dictionary<string, List<string>> errors, string prefix, HostTimezoneMetadata? timezone)
    {
        if (timezone is null) return;
        OptionalMaxLength(errors, $"{prefix}.id", timezone.Id, 128);
        OptionalMaxLength(errors, $"{prefix}.display_name", timezone.DisplayName, 255);
        OptionalMaxLength(errors, $"{prefix}.standard_name", timezone.StandardName, 255);
        OptionalMaxLength(errors, $"{prefix}.daylight_name", timezone.DaylightName, 255);
        ValidateOffsetMinutes(errors, $"{prefix}.base_utc_offset_minutes", timezone.BaseUtcOffsetMinutes);
        ValidateOffsetMinutes(errors, $"{prefix}.utc_offset_minutes", timezone.UtcOffsetMinutes);
    }

    private static void ValidateStringList(
        Dictionary<string, List<string>> errors,
        string key,
        IReadOnlyList<string> values,
        bool requireNonEmptyItems)
    {
        if (values.Count > ContractLimits.MaxMetadataListItems) Add(errors, key, $"List contains more than {ContractLimits.MaxMetadataListItems} entries.");
        for (var index = 0; index < values.Count; index++)
        {
            if (requireNonEmptyItems)
            {
                RequireLength(errors, $"{key}[{index}]", values[index], 1, 128);
            }
            else
            {
                OptionalMaxLength(errors, $"{key}[{index}]", values[index], 128);
            }
        }
    }

    private static void ValidateFieldList(Dictionary<string, List<string>> errors, string key, IReadOnlyList<string> values)
    {
        if (values.Count > ContractLimits.MaxMetadataListItems || values.Distinct(StringComparer.Ordinal).Count() != values.Count)
            Add(errors, key, $"Field list must contain at most {ContractLimits.MaxMetadataListItems} unique entries.");
        for (var index = 0; index < values.Count; index++) RequireLength(errors, $"{key}[{index}]", values[index], 1, 256);
    }

    private static void ValidateMap(Dictionary<string, List<string>> errors, string key, IReadOnlyDictionary<string, string> values, int maxEntries, int maxKeyLength, int maxValueLength)
    {
        if (values.Count > maxEntries) Add(errors, key, $"Map contains more than {maxEntries} entries.");
        foreach (var pair in values)
        {
            RequireLength(errors, $"{key}.key", pair.Key, 1, maxKeyLength);
            OptionalMaxLength(errors, $"{key}.{pair.Key}", pair.Value, maxValueLength);
        }
    }

    private static bool IsLowerHexSha256(string value) => value.Length == 64 && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void ValidateTimestamp(Dictionary<string, List<string>> errors, string key, DateTimeOffset? value)
    {
        if (value.HasValue && value.Value == default) Add(errors, key, "Timestamp must not be the default value.");
    }

    private static void ValidateNotExcessivelyFuture(
        Dictionary<string, List<string>> errors,
        string key,
        DateTimeOffset? value,
        DateTimeOffset receivedAtUtc)
    {
        if (value.HasValue && value.Value.ToUniversalTime() > receivedAtUtc + MaximumFutureTimestampSkew)
        {
            Add(errors, key,
                $"Timestamp must not be more than {MaximumFutureTimestampSkew.TotalMinutes:0} minutes ahead of server receive time.");
        }
    }

    private static void ValidateNonNegative(Dictionary<string, List<string>> errors, string key, long? value)
    {
        if (value < 0) Add(errors, key, "Value must be greater than or equal to zero.");
    }

    private static void ValidateOffsetMinutes(Dictionary<string, List<string>> errors, string key, int? value)
    {
        if (value is < -14 * 60 or > 14 * 60) Add(errors, key, "UTC offset minutes must be between -840 and 840.");
    }

    private static void OptionalMaxLength(Dictionary<string, List<string>> errors, string key, string? value, int maxLength)
    {
        if (value is not null && value.Length > maxLength) Add(errors, key, $"Value length must be less than or equal to {maxLength} characters.");
    }

    private static void RequireLength(Dictionary<string, List<string>> errors, string key, string? value, int minLength, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            Add(errors, key, "Value is required.");
            return;
        }
        if (value.Length < minLength || value.Length > maxLength) Add(errors, key, $"Value length must be between {minLength} and {maxLength} characters.");
    }

    private static Dictionary<string, List<string>> NewErrorBag() => new(StringComparer.Ordinal);

    private static void Add(Dictionary<string, List<string>> errors, string key, string message)
    {
        if (!errors.TryGetValue(key, out var messages))
        {
            messages = new List<string>();
            errors[key] = messages;
        }
        messages.Add(message);
    }

    private static Dictionary<string, string[]> ToValidationProblem(Dictionary<string, List<string>> errors) =>
        errors.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.Ordinal);
}
