using System.Text.Json;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Ingestion;

public static class RequestValidation
{
    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "verbose",
        "information",
        "warning",
        "error",
        "critical",
        "audit_success",
        "audit_failure"
    };

    private static readonly HashSet<string> AllowedSourceStatuses = new(StringComparer.OrdinalIgnoreCase)
    {
        SourceHealthStatuses.Healthy,
        SourceHealthStatuses.Missing,
        SourceHealthStatuses.Disabled,
        SourceHealthStatuses.Stale,
        SourceHealthStatuses.Error,
        SourceHealthStatuses.NotApplicable,
        SourceHealthStatuses.Excepted
    };

    public static Dictionary<string, string[]> ValidateRegistration(AgentRegistrationRequest request)
    {
        var errors = NewErrorBag();
        RequireLength(errors, nameof(request.AgentId), request.AgentId, 1, 128);
        RequireLength(errors, nameof(request.Hostname), request.Hostname, 1, 255);
        RequireLength(errors, nameof(request.OsVersion), request.OsVersion, 1, 255);
        RequireLength(errors, nameof(request.AgentVersion), request.AgentVersion, 1, 64);
        return ToValidationProblem(errors);
    }

    public static Dictionary<string, string[]> ValidateHeartbeat(HeartbeatRequest request)
    {
        var errors = NewErrorBag();
        RequireLength(errors, nameof(request.AgentId), request.AgentId, 1, 128);
        RequireLength(errors, nameof(request.Hostname), request.Hostname, 1, 255);
        RequireLength(errors, nameof(request.AgentVersion), request.AgentVersion, 1, 64);
        RequireLength(errors, nameof(request.Os), request.Os, 1, 255);

        if (request.QueueDepth < 0)
        {
            Add(errors, nameof(request.QueueDepth), "Queue depth must be greater than or equal to zero.");
        }

        if (request.CpuPercent < 0)
        {
            Add(errors, nameof(request.CpuPercent), "CPU percent must be greater than or equal to zero.");
        }

        if (request.MemoryMb < 0)
        {
            Add(errors, nameof(request.MemoryMb), "Memory MB must be greater than or equal to zero.");
        }

        if (request.QueueMetrics is not null)
        {
            if (request.QueueMetrics.QueueDepth < 0)
            {
                Add(errors, "queue_metrics.queue_depth", "Queue depth must be greater than or equal to zero.");
            }

            if (request.QueueMetrics.PoisonDepth < 0)
            {
                Add(errors, "queue_metrics.poison_depth", "Poison depth must be greater than or equal to zero.");
            }
        }

        for (var index = 0; index < request.SourceHealth.Count; index++)
        {
            var source = request.SourceHealth[index];
            RequireLength(errors, $"source_health[{index}].source_id", source.SourceId, 1, 128);
            RequireLength(errors, $"source_health[{index}].display_name", source.DisplayName, 1, 255);
            RequireLength(errors, $"source_health[{index}].channel", source.Channel, 1, 255);
            if (!AllowedSourceStatuses.Contains(source.Status))
            {
                Add(errors, $"source_health[{index}].status", "Source status is not supported.");
            }
        }

        return ToValidationProblem(errors);
    }

    public static Dictionary<string, string[]> ValidateBatch(IngestBatchRequest batch, int maxEventsPerBatch)
    {
        var errors = NewErrorBag();
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

        if (batch.Events.Count > maxEventsPerBatch)
        {
            Add(errors, nameof(batch.Events), $"Batch contains more than {maxEventsPerBatch} events.");
        }

        for (var index = 0; index < batch.Events.Count; index++)
        {
            ValidateEvent(errors, batch.AgentId, batch.Events[index], index);
        }

        return ToValidationProblem(errors);
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
        }

        return ToValidationProblem(errors);
    }

    private static void ValidateEvent(Dictionary<string, List<string>> errors, string batchAgentId, EventEnvelope? envelope, int index)
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
        RequireLength(errors, $"{prefix}.channel", envelope.Channel, 1, 255);
        RequireLength(errors, $"{prefix}.provider", envelope.Provider, 1, 255);

        if (!string.Equals(envelope.Source, EventSources.WindowsEventLog, StringComparison.Ordinal))
        {
            Add(errors, $"{prefix}.source", "Source must be windows_event_log.");
        }

        if (envelope.WindowsEventId < 0 || envelope.WindowsEventId > 65535)
        {
            Add(errors, $"{prefix}.windows_event_id", "Windows event ID must be between 0 and 65535.");
        }

        if (envelope.RecordId < 0)
        {
            Add(errors, $"{prefix}.record_id", "Record ID must be greater than or equal to zero.");
        }

        if (envelope.EventTime == default)
        {
            Add(errors, $"{prefix}.event_time", "Event timestamp is required.");
        }

        if (string.IsNullOrWhiteSpace(envelope.Severity) || !AllowedSeverities.Contains(envelope.Severity))
        {
            Add(errors, $"{prefix}.severity", "Severity is not supported.");
        }

        if (envelope.Message is null)
        {
            Add(errors, $"{prefix}.message", "Message is required.");
        }
        else if (envelope.Message.Length > 20000)
        {
            Add(errors, $"{prefix}.message", "Message is too long.");
        }

        if (envelope.Raw.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            Add(errors, $"{prefix}.raw", "Raw event data is required.");
        }
    }

    private static Dictionary<string, List<string>> NewErrorBag()
    {
        return new Dictionary<string, List<string>>(StringComparer.Ordinal);
    }

    private static void RequireLength(Dictionary<string, List<string>> errors, string key, string? value, int minLength, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            Add(errors, key, "Value is required.");
            return;
        }

        if (value.Length < minLength || value.Length > maxLength)
        {
            Add(errors, key, $"Value length must be between {minLength} and {maxLength} characters.");
        }
    }

    private static void Add(Dictionary<string, List<string>> errors, string key, string message)
    {
        if (!errors.TryGetValue(key, out var messages))
        {
            messages = new List<string>();
            errors[key] = messages;
        }

        messages.Add(message);
    }

    private static Dictionary<string, string[]> ToValidationProblem(Dictionary<string, List<string>> errors)
    {
        return errors.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.Ordinal);
    }
}
