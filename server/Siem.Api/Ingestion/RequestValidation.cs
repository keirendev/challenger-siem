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
