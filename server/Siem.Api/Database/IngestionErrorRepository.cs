using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed class IngestionErrorRepository(NpgsqlDataSource dataSource)
{
    private const int MaxErrorMessageLength = 1000;
    private const int MaxFieldCount = 25;
    private const int MaxSampleEvents = 5;

    public async Task RecordValidationErrorsAsync(
        IngestBatchRequest batch,
        IReadOnlyDictionary<string, string[]> validationErrors,
        CancellationToken cancellationToken)
    {
        if (validationErrors.Count == 0)
        {
            return;
        }

        var payload = BuildSafePayload(batch, validationErrors);
        var errorMessage = string.Join(
            "; ",
            validationErrors
                .Take(MaxFieldCount)
                .Select(pair => $"{pair.Key}: {string.Join(", ", pair.Value)}"));

        if (errorMessage.Length > MaxErrorMessageLength)
        {
            errorMessage = errorMessage[..MaxErrorMessageLength];
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into ingestion_errors (agent_id, batch_id, event_id, error_code, error_message, payload)
            values (@agent_id, @batch_id, @event_id, @error_code, @error_message, @payload);
            """;
        command.Parameters.AddWithValue("agent_id", string.IsNullOrWhiteSpace(batch.AgentId) ? DBNull.Value : batch.AgentId);
        command.Parameters.AddWithValue("batch_id", batch.BatchId == Guid.Empty ? DBNull.Value : batch.BatchId);
        command.Parameters.AddWithValue("event_id", FirstEventId(batch, validationErrors) ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("error_code", "validation_failed");
        command.Parameters.AddWithValue("error_message", errorMessage);
        var payloadParameter = command.Parameters.Add("payload", NpgsqlDbType.Jsonb);
        payloadParameter.Value = JsonSerializer.Serialize(payload);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static object BuildSafePayload(
        IngestBatchRequest batch,
        IReadOnlyDictionary<string, string[]> validationErrors)
    {
        var fields = validationErrors
            .Take(MaxFieldCount)
            .ToDictionary(
                pair => pair.Key,
                pair => pair.Value.Take(5).ToArray(),
                StringComparer.Ordinal);

        var events = batch.Events ?? Array.Empty<EventEnvelope>();
        var sampleEvents = events
            .Take(MaxSampleEvents)
            .Select(@event => new
            {
                event_id = @event.EventId == Guid.Empty ? (Guid?)null : @event.EventId,
                agent_id = BlankToNull(@event.AgentId),
                hostname = BlankToNull(@event.Hostname),
                channel = BlankToNull(@event.Channel),
                provider = BlankToNull(@event.Provider),
                windows_event_id = @event.WindowsEventId,
                record_id = @event.RecordId,
                raw_omitted = true
            })
            .ToArray();

        return new
        {
            batch = new
            {
                agent_id = BlankToNull(batch.AgentId),
                batch_id = batch.BatchId == Guid.Empty ? (Guid?)null : batch.BatchId,
                sent_at = batch.SentAt == default ? (DateTimeOffset?)null : batch.SentAt,
                event_count = events.Count
            },
            validation = new
            {
                field_count = validationErrors.Count,
                fields
            },
            sample_events = sampleEvents,
            note = "Authorization headers, bearer tokens, event messages, and raw event payloads are not stored in this context."
        };
    }

    private static Guid? FirstEventId(
        IngestBatchRequest batch,
        IReadOnlyDictionary<string, string[]> validationErrors)
    {
        foreach (var key in validationErrors.Keys)
        {
            if (!key.StartsWith("events[", StringComparison.Ordinal))
            {
                continue;
            }

            var closeBracket = key.IndexOf(']', StringComparison.Ordinal);
            if (closeBracket <= "events[".Length)
            {
                continue;
            }

            var indexValue = key["events[".Length..closeBracket];
            var events = batch.Events ?? Array.Empty<EventEnvelope>();
            if (!int.TryParse(indexValue, out var index) || index < 0 || index >= events.Count)
            {
                continue;
            }

            var eventId = events[index].EventId;
            return eventId == Guid.Empty ? null : eventId;
        }

        return null;
    }

    private static string? BlankToNull(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
