using System.Text;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record StoreEventsResult(int Accepted, int Duplicates);

public sealed class EventRepository(NpgsqlDataSource dataSource)
{
    public async Task<StoreEventsResult> StoreEventsAsync(IngestBatchRequest batch, CancellationToken cancellationToken)
    {
        var accepted = 0;
        var duplicates = 0;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        foreach (var envelope in batch.Events)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                insert into events (
                    event_id,
                    agent_id,
                    hostname,
                    source,
                    channel,
                    provider,
                    windows_event_id,
                    record_id,
                    event_time,
                    severity,
                    message,
                    raw_json
                )
                values (
                    @event_id,
                    @agent_id,
                    @hostname,
                    @source,
                    @channel,
                    @provider,
                    @windows_event_id,
                    @record_id,
                    @event_time,
                    @severity,
                    @message,
                    @raw_json
                )
                on conflict (agent_id, event_id) do nothing
                returning id;
                """;
            command.Parameters.AddWithValue("event_id", envelope.EventId);
            command.Parameters.AddWithValue("agent_id", envelope.AgentId);
            command.Parameters.AddWithValue("hostname", envelope.Hostname);
            command.Parameters.AddWithValue("source", envelope.Source);
            command.Parameters.AddWithValue("channel", envelope.Channel);
            command.Parameters.AddWithValue("provider", envelope.Provider);
            command.Parameters.AddWithValue("windows_event_id", envelope.WindowsEventId);
            command.Parameters.AddWithValue("record_id", envelope.RecordId);
            command.Parameters.AddWithValue("event_time", envelope.EventTime.ToUniversalTime());
            command.Parameters.AddWithValue("severity", envelope.Severity);
            command.Parameters.AddWithValue("message", envelope.Message);

            var rawJson = envelope.Raw.ValueKind == JsonValueKind.Undefined ? "{}" : envelope.Raw.GetRawText();
            var rawParameter = command.Parameters.Add("raw_json", NpgsqlDbType.Jsonb);
            rawParameter.Value = rawJson;

            var result = await command.ExecuteScalarAsync(cancellationToken);
            if (result is null || result == DBNull.Value)
            {
                duplicates++;
            }
            else
            {
                accepted++;
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new StoreEventsResult(accepted, duplicates);
    }

    public async Task<IReadOnlyList<EventEnvelope>> SearchEventsAsync(EventSearchQuery query, CancellationToken cancellationToken)
    {
        var where = new List<string>();
        var limit = Math.Clamp(query.Limit, 1, 500);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        if (!string.IsNullOrWhiteSpace(query.Hostname))
        {
            where.Add("hostname = @hostname");
            command.Parameters.AddWithValue("hostname", query.Hostname);
        }

        if (!string.IsNullOrWhiteSpace(query.AgentId))
        {
            where.Add("agent_id = @agent_id");
            command.Parameters.AddWithValue("agent_id", query.AgentId);
        }

        if (!string.IsNullOrWhiteSpace(query.Channel))
        {
            where.Add("channel = @channel");
            command.Parameters.AddWithValue("channel", query.Channel);
        }

        if (query.WindowsEventId.HasValue)
        {
            where.Add("windows_event_id = @windows_event_id");
            command.Parameters.AddWithValue("windows_event_id", query.WindowsEventId.Value);
        }

        if (query.From.HasValue)
        {
            where.Add("event_time >= @from");
            command.Parameters.AddWithValue("from", query.From.Value.ToUniversalTime());
        }

        if (query.To.HasValue)
        {
            where.Add("event_time <= @to");
            command.Parameters.AddWithValue("to", query.To.Value.ToUniversalTime());
        }

        if (!string.IsNullOrWhiteSpace(query.Keyword))
        {
            where.Add("(message ilike @keyword or raw_json::text ilike @keyword)");
            command.Parameters.AddWithValue("keyword", $"%{query.Keyword.Trim()}%");
        }

        command.Parameters.AddWithValue("limit", limit);

        var sql = new StringBuilder("""
            select
                event_id,
                agent_id,
                hostname,
                source,
                channel,
                provider,
                windows_event_id,
                record_id,
                event_time,
                ingest_time,
                severity,
                message,
                raw_json
            from events
            """);

        if (where.Count > 0)
        {
            sql.Append(" where ");
            sql.Append(string.Join(" and ", where));
        }

        sql.Append(" order by event_time desc, id desc limit @limit;");
        command.CommandText = sql.ToString();

        var results = new List<EventEnvelope>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var rawJson = reader.GetString(reader.GetOrdinal("raw_json"));
            using var rawDocument = JsonDocument.Parse(rawJson);

            results.Add(new EventEnvelope
            {
                EventId = reader.GetGuid(reader.GetOrdinal("event_id")),
                AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
                Hostname = reader.GetString(reader.GetOrdinal("hostname")),
                Source = reader.GetString(reader.GetOrdinal("source")),
                Channel = reader.GetString(reader.GetOrdinal("channel")),
                Provider = reader.GetString(reader.GetOrdinal("provider")),
                WindowsEventId = reader.GetInt32(reader.GetOrdinal("windows_event_id")),
                RecordId = reader.GetInt64(reader.GetOrdinal("record_id")),
                EventTime = ReadDateTimeOffset(reader, "event_time"),
                IngestTime = ReadDateTimeOffset(reader, "ingest_time"),
                Severity = reader.GetString(reader.GetOrdinal("severity")),
                Message = reader.GetString(reader.GetOrdinal("message")),
                Raw = rawDocument.RootElement.Clone()
            });
        }

        return results;
    }

    private static DateTimeOffset ReadDateTimeOffset(NpgsqlDataReader reader, string columnName)
    {
        var value = reader.GetValue(reader.GetOrdinal(columnName));
        return value switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => throw new InvalidOperationException($"Column '{columnName}' did not contain a timestamp value.")
        };
    }
}
