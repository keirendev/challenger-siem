using System.Text;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record StoreEventsResult(
    int Accepted,
    int Duplicates,
    IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds);

public sealed record ManagedStorageAccounting(long TableBytes, long IndexBytes, long TotalBytes, long EventRows, DateTimeOffset MeasuredAt);

public sealed class EventRepository(NpgsqlDataSource dataSource)
{
    public async Task<StoreEventsResult> StoreEventsAsync(IngestBatchRequest batch, CancellationToken cancellationToken)
    {
        var accepted = 0;
        var duplicates = 0;
        var acceptedEventIds = new List<Guid>();
        var duplicateEventIds = new List<Guid>();

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
                    platform, source_id, event_code, facility, unit, checkpoint_json, deduplication_json, data_handling_json,
                    channel,
                    provider,
                    windows_event_id,
                    record_id,
                    event_time,
                    host_timezone,
                    severity,
                    message,
                    raw_json,
                    event_category,
                    event_action,
                    normalized_json,
                    user_name,
                    target_user_name,
                    process_image,
                    process_command_line,
                    source_ip,
                    destination_ip,
                    service_name,
                    file_path,
                    registry_key
                )
                values (
                    @event_id,
                    @agent_id,
                    @hostname,
                    @source,
                    @platform, @source_id, @event_code, @facility, @unit, @checkpoint_json, @deduplication_json, @data_handling_json,
                    @channel,
                    @provider,
                    @windows_event_id,
                    @record_id,
                    @event_time,
                    @host_timezone,
                    @severity,
                    @message,
                    @raw_json,
                    @event_category,
                    @event_action,
                    @normalized_json,
                    @user_name,
                    @target_user_name,
                    @process_image,
                    @process_command_line,
                    @source_ip,
                    @destination_ip,
                    @service_name,
                    @file_path,
                    @registry_key
                )
                on conflict (agent_id, event_id) do nothing
                returning id;
                """;
            command.Parameters.AddWithValue("event_id", envelope.EventId);
            command.Parameters.AddWithValue("agent_id", envelope.AgentId);
            command.Parameters.AddWithValue("hostname", envelope.Hostname);
            command.Parameters.AddWithValue("source", envelope.Source);
            command.Parameters.AddWithValue("platform", DbValue(envelope.Platform));
            command.Parameters.AddWithValue("source_id", DbValue(envelope.SourceId));
            command.Parameters.AddWithValue("event_code", DbValue(envelope.EventCode));
            command.Parameters.AddWithValue("facility", DbValue(envelope.Facility));
            command.Parameters.AddWithValue("unit", DbValue(envelope.Unit));
            Jsonb.Add(command, "checkpoint_json", envelope.Checkpoint);
            Jsonb.Add(command, "deduplication_json", envelope.Deduplication);
            Jsonb.Add(command, "data_handling_json", envelope.DataHandling);
            command.Parameters.AddWithValue("channel", DbValue(envelope.Channel));
            command.Parameters.AddWithValue("provider", DbValue(envelope.Provider));
            command.Parameters.AddWithValue("windows_event_id", envelope.WindowsEventId.HasValue ? envelope.WindowsEventId.Value : DBNull.Value);
            command.Parameters.AddWithValue("record_id", envelope.RecordId.HasValue ? envelope.RecordId.Value : DBNull.Value);
            command.Parameters.AddWithValue("event_time", envelope.EventTime.ToUniversalTime());
            Jsonb.Add(command, "host_timezone", envelope.HostTimezone);
            command.Parameters.AddWithValue("severity", envelope.Severity);
            command.Parameters.AddWithValue("message", envelope.Message);

            var rawJson = envelope.Raw.ValueKind == JsonValueKind.Undefined ? "{}" : envelope.Raw.GetRawText();
            var rawParameter = command.Parameters.Add("raw_json", NpgsqlDbType.Jsonb);
            rawParameter.Value = rawJson;
            command.Parameters.AddWithValue("event_category", DbValue(envelope.Normalized?.Category));
            command.Parameters.AddWithValue("event_action", DbValue(envelope.Normalized?.Action));
            var normalizedParameter = command.Parameters.Add("normalized_json", NpgsqlDbType.Jsonb);
            normalizedParameter.Value = envelope.Normalized is null ? DBNull.Value : JsonSerializer.Serialize(envelope.Normalized, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            command.Parameters.AddWithValue("user_name", DbValue(envelope.Normalized?.UserName));
            command.Parameters.AddWithValue("target_user_name", DbValue(envelope.Normalized?.TargetUserName));
            command.Parameters.AddWithValue("process_image", DbValue(envelope.Normalized?.ProcessImage));
            command.Parameters.AddWithValue("process_command_line", DbValue(Truncate(envelope.Normalized?.ProcessCommandLine, 4096)));
            command.Parameters.AddWithValue("source_ip", DbValue(envelope.Normalized?.SourceIp));
            command.Parameters.AddWithValue("destination_ip", DbValue(envelope.Normalized?.DestinationIp));
            command.Parameters.AddWithValue("service_name", DbValue(envelope.Normalized?.ServiceName));
            command.Parameters.AddWithValue("file_path", DbValue(envelope.Normalized?.FilePath));
            command.Parameters.AddWithValue("registry_key", DbValue(envelope.Normalized?.RegistryKey));

            var result = await command.ExecuteScalarAsync(cancellationToken);
            if (result is null || result == DBNull.Value)
            {
                duplicates++;
                duplicateEventIds.Add(envelope.EventId);
            }
            else
            {
                accepted++;
                acceptedEventIds.Add(envelope.EventId);
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new StoreEventsResult(accepted, duplicates, acceptedEventIds, duplicateEventIds);
    }

    public async Task<IReadOnlyList<EventEnvelope>> SearchEventsAsync(EventSearchQuery query, CancellationToken cancellationToken, int offset = 0)
    {
        var where = new List<string>();
        var limit = Math.Clamp(query.Limit, 1, 500);
        var clampedOffset = Math.Max(0, offset);

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

        AddTextFilter(where, command, "source", "source", query.Source, exact: true);
        AddTextFilter(where, command, "platform", "platform", query.Platform, exact: true);
        AddTextFilter(where, command, "source_id", "source_id", query.SourceId, exact: true);
        AddTextFilter(where, command, "event_code", "event_code", query.EventCode, exact: true);

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
            where.Add("(message ilike @keyword or raw_json::text ilike @keyword or normalized_json::text ilike @keyword)");
            command.Parameters.AddWithValue("keyword", $"%{query.Keyword.Trim()}%");
        }

        AddTextFilter(where, command, "event_category", "category", query.Category, exact: true);
        AddTextFilter(where, command, "event_action", "action", query.Action, exact: true);
        AddTextFilter(where, command, "user_name", "user_name", query.UserName, exact: false);
        AddTextFilter(where, command, "process_image", "process_image", query.ProcessImage, exact: false);
        AddTextFilter(where, command, "source_ip", "source_ip", query.SourceIp, exact: true);
        AddTextFilter(where, command, "destination_ip", "destination_ip", query.DestinationIp, exact: true);
        AddTextFilter(where, command, "service_name", "service_name", query.ServiceName, exact: false);
        AddTextFilter(where, command, "file_path", "file_path", query.FilePath, exact: false);
        AddTextFilter(where, command, "registry_key", "registry_key", query.RegistryKey, exact: false);

        command.Parameters.AddWithValue("limit", limit);
        command.Parameters.AddWithValue("offset", clampedOffset);

        var sql = new StringBuilder("""
            select
                event_id,
                agent_id,
                hostname,
                source,
                platform, source_id, event_code, facility, unit, checkpoint_json, deduplication_json, data_handling_json,
                channel,
                provider,
                windows_event_id,
                record_id,
                event_time,
                host_timezone,
                ingest_time,
                severity,
                message,
                raw_json,
                normalized_json
            from events
            """);

        if (where.Count > 0)
        {
            sql.Append(" where ");
            sql.Append(string.Join(" and ", where));
        }

        sql.Append(" order by event_time desc, id desc limit @limit offset @offset;");
        command.CommandText = sql.ToString();

        var results = new List<EventEnvelope>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ReadEventEnvelope(reader));
        }

        return results;
    }

    public async Task<EventEnvelope?> GetEventAsync(string agentId, Guid eventId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select
                event_id,
                agent_id,
                hostname,
                source,
                platform, source_id, event_code, facility, unit, checkpoint_json, deduplication_json, data_handling_json,
                channel,
                provider,
                windows_event_id,
                record_id,
                event_time,
                host_timezone,
                ingest_time,
                severity,
                message,
                raw_json,
                normalized_json
            from events
            where agent_id = @agent_id
              and event_id = @event_id
            limit 1;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("event_id", eventId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadEventEnvelope(reader) : null;
    }

    private static EventEnvelope ReadEventEnvelope(NpgsqlDataReader reader)
    {
        var rawJson = reader.GetString(reader.GetOrdinal("raw_json"));
        using var rawDocument = JsonDocument.Parse(rawJson);
        var normalized = ReadNormalized(reader);

        return new EventEnvelope
        {
            EventId = reader.GetGuid(reader.GetOrdinal("event_id")),
            AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
            Hostname = reader.GetString(reader.GetOrdinal("hostname")),
            Source = reader.GetString(reader.GetOrdinal("source")),
            Platform = ReadNullableString(reader, "platform"),
            SourceId = ReadNullableString(reader, "source_id"),
            EventCode = ReadNullableString(reader, "event_code"),
            Facility = ReadNullableString(reader, "facility"),
            Unit = ReadNullableString(reader, "unit"),
            Checkpoint = Jsonb.Read<SourceCheckpoint>(reader, "checkpoint_json"),
            Deduplication = Jsonb.Read<EventDeduplicationMetadata>(reader, "deduplication_json"),
            DataHandling = Jsonb.Read<DataHandlingMetadata>(reader, "data_handling_json"),
            Channel = ReadNullableString(reader, "channel"),
            Provider = ReadNullableString(reader, "provider"),
            WindowsEventId = ReadNullableInt32(reader, "windows_event_id"),
            RecordId = ReadNullableInt64(reader, "record_id"),
            EventTime = ReadDateTimeOffset(reader, "event_time"),
            HostTimezone = Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone"),
            IngestTime = ReadDateTimeOffset(reader, "ingest_time"),
            Severity = reader.GetString(reader.GetOrdinal("severity")),
            Message = reader.GetString(reader.GetOrdinal("message")),
            Normalized = normalized,
            Raw = rawDocument.RootElement.Clone()
        };
    }

    public async Task<ManagedStorageAccounting> GetManagedStorageAccountingAsync(CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select pg_relation_size('public.events'), pg_indexes_size('public.events'),
                   pg_total_relation_size('public.events'), count(*) from events;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), DateTimeOffset.UtcNow);
    }

    private static string? ReadNullableString(NpgsqlDataReader reader, string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetString(reader.GetOrdinal(name));
    private static int? ReadNullableInt32(NpgsqlDataReader reader, string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetInt32(reader.GetOrdinal(name));
    private static long? ReadNullableInt64(NpgsqlDataReader reader, string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetInt64(reader.GetOrdinal(name));

    private static void AddTextFilter(List<string> where, NpgsqlCommand command, string column, string parameterName, string? value, bool exact)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (exact)
        {
            where.Add($"{column} = @{parameterName}");
            command.Parameters.AddWithValue(parameterName, value.Trim());
        }
        else
        {
            where.Add($"{column} ilike @{parameterName}");
            command.Parameters.AddWithValue(parameterName, $"%{value.Trim()}%");
        }
    }

    private static object DbValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? DBNull.Value : value;
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private static NormalizedEventFields? ReadNormalized(NpgsqlDataReader reader)
    {
        var ordinal = reader.GetOrdinal("normalized_json");
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }

        return JsonSerializer.Deserialize<NormalizedEventFields>(reader.GetString(ordinal), new JsonSerializerOptions(JsonSerializerDefaults.Web));
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
