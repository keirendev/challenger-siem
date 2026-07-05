using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed class SourceHealthRepository(NpgsqlDataSource dataSource)
{
    public async Task<SourceHealthResponse> SearchAsync(string? agentId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var summaries = await LoadSummariesAsync(connection, agentId, cancellationToken);
        var sources = await LoadSourcesAsync(connection, agentId, cancellationToken);
        return new SourceHealthResponse
        {
            Summaries = summaries,
            Sources = sources
        };
    }

    private static async Task<IReadOnlyList<CoverageSummary>> LoadSummariesAsync(
        NpgsqlConnection connection,
        string? agentId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            with latest_heartbeat as (
                select distinct on (agent_id)
                    agent_id,
                    heartbeat_time,
                    queue_depth
                from agent_heartbeats
                order by agent_id, heartbeat_time desc
            ), health as (
                select
                    agent_id,
                    count(*) filter (where required_source and status in ('missing', 'disabled'))::int as missing_mandatory_sources,
                    count(*) filter (where status = 'stale')::int as stale_sources,
                    count(*) filter (where status = 'error')::int as error_sources,
                    bool_or(status in ('missing', 'disabled', 'error')) as unhealthy,
                    count(*) filter (where status = 'healthy')::int as healthy_sources
                from source_health
                group by agent_id
            )
            select
                a.agent_id,
                a.hostname,
                coalesce(h.missing_mandatory_sources, 0) as missing_mandatory_sources,
                coalesce(h.stale_sources, 0) as stale_sources,
                coalesce(h.error_sources, 0) as error_sources,
                coalesce(lh.queue_depth, 0) as queue_depth,
                lh.heartbeat_time as last_heartbeat_time,
                case
                    when a.last_seen is null then 'L0'
                    when coalesce(h.missing_mandatory_sources, 0) = 0 and coalesce(h.error_sources, 0) = 0 and coalesce(h.healthy_sources, 0) >= 12 then 'L2'
                    when coalesce(h.healthy_sources, 0) >= 1 then 'L1'
                    else 'L0'
                end as current_level,
                case
                    when coalesce(h.missing_mandatory_sources, 0) > 0 or coalesce(h.error_sources, 0) > 0 then 'error'
                    when coalesce(h.stale_sources, 0) > 0 then 'stale'
                    when coalesce(h.healthy_sources, 0) = 0 then 'missing'
                    else 'healthy'
                end as overall_status
            from agents a
            left join health h on h.agent_id = a.agent_id
            left join latest_heartbeat lh on lh.agent_id = a.agent_id
            """;
        if (!string.IsNullOrWhiteSpace(agentId))
        {
            command.CommandText += " where a.agent_id = @agent_id";
            command.Parameters.AddWithValue("agent_id", agentId);
        }

        command.CommandText += " order by a.hostname asc, a.agent_id asc limit 500;";

        var results = new List<CoverageSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new CoverageSummary
            {
                AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
                Hostname = reader.GetString(reader.GetOrdinal("hostname")),
                TargetLevel = WindowsCoverageLevel.L2,
                CurrentLevel = Enum.Parse<WindowsCoverageLevel>(reader.GetString(reader.GetOrdinal("current_level"))),
                OverallStatus = reader.GetString(reader.GetOrdinal("overall_status")),
                MissingMandatorySources = reader.GetInt32(reader.GetOrdinal("missing_mandatory_sources")),
                StaleSources = reader.GetInt32(reader.GetOrdinal("stale_sources")),
                ErrorSources = reader.GetInt32(reader.GetOrdinal("error_sources")),
                QueueDepth = reader.GetInt32(reader.GetOrdinal("queue_depth")),
                LastHeartbeatTime = ReadNullableDateTimeOffset(reader, "last_heartbeat_time")
            });
        }

        return results;
    }

    private static async Task<IReadOnlyList<SourceHealthReport>> LoadSourcesAsync(
        NpgsqlConnection connection,
        string? agentId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select
                source_id,
                display_name,
                channel,
                coverage_level,
                status,
                required_source,
                enabled,
                last_event_time,
                last_record_id,
                oldest_record_id,
                newest_record_id,
                log_size_bytes,
                retention_days,
                lag_seconds,
                error_code,
                error_message,
                gap_detected,
                cleared_detected,
                bookmark_gap_detected,
                config_hash,
                source_version,
                details
            from source_health
            """;
        if (!string.IsNullOrWhiteSpace(agentId))
        {
            command.CommandText += " where agent_id = @agent_id";
            command.Parameters.AddWithValue("agent_id", agentId);
        }

        command.CommandText += " order by coverage_level asc, display_name asc limit 1000;";

        var results = new List<SourceHealthReport>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new SourceHealthReport
            {
                SourceId = reader.GetString(reader.GetOrdinal("source_id")),
                DisplayName = reader.GetString(reader.GetOrdinal("display_name")),
                Channel = reader.GetString(reader.GetOrdinal("channel")),
                CoverageLevel = Enum.Parse<WindowsCoverageLevel>(reader.GetString(reader.GetOrdinal("coverage_level"))),
                Status = reader.GetString(reader.GetOrdinal("status")),
                Required = reader.GetBoolean(reader.GetOrdinal("required_source")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                LastEventTime = ReadNullableDateTimeOffset(reader, "last_event_time"),
                LastRecordId = ReadNullableInt64(reader, "last_record_id"),
                OldestRecordId = ReadNullableInt64(reader, "oldest_record_id"),
                NewestRecordId = ReadNullableInt64(reader, "newest_record_id"),
                LogSizeBytes = ReadNullableInt64(reader, "log_size_bytes"),
                RetentionDays = ReadNullableInt32(reader, "retention_days"),
                LagSeconds = ReadNullableInt64(reader, "lag_seconds"),
                ErrorCode = ReadNullableString(reader, "error_code"),
                ErrorMessage = ReadNullableString(reader, "error_message"),
                GapDetected = reader.GetBoolean(reader.GetOrdinal("gap_detected")),
                ClearedDetected = reader.GetBoolean(reader.GetOrdinal("cleared_detected")),
                BookmarkGapDetected = reader.GetBoolean(reader.GetOrdinal("bookmark_gap_detected")),
                ConfigHash = ReadNullableString(reader, "config_hash"),
                SourceVersion = ReadNullableString(reader, "source_version"),
                Details = ReadStringDictionary(reader, "details")
            });
        }

        return results;
    }

    private static IReadOnlyDictionary<string, string> ReadStringDictionary(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        if (reader.IsDBNull(ordinal))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        return JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(ordinal), new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    private static string? ReadNullableString(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static int? ReadNullableInt32(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static long? ReadNullableInt64(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    }

    private static DateTimeOffset? ReadNullableDateTimeOffset(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }

        var value = reader.GetValue(ordinal);
        return value switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => null
        };
    }
}
