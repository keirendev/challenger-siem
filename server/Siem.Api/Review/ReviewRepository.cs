using System.Globalization;
using System.Text;
using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Review;

public sealed class ReviewRepository(NpgsqlDataSource dataSource)
{
    public async Task<DashboardSummary> GetDashboardSummaryAsync(
        TimeSpan staleAgentAfter,
        TimeSpan recentEventWindow,
        CancellationToken cancellationToken)
    {
        var staleCutoff = DateTimeOffset.UtcNow.Subtract(staleAgentAfter);
        var recentEventCutoff = DateTimeOffset.UtcNow.Subtract(recentEventWindow);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            with latest_heartbeat as (
                select distinct on (agent_id)
                    agent_id,
                    heartbeat_time,
                    queue_depth
                from agent_heartbeats
                order by agent_id, heartbeat_time desc
            )
            select
                count(*)::bigint as total_agents,
                count(*) filter (where a.last_seen >= @stale_cutoff)::bigint as recent_agents,
                count(*) filter (where a.last_seen < @stale_cutoff)::bigint as stale_agents,
                count(*) filter (where coalesce(lh.queue_depth, 0) > 0)::bigint as agents_with_queued_events,
                (select count(*)::bigint from events where ingest_time >= @recent_event_cutoff) as recent_event_count,
                (select max(ingest_time) from events) as latest_ingest_time
            from agents a
            left join latest_heartbeat lh on lh.agent_id = a.agent_id;
            """;
        command.Parameters.AddWithValue("stale_cutoff", staleCutoff.ToUniversalTime());
        command.Parameters.AddWithValue("recent_event_cutoff", recentEventCutoff.ToUniversalTime());

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return DashboardSummary.Empty;
        }

        return new DashboardSummary(
            ReadInt64(reader, "total_agents"),
            ReadInt64(reader, "recent_agents"),
            ReadInt64(reader, "stale_agents"),
            ReadInt64(reader, "agents_with_queued_events"),
            ReadInt64(reader, "recent_event_count"),
            ReadNullableDateTimeOffset(reader, "latest_ingest_time"));
    }

    public async Task<IReadOnlyList<AgentInventoryItem>> SearchAgentsAsync(
        AgentInventoryQuery query,
        TimeSpan staleAgentAfter,
        CancellationToken cancellationToken)
    {
        var staleCutoff = DateTimeOffset.UtcNow.Subtract(staleAgentAfter);
        var where = new List<string>();

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("stale_cutoff", staleCutoff.ToUniversalTime());

        if (!string.IsNullOrWhiteSpace(query.Hostname))
        {
            where.Add("a.hostname ilike @hostname");
            command.Parameters.AddWithValue("hostname", $"%{query.Hostname.Trim()}%");
        }

        if (!string.IsNullOrWhiteSpace(query.AgentId))
        {
            where.Add("a.agent_id ilike @agent_id");
            command.Parameters.AddWithValue("agent_id", $"%{query.AgentId.Trim()}%");
        }

        switch (query.Health?.Trim().ToLowerInvariant())
        {
            case "recent":
                where.Add("a.last_seen >= @stale_cutoff");
                break;
            case "stale":
                where.Add("a.last_seen < @stale_cutoff");
                break;
            case "queued":
                where.Add("coalesce(lh.queue_depth, 0) > 0");
                break;
        }

        var sql = new StringBuilder("""
            select
                a.agent_id,
                a.hostname,
                a.machine_guid,
                a.os_version,
                a.agent_version,
                a.first_seen,
                a.last_seen,
                a.status,
                lh.heartbeat_time as latest_heartbeat_time,
                lh.queue_depth as latest_queue_depth,
                lh.last_event_time,
                (a.last_seen < @stale_cutoff) as is_stale,
                coalesce(sh.missing_mandatory_sources, 0) as missing_mandatory_sources,
                coalesce(sh.stale_sources, 0) as stale_sources,
                coalesce(sh.error_sources, 0) as error_sources,
                case
                    when coalesce(sh.missing_mandatory_sources, 0) = 0 and coalesce(sh.error_sources, 0) = 0 and coalesce(sh.healthy_sources, 0) >= 12 then 'L2'
                    when coalesce(sh.healthy_sources, 0) >= 1 then 'L1'
                    else 'L0'
                end as current_coverage_level,
                case
                    when coalesce(sh.missing_mandatory_sources, 0) > 0 or coalesce(sh.error_sources, 0) > 0 then 'error'
                    when coalesce(sh.stale_sources, 0) > 0 then 'stale'
                    when coalesce(sh.healthy_sources, 0) = 0 then 'missing'
                    else 'healthy'
                end as coverage_status
            from agents a
            left join lateral (
                select heartbeat_time, queue_depth, last_event_time
                from agent_heartbeats
                where agent_id = a.agent_id
                order by heartbeat_time desc
                limit 1
            ) lh on true
            left join lateral (
                select
                    count(*) filter (where required_source and status in ('missing', 'disabled'))::int as missing_mandatory_sources,
                    count(*) filter (where status = 'stale')::int as stale_sources,
                    count(*) filter (where status = 'error')::int as error_sources,
                    count(*) filter (where status = 'healthy')::int as healthy_sources
                from source_health
                where agent_id = a.agent_id
            ) sh on true
            """);

        if (where.Count > 0)
        {
            sql.Append(" where ");
            sql.Append(string.Join(" and ", where));
        }

        sql.Append(" order by a.last_seen desc, a.agent_id asc limit 500;");
        command.CommandText = sql.ToString();

        var results = new List<AgentInventoryItem>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AgentInventoryItem(
                reader.GetString(reader.GetOrdinal("agent_id")),
                reader.GetString(reader.GetOrdinal("hostname")),
                ReadNullableString(reader, "machine_guid"),
                reader.GetString(reader.GetOrdinal("os_version")),
                reader.GetString(reader.GetOrdinal("agent_version")),
                ReadDateTimeOffset(reader, "first_seen"),
                ReadDateTimeOffset(reader, "last_seen"),
                reader.GetString(reader.GetOrdinal("status")),
                ReadNullableDateTimeOffset(reader, "latest_heartbeat_time"),
                ReadNullableInt32(reader, "latest_queue_depth"),
                ReadNullableDateTimeOffset(reader, "last_event_time"),
                reader.GetBoolean(reader.GetOrdinal("is_stale")),
                Enum.Parse<WindowsCoverageLevel>(reader.GetString(reader.GetOrdinal("current_coverage_level"))),
                reader.GetString(reader.GetOrdinal("coverage_status")),
                reader.GetInt32(reader.GetOrdinal("missing_mandatory_sources")),
                reader.GetInt32(reader.GetOrdinal("stale_sources")),
                reader.GetInt32(reader.GetOrdinal("error_sources"))));
        }

        return results;
    }

    public async Task<DatabaseStatus> CheckDatabaseAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "select 1;";
            await command.ExecuteScalarAsync(cancellationToken);
            return DatabaseStatus.Connected;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new DatabaseStatus(false, ex.GetType().Name);
        }
    }

    private static long ReadInt64(NpgsqlDataReader reader, string columnName)
    {
        return Convert.ToInt64(reader.GetValue(reader.GetOrdinal(columnName)), CultureInfo.InvariantCulture);
    }

    private static int? ReadNullableInt32(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static string? ReadNullableString(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static DateTimeOffset ReadDateTimeOffset(NpgsqlDataReader reader, string columnName)
    {
        return ToDateTimeOffset(reader.GetValue(reader.GetOrdinal(columnName)));
    }

    private static DateTimeOffset? ReadNullableDateTimeOffset(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : ToDateTimeOffset(reader.GetValue(ordinal));
    }

    private static DateTimeOffset ToDateTimeOffset(object value)
    {
        return value switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => throw new InvalidOperationException("Column did not contain a timestamp value.")
        };
    }
}
