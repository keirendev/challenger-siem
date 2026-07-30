using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed record DashboardAggregationResponse(
    int TimeRangeHours,
    DateTimeOffset FromUtc,
    DateTimeOffset ToUtc,
    DateTimeOffset MeasuredAtUtc,
    DateTimeOffset? LatestIngestUtc,
    bool PartialData,
    string FreshnessState,
    IReadOnlyList<DashboardBucket> EventBuckets,
    IReadOnlyList<DashboardCount> EventSources,
    IReadOnlyList<DashboardCount> Severities,
    IReadOnlyList<DashboardCount> AlertStatuses,
    IReadOnlyList<DashboardCount> SourceHealthStates);

public sealed record DashboardBucket(DateTimeOffset BucketUtc, long EventCount);
public sealed record DashboardCount(string Key, long Count);

public sealed class DashboardRepository(NpgsqlDataSource dataSource)
{
    public async Task<DashboardAggregationResponse> GetAggregationsAsync(int requestedHours, CancellationToken cancellationToken)
    {
        var hours = Math.Clamp(requestedHours, 1, 168);
        var now = DateTimeOffset.UtcNow;
        var from = now.AddHours(-hours);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var buckets = await LoadBucketsAsync(connection, from, now, cancellationToken);
        var sources = await LoadCountsAsync(connection, "select coalesce(source_id, source, 'unknown') as key, count(*)::bigint from events where event_time between @from and @to group by key order by count(*) desc, key asc limit 12;", from, now, cancellationToken);
        var severities = await LoadCountsAsync(connection, "select severity as key, count(*)::bigint from events where event_time between @from and @to group by key order by count(*) desc, key asc limit 12;", from, now, cancellationToken);
        var alertStatuses = await LoadCountsAsync(connection, "select status as key, count(*)::bigint from alerts where created_at between @from and @to group by key order by count(*) desc, key asc limit 12;", from, now, cancellationToken);
        var sourceHealth = await LoadSourceHealthCountsAsync(connection, cancellationToken);
        var latest = await LoadLatestIngestAsync(connection, cancellationToken);
        var freshness = latest is null ? "unknown" : now - latest > TimeSpan.FromMinutes(15) ? "stale" : "fresh";
        var partial = freshness != "fresh" || sourceHealth.Any(item => item.Key is "stale" or "degraded" or "missing" or "permission_denied" or "error");
        return new(hours, from, now, now, latest, partial, freshness, buckets, sources, severities, alertStatuses, sourceHealth);
    }

    private static async Task<IReadOnlyList<DashboardBucket>> LoadBucketsAsync(NpgsqlConnection connection, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select date_trunc('hour', event_time), count(*)::bigint from events where event_time between @from and @to group by 1 order by 1 asc limit 168;";
        command.Parameters.AddWithValue("from", from);
        command.Parameters.AddWithValue("to", to);
        var rows = new List<DashboardBucket>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) rows.Add(new(ReadTime(reader, 0), reader.GetInt64(1)));
        return rows;
    }

    private static async Task<IReadOnlyList<DashboardCount>> LoadCountsAsync(NpgsqlConnection connection, string sql, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("from", from);
        command.Parameters.AddWithValue("to", to);
        var rows = new List<DashboardCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) rows.Add(new(reader.GetString(0), reader.GetInt64(1)));
        return rows;
    }

    private static async Task<IReadOnlyList<DashboardCount>> LoadSourceHealthCountsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select status, count(*)::bigint from source_health group by status order by count(*) desc, status asc limit 16;";
        var rows = new List<DashboardCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) rows.Add(new(reader.GetString(0), reader.GetInt64(1)));
        return rows;
    }

    private static async Task<DateTimeOffset?> LoadLatestIngestAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select max(ingest_time) from events;";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : value is DateTimeOffset offset ? offset.ToUniversalTime() : new DateTimeOffset((DateTime)value, TimeSpan.Zero);
    }

    private static DateTimeOffset ReadTime(NpgsqlDataReader reader, int ordinal) =>
        reader.GetFieldValue<DateTimeOffset>(ordinal).ToUniversalTime();
}
