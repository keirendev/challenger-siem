using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Npgsql;
using NpgsqlTypes;

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

public sealed record DashboardLayoutRecord(
    Guid LayoutId,
    Guid OwnerOperatorId,
    string OwnerUsername,
    string Name,
    string Visibility,
    int TimeRangeHours,
    int RefreshMinutes,
    JsonElement Layout,
    int Version,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record DashboardLayoutRequest(
    string Name,
    string Visibility,
    int TimeRangeHours,
    int RefreshMinutes,
    JsonElement? Layout,
    int? ExpectedVersion);

public sealed class DashboardRepository(NpgsqlDataSource dataSource)
{
    private const int MaxBuckets = 168;
    private const int MaxLayoutJsonChars = 8000;

    public async Task<DashboardAggregationResponse> GetAggregationsAsync(int requestedHours, CancellationToken cancellationToken)
    {
        var hours = Math.Clamp(requestedHours, 1, 168);
        var now = DateTimeOffset.UtcNow;
        var from = now.AddHours(-hours);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var buckets = await LoadBucketsAsync(connection, from, now, cancellationToken);
        var sources = await LoadCountsAsync(connection, "select coalesce(source_id, source, 'unknown') as key, count(*)::bigint from events where event_time >= @from and event_time <= @to group by key order by count(*) desc, key asc limit 12;", from, now, cancellationToken);
        var severities = await LoadCountsAsync(connection, "select coalesce(severity, 'unknown') as key, count(*)::bigint from events where event_time >= @from and event_time <= @to group by key order by count(*) desc, key asc limit 12;", from, now, cancellationToken);
        var alertStatuses = await LoadCountsAsync(connection, "select coalesce(status, 'unknown') as key, count(*)::bigint from alerts where created_at >= @from and created_at <= @to group by key order by count(*) desc, key asc limit 12;", from, now, cancellationToken);
        var sourceHealth = await LoadUnboundedStatusCountsAsync(connection, cancellationToken);
        var latest = await LoadLatestIngestAsync(connection, cancellationToken);
        var staleOrDegraded = sourceHealth.Any(item => item.Key is "stale" or "degraded" or "missing" or "permission_denied" or "error");
        var freshness = latest is null ? "unknown" : now - latest > TimeSpan.FromMinutes(15) ? "stale" : "fresh";
        var partial = staleOrDegraded || freshness != "fresh";
        return new DashboardAggregationResponse(hours, from, now, now, latest, partial, freshness, buckets, sources, severities, alertStatuses, sourceHealth);
    }

    public async Task<IReadOnlyList<DashboardLayoutRecord>> ListLayoutsAsync(Guid operatorId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select d.layout_id, d.owner_operator_id, o.username, d.name, d.visibility, d.time_range_hours, d.refresh_minutes, d.layout_json, d.version, d.created_at, d.updated_at
            from dashboard_layouts d
            join operators o on o.operator_id = d.owner_operator_id
            where d.owner_operator_id = @operator_id or d.visibility = 'shared'
            order by d.updated_at desc
            limit 100;
            """;
        command.Parameters.AddWithValue("operator_id", operatorId);
        return await ReadLayoutsAsync(command, cancellationToken);
    }

    public async Task<DashboardLayoutRecord> SaveLayoutAsync(Guid operatorId, string actor, string role, DashboardLayoutRequest request, HttpContext context, SecurityAuditRepository audit, CancellationToken cancellationToken)
    {
        ValidateLayoutRequest(request, role, creating: true);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var layoutId = Guid.NewGuid();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into dashboard_layouts(layout_id, owner_operator_id, name, visibility, time_range_hours, refresh_minutes, layout_json)
            values(@layout_id, @owner_operator_id, @name, @visibility, @time_range_hours, @refresh_minutes, @layout::jsonb)
            returning layout_id, owner_operator_id, @actor as username, name, visibility, time_range_hours, refresh_minutes, layout_json, version, created_at, updated_at;
            """;
        AddLayoutParameters(command, layoutId, operatorId, request, actor);
        var saved = (await ReadLayoutsAsync(command, cancellationToken)).Single();
        await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name,
            "dashboard_layout.create", "success", "dashboard_layout", saved.LayoutId.ToString(), context,
            new Dictionary<string, object?> { ["visibility"] = saved.Visibility, ["time_range_hours"] = saved.TimeRangeHours }, cancellationToken);
        return saved;
    }

    public async Task<DashboardLayoutRecord?> UpdateLayoutAsync(Guid operatorId, string actor, string role, Guid layoutId, DashboardLayoutRequest request, HttpContext context, SecurityAuditRepository audit, CancellationToken cancellationToken)
    {
        ValidateLayoutRequest(request, role, creating: false);
        var expected = request.ExpectedVersion ?? 0;
        if (expected < 1) throw new ArgumentException("Expected version is required for saved dashboard updates.");
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            update dashboard_layouts
            set name=@name, visibility=@visibility, time_range_hours=@time_range_hours, refresh_minutes=@refresh_minutes,
                layout_json=@layout::jsonb, version=version+1, updated_at=now()
            where layout_id=@layout_id
              and owner_operator_id=@owner_operator_id
              and version=@expected_version
            returning layout_id, owner_operator_id, @actor as username, name, visibility, time_range_hours, refresh_minutes, layout_json, version, created_at, updated_at;
            """;
        AddLayoutParameters(command, layoutId, operatorId, request, actor);
        command.Parameters.AddWithValue("expected_version", expected);
        var updated = (await ReadLayoutsAsync(command, cancellationToken)).SingleOrDefault();
        if (updated is not null)
        {
            await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name,
                "dashboard_layout.update", "success", "dashboard_layout", updated.LayoutId.ToString(), context,
                new Dictionary<string, object?> { ["version"] = updated.Version, ["visibility"] = updated.Visibility }, cancellationToken);
        }
        return updated;
    }

    private static void ValidateLayoutRequest(DashboardLayoutRequest request, string role, bool creating)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length is < 1 or > 96)
            throw new ArgumentException("Dashboard layout name is required and must be 96 characters or less.");
        if (request.Visibility is not "private" and not "shared")
            throw new ArgumentException("Dashboard visibility must be private or shared.");
        if (request.Visibility == "shared" && role != OperatorRoles.Admin && role != OperatorRoles.DetectionEngineer)
            throw new ArgumentException("Shared dashboard layouts require detection-engineer or admin role.");
        if (request.TimeRangeHours is < 1 or > 168)
            throw new ArgumentException("Dashboard time range must be between 1 and 168 hours.");
        if (request.RefreshMinutes is < 1 or > 1440)
            throw new ArgumentException("Dashboard refresh interval must be between 1 and 1440 minutes.");
        var layout = request.Layout?.GetRawText() ?? "{}";
        if (layout.Length > MaxLayoutJsonChars)
            throw new ArgumentException("Dashboard layout metadata is too large.");
        if (layout.Contains("<script", StringComparison.OrdinalIgnoreCase) || layout.Contains("api_token", StringComparison.OrdinalIgnoreCase) || layout.Contains("password", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Dashboard layout metadata must not contain scripts or secret-shaped values.");
    }

    private static void AddLayoutParameters(NpgsqlCommand command, Guid layoutId, Guid operatorId, DashboardLayoutRequest request, string actor)
    {
        command.Parameters.AddWithValue("layout_id", layoutId);
        command.Parameters.AddWithValue("owner_operator_id", operatorId);
        command.Parameters.AddWithValue("actor", actor);
        command.Parameters.AddWithValue("name", request.Name.Trim());
        command.Parameters.AddWithValue("visibility", request.Visibility);
        command.Parameters.AddWithValue("time_range_hours", Math.Clamp(request.TimeRangeHours, 1, 168));
        command.Parameters.AddWithValue("refresh_minutes", Math.Clamp(request.RefreshMinutes, 1, 1440));
        command.Parameters.Add("layout", NpgsqlDbType.Jsonb).Value = request.Layout?.GetRawText() ?? "{}";
    }

    private static async Task<IReadOnlyList<DashboardBucket>> LoadBucketsAsync(NpgsqlConnection connection, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select date_trunc('hour', event_time) as bucket, count(*)::bigint as count
            from events
            where event_time >= @from and event_time <= @to
            group by bucket
            order by bucket asc
            limit @limit;
            """;
        command.Parameters.AddWithValue("from", from);
        command.Parameters.AddWithValue("to", to);
        command.Parameters.AddWithValue("limit", MaxBuckets);
        var results = new List<DashboardBucket>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new DashboardBucket(ReadDateTimeOffset(reader, 0), reader.GetInt64(1)));
        }
        return results;
    }

    private static async Task<IReadOnlyList<DashboardCount>> LoadCountsAsync(NpgsqlConnection connection, string sql, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("from", from);
        command.Parameters.AddWithValue("to", to);
        var results = new List<DashboardCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new DashboardCount(reader.GetString(0), reader.GetInt64(1)));
        }
        return results;
    }

    private static async Task<IReadOnlyList<DashboardCount>> LoadUnboundedStatusCountsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select status as key, count(*)::bigint from source_health group by status order by count(*) desc, status asc limit 16;";
        var results = new List<DashboardCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(new DashboardCount(reader.GetString(0), reader.GetInt64(1)));
        return results;
    }

    private static async Task<DateTimeOffset?> LoadLatestIngestAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select max(ingest_time) from events;";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : ToDateTimeOffset(value);
    }

    private static async Task<IReadOnlyList<DashboardLayoutRecord>> ReadLayoutsAsync(NpgsqlCommand command, CancellationToken cancellationToken)
    {
        var results = new List<DashboardLayoutRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(reader.GetOrdinal("layout_json"));
            results.Add(new DashboardLayoutRecord(
                reader.GetGuid(reader.GetOrdinal("layout_id")),
                reader.GetGuid(reader.GetOrdinal("owner_operator_id")),
                reader.GetString(reader.GetOrdinal("username")),
                reader.GetString(reader.GetOrdinal("name")),
                reader.GetString(reader.GetOrdinal("visibility")),
                reader.GetInt32(reader.GetOrdinal("time_range_hours")),
                reader.GetInt32(reader.GetOrdinal("refresh_minutes")),
                JsonDocument.Parse(json).RootElement.Clone(),
                reader.GetInt32(reader.GetOrdinal("version")),
                ReadDateTimeOffset(reader, reader.GetOrdinal("created_at")),
                ReadDateTimeOffset(reader, reader.GetOrdinal("updated_at"))));
        }
        return results;
    }

    private static DateTimeOffset ReadDateTimeOffset(NpgsqlDataReader reader, int ordinal) => ToDateTimeOffset(reader.GetValue(ordinal));
    private static DateTimeOffset ToDateTimeOffset(object value) => value switch
    {
        DateTimeOffset dto => dto.ToUniversalTime(),
        DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
        _ => throw new InvalidOperationException("Expected timestamp value.")
    };
}
