using System.Text.Json;
using System.Text.Json.Serialization;
using Challenger.Siem.Api.Configuration;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record ManagedTelemetryTableAccounting(
    string TableName,
    long RowCount,
    long LiveBytes,
    long RelationBytes,
    long IndexBytes,
    long TotalRelationBytes);

public sealed record RetentionCategorySummary(
    string TableName,
    string Category,
    long EligibleRows,
    long RemovedRows,
    long EstimatedBytes,
    DateTimeOffset? OldestTimestamp,
    DateTimeOffset? NewestTimestamp);

public sealed record RetentionRunSummary(
    Guid RunId,
    string Mode,
    string Status,
    string Trigger,
    bool AdvisoryLockAcquired,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt,
    DateTimeOffset RetentionCutoff,
    long CapacityBytes,
    long EmergencyTargetBytes,
    ManagedStorageAccounting Before,
    ManagedStorageAccounting? After,
    long RemovedRows,
    long RemovedEventRows,
    long EstimatedRemovedBytes,
    string ThresholdState,
    string RetentionLagState,
    IReadOnlyList<RetentionCategorySummary> Categories,
    IReadOnlyList<string> ManagedTables,
    IReadOnlyList<string> ProtectedTables);

public sealed record RetentionStatusResponse(
    ManagedStorageAccounting Accounting,
    bool Enabled,
    bool AdvisoryLockAvailable,
    DateTimeOffset RetentionCutoff,
    string RetentionLagState,
    RetentionRunSummary? LastRun,
    IReadOnlyList<string> ManagedTables,
    IReadOnlyList<string> ProtectedTables);

public sealed record RetentionRunRequest(
    [property: JsonPropertyName("dry_run")] bool DryRun = true,
    [property: JsonPropertyName("emergency")] bool Emergency = false,
    [property: JsonPropertyName("max_batches")] int? MaxBatches = null);

public sealed class RetentionRepository(NpgsqlDataSource dataSource, EventRepository events)
{
    public static readonly IReadOnlyList<string> ManagedTables = new[]
    {
        "events",
        "agent_heartbeats",
        "asset_inventory_snapshots",
        "ingestion_errors"
    };

    public static readonly IReadOnlyList<string> ProtectedTables = new[]
    {
        "agents",
        "operators",
        "operator_sessions",
        "security_audit_events",
        "alerts",
        "alert_evidence",
        "coverage_exceptions",
        "detection_rules",
        "investigation_graphs",
        "investigation_graph_nodes",
        "investigation_graph_edges",
        "investigation_graph_proposals",
        "investigation_graph_audit",
        "soc_agent_turns",
        "soc_agent_sessions",
        "soc_agent_messages",
        "source_health"
    };

    public async Task<RetentionStatusResponse> GetStatusAsync(ManagedRetentionOptions options, CancellationToken cancellationToken)
    {
        var accounting = await events.GetManagedStorageAccountingAsync(options.ManagedCapacityBytes, cancellationToken, options.TargetRetentionDays);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var lockAvailable = await TryProbeLockAsync(connection, options.AdvisoryLockKey, cancellationToken);
        var lastRun = await ReadLastRunAsync(connection, options, cancellationToken);
        var cutoff = DateTimeOffset.UtcNow.AddDays(-options.TargetRetentionDays);
        return new RetentionStatusResponse(accounting, options.Enabled, lockAvailable, cutoff, accounting.RetentionLagState, lastRun, ManagedTables, ProtectedTables);
    }

    public async Task<RetentionRunSummary> RunAsync(ManagedRetentionOptions options, RetentionRunRequest request, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var cutoff = started.AddDays(-options.TargetRetentionDays);
        var mode = request.DryRun ? "dry_run" : "execute";
        var runId = Guid.NewGuid();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var before = await events.GetManagedStorageAccountingAsync(options.ManagedCapacityBytes, cancellationToken, options.TargetRetentionDays);
        if (!options.Enabled)
        {
            return new RetentionRunSummary(runId, mode, "disabled", request.Emergency ? "emergency" : "scheduled", false, started, DateTimeOffset.UtcNow, cutoff, options.ManagedCapacityBytes, EmergencyTargetBytes(options), before, before, 0, 0, 0, before.WarningState, before.RetentionLagState, Array.Empty<RetentionCategorySummary>(), ManagedTables, ProtectedTables);
        }

        var locked = await TryAcquireLockAsync(connection, options.AdvisoryLockKey, cancellationToken);
        if (!locked)
        {
            return new RetentionRunSummary(runId, mode, "lock_not_acquired", request.Emergency ? "emergency" : "scheduled", false, started, DateTimeOffset.UtcNow, cutoff, options.ManagedCapacityBytes, EmergencyTargetBytes(options), before, before, 0, 0, 0, before.WarningState, before.RetentionLagState, Array.Empty<RetentionCategorySummary>(), ManagedTables, ProtectedTables);
        }

        try
        {
            var categories = new Dictionary<(string Table, string Category), MutableCategory>();
            var emergency = request.Emergency || before.TotalBytes >= options.ManagedCapacityBytes;
            var maxBatches = Math.Clamp(request.MaxBatches ?? options.MaxBatchesPerRun, 1, options.MaxBatchesPerRun);

            if (request.DryRun)
            {
                await AddDryRunSummariesAsync(connection, cutoff, emergency, categories, cancellationToken);
                var dryRunCategories = ToSummaries(categories);
                var completed = new RetentionRunSummary(runId, mode, "completed", emergency ? "emergency" : "scheduled", true, started, DateTimeOffset.UtcNow, cutoff, options.ManagedCapacityBytes, EmergencyTargetBytes(options), before, before, 0, 0, 0, before.WarningState, before.RetentionLagState, dryRunCategories, ManagedTables, ProtectedTables);
                await StoreRunAsync(connection, completed, cancellationToken);
                return completed;
            }

            var batches = 0;
            long removedRows = 0;
            long removedEventRows = 0;
            long removedBytes = 0;

            async Task<bool> DeleteBatch(Func<Task<DeleteBatchResult>> delete)
            {
                if (batches >= maxBatches)
                {
                    return false;
                }
                var result = await delete();
                if (result.Rows == 0)
                {
                    return false;
                }
                batches++;
                removedRows += result.Rows;
                removedEventRows += result.EventRows;
                removedBytes += result.EstimatedBytes;
                Merge(categories, result.Categories);
                return true;
            }

            foreach (var table in new[] { "ingestion_errors", "agent_heartbeats", "asset_inventory_snapshots" })
            {
                while (await DeleteBatch(() => DeleteHistoryBatchAsync(connection, table, cutoff, options.CleanupBatchSize, cancellationToken))) { }
            }

            while (await DeleteBatch(() => DeleteEventsBatchAsync(connection, runId, cutoff, includeMandatory: true, options.CleanupBatchSize, cancellationToken))) { }

            if (emergency)
            {
                while (batches < maxBatches && (await events.GetManagedStorageAccountingAsync(options.ManagedCapacityBytes, cancellationToken, options.TargetRetentionDays)).TotalBytes > EmergencyTargetBytes(options))
                {
                    var progressed = false;
                    foreach (var table in new[] { "ingestion_errors", "agent_heartbeats", "asset_inventory_snapshots" })
                    {
                        progressed |= await DeleteBatch(() => DeleteHistoryBatchAsync(connection, table, cutoff: null, options.CleanupBatchSize, cancellationToken));
                        if (batches >= maxBatches) break;
                    }
                    if (batches >= maxBatches) break;
                    progressed |= await DeleteBatch(() => DeleteEventsBatchAsync(connection, runId, cutoff: null, includeMandatory: false, options.CleanupBatchSize, cancellationToken));
                    if (!progressed)
                    {
                        progressed |= await DeleteBatch(() => DeleteEventsBatchAsync(connection, runId, cutoff: null, includeMandatory: true, options.CleanupBatchSize, cancellationToken));
                    }
                    if (!progressed) break;
                }
            }

            var after = await events.GetManagedStorageAccountingAsync(options.ManagedCapacityBytes, cancellationToken, options.TargetRetentionDays);
            var status = batches >= maxBatches && removedRows > 0 && after.TotalBytes > EmergencyTargetBytes(options) ? "bounded_incomplete" : "completed";
            var summary = new RetentionRunSummary(runId, mode, status, emergency ? "emergency" : "scheduled", true, started, DateTimeOffset.UtcNow, cutoff, options.ManagedCapacityBytes, EmergencyTargetBytes(options), before, after, removedRows, removedEventRows, removedBytes, after.WarningState, after.RetentionLagState, ToSummaries(categories), ManagedTables, ProtectedTables);
            await StoreRunAsync(connection, summary, cancellationToken);
            return summary;
        }
        finally
        {
            await ReleaseLockAsync(connection, options.AdvisoryLockKey, CancellationToken.None);
        }
    }

    private static long EmergencyTargetBytes(ManagedRetentionOptions options) => options.ManagedCapacityBytes * options.EmergencyTargetPercent / 100;

    private static async Task<bool> TryProbeLockAsync(NpgsqlConnection connection, long key, CancellationToken cancellationToken)
    {
        var acquired = await TryAcquireLockAsync(connection, key, cancellationToken);
        if (acquired) await ReleaseLockAsync(connection, key, cancellationToken);
        return acquired;
    }

    private static async Task<bool> TryAcquireLockAsync(NpgsqlConnection connection, long key, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select pg_try_advisory_lock(@key);";
        command.Parameters.AddWithValue("key", key);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }

    private static async Task ReleaseLockAsync(NpgsqlConnection connection, long key, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select pg_advisory_unlock(@key);";
        command.Parameters.AddWithValue("key", key);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task AddDryRunSummariesAsync(NpgsqlConnection connection, DateTimeOffset cutoff, bool emergency, Dictionary<(string Table, string Category), MutableCategory> categories, CancellationToken cancellationToken)
    {
        var effectiveCutoff = emergency ? (DateTimeOffset?)null : cutoff;
        foreach (var table in new[] { "ingestion_errors", "agent_heartbeats", "asset_inventory_snapshots" })
        {
            await AddHistoryDryRunAsync(connection, table, effectiveCutoff, categories, cancellationToken);
        }
        await AddEventsDryRunAsync(connection, effectiveCutoff, includeMandatory: true, categories, cancellationToken);
    }

    private static async Task AddHistoryDryRunAsync(NpgsqlConnection connection, string table, DateTimeOffset? cutoff, Dictionary<(string Table, string Category), MutableCategory> categories, CancellationToken cancellationToken)
    {
        var (timeColumn, category) = table switch
        {
            "agent_heartbeats" => ("heartbeat_time", "optional_heartbeat_history"),
            "asset_inventory_snapshots" => ("collected_at", "optional_inventory_snapshots"),
            "ingestion_errors" => ("error_time", "optional_ingestion_errors"),
            _ => throw new ArgumentOutOfRangeException(nameof(table), table, "Table is not in the managed retention allowlist.")
        };
        await using var command = connection.CreateCommand();
        command.CommandText = $"select count(*), coalesce(sum(pg_column_size({table}.*)),0), min({timeColumn}), max({timeColumn}) from {table}" + (cutoff.HasValue ? $" where {timeColumn} < @cutoff" : string.Empty);
        if (cutoff.HasValue) command.Parameters.AddWithValue("cutoff", cutoff.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (await reader.ReadAsync(cancellationToken)) Add(categories, table, category, reader.GetInt64(0), 0, reader.GetInt64(1), ReadNullableDateTimeOffset(reader, 2), ReadNullableDateTimeOffset(reader, 3));
    }

    private static async Task AddEventsDryRunAsync(NpgsqlConnection connection, DateTimeOffset? cutoff, bool includeMandatory, Dictionary<(string Table, string Category), MutableCategory> categories, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select retention_category, count(*), coalesce(sum(row_bytes),0), min(event_time), max(event_time)
            from (
                select event_time, pg_column_size(events.*) as row_bytes,
                       case
                         when source = 'windows_event_log' and channel in ('Security','System','Application') then 'mandatory_windows_event_log'
                         when source_id = 'linux-journal-l1' then 'mandatory_linux_journal'
                         when source in ('agent_health','inventory_diff') then 'optional_operational_events'
                         else 'optional_extended_events'
                       end as retention_category,
                       case
                         when source = 'windows_event_log' and channel in ('Security','System','Application') then true
                         when source_id = 'linux-journal-l1' then true
                         else false
                       end as mandatory
                from events
            ) candidate
            where (@cutoff::timestamptz is null or event_time < @cutoff)
              and (@include_mandatory or not mandatory)
            group by retention_category;
            """;
        command.Parameters.Add("cutoff", NpgsqlDbType.TimestampTz).Value = cutoff.HasValue ? cutoff.Value : DBNull.Value;
        command.Parameters.AddWithValue("include_mandatory", includeMandatory);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) Add(categories, "events", reader.GetString(0), reader.GetInt64(1), 0, reader.GetInt64(2), ReadNullableDateTimeOffset(reader, 3), ReadNullableDateTimeOffset(reader, 4));
    }

    private static async Task<DeleteBatchResult> DeleteHistoryBatchAsync(NpgsqlConnection connection, string table, DateTimeOffset? cutoff, int limit, CancellationToken cancellationToken)
    {
        var (timeColumn, category) = table switch
        {
            "agent_heartbeats" => ("heartbeat_time", "optional_heartbeat_history"),
            "asset_inventory_snapshots" => ("collected_at", "optional_inventory_snapshots"),
            "ingestion_errors" => ("error_time", "optional_ingestion_errors"),
            _ => throw new ArgumentOutOfRangeException(nameof(table), table, "Table is not in the managed retention allowlist.")
        };
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            with candidate as (
                select ctid, {timeColumn} as retained_at, pg_column_size({table}.*) as row_bytes
                from {table}
                where (@cutoff::timestamptz is null or {timeColumn} < @cutoff)
                order by {timeColumn} asc
                limit @limit
                for update skip locked
            ), deleted as (
                delete from {table} target using candidate c
                where target.ctid = c.ctid
                returning c.retained_at, c.row_bytes
            )
            select count(*), coalesce(sum(row_bytes),0), min(retained_at), max(retained_at) from deleted;
            """;
        command.Parameters.Add("cutoff", NpgsqlDbType.TimestampTz).Value = cutoff.HasValue ? cutoff.Value : DBNull.Value;
        command.Parameters.AddWithValue("limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        var result = DeleteBatchResult.FromSingle(table, category, reader.GetInt64(0), 0, reader.GetInt64(1), ReadNullableDateTimeOffset(reader, 2), ReadNullableDateTimeOffset(reader, 3));
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static async Task<DeleteBatchResult> DeleteEventsBatchAsync(NpgsqlConnection connection, Guid runId, DateTimeOffset? cutoff, bool includeMandatory, int limit, CancellationToken cancellationToken)
    {
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            with candidate as (
                select ctid, agent_id, event_id, event_time, pg_column_size(events.*) as row_bytes,
                       case
                         when source = 'windows_event_log' and channel in ('Security','System','Application') then 'mandatory_windows_event_log'
                         when source_id = 'linux-journal-l1' then 'mandatory_linux_journal'
                         when source in ('agent_health','inventory_diff') then 'optional_operational_events'
                         else 'optional_extended_events'
                       end as retention_category,
                       case
                         when source = 'windows_event_log' and channel in ('Security','System','Application') then 1
                         when source_id = 'linux-journal-l1' then 1
                         else 0
                       end as priority
                from events
                where (@cutoff::timestamptz is null or event_time < @cutoff)
                  and (@include_mandatory or not (source = 'windows_event_log' and channel in ('Security','System','Application') or source_id = 'linux-journal-l1'))
                order by priority asc, event_time asc, id asc
                limit @limit
                for update skip locked
            ), retained_reference as (
                insert into managed_retention_removed_events(run_id, agent_id, event_id, event_time, category, removed_at)
                select @run_id, agent_id, event_id, event_time, retention_category, now() from candidate
                on conflict (agent_id, event_id) do nothing
            ), deleted as (
                delete from events e using candidate c
                where e.ctid = c.ctid
                returning c.retention_category, c.event_time, c.row_bytes
            )
            select retention_category, count(*), coalesce(sum(row_bytes),0), min(event_time), max(event_time)
            from deleted
            group by retention_category;
            """;
        command.Parameters.Add("cutoff", NpgsqlDbType.TimestampTz).Value = cutoff.HasValue ? cutoff.Value : DBNull.Value;
        command.Parameters.AddWithValue("include_mandatory", includeMandatory);
        command.Parameters.AddWithValue("limit", limit);
        command.Parameters.AddWithValue("run_id", runId);
        var categories = new List<RetentionCategorySummary>();
        long rows = 0;
        long bytes = 0;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var count = reader.GetInt64(1);
            var estimatedBytes = reader.GetInt64(2);
            rows += count;
            bytes += estimatedBytes;
            categories.Add(new RetentionCategorySummary("events", reader.GetString(0), count, count, estimatedBytes, ReadNullableDateTimeOffset(reader, 3), ReadNullableDateTimeOffset(reader, 4)));
        }
        await reader.DisposeAsync();
        await transaction.CommitAsync(cancellationToken);
        return new DeleteBatchResult(rows, rows, bytes, categories);
    }

    private async Task<RetentionRunSummary?> ReadLastRunAsync(NpgsqlConnection connection, ManagedRetentionOptions options, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select details from managed_retention_runs order by started_at desc limit 1;";
        var json = await command.ExecuteScalarAsync(cancellationToken) as string;
        return string.IsNullOrWhiteSpace(json) ? null : JsonSerializer.Deserialize<RetentionRunSummary>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }

    private static async Task StoreRunAsync(NpgsqlConnection connection, RetentionRunSummary summary, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into managed_retention_runs(run_id, mode, status, trigger, started_at, completed_at, retention_cutoff, rows_removed, event_rows_removed, estimated_removed_bytes, details)
            values (@run_id, @mode, @status, @trigger, @started_at, @completed_at, @retention_cutoff, @rows_removed, @event_rows_removed, @estimated_removed_bytes, @details::jsonb);
            """;
        command.Parameters.AddWithValue("run_id", summary.RunId);
        command.Parameters.AddWithValue("mode", summary.Mode);
        command.Parameters.AddWithValue("status", summary.Status);
        command.Parameters.AddWithValue("trigger", summary.Trigger);
        command.Parameters.AddWithValue("started_at", summary.StartedAt);
        command.Parameters.AddWithValue("completed_at", summary.CompletedAt ?? DateTimeOffset.UtcNow);
        command.Parameters.AddWithValue("retention_cutoff", summary.RetentionCutoff);
        command.Parameters.AddWithValue("rows_removed", summary.RemovedRows);
        command.Parameters.AddWithValue("event_rows_removed", summary.RemovedEventRows);
        command.Parameters.AddWithValue("estimated_removed_bytes", summary.EstimatedRemovedBytes);
        command.Parameters.Add("details", NpgsqlDbType.Jsonb).Value = JsonSerializer.Serialize(summary, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void Merge(Dictionary<(string Table, string Category), MutableCategory> target, IReadOnlyList<RetentionCategorySummary> source)
    {
        foreach (var item in source)
        {
            Add(target, item.TableName, item.Category, item.EligibleRows, item.RemovedRows, item.EstimatedBytes, item.OldestTimestamp, item.NewestTimestamp);
        }
    }

    private static void Add(Dictionary<(string Table, string Category), MutableCategory> target, string table, string category, long eligibleRows, long removedRows, long bytes, DateTimeOffset? oldest, DateTimeOffset? newest)
    {
        if (eligibleRows == 0 && removedRows == 0) return;
        var key = (table, category);
        if (!target.TryGetValue(key, out var existing))
        {
            existing = new MutableCategory(table, category);
            target[key] = existing;
        }
        existing.EligibleRows += eligibleRows;
        existing.RemovedRows += removedRows;
        existing.EstimatedBytes += bytes;
        existing.OldestTimestamp = Min(existing.OldestTimestamp, oldest);
        existing.NewestTimestamp = Max(existing.NewestTimestamp, newest);
    }

    private static IReadOnlyList<RetentionCategorySummary> ToSummaries(Dictionary<(string Table, string Category), MutableCategory> categories) => categories.Values
        .OrderBy(item => item.TableName, StringComparer.Ordinal)
        .ThenBy(item => item.Category, StringComparer.Ordinal)
        .Select(item => new RetentionCategorySummary(item.TableName, item.Category, item.EligibleRows, item.RemovedRows, item.EstimatedBytes, item.OldestTimestamp, item.NewestTimestamp))
        .ToArray();

    private static DateTimeOffset? ReadNullableDateTimeOffset(NpgsqlDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal)) return null;
        var value = reader.GetValue(ordinal);
        return value switch
        {
            DateTimeOffset dto => dto.ToUniversalTime(),
            DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
            _ => null
        };
    }

    private static DateTimeOffset? Min(DateTimeOffset? left, DateTimeOffset? right) => !left.HasValue ? right : !right.HasValue ? left : left.Value <= right.Value ? left : right;
    private static DateTimeOffset? Max(DateTimeOffset? left, DateTimeOffset? right) => !left.HasValue ? right : !right.HasValue ? left : left.Value >= right.Value ? left : right;

    private sealed class MutableCategory(string table, string category)
    {
        public string TableName { get; } = table;
        public string Category { get; } = category;
        public long EligibleRows { get; set; }
        public long RemovedRows { get; set; }
        public long EstimatedBytes { get; set; }
        public DateTimeOffset? OldestTimestamp { get; set; }
        public DateTimeOffset? NewestTimestamp { get; set; }
    }

    private sealed record DeleteBatchResult(long Rows, long EventRows, long EstimatedBytes, IReadOnlyList<RetentionCategorySummary> Categories)
    {
        public static DeleteBatchResult FromSingle(string table, string category, long rows, long eventRows, long estimatedBytes, DateTimeOffset? oldest, DateTimeOffset? newest) =>
            new(rows, eventRows, estimatedBytes, rows == 0 ? Array.Empty<RetentionCategorySummary>() : new[] { new RetentionCategorySummary(table, category, rows, rows, estimatedBytes, oldest, newest) });
    }
}
