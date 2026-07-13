using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed class HeartbeatRepository(NpgsqlDataSource dataSource)
{
    public async Task InsertHeartbeatAsync(HeartbeatRequest request, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into agent_heartbeats (
                    agent_id,
                    hostname,
                    agent_version,
                    os,
                    last_event_time,
                    host_timezone,
                    queue_depth,
                    cpu_percent,
                    memory_mb,
                    config_hash,
                    queue_metrics,
                    source_manifest,
                    source_health_summary,
                    tamper_checks
                )
                values (
                    @agent_id,
                    @hostname,
                    @agent_version,
                    @os,
                    @last_event_time,
                    @host_timezone,
                    @queue_depth,
                    @cpu_percent,
                    @memory_mb,
                    @config_hash,
                    @queue_metrics,
                    @source_manifest,
                    @source_health_summary,
                    @tamper_checks
                );
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("hostname", request.Hostname);
            command.Parameters.AddWithValue("agent_version", request.AgentVersion);
            command.Parameters.AddWithValue("os", request.Os);
            command.Parameters.AddWithValue("last_event_time", request.LastEventTime.HasValue ? request.LastEventTime.Value.ToUniversalTime() : (object)DBNull.Value);
            Jsonb.Add(command, "host_timezone", request.HostTimezone);
            command.Parameters.AddWithValue("queue_depth", request.QueueDepth);
            command.Parameters.AddWithValue("cpu_percent", request.CpuPercent.HasValue ? request.CpuPercent.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("memory_mb", request.MemoryMb.HasValue ? request.MemoryMb.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("config_hash", string.IsNullOrWhiteSpace(request.ConfigHash) ? (object)DBNull.Value : request.ConfigHash);
            AddJsonb(command, "queue_metrics", request.QueueMetrics);
            AddJsonb(command, "source_manifest", request.SourceManifest);
            AddJsonb(command, "source_health_summary", request.SourceHealth);
            AddJsonb(command, "tamper_checks", request.TamperChecks);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var source in request.SourceHealth)
        {
            var effectiveStatus = SourceHealthRules.EffectiveStatus(source, now);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                insert into source_health (
                    agent_id,
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
                    details,
                    host_timezone,
                    updated_at
                )
                values (
                    @agent_id,
                    @source_id,
                    @display_name,
                    @channel,
                    @coverage_level,
                    @status,
                    @required_source,
                    @enabled,
                    @last_event_time,
                    @last_record_id,
                    @oldest_record_id,
                    @newest_record_id,
                    @log_size_bytes,
                    @retention_days,
                    @lag_seconds,
                    @error_code,
                    @error_message,
                    @gap_detected,
                    @cleared_detected,
                    @bookmark_gap_detected,
                    @config_hash,
                    @source_version,
                    @details,
                    @host_timezone,
                    now()
                )
                on conflict (agent_id, source_id) do update set
                    display_name = excluded.display_name,
                    channel = excluded.channel,
                    coverage_level = excluded.coverage_level,
                    status = excluded.status,
                    required_source = excluded.required_source,
                    enabled = excluded.enabled,
                    last_event_time = excluded.last_event_time,
                    last_record_id = excluded.last_record_id,
                    oldest_record_id = excluded.oldest_record_id,
                    newest_record_id = excluded.newest_record_id,
                    log_size_bytes = excluded.log_size_bytes,
                    retention_days = excluded.retention_days,
                    lag_seconds = excluded.lag_seconds,
                    error_code = excluded.error_code,
                    error_message = excluded.error_message,
                    gap_detected = excluded.gap_detected,
                    cleared_detected = excluded.cleared_detected,
                    bookmark_gap_detected = excluded.bookmark_gap_detected,
                    config_hash = excluded.config_hash,
                    source_version = excluded.source_version,
                    details = excluded.details,
                    host_timezone = excluded.host_timezone,
                    updated_at = now();
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("source_id", source.SourceId);
            command.Parameters.AddWithValue("display_name", source.DisplayName);
            command.Parameters.AddWithValue("channel", source.Channel!);
            command.Parameters.AddWithValue("coverage_level", source.CoverageLevel.ToString());
            command.Parameters.AddWithValue("status", effectiveStatus);
            command.Parameters.AddWithValue("required_source", source.Required);
            command.Parameters.AddWithValue("enabled", source.Enabled);
            command.Parameters.AddWithValue("last_event_time", source.LastEventTime.HasValue ? source.LastEventTime.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("last_record_id", source.LastRecordId.HasValue ? source.LastRecordId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("oldest_record_id", source.OldestRecordId.HasValue ? source.OldestRecordId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("newest_record_id", source.NewestRecordId.HasValue ? source.NewestRecordId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("log_size_bytes", source.LogSizeBytes.HasValue ? source.LogSizeBytes.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("retention_days", source.RetentionDays.HasValue ? source.RetentionDays.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("lag_seconds", source.LagSeconds.HasValue ? source.LagSeconds.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("error_code", string.IsNullOrWhiteSpace(source.ErrorCode) ? (object)DBNull.Value : source.ErrorCode);
            command.Parameters.AddWithValue("error_message", string.IsNullOrWhiteSpace(source.ErrorMessage) ? (object)DBNull.Value : source.ErrorMessage);
            command.Parameters.AddWithValue("gap_detected", source.GapDetected);
            command.Parameters.AddWithValue("cleared_detected", source.ClearedDetected);
            command.Parameters.AddWithValue("bookmark_gap_detected", source.BookmarkGapDetected);
            command.Parameters.AddWithValue("config_hash", string.IsNullOrWhiteSpace(source.ConfigHash) ? (object)DBNull.Value : source.ConfigHash);
            command.Parameters.AddWithValue("source_version", string.IsNullOrWhiteSpace(source.SourceVersion) ? (object)DBNull.Value : source.SourceVersion);
            AddJsonb(command, "details", source.Details);
            Jsonb.Add(command, "host_timezone", source.HostTimezone ?? request.HostTimezone);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                update agents
                set hostname = @hostname,
                    agent_version = @agent_version,
                    host_timezone = coalesce(@host_timezone, host_timezone),
                    last_seen = now(),
                    updated_at = now()
                where agent_id = @agent_id;
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("hostname", request.Hostname);
            command.Parameters.AddWithValue("agent_version", request.AgentVersion);
            Jsonb.Add(command, "host_timezone", request.HostTimezone);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static void AddJsonb(NpgsqlCommand command, string name, object? value)
    {
        var parameter = command.Parameters.Add(name, NpgsqlDbType.Jsonb);
        parameter.Value = value is null ? DBNull.Value : JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }
}
