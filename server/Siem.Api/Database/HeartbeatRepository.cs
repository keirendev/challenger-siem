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
                    resource_metrics,
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
                    @resource_metrics,
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
            AddJsonb(command, "resource_metrics", request.ResourceMetrics);
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
                    platform,
                    source_kind,
                    channel,
                    source_namespace,
                    facility,
                    unit,
                    applicability,
                    applicability_reason,
                    coverage_level,
                    status,
                    required_source,
                    enabled,
                    last_event_time,
                    observed_at,
                    last_record_id,
                    oldest_record_id,
                    newest_record_id,
                    log_size_bytes,
                    retention_days,
                    lag_seconds,
                    silence_seconds,
                    event_rate_per_minute,
                    error_code,
                    error_message,
                    gap_detected,
                    cleared_detected,
                    bookmark_gap_detected,
                    gap_count,
                    permission_denied_since,
                    recovered_at,
                    transition_state,
                    transitioned_at,
                    dropped_events,
                    poison_events,
                    config_hash,
                    source_version,
                    requirement_kind,
                    applicable_roles,
                    prerequisite_statuses,
                    event_family_statuses,
                    collected_checkpoint,
                    acknowledged_checkpoint,
                    details,
                    host_timezone,
                    updated_at
                )
                values (
                    @agent_id,
                    @source_id,
                    @display_name,
                    @platform,
                    @source_kind,
                    @channel,
                    @source_namespace,
                    @facility,
                    @unit,
                    @applicability,
                    @applicability_reason,
                    @coverage_level,
                    @status,
                    @required_source,
                    @enabled,
                    @last_event_time,
                    @observed_at,
                    @last_record_id,
                    @oldest_record_id,
                    @newest_record_id,
                    @log_size_bytes,
                    @retention_days,
                    @lag_seconds,
                    @silence_seconds,
                    @event_rate_per_minute,
                    @error_code,
                    @error_message,
                    @gap_detected,
                    @cleared_detected,
                    @bookmark_gap_detected,
                    @gap_count,
                    @permission_denied_since,
                    @recovered_at,
                    @transition_state,
                    @transitioned_at,
                    @dropped_events,
                    @poison_events,
                    @config_hash,
                    @source_version,
                    @requirement_kind,
                    @applicable_roles,
                    @prerequisite_statuses,
                    @event_family_statuses,
                    @collected_checkpoint,
                    @acknowledged_checkpoint,
                    @details,
                    @host_timezone,
                    now()
                )
                on conflict (agent_id, source_id) do update set
                    display_name = excluded.display_name,
                    platform = excluded.platform,
                    source_kind = excluded.source_kind,
                    channel = excluded.channel,
                    source_namespace = excluded.source_namespace,
                    facility = excluded.facility,
                    unit = excluded.unit,
                    applicability = excluded.applicability,
                    applicability_reason = excluded.applicability_reason,
                    coverage_level = excluded.coverage_level,
                    status = excluded.status,
                    required_source = excluded.required_source,
                    enabled = excluded.enabled,
                    last_event_time = excluded.last_event_time,
                    observed_at = excluded.observed_at,
                    last_record_id = excluded.last_record_id,
                    oldest_record_id = excluded.oldest_record_id,
                    newest_record_id = excluded.newest_record_id,
                    log_size_bytes = excluded.log_size_bytes,
                    retention_days = excluded.retention_days,
                    lag_seconds = excluded.lag_seconds,
                    silence_seconds = excluded.silence_seconds,
                    event_rate_per_minute = excluded.event_rate_per_minute,
                    error_code = excluded.error_code,
                    error_message = excluded.error_message,
                    gap_detected = excluded.gap_detected,
                    cleared_detected = excluded.cleared_detected,
                    bookmark_gap_detected = excluded.bookmark_gap_detected,
                    gap_count = excluded.gap_count,
                    permission_denied_since = excluded.permission_denied_since,
                    recovered_at = excluded.recovered_at,
                    transition_state = excluded.transition_state,
                    transitioned_at = excluded.transitioned_at,
                    dropped_events = excluded.dropped_events,
                    poison_events = excluded.poison_events,
                    config_hash = excluded.config_hash,
                    source_version = excluded.source_version,
                    requirement_kind = excluded.requirement_kind,
                    applicable_roles = excluded.applicable_roles,
                    prerequisite_statuses = excluded.prerequisite_statuses,
                    event_family_statuses = excluded.event_family_statuses,
                    collected_checkpoint = excluded.collected_checkpoint,
                    acknowledged_checkpoint = excluded.acknowledged_checkpoint,
                    details = excluded.details,
                    host_timezone = excluded.host_timezone,
                    updated_at = now();
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("source_id", source.SourceId);
            command.Parameters.AddWithValue("display_name", source.DisplayName);
            command.Parameters.AddWithValue("platform", string.IsNullOrWhiteSpace(source.Platform) ? (object)DBNull.Value : source.Platform);
            command.Parameters.AddWithValue("source_kind", string.IsNullOrWhiteSpace(source.SourceKind) ? (object)DBNull.Value : source.SourceKind);
            command.Parameters.AddWithValue("channel", string.IsNullOrWhiteSpace(source.Channel) ? (object)DBNull.Value : source.Channel);
            command.Parameters.AddWithValue("source_namespace", string.IsNullOrWhiteSpace(source.SourceNamespace) ? (object)DBNull.Value : source.SourceNamespace);
            command.Parameters.AddWithValue("facility", string.IsNullOrWhiteSpace(source.Facility) ? (object)DBNull.Value : source.Facility);
            command.Parameters.AddWithValue("unit", string.IsNullOrWhiteSpace(source.Unit) ? (object)DBNull.Value : source.Unit);
            command.Parameters.AddWithValue("applicability", string.IsNullOrWhiteSpace(source.Applicability) ? (object)DBNull.Value : source.Applicability);
            command.Parameters.AddWithValue("applicability_reason", string.IsNullOrWhiteSpace(source.ApplicabilityReason) ? (object)DBNull.Value : source.ApplicabilityReason);
            command.Parameters.AddWithValue("coverage_level", source.CoverageLevel.ToString());
            command.Parameters.AddWithValue("status", effectiveStatus);
            command.Parameters.AddWithValue("required_source", source.Required);
            command.Parameters.AddWithValue("enabled", source.Enabled);
            command.Parameters.AddWithValue("last_event_time", source.LastEventTime.HasValue ? source.LastEventTime.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("observed_at", source.ObservedAt.HasValue ? source.ObservedAt.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("last_record_id", source.LastRecordId.HasValue ? source.LastRecordId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("oldest_record_id", source.OldestRecordId.HasValue ? source.OldestRecordId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("newest_record_id", source.NewestRecordId.HasValue ? source.NewestRecordId.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("log_size_bytes", source.LogSizeBytes.HasValue ? source.LogSizeBytes.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("retention_days", source.RetentionDays.HasValue ? source.RetentionDays.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("lag_seconds", source.LagSeconds.HasValue ? source.LagSeconds.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("silence_seconds", source.SilenceSeconds.HasValue ? source.SilenceSeconds.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("event_rate_per_minute", source.EventRatePerMinute.HasValue ? source.EventRatePerMinute.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("error_code", string.IsNullOrWhiteSpace(source.ErrorCode) ? (object)DBNull.Value : source.ErrorCode);
            command.Parameters.AddWithValue("error_message", string.IsNullOrWhiteSpace(source.ErrorMessage) ? (object)DBNull.Value : source.ErrorMessage);
            command.Parameters.AddWithValue("gap_detected", source.GapDetected);
            command.Parameters.AddWithValue("cleared_detected", source.ClearedDetected);
            command.Parameters.AddWithValue("bookmark_gap_detected", source.BookmarkGapDetected);
            command.Parameters.AddWithValue("gap_count", source.GapCount.HasValue ? source.GapCount.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("permission_denied_since", source.PermissionDeniedSince.HasValue ? source.PermissionDeniedSince.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("recovered_at", source.RecoveredAt.HasValue ? source.RecoveredAt.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("transition_state", string.IsNullOrWhiteSpace(source.TransitionState) ? (object)DBNull.Value : source.TransitionState);
            command.Parameters.AddWithValue("transitioned_at", source.TransitionedAt.HasValue ? source.TransitionedAt.Value.ToUniversalTime() : (object)DBNull.Value);
            command.Parameters.AddWithValue("dropped_events", source.DroppedEvents.HasValue ? source.DroppedEvents.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("poison_events", source.PoisonEvents.HasValue ? source.PoisonEvents.Value : (object)DBNull.Value);
            command.Parameters.AddWithValue("config_hash", string.IsNullOrWhiteSpace(source.ConfigHash) ? (object)DBNull.Value : source.ConfigHash);
            command.Parameters.AddWithValue("source_version", string.IsNullOrWhiteSpace(source.SourceVersion) ? (object)DBNull.Value : source.SourceVersion);
            command.Parameters.AddWithValue("requirement_kind", string.IsNullOrWhiteSpace(source.Requirement) ? (object)DBNull.Value : source.Requirement);
            AddJsonb(command, "applicable_roles", source.ApplicableRoles);
            AddJsonb(command, "prerequisite_statuses", source.PrerequisiteStatuses);
            AddJsonb(command, "event_family_statuses", source.EventFamilyStatuses);
            AddJsonb(command, "collected_checkpoint", source.CollectedCheckpoint);
            AddJsonb(command, "acknowledged_checkpoint", source.AcknowledgedCheckpoint);
            AddJsonb(command, "details", source.Details);
            Jsonb.Add(command, "host_timezone", source.HostTimezone ?? request.HostTimezone);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // Source manifest/health arrays are a current full snapshot. Preserve the
        // historical row for an omitted source, but do not let its previous healthy
        // state continue to satisfy current coverage after it disappears.
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                update source_health sh
                set status = 'missing',
                    enabled = false,
                    error_code = 'source_omitted_from_latest_heartbeat',
                    error_message = 'Source was omitted from the latest full source-health snapshot.',
                    gap_detected = true,
                    transition_state = 'degraded',
                    transitioned_at = now(),
                    details = coalesce(sh.details, '{}'::jsonb) || jsonb_build_object(
                        'active_gap', 'true',
                        'omission_reason', 'source_omitted_from_latest_heartbeat'),
                    updated_at = now()
                where sh.agent_id = @agent_id
                  and not (lower(sh.source_id) = any(@submitted_source_ids))
                  and (
                      @portable_full_snapshot
                      or exists (
                          select 1
                          from agents a
                          where a.agent_id = @agent_id and a.platform = 'linux'));
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("submitted_source_ids", request.SourceHealth.Select(source => source.SourceId.ToLowerInvariant()).Distinct(StringComparer.Ordinal).ToArray());
            command.Parameters.AddWithValue(
                "portable_full_snapshot",
                string.Equals(request.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase)
                || request.SourceManifest.Any(source => TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind))
                || request.SourceHealth.Any(source => TelemetrySourceKinds.UsesPortableIdentity(source.SourceKind)));
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
                    platform = coalesce(@platform, platform),
                    host_id = coalesce(@host_id, host_id),
                    last_seen = now(),
                    updated_at = now()
                where agent_id = @agent_id;
                """;
            command.Parameters.AddWithValue("agent_id", request.AgentId);
            command.Parameters.AddWithValue("hostname", request.Hostname);
            command.Parameters.AddWithValue("agent_version", request.AgentVersion);
            Jsonb.Add(command, "host_timezone", request.HostTimezone);
            command.Parameters.AddWithValue("platform", string.IsNullOrWhiteSpace(request.Platform) ? (object)DBNull.Value : request.Platform);
            command.Parameters.AddWithValue("host_id", string.IsNullOrWhiteSpace(request.HostId) ? (object)DBNull.Value : request.HostId);
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
