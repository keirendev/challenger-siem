using System.Globalization;
using System.Text;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Review;

public sealed class ReviewRepository(NpgsqlDataSource dataSource)
{
    private static readonly string[] LinuxL1MandatorySourceIds = LinuxTelemetrySourceCatalog.L1
        .Where(source => source.Requirement == SourceRequirementKinds.Mandatory)
        .Select(source => source.SourceId)
        .ToArray();

    private static readonly string[] LinuxL2MandatorySourceIds = LinuxTelemetrySourceCatalog.L2Security
        .Where(source => source.Requirement == SourceRequirementKinds.Mandatory)
        .Select(source => source.SourceId)
        .ToArray();

    private static readonly string[] LinuxL2RoleSourceIds = LinuxTelemetrySourceCatalog.L2Security
        .Where(source => source.Requirement == SourceRequirementKinds.RoleSpecific)
        .Select(source => source.SourceId)
        .ToArray();

    private static readonly string[] LinuxL4MandatorySourceIds =
    [
        LinuxTelemetrySourceIds.PolicyPostureDrift,
        LinuxTelemetrySourceIds.AgentPerformanceSlo
    ];

    private static readonly string[] LinuxL4RoleSourceIds =
    [
        LinuxTelemetrySourceIds.RoleWeb,
        LinuxTelemetrySourceIds.RoleDatabase,
        LinuxTelemetrySourceIds.RoleDns,
        LinuxTelemetrySourceIds.RoleFileServer,
        LinuxTelemetrySourceIds.RoleContainer,
        LinuxTelemetrySourceIds.RoleIdentity
    ];

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
                    queue_depth,
                    queue_metrics
                from agent_heartbeats
                order by agent_id, heartbeat_time desc
            ), current_health as (
                select
                    sh.*,
                    case
                        when sh.status = 'healthy'
                             and lower(sh.source_id) = any(@linux_performance_polling_source_ids)
                             and sh.observed_at > @future_observation_cutoff then 'degraded'
                        when sh.status = 'healthy'
                             and lower(sh.source_id) = any(@linux_performance_polling_source_ids)
                             and (sh.observed_at is null or sh.observed_at < @performance_source_health_stale_cutoff) then 'stale'
                        when sh.status = 'healthy'
                             and lower(sh.source_id) = any(@linux_two_hour_polling_source_ids)
                             and sh.observed_at > @future_observation_cutoff then 'degraded'
                        when sh.status = 'healthy'
                             and lower(sh.source_id) = any(@linux_two_hour_polling_source_ids)
                             and (sh.observed_at is null or sh.observed_at < @passive_source_health_stale_cutoff) then 'stale'
                        when sh.status = 'healthy'
                             and not (lower(sh.source_id) = any(@linux_all_polling_source_ids))
                             and sh.coverage_level in ('L2', 'L3', 'L4')
                             and (sh.requirement_kind = 'mandatory' or (sh.requirement_kind = 'role_specific' and sh.applicability = 'applicable') or (sh.requirement_kind is null and sh.required_source))
                             and sh.last_event_time is not null
                             and sh.last_event_time < @source_health_stale_cutoff then 'stale'
                        else sh.status
                    end as effective_status
                from source_health sh
            ), health_rollup as (
                select
                    agent_id,
                    count(*) filter (where effective_status in ('degraded','stale','permission_denied','unsupported','error'))::int as degraded_source_count,
                    count(*) filter (
                        where gap_detected
                           or bookmark_gap_detected
                           or cleared_detected
                           or details ->> 'active_gap' in ('present', 'true', 'active', 'detected')
                           or details ->> 'active_bookmark_gap' in ('present', 'true', 'active', 'detected')
                           or (
                               not (lower(source_id) = any(@linux_all_polling_source_ids))
                               and (coalesce(gap_count, 0) > 0 or coalesce(dropped_events, 0) > 0)))::int as gap_source_count,
                    count(*) filter (where coalesce(transition_state, '') = 'degraded' or details ->> 'throttle_state' = 'throttled')::int as throttled_source_count
                from current_health
                group by agent_id
            )
            select
                count(*) filter (where a.status = 'active')::bigint as active_agents,
                count(*) filter (where a.status = 'active' and a.last_seen >= @stale_cutoff)::bigint as recent_active_agents,
                count(*) filter (where a.status = 'active' and a.last_seen < @stale_cutoff)::bigint as stale_active_agents,
                count(*) filter (where a.status = 'disabled')::bigint as retired_agents,
                count(*)::bigint as historical_agents,
                count(*) filter (where a.status = 'active' and coalesce(lh.queue_depth, 0) > 0)::bigint as agents_with_queued_events,
                count(*) filter (where a.status = 'active' and (coalesce(nullif(lh.queue_metrics ->> 'pressure_state',''), 'normal') not in ('normal','unknown') or coalesce(hr.throttled_source_count, 0) > 0))::bigint as agents_with_pressure,
                count(*) filter (where a.status = 'active' and coalesce(hr.gap_source_count, 0) > 0)::bigint as agents_with_source_gaps,
                count(*) filter (where a.status = 'active' and coalesce(hr.degraded_source_count, 0) > 0)::bigint as agents_with_degraded_sources,
                count(*) filter (where a.status = 'active' and coalesce((lh.queue_metrics ->> 'used_percent')::numeric, 0) >= 70)::bigint as agents_with_capacity_warnings,
                (select count(*)::bigint from events where ingest_time >= @recent_event_cutoff) as recent_event_count,
                (select max(ingest_time) from events) as latest_ingest_time
            from agents a
            left join latest_heartbeat lh on lh.agent_id = a.agent_id
            left join health_rollup hr on hr.agent_id = a.agent_id;
            """;
        command.Parameters.AddWithValue("stale_cutoff", staleCutoff.ToUniversalTime());
        command.Parameters.AddWithValue("recent_event_cutoff", recentEventCutoff.ToUniversalTime());
        var linuxL3RequiredSourceIds = LinuxTelemetrySourceCatalog.L3Passive
            .Where(source => source.Requirement == SourceRequirementKinds.Mandatory)
            .Select(source => source.SourceId)
            .ToArray();
        var sourceHealthEvaluatedAt = DateTimeOffset.UtcNow;
        command.Parameters.AddWithValue("linux_l3_required_source_ids", linuxL3RequiredSourceIds);
        AddLinuxPollingParameters(command);
        command.Parameters.AddWithValue("source_health_stale_cutoff", sourceHealthEvaluatedAt.Subtract(SourceHealthRules.DefaultStaleAfter));
        command.Parameters.AddWithValue("passive_source_health_stale_cutoff", sourceHealthEvaluatedAt.Subtract(SourceHealthRules.PassivePollingStaleAfter));
        command.Parameters.AddWithValue("performance_source_health_stale_cutoff", sourceHealthEvaluatedAt.Subtract(SourceHealthRules.PerformanceSloStaleAfter));
        command.Parameters.AddWithValue("future_observation_cutoff", sourceHealthEvaluatedAt.Add(SourceHealthRules.MaximumFutureObservationSkew));

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return DashboardSummary.Empty;
        }

        return new DashboardSummary(
            ReadInt64(reader, "active_agents"),
            ReadInt64(reader, "recent_active_agents"),
            ReadInt64(reader, "stale_active_agents"),
            ReadInt64(reader, "retired_agents"),
            ReadInt64(reader, "historical_agents"),
            ReadInt64(reader, "agents_with_queued_events"),
            ReadInt64(reader, "agents_with_pressure"),
            ReadInt64(reader, "agents_with_source_gaps"),
            ReadInt64(reader, "agents_with_degraded_sources"),
            ReadInt64(reader, "agents_with_capacity_warnings"),
            ReadInt64(reader, "recent_event_count"),
            ReadNullableDateTimeOffset(reader, "latest_ingest_time"));
    }

    public async Task<IReadOnlyList<AgentInventoryItem>> SearchAgentsAsync(
        AgentInventoryQuery query,
        TimeSpan staleAgentAfter,
        CancellationToken cancellationToken,
        int limit = 500,
        int offset = 0)
    {
        var staleCutoff = DateTimeOffset.UtcNow.Subtract(staleAgentAfter);
        var clampedLimit = Math.Clamp(limit, 1, 500);
        var clampedOffset = Math.Max(0, offset);
        var where = new List<string>();

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("stale_cutoff", staleCutoff.ToUniversalTime());
        var linuxL3RequiredSourceIds = LinuxTelemetrySourceCatalog.L3Passive
            .Where(source => source.Requirement == SourceRequirementKinds.Mandatory)
            .Select(source => source.SourceId)
            .ToArray();
        command.Parameters.AddWithValue("linux_l3_required_source_ids", linuxL3RequiredSourceIds);
        command.Parameters.AddWithValue("linux_l3_required_source_count", linuxL3RequiredSourceIds.Length);
        command.Parameters.AddWithValue("linux_l1_mandatory_source_ids", LinuxL1MandatorySourceIds);
        command.Parameters.AddWithValue("linux_l1_mandatory_source_count", LinuxL1MandatorySourceIds.Length);
        command.Parameters.AddWithValue("linux_l2_mandatory_source_ids", LinuxL2MandatorySourceIds);
        command.Parameters.AddWithValue("linux_l2_mandatory_source_count", LinuxL2MandatorySourceIds.Length);
        command.Parameters.AddWithValue("linux_l2_role_source_ids", LinuxL2RoleSourceIds);
        command.Parameters.AddWithValue("linux_l2_role_source_count", LinuxL2RoleSourceIds.Length);
        command.Parameters.AddWithValue("linux_l4_mandatory_source_ids", LinuxL4MandatorySourceIds);
        command.Parameters.AddWithValue("linux_l4_mandatory_source_count", LinuxL4MandatorySourceIds.Length);
        command.Parameters.AddWithValue("linux_l4_role_source_ids", LinuxL4RoleSourceIds);
        command.Parameters.AddWithValue("linux_l4_role_source_count", LinuxL4RoleSourceIds.Length);
        var sourceHealthEvaluatedAt = DateTimeOffset.UtcNow;
        AddLinuxPollingParameters(command);
        command.Parameters.AddWithValue("source_health_stale_cutoff", sourceHealthEvaluatedAt.Subtract(SourceHealthRules.DefaultStaleAfter));
        command.Parameters.AddWithValue("passive_source_health_stale_cutoff", sourceHealthEvaluatedAt.Subtract(SourceHealthRules.PassivePollingStaleAfter));
        command.Parameters.AddWithValue("performance_source_health_stale_cutoff", sourceHealthEvaluatedAt.Subtract(SourceHealthRules.PerformanceSloStaleAfter));
        command.Parameters.AddWithValue("future_observation_cutoff", sourceHealthEvaluatedAt.Add(SourceHealthRules.MaximumFutureObservationSkew));

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

        switch (NormalizeStatusFilter(query.Status))
        {
            case "active":
                where.Add("a.status = 'active'");
                break;
            case "disabled":
                where.Add("a.status = 'disabled'");
                break;
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

        switch (query.Platform?.Trim().ToLowerInvariant())
        {
            case TelemetryPlatforms.Windows:
                where.Add("coalesce(a.platform, sh.platform, 'windows') = 'windows'");
                break;
            case TelemetryPlatforms.Linux:
                where.Add("coalesce(a.platform, sh.platform, 'windows') = 'linux'");
                break;
            case "unknown":
                where.Add("a.platform is null and sh.platform is null");
                break;
        }

        if (query.CoverageLevel.HasValue)
        {
            where.Add("coverage.current_coverage_level = @coverage_level");
            command.Parameters.AddWithValue("coverage_level", query.CoverageLevel.Value.ToString());
        }

        switch (query.SourceIssue?.Trim().ToLowerInvariant())
        {
            case "missing":
                where.Add("coalesce(sh.missing_mandatory_sources, 0) > 0");
                break;
            case "stale":
                where.Add("coalesce(sh.stale_sources, 0) > 0");
                break;
            case "degraded":
                where.Add("coalesce(sh.degraded_sources, 0) > 0");
                break;
            case "permission_denied":
                where.Add("coalesce(sh.permission_denied_sources, 0) > 0");
                break;
            case "unsupported":
                where.Add("coalesce(sh.unsupported_sources, 0) > 0");
                break;
            case "error":
                where.Add("coalesce(sh.error_sources, 0) > 0");
                break;
            case "gap":
                where.Add("coalesce(sh.gap_sources, 0) > 0");
                break;
        }

        switch (query.Pressure?.Trim().ToLowerInvariant())
        {
            case "any":
                where.Add("pressure.has_pressure");
                break;
            case "warning":
            case "high":
            case "critical":
            case "full":
            case "throttled":
                where.Add("pressure.pressure_state = @pressure_state");
                command.Parameters.AddWithValue("pressure_state", query.Pressure.Trim().ToLowerInvariant());
                break;
        }

        if (string.Equals(query.Gap, "yes", StringComparison.OrdinalIgnoreCase))
        {
            where.Add("coalesce(sh.gap_sources, 0) > 0");
        }

        switch (query.Capacity?.Trim().ToLowerInvariant())
        {
            case "warning_70":
            case "warning_85":
            case "critical_95":
            case "over_capacity":
            case "unknown":
            case "normal":
                where.Add("capacity.capacity_state = @capacity_state");
                command.Parameters.AddWithValue("capacity_state", query.Capacity.Trim().ToLowerInvariant());
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
                a.host_timezone,
                coalesce(a.platform, sh.platform, 'windows') as platform,
                lh.heartbeat_time as latest_heartbeat_time,
                lh.queue_depth as latest_queue_depth,
                nullif(lh.queue_metrics ->> 'used_percent', '')::numeric as queue_used_percent,
                pressure.pressure_state as queue_pressure_state,
                lh.last_event_time,
                (a.last_seen < @stale_cutoff) as is_stale,
                coalesce(sh.missing_mandatory_sources, 0) as missing_mandatory_sources,
                coalesce(sh.stale_sources, 0) as stale_sources,
                coalesce(sh.error_sources, 0) as error_sources,
                coalesce(sh.degraded_sources, 0) as degraded_sources,
                coalesce(sh.permission_denied_sources, 0) as permission_denied_sources,
                coalesce(sh.unsupported_sources, 0) as unsupported_sources,
                coalesce(sh.gap_sources, 0) as gap_sources,
                coverage.current_coverage_level,
                coverage.coverage_status,
                pressure.has_pressure,
                pressure.is_throttled,
                capacity.capacity_state
            from agents a
            left join lateral (
                select heartbeat_time, queue_depth, queue_metrics, last_event_time
                from agent_heartbeats
                where agent_id = a.agent_id
                order by heartbeat_time desc
                limit 1
            ) lh on true
            left join lateral (
                select
                    max(platform) as platform,
                    (
                        count(*) filter (where in_coverage_status_scope and (required_source or (requirement_kind = 'role_specific' and applicability = 'applicable')) and effective_status in ('missing', 'disabled'))
                        + case
                            when count(*) filter (
                                where lower(source_id) = any(@linux_l3_required_source_ids)
                                  and (enabled or applicability = 'applicable')
                                  and coalesce(applicability, 'applicable') not in ('not_applicable', 'unsupported')) > 0
                                then greatest(
                                    @linux_l3_required_source_count
                                    - count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids)),
                                    0)
                            else 0
                          end
                        + case
                            when count(*) filter (
                                where lower(source_id) = any(@linux_l4_mandatory_source_ids)
                                  and (enabled or details ->> 'approval_state' = 'missing_or_mismatched')) > 0
                                then greatest(
                                    @linux_l4_mandatory_source_count
                                    - count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_mandatory_source_ids)),
                                    0)
                                   + greatest(
                                    @linux_l4_role_source_count
                                    - count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids)),
                                    0)
                            else 0
                          end
                    )::int as missing_mandatory_sources,
                    count(*) filter (where in_coverage_status_scope and effective_status = 'stale')::int as stale_sources,
                    count(*) filter (
                        where in_coverage_status_scope
                          and effective_status = 'stale'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_stale_sources,
                    count(*) filter (where in_coverage_status_scope and effective_status = 'error')::int as error_sources,
                    count(*) filter (
                        where in_coverage_status_scope
                          and effective_status = 'error'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_error_sources,
                    count(*) filter (where in_coverage_status_scope and effective_status = 'degraded')::int as degraded_sources,
                    count(*) filter (
                        where in_coverage_status_scope
                          and effective_status = 'degraded'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_degraded_sources,
                    count(*) filter (where in_coverage_status_scope and effective_status = 'permission_denied')::int as permission_denied_sources,
                    count(*) filter (
                        where in_coverage_status_scope
                          and effective_status = 'permission_denied'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_permission_denied_sources,
                    count(*) filter (
                        where in_coverage_status_scope
                          and (required_source or (requirement_kind = 'role_specific' and applicability = 'applicable'))
                          and effective_status = 'permission_denied')::int as mandatory_permission_denied_sources,
                    count(*) filter (where in_coverage_status_scope and (required_source or (requirement_kind = 'role_specific' and applicability = 'applicable')) and effective_status = 'unsupported')::int as mandatory_unsupported_sources,
                    count(*) filter (where in_coverage_status_scope and effective_status = 'unsupported')::int as unsupported_sources,
                    count(*) filter (where in_coverage_status_scope and effective_status = 'healthy')::int as healthy_sources,
                    count(*) filter (
                        where in_coverage_status_scope
                          and (
                              gap_detected
                              or bookmark_gap_detected
                              or cleared_detected
                              or details ->> 'active_gap' in ('present', 'true', 'active', 'detected')
                              or details ->> 'active_bookmark_gap' in ('present', 'true', 'active', 'detected')
                              or (
                                  not (lower(source_id) = any(@linux_all_polling_source_ids))
                                  and (coalesce(gap_count, 0) > 0 or coalesce(dropped_events, 0) > 0)))
                    )::int as gap_sources,
                    count(*) filter (where in_coverage_status_scope and (coalesce(transition_state, '') = 'degraded' or details ->> 'throttle_state' = 'throttled'))::int as throttled_sources,
                    count(*) filter (where coverage_level = 'L1' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)))::int as l1_required_sources,
                    count(*) filter (where coverage_level = 'L1' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and effective_status in ('healthy', 'excepted'))::int as l1_covered_required_sources,
                    count(*) filter (where coverage_level = 'L2' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)))::int as l2_required_sources,
                    count(*) filter (where coverage_level = 'L2' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and effective_status in ('healthy', 'excepted'))::int as l2_covered_required_sources,
                    count(*) filter (where coverage_level = 'L3' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)))::int as l3_required_sources,
                    count(*) filter (where coverage_level = 'L3' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and effective_status in ('healthy', 'excepted'))::int as l3_covered_required_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids) and coverage_level = 'L3' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status in ('healthy', 'excepted'))::int as linux_l3_canonical_covered_sources,
                    count(*) filter (where coverage_level = 'L1' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l1_strict_healthy_sources,
                    count(*) filter (where coverage_level = 'L2' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l2_strict_healthy_sources,
                    count(*) filter (where coverage_level = 'L3' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l3_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l1_mandatory_source_ids) and coverage_level = 'L1' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as linux_l1_canonical_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_mandatory_source_ids) and coverage_level = 'L2' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as linux_l2_canonical_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids))::int as linux_l2_role_present_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids) and coverage_level = 'L2' and requirement_kind = 'role_specific' and applicability in ('applicable', 'not_applicable'))::int as linux_l2_role_resolved_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids) and coverage_level = 'L2' and requirement_kind = 'role_specific' and applicability = 'applicable')::int as linux_l2_role_applicable_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids) and coverage_level = 'L2' and requirement_kind = 'role_specific' and applicability = 'applicable' and enabled and effective_status = 'healthy')::int as linux_l2_role_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids) and coverage_level = 'L3' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as linux_l3_canonical_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_mandatory_source_ids) and coverage_level = 'L4' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as linux_l4_canonical_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids) and coverage_level = 'L4' and requirement_kind = 'role_specific' and applicability in ('applicable', 'not_applicable'))::int as linux_l4_role_resolved_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids) and coverage_level = 'L4' and requirement_kind = 'role_specific' and applicability = 'applicable')::int as linux_l4_role_applicable_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids) and coverage_level = 'L4' and requirement_kind = 'role_specific' and applicability = 'applicable' and enabled and effective_status = 'healthy')::int as linux_l4_role_healthy_sources,
                    count(*) filter (where source_id = 'sysmon-operational' and effective_status in ('healthy', 'excepted'))::int as windows_l3_required_healthy_sources
                from (
                    select
                        health_source.*,
                        case
                            when health_source.status = 'healthy'
                                 and lower(health_source.source_id) = any(@linux_performance_polling_source_ids)
                                 and health_source.observed_at > @future_observation_cutoff then 'degraded'
                            when health_source.status = 'healthy'
                                 and lower(health_source.source_id) = any(@linux_performance_polling_source_ids)
                                 and (health_source.observed_at is null or health_source.observed_at < @performance_source_health_stale_cutoff) then 'stale'
                            when health_source.status = 'healthy'
                                 and lower(health_source.source_id) = any(@linux_two_hour_polling_source_ids)
                                 and health_source.observed_at > @future_observation_cutoff then 'degraded'
                            when health_source.status = 'healthy'
                                 and lower(health_source.source_id) = any(@linux_two_hour_polling_source_ids)
                                 and (health_source.observed_at is null or health_source.observed_at < @passive_source_health_stale_cutoff) then 'stale'
                            when health_source.status = 'healthy'
                                 and not (lower(health_source.source_id) = any(@linux_all_polling_source_ids))
                                 and health_source.coverage_level in ('L2', 'L3', 'L4')
                                 and (health_source.requirement_kind = 'mandatory' or (health_source.requirement_kind = 'role_specific' and health_source.applicability = 'applicable') or (health_source.requirement_kind is null and health_source.required_source))
                                 and health_source.last_event_time is not null
                                 and health_source.last_event_time < @source_health_stale_cutoff then 'stale'
                            else health_source.status
                        end as effective_status,
                        (
                            coalesce(a.platform, health_source.platform, 'windows') <> 'linux'
                            or health_source.coverage_level not in ('L3', 'L4')
                            or (health_source.coverage_level = 'L3' and (
                                health_source.enabled
                                or exists (
                                select 1
                                from source_health attempted_l3
                                where attempted_l3.agent_id = a.agent_id
                                  and lower(attempted_l3.source_id) = any(@linux_l3_required_source_ids)
                                  and (attempted_l3.enabled or attempted_l3.applicability = 'applicable')
                                  and coalesce(attempted_l3.applicability, 'applicable') not in ('not_applicable', 'unsupported')
                                )))
                            or (health_source.coverage_level = 'L4' and (
                                health_source.enabled
                                or (health_source.requirement_kind = 'role_specific' and health_source.applicability = 'applicable')
                                or health_source.details ->> 'approval_state' = 'missing_or_mismatched'
                                or exists (
                                    select 1
                                    from source_health attempted_l4
                                    where attempted_l4.agent_id = a.agent_id
                                      and lower(attempted_l4.source_id) = any(@linux_l4_mandatory_source_ids)
                                      and (attempted_l4.enabled or attempted_l4.details ->> 'approval_state' = 'missing_or_mismatched')
                                )))
                        ) as in_coverage_status_scope
                    from source_health health_source
                    where health_source.agent_id = a.agent_id
                ) scoped_health
            ) sh on true
            cross join lateral (
                select
                    case
                        when coalesce(a.platform, sh.platform, 'windows') = 'linux'
                             and @linux_l4_mandatory_source_count = 2
                             and @linux_l4_role_source_count > 0
                             and @linux_l1_mandatory_source_count > 0
                             and coalesce(sh.linux_l1_canonical_strict_healthy_sources, 0) = @linux_l1_mandatory_source_count
                             and @linux_l2_mandatory_source_count > 0
                             and coalesce(sh.linux_l2_canonical_strict_healthy_sources, 0) = @linux_l2_mandatory_source_count
                             and @linux_l2_role_source_count > 0
                             and coalesce(sh.linux_l2_role_present_sources, 0) = @linux_l2_role_source_count
                             and coalesce(sh.linux_l2_role_resolved_sources, 0) = @linux_l2_role_source_count
                             and coalesce(sh.linux_l2_role_strict_healthy_sources, 0) = coalesce(sh.linux_l2_role_applicable_sources, 0)
                             and @linux_l3_required_source_count > 0
                             and coalesce(sh.linux_l3_canonical_strict_healthy_sources, 0) = @linux_l3_required_source_count
                             and coalesce(sh.linux_l4_canonical_healthy_sources, 0) = @linux_l4_mandatory_source_count
                             and coalesce(sh.linux_l4_role_resolved_sources, 0) = @linux_l4_role_source_count
                             and coalesce(sh.linux_l4_role_healthy_sources, 0) = coalesce(sh.linux_l4_role_applicable_sources, 0) then 'L4'
                        when coalesce(a.platform, sh.platform, 'windows') = 'linux'
                             and @linux_l3_required_source_count > 0
                             and coalesce(sh.l1_required_sources, 0) > 0
                             and sh.l1_required_sources = sh.l1_covered_required_sources
                             and coalesce(sh.l2_required_sources, 0) > 0
                             and sh.l2_required_sources = sh.l2_covered_required_sources
                             and coalesce(sh.l3_required_sources, 0) >= @linux_l3_required_source_count
                             and sh.l3_required_sources = sh.l3_covered_required_sources
                             and coalesce(sh.linux_l3_canonical_covered_sources, 0) = @linux_l3_required_source_count then 'L3'
                        when coalesce(a.platform, sh.platform, 'windows') = 'linux'
                             and coalesce(sh.l1_required_sources, 0) > 0
                             and sh.l1_required_sources = sh.l1_covered_required_sources
                             and coalesce(sh.l2_required_sources, 0) > 0
                             and sh.l2_required_sources = sh.l2_covered_required_sources then 'L2'
                        when coalesce(a.platform, sh.platform, 'windows') = 'linux'
                             and coalesce(sh.l1_required_sources, 0) > 0
                             and sh.l1_required_sources = sh.l1_covered_required_sources then 'L1'
                        when coalesce(a.platform, sh.platform, 'windows') <> 'linux' and coalesce(sh.error_sources, 0) = 0 and coalesce(sh.stale_sources, 0) = 0 and coalesce(sh.l2_covered_required_sources, 0) >= 13 and coalesce(sh.windows_l3_required_healthy_sources, 0) >= 1 then 'L3'
                        when coalesce(a.platform, sh.platform, 'windows') <> 'linux' and coalesce(sh.missing_mandatory_sources, 0) = 0 and coalesce(sh.error_sources, 0) = 0 and coalesce(sh.l2_covered_required_sources, 0) >= 13 then 'L2'
                        when coalesce(sh.healthy_sources, 0) >= 1 then 'L1'
                        else 'L0'
                    end as current_coverage_level,
                    case
                        when coalesce(sh.aggregate_error_sources, 0) > 0 then 'error'
                        when coalesce(sh.mandatory_permission_denied_sources, 0) > 0 then 'permission_denied'
                        when coalesce(sh.mandatory_unsupported_sources, 0) > 0 then 'unsupported'
                        when coalesce(sh.missing_mandatory_sources, 0) > 0 then 'missing'
                        when coalesce(sh.aggregate_stale_sources, 0) > 0 then 'stale'
                        when coalesce(sh.aggregate_permission_denied_sources, 0) > 0 then 'permission_denied'
                        when coalesce(sh.aggregate_degraded_sources, 0) > 0 then 'degraded'
                        when coalesce(sh.healthy_sources, 0) = 0 then 'missing'
                        else 'healthy'
                    end as coverage_status
            ) coverage
            cross join lateral (
                select
                    case
                        when coalesce(sh.throttled_sources, 0) > 0 then 'throttled'
                        else coalesce(nullif(lh.queue_metrics ->> 'pressure_state', ''), 'unknown')
                    end as pressure_state,
                    (coalesce(nullif(lh.queue_metrics ->> 'pressure_state', ''), 'normal') not in ('normal','unknown') or coalesce(sh.throttled_sources, 0) > 0) as has_pressure,
                    (coalesce(sh.throttled_sources, 0) > 0 or coalesce(nullif(lh.queue_metrics ->> 'pressure_state', ''), '') = 'throttled') as is_throttled
            ) pressure
            cross join lateral (
                select case
                    when nullif(lh.queue_metrics ->> 'used_percent', '') is null then 'unknown'
                    when nullif(lh.queue_metrics ->> 'used_percent', '')::numeric >= 100 then 'over_capacity'
                    when nullif(lh.queue_metrics ->> 'used_percent', '')::numeric >= 95 then 'critical_95'
                    when nullif(lh.queue_metrics ->> 'used_percent', '')::numeric >= 85 then 'warning_85'
                    when nullif(lh.queue_metrics ->> 'used_percent', '')::numeric >= 70 then 'warning_70'
                    else 'normal'
                end as capacity_state
            ) capacity
            """);

        if (where.Count > 0)
        {
            sql.Append(" where ");
            sql.Append(string.Join(" and ", where));
        }

        command.Parameters.AddWithValue("limit", clampedLimit);
        command.Parameters.AddWithValue("offset", clampedOffset);

        sql.Append(" order by a.last_seen desc, a.agent_id asc limit @limit offset @offset;");
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
                ReadNullableDecimal(reader, "queue_used_percent"),
                reader.GetString(reader.GetOrdinal("queue_pressure_state")),
                ReadNullableDateTimeOffset(reader, "last_event_time"),
                reader.GetBoolean(reader.GetOrdinal("is_stale")),
                reader.GetString(reader.GetOrdinal("platform")),
                Enum.Parse<WindowsCoverageLevel>(reader.GetString(reader.GetOrdinal("current_coverage_level"))),
                reader.GetString(reader.GetOrdinal("coverage_status")),
                reader.GetInt32(reader.GetOrdinal("missing_mandatory_sources")),
                reader.GetInt32(reader.GetOrdinal("stale_sources")),
                reader.GetInt32(reader.GetOrdinal("error_sources")),
                reader.GetInt32(reader.GetOrdinal("degraded_sources")),
                reader.GetInt32(reader.GetOrdinal("permission_denied_sources")),
                reader.GetInt32(reader.GetOrdinal("unsupported_sources")),
                reader.GetInt32(reader.GetOrdinal("gap_sources")),
                reader.GetBoolean(reader.GetOrdinal("has_pressure")),
                reader.GetBoolean(reader.GetOrdinal("is_throttled")),
                reader.GetString(reader.GetOrdinal("capacity_state")),
                Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone")));
        }

        return results;
    }

    public async Task<StaleAgentCleanupPreview> GetStaleAgentCleanupPreviewAsync(
        TimeSpan staleAgentAfter,
        int sampleLimit,
        CancellationToken cancellationToken)
    {
        var cutoff = DateTimeOffset.UtcNow.Subtract(staleAgentAfter);
        var clampedSampleLimit = Math.Clamp(sampleLimit, 0, 50);
        var sampleAgentIds = new List<string>();
        long candidateCount = 0;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            with candidates as (
                select agent_id, last_seen
                from agents
                where status = 'active'
                  and last_seen < @cutoff
            ), counted as (
                select count(*)::bigint as candidate_count
                from candidates
            ), sampled as (
                select agent_id
                from candidates
                order by last_seen asc, agent_id asc
                limit @sample_limit
            )
            select counted.candidate_count, sampled.agent_id
            from counted
            left join sampled on true;
            """;
        command.Parameters.AddWithValue("cutoff", cutoff.ToUniversalTime());
        command.Parameters.AddWithValue("sample_limit", clampedSampleLimit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            candidateCount = ReadInt64(reader, "candidate_count");
            var agentId = ReadNullableString(reader, "agent_id");
            if (!string.IsNullOrWhiteSpace(agentId))
            {
                sampleAgentIds.Add(agentId);
            }
        }

        return new StaleAgentCleanupPreview(cutoff, candidateCount, sampleAgentIds);
    }

    public async Task<StaleAgentCleanupSummary> DisableStaleAgentsAsync(
        TimeSpan staleAgentAfter,
        int sampleLimit,
        CancellationToken cancellationToken)
    {
        var cutoff = DateTimeOffset.UtcNow.Subtract(staleAgentAfter);
        var clampedSampleLimit = Math.Clamp(sampleLimit, 0, 50);
        var sampleAgentIds = new List<string>();
        long candidateCount = 0;
        long skippedRecentCount = 0;
        long disabledCount = 0;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var countCommand = connection.CreateCommand())
        {
            countCommand.Transaction = transaction;
            countCommand.CommandText = """
                select
                    count(*) filter (where status = 'active' and last_seen < @cutoff)::bigint as candidate_count,
                    count(*) filter (where status = 'active' and last_seen >= @cutoff)::bigint as skipped_recent_count
                from agents;
                """;
            countCommand.Parameters.AddWithValue("cutoff", cutoff.ToUniversalTime());
            await using var countReader = await countCommand.ExecuteReaderAsync(cancellationToken);
            if (await countReader.ReadAsync(cancellationToken))
            {
                candidateCount = ReadInt64(countReader, "candidate_count");
                skippedRecentCount = ReadInt64(countReader, "skipped_recent_count");
            }
        }

        await using (var updateCommand = connection.CreateCommand())
        {
            updateCommand.Transaction = transaction;
            updateCommand.CommandText = """
                with disabled as (
                    update agents
                    set status = 'disabled', updated_at = now()
                    where status = 'active'
                      and last_seen < @cutoff
                    returning agent_id
                ), counted as (
                    select count(*)::bigint as disabled_count
                    from disabled
                ), sampled as (
                    select agent_id
                    from disabled
                    order by agent_id asc
                    limit @sample_limit
                )
                select counted.disabled_count, sampled.agent_id
                from counted
                left join sampled on true;
                """;
            updateCommand.Parameters.AddWithValue("cutoff", cutoff.ToUniversalTime());
            updateCommand.Parameters.AddWithValue("sample_limit", clampedSampleLimit);

            await using var updateReader = await updateCommand.ExecuteReaderAsync(cancellationToken);
            while (await updateReader.ReadAsync(cancellationToken))
            {
                disabledCount = ReadInt64(updateReader, "disabled_count");
                var agentId = ReadNullableString(updateReader, "agent_id");
                if (!string.IsNullOrWhiteSpace(agentId))
                {
                    sampleAgentIds.Add(agentId);
                }
            }
        }

        await transaction.CommitAsync(cancellationToken);
        return new StaleAgentCleanupSummary(cutoff, candidateCount, disabledCount, skippedRecentCount, sampleAgentIds);
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

    private static void AddLinuxPollingParameters(NpgsqlCommand command)
    {
        var twoHourPollingSourceIds = SourceHealthRules.TwoHourPollingSourceIds
            .Concat(LinuxL4RoleSourceIds)
            .Append(LinuxL4MandatorySourceIds[0])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var performancePollingSourceIds = SourceHealthRules.PerformanceSloSourceIds.ToArray();
        command.Parameters.AddWithValue("linux_two_hour_polling_source_ids", twoHourPollingSourceIds);
        command.Parameters.AddWithValue("linux_performance_polling_source_ids", performancePollingSourceIds);
        command.Parameters.AddWithValue(
            "linux_all_polling_source_ids",
            twoHourPollingSourceIds.Concat(performancePollingSourceIds).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static string NormalizeStatusFilter(string? status)
    {
        return status?.Trim().ToLowerInvariant() switch
        {
            "all" => "all",
            "disabled" => "disabled",
            _ => "active"
        };
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

    private static decimal? ReadNullableDecimal(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetDecimal(ordinal);
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
