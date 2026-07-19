using System.Text.Json;
using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed record BoundedSourceHealthCollectionState(int Returned, bool Truncated);

public sealed record BoundedSourceHealthResult(
    SourceHealthResponse Health,
    int NestedLimit,
    int ReturnedNestedRecords,
    bool Truncated,
    IReadOnlyDictionary<string, BoundedSourceHealthCollectionState> Collections);

public sealed class SourceHealthRepository(NpgsqlDataSource dataSource)
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

    public Task<SourceHealthResponse> SearchAsync(string? agentId, CancellationToken cancellationToken) =>
        SearchAsync(agentId, WindowsCoverageLevel.L2, cancellationToken);

    public async Task<SourceHealthResponse> SearchAsync(string? agentId, WindowsCoverageLevel targetLevel, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var summaries = await LoadSummariesAsync(connection, agentId, targetLevel, 500, cancellationToken);
        var sources = await LoadSourcesAsync(connection, agentId, 1000, cancellationToken);
        (summaries, sources) = await MergeExpectedSourcesAsync(connection, agentId, targetLevel, summaries, sources, cancellationToken);

        return new SourceHealthResponse
        {
            Summaries = summaries,
            Sources = sources
        };
    }

    public async Task<BoundedSourceHealthResult> SearchBoundedAsync(
        string agentId,
        WindowsCoverageLevel targetLevel,
        int nestedLimit,
        CancellationToken cancellationToken)
    {
        if (nestedLimit is < 1 or > 100)
        {
            throw new ArgumentException("Nested source-health record limit must be between 1 and 100.", nameof(nestedLimit));
        }

        var fetchLimit = nestedLimit + 1;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var summaries = await LoadSummariesAsync(connection, agentId, targetLevel, fetchLimit, cancellationToken);
        var sources = await LoadSourcesAsync(connection, agentId, fetchLimit, cancellationToken);
        (summaries, sources) = await MergeExpectedSourcesAsync(connection, agentId, targetLevel, summaries, sources, cancellationToken);

        var summaryProbe = summaries.Take(fetchLimit).ToArray();
        var sourceProbe = sources.Take(fetchLimit).ToArray();
        var collections = new Dictionary<string, BoundedSourceHealthCollectionState>(StringComparer.Ordinal)
        {
            ["summaries"] = State(summaryProbe, nestedLimit),
            ["sources"] = State(sourceProbe, nestedLimit)
        };
        var health = new SourceHealthResponse
        {
            Summaries = summaryProbe.Take(nestedLimit).ToArray(),
            Sources = sourceProbe.Take(nestedLimit).ToArray()
        };
        var returned = collections.Values.Sum(item => item.Returned);
        return new BoundedSourceHealthResult(
            health,
            nestedLimit,
            returned,
            collections.Values.Any(item => item.Truncated),
            collections);
    }

    private static async Task<(IReadOnlyList<CoverageSummary> Summaries, IReadOnlyList<SourceHealthReport> Sources)> MergeExpectedSourcesAsync(
        NpgsqlConnection connection,
        string? agentId,
        WindowsCoverageLevel targetLevel,
        IReadOnlyList<CoverageSummary> summaries,
        IReadOnlyList<SourceHealthReport> sources,
        CancellationToken cancellationToken)
    {

        if (!string.IsNullOrWhiteSpace(agentId) && summaries.Count > 0)
        {
            var summary = summaries[0];
            var platform = summary.Platform
                ?? sources.Select(source => source.Platform).FirstOrDefault(value => value is not null)
                ?? TelemetryPlatforms.Windows;
            var exceptions = await LoadActiveCoverageExceptionsAsync(connection, agentId, summary.Hostname, cancellationToken);
            sources = TelemetryCoverageEvaluator.MergeExpectedSources(sources, targetLevel, exceptions, DateTimeOffset.UtcNow, platform);
            summaries = summaries
                .Select(item => TelemetryCoverageEvaluator.RecalculateSummary(item with { Platform = platform }, sources, targetLevel))
                .ToArray();
        }

        return (summaries, sources);
    }

    private static async Task<IReadOnlyList<CoverageSummary>> LoadSummariesAsync(
        NpgsqlConnection connection,
        string? agentId,
        WindowsCoverageLevel targetLevel,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            with latest_heartbeat as (
                select distinct on (agent_id)
                    agent_id,
                    heartbeat_time,
                    queue_depth,
                    queue_metrics,
                    resource_metrics
                from agent_heartbeats
                order by agent_id, heartbeat_time desc
            ), target_scoped_health as (
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
                left join agents scoped_agent on scoped_agent.agent_id = sh.agent_id
                where coalesce(scoped_agent.platform, sh.platform, 'windows') <> 'linux'
                   or @target_level = 'L4'
                   or (@target_level = 'L3' and sh.coverage_level in ('L1', 'L2', 'L3'))
                   or (@target_level = 'L2' and sh.coverage_level in ('L1', 'L2'))
                   or (@target_level = 'L1' and sh.coverage_level = 'L1')
            ), health as (
                select
                    agent_id,
                    count(*) filter (where (required_source or (requirement_kind = 'role_specific' and applicability = 'applicable')) and effective_status in ('missing', 'disabled'))::int as reported_missing_mandatory_sources,
                    count(*) filter (where (required_source or (requirement_kind = 'role_specific' and applicability = 'applicable')) and effective_status = 'permission_denied')::int as mandatory_permission_denied_sources,
                    count(*) filter (where (required_source or (requirement_kind = 'role_specific' and applicability = 'applicable')) and effective_status = 'unsupported')::int as mandatory_unsupported_sources,
                    count(*) filter (where effective_status = 'stale')::int as stale_sources,
                    count(*) filter (
                        where effective_status = 'stale'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_stale_sources,
                    count(*) filter (where effective_status = 'error')::int as error_sources,
                    count(*) filter (
                        where effective_status = 'error'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_error_sources,
                    count(*) filter (where effective_status = 'degraded')::int as degraded_sources,
                    count(*) filter (
                        where effective_status = 'degraded'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_degraded_sources,
                    count(*) filter (where effective_status = 'permission_denied')::int as permission_denied_sources,
                    count(*) filter (
                        where effective_status = 'permission_denied'
                          and not (
                              coalesce(requirement_kind, case when required_source then 'mandatory' else 'optional' end) = 'optional'
                              and coalesce(applicability, '') = 'unknown'))::int as aggregate_permission_denied_sources,
                    count(*) filter (where effective_status = 'unsupported')::int as unsupported_sources,
                    count(*) filter (where effective_status = 'excepted')::int as excepted_sources,
                    count(*) filter (where effective_status = 'not_applicable')::int as not_applicable_sources,
                    count(*) filter (where coverage_level = 'L1' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)))::int as l1_mandatory_sources,
                    count(*) filter (where coverage_level = 'L1' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and effective_status in ('healthy', 'excepted'))::int as l1_covered_mandatory_sources,
                    count(*) filter (where coverage_level = 'L2' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)))::int as l2_mandatory_sources,
                    count(*) filter (where coverage_level = 'L2' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and effective_status in ('healthy', 'excepted'))::int as l2_covered_mandatory_sources,
                    count(*) filter (where coverage_level = 'L3' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)))::int as l3_mandatory_sources,
                    count(*) filter (where coverage_level = 'L3' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and effective_status in ('healthy', 'excepted'))::int as l3_covered_mandatory_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids) and coverage_level = 'L3' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status in ('healthy', 'excepted'))::int as l3_canonical_covered_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids))::int as l3_canonical_present_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids) and (enabled or applicability = 'applicable') and coalesce(applicability, 'applicable') not in ('not_applicable', 'unsupported'))::int as l3_canonical_attempted_sources,
                    count(*) filter (where coverage_level = 'L3' and enabled and coalesce(applicability, 'applicable') not in ('not_applicable', 'unsupported'))::int as l3_applicable_sources,
                    count(*) filter (where coverage_level = 'L3' and enabled and coalesce(applicability, 'applicable') not in ('not_applicable', 'unsupported') and effective_status in ('healthy', 'excepted'))::int as l3_covered_applicable_sources,
                    count(*) filter (where coverage_level = 'L1' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l1_strict_healthy_sources,
                    count(*) filter (where coverage_level = 'L2' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l2_strict_healthy_sources,
                    count(*) filter (where coverage_level = 'L3' and (requirement_kind = 'mandatory' or (requirement_kind = 'role_specific' and applicability = 'applicable') or (requirement_kind is null and required_source)) and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l3_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l1_mandatory_source_ids) and coverage_level = 'L1' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l1_canonical_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_mandatory_source_ids) and coverage_level = 'L2' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l2_canonical_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids))::int as l2_role_present_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids) and coverage_level = 'L2' and requirement_kind = 'role_specific' and applicability in ('applicable', 'not_applicable'))::int as l2_role_resolved_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids) and coverage_level = 'L2' and requirement_kind = 'role_specific' and applicability = 'applicable')::int as l2_role_applicable_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l2_role_source_ids) and coverage_level = 'L2' and requirement_kind = 'role_specific' and applicability = 'applicable' and enabled and effective_status = 'healthy')::int as l2_role_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l3_required_source_ids) and coverage_level = 'L3' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l3_canonical_strict_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_mandatory_source_ids))::int as l4_canonical_present_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_mandatory_source_ids) and coverage_level = 'L4' and requirement_kind = 'mandatory' and enabled and applicability = 'applicable' and effective_status = 'healthy')::int as l4_canonical_healthy_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_mandatory_source_ids) and (enabled or applicability = 'applicable'))::int as l4_canonical_attempted_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids))::int as l4_role_present_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids) and coverage_level = 'L4' and requirement_kind = 'role_specific' and applicability in ('applicable', 'not_applicable'))::int as l4_role_resolved_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids) and coverage_level = 'L4' and requirement_kind = 'role_specific' and applicability = 'applicable')::int as l4_role_applicable_sources,
                    count(distinct lower(source_id)) filter (where lower(source_id) = any(@linux_l4_role_source_ids) and coverage_level = 'L4' and requirement_kind = 'role_specific' and applicability = 'applicable' and enabled and effective_status = 'healthy')::int as l4_role_healthy_sources,
                    count(*) filter (where effective_status = 'healthy')::int as healthy_sources,
                    max(platform) as platform
                from target_scoped_health
                group by agent_id
            ), health_with_expected as (
                select
                    health.*,
                    (
                        reported_missing_mandatory_sources
                        + case
                            when @target_level in ('L3', 'L4')
                                 and platform = 'linux'
                                 and l3_canonical_attempted_sources > 0
                                then greatest(@linux_l3_required_source_count - l3_canonical_present_sources, 0)
                            else 0
                          end
                        + case
                            when @target_level = 'L4'
                                 and platform = 'linux'
                                 and l4_canonical_attempted_sources > 0
                                then greatest(@linux_l4_mandatory_source_count - l4_canonical_present_sources, 0)
                                   + greatest(@linux_l4_role_source_count - l4_role_present_sources, 0)
                            else 0
                          end
                    )::int as missing_mandatory_sources
                from health
            )
            select
                a.agent_id,
                a.hostname,
                a.host_timezone,
                coalesce(a.platform, h.platform) as platform,
                coalesce(h.missing_mandatory_sources, 0) as missing_mandatory_sources,
                coalesce(h.stale_sources, 0) as stale_sources,
                coalesce(h.error_sources, 0) as error_sources,
                coalesce(h.degraded_sources, 0) as degraded_sources,
                coalesce(h.permission_denied_sources, 0) as permission_denied_sources,
                coalesce(h.unsupported_sources, 0) as unsupported_sources,
                coalesce(h.excepted_sources, 0) as excepted_sources,
                coalesce(h.not_applicable_sources, 0) as not_applicable_sources,
                coalesce(lh.queue_depth, 0) as queue_depth,
                lh.queue_metrics,
                lh.resource_metrics,
                lh.heartbeat_time as last_heartbeat_time,
                case
                    when a.last_seen is null then 'L0'
                    when @target_level = 'L4'
                         and coalesce(a.platform, h.platform) = 'linux'
                         and @linux_l4_mandatory_source_count = 2
                         and @linux_l4_role_source_count > 0
                         and @linux_l1_mandatory_source_count > 0
                         and coalesce(h.l1_canonical_strict_healthy_sources, 0) = @linux_l1_mandatory_source_count
                         and @linux_l2_mandatory_source_count > 0
                         and coalesce(h.l2_canonical_strict_healthy_sources, 0) = @linux_l2_mandatory_source_count
                         and @linux_l2_role_source_count > 0
                         and coalesce(h.l2_role_present_sources, 0) = @linux_l2_role_source_count
                         and coalesce(h.l2_role_resolved_sources, 0) = @linux_l2_role_source_count
                         and coalesce(h.l2_role_strict_healthy_sources, 0) = coalesce(h.l2_role_applicable_sources, 0)
                         and @linux_l3_required_source_count > 0
                         and coalesce(h.l3_canonical_strict_healthy_sources, 0) = @linux_l3_required_source_count
                         and coalesce(h.l4_canonical_healthy_sources, 0) = @linux_l4_mandatory_source_count
                         and coalesce(h.l4_role_resolved_sources, 0) = @linux_l4_role_source_count
                         and coalesce(h.l4_role_healthy_sources, 0) = coalesce(h.l4_role_applicable_sources, 0) then 'L4'
                    when @target_level in ('L3', 'L4')
                         and coalesce(a.platform, h.platform) = 'linux'
                         and @linux_l3_required_source_count > 0
                         and coalesce(h.l1_mandatory_sources, 0) > 0
                         and h.l1_mandatory_sources = h.l1_covered_mandatory_sources
                         and coalesce(h.l2_mandatory_sources, 0) > 0
                         and h.l2_mandatory_sources = h.l2_covered_mandatory_sources
                         and coalesce(h.l3_mandatory_sources, 0) >= @linux_l3_required_source_count
                         and coalesce(h.l3_mandatory_sources, 0) = coalesce(h.l3_covered_mandatory_sources, 0)
                         and coalesce(h.l3_canonical_covered_sources, 0) = @linux_l3_required_source_count
                         and coalesce(h.l3_applicable_sources, 0) > 0
                         and coalesce(h.l3_covered_applicable_sources, 0) > 0 then 'L3'
                    when @target_level in ('L2', 'L3', 'L4')
                         and coalesce(a.platform, h.platform) = 'linux'
                         and coalesce(h.l1_mandatory_sources, 0) > 0
                         and h.l1_mandatory_sources = h.l1_covered_mandatory_sources
                         and coalesce(h.l2_mandatory_sources, 0) > 0
                         and h.l2_mandatory_sources = h.l2_covered_mandatory_sources then 'L2'
                    when @target_level in ('L1', 'L2', 'L3', 'L4')
                         and coalesce(a.platform, h.platform) = 'linux'
                         and coalesce(h.l1_mandatory_sources, 0) > 0
                         and h.l1_mandatory_sources = h.l1_covered_mandatory_sources then 'L1'
                    when @target_level in ('L2', 'L3', 'L4')
                         and coalesce(a.platform, h.platform) <> 'linux'
                         and coalesce(h.missing_mandatory_sources, 0) = 0
                         and coalesce(h.error_sources, 0) = 0
                         and coalesce(h.healthy_sources, 0) >= 12 then 'L2'
                    when @target_level in ('L1', 'L2', 'L3', 'L4')
                         and coalesce(a.platform, h.platform) <> 'linux'
                         and coalesce(h.healthy_sources, 0) >= 1 then 'L1'
                    else 'L0'
                end as current_level,
                case
                    when coalesce(h.aggregate_error_sources, 0) > 0 then 'error'
                    when coalesce(h.mandatory_permission_denied_sources, 0) > 0 then 'permission_denied'
                    when coalesce(h.mandatory_unsupported_sources, 0) > 0 then 'unsupported'
                    when coalesce(h.missing_mandatory_sources, 0) > 0 then 'missing'
                    when coalesce(h.aggregate_stale_sources, 0) > 0 then 'stale'
                    when coalesce(h.aggregate_permission_denied_sources, 0) > 0 then 'permission_denied'
                    when coalesce(h.aggregate_degraded_sources, 0) > 0 then 'degraded'
                    when coalesce(h.healthy_sources, 0) = 0 then 'missing'
                    else 'healthy'
                end as overall_status
            from agents a
            left join health_with_expected h on h.agent_id = a.agent_id
            left join latest_heartbeat lh on lh.agent_id = a.agent_id
            """;
        if (!string.IsNullOrWhiteSpace(agentId))
        {
            command.CommandText += " where a.agent_id = @agent_id";
            command.Parameters.AddWithValue("agent_id", agentId);
        }

        command.CommandText += " order by a.hostname asc, a.agent_id asc limit @limit;";
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
        var twoHourPollingSourceIds = SourceHealthRules.TwoHourPollingSourceIds
            .Concat(LinuxL4RoleSourceIds)
            .Append(LinuxL4MandatorySourceIds[0])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var performancePollingSourceIds = SourceHealthRules.PerformanceSloSourceIds.ToArray();
        command.Parameters.AddWithValue("linux_two_hour_polling_source_ids", twoHourPollingSourceIds);
        command.Parameters.AddWithValue("linux_performance_polling_source_ids", performancePollingSourceIds);
        command.Parameters.AddWithValue("linux_all_polling_source_ids", twoHourPollingSourceIds.Concat(performancePollingSourceIds).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        var now = DateTimeOffset.UtcNow;
        command.Parameters.AddWithValue("source_health_stale_cutoff", now.Subtract(SourceHealthRules.DefaultStaleAfter));
        command.Parameters.AddWithValue("passive_source_health_stale_cutoff", now.Subtract(SourceHealthRules.PassivePollingStaleAfter));
        command.Parameters.AddWithValue("performance_source_health_stale_cutoff", now.Subtract(SourceHealthRules.PerformanceSloStaleAfter));
        command.Parameters.AddWithValue("future_observation_cutoff", now.Add(SourceHealthRules.MaximumFutureObservationSkew));
        command.Parameters.AddWithValue("target_level", targetLevel.ToString());
        command.Parameters.AddWithValue("limit", limit);

        var results = new List<CoverageSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new CoverageSummary
            {
                AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
                Hostname = reader.GetString(reader.GetOrdinal("hostname")),
                Platform = ReadNullableString(reader, "platform"),
                TargetLevel = targetLevel,
                CurrentLevel = Enum.Parse<WindowsCoverageLevel>(reader.GetString(reader.GetOrdinal("current_level"))),
                OverallStatus = reader.GetString(reader.GetOrdinal("overall_status")),
                MissingMandatorySources = reader.GetInt32(reader.GetOrdinal("missing_mandatory_sources")),
                StaleSources = reader.GetInt32(reader.GetOrdinal("stale_sources")),
                ErrorSources = reader.GetInt32(reader.GetOrdinal("error_sources")),
                DegradedSources = reader.GetInt32(reader.GetOrdinal("degraded_sources")),
                PermissionDeniedSources = reader.GetInt32(reader.GetOrdinal("permission_denied_sources")),
                UnsupportedSources = reader.GetInt32(reader.GetOrdinal("unsupported_sources")),
                ExceptedSources = reader.GetInt32(reader.GetOrdinal("excepted_sources")),
                NotApplicableSources = reader.GetInt32(reader.GetOrdinal("not_applicable_sources")),
                QueueDepth = reader.GetInt32(reader.GetOrdinal("queue_depth")),
                QueueMetrics = Jsonb.Read<QueueSloMetrics>(reader, "queue_metrics"),
                ResourceMetrics = Jsonb.Read<AgentResourceMetrics>(reader, "resource_metrics"),
                LastHeartbeatTime = ReadNullableDateTimeOffset(reader, "last_heartbeat_time"),
                HostTimezone = Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone")
            });
        }

        return results;
    }

    private static async Task<IReadOnlyList<SourceHealthReport>> LoadSourcesAsync(
        NpgsqlConnection connection,
        string? agentId,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select
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
                host_timezone
            from source_health
            """;
        if (!string.IsNullOrWhiteSpace(agentId))
        {
            command.CommandText += " where agent_id = @agent_id";
            command.Parameters.AddWithValue("agent_id", agentId);
        }

        command.CommandText += " order by coverage_level asc, display_name asc limit @limit;";
        command.Parameters.AddWithValue("limit", limit);

        var results = new List<SourceHealthReport>();
        var evaluatedAt = DateTimeOffset.UtcNow;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var report = new SourceHealthReport
            {
                SourceId = reader.GetString(reader.GetOrdinal("source_id")),
                DisplayName = reader.GetString(reader.GetOrdinal("display_name")),
                Platform = ReadNullableString(reader, "platform"),
                SourceKind = ReadNullableString(reader, "source_kind"),
                Channel = ReadNullableString(reader, "channel"),
                SourceNamespace = ReadNullableString(reader, "source_namespace"),
                Facility = ReadNullableString(reader, "facility"),
                Unit = ReadNullableString(reader, "unit"),
                Applicability = ReadNullableString(reader, "applicability"),
                ApplicabilityReason = ReadNullableString(reader, "applicability_reason"),
                CoverageLevel = Enum.Parse<WindowsCoverageLevel>(reader.GetString(reader.GetOrdinal("coverage_level"))),
                Status = reader.GetString(reader.GetOrdinal("status")),
                Required = reader.GetBoolean(reader.GetOrdinal("required_source")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                LastEventTime = ReadNullableDateTimeOffset(reader, "last_event_time"),
                ObservedAt = ReadNullableDateTimeOffset(reader, "observed_at"),
                HostTimezone = Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone"),
                LastRecordId = ReadNullableInt64(reader, "last_record_id"),
                OldestRecordId = ReadNullableInt64(reader, "oldest_record_id"),
                NewestRecordId = ReadNullableInt64(reader, "newest_record_id"),
                LogSizeBytes = ReadNullableInt64(reader, "log_size_bytes"),
                RetentionDays = ReadNullableInt32(reader, "retention_days"),
                LagSeconds = ReadNullableInt64(reader, "lag_seconds"),
                SilenceSeconds = ReadNullableInt64(reader, "silence_seconds"),
                EventRatePerMinute = ReadNullableDecimal(reader, "event_rate_per_minute"),
                ErrorCode = ReadNullableString(reader, "error_code"),
                ErrorMessage = ReadNullableString(reader, "error_message"),
                GapDetected = reader.GetBoolean(reader.GetOrdinal("gap_detected")),
                ClearedDetected = reader.GetBoolean(reader.GetOrdinal("cleared_detected")),
                BookmarkGapDetected = reader.GetBoolean(reader.GetOrdinal("bookmark_gap_detected")),
                GapCount = ReadNullableInt64(reader, "gap_count"),
                PermissionDeniedSince = ReadNullableDateTimeOffset(reader, "permission_denied_since"),
                RecoveredAt = ReadNullableDateTimeOffset(reader, "recovered_at"),
                TransitionState = ReadNullableString(reader, "transition_state"),
                TransitionedAt = ReadNullableDateTimeOffset(reader, "transitioned_at"),
                DroppedEvents = ReadNullableInt64(reader, "dropped_events"),
                PoisonEvents = ReadNullableInt64(reader, "poison_events"),
                ConfigHash = ReadNullableString(reader, "config_hash"),
                SourceVersion = ReadNullableString(reader, "source_version"),
                Requirement = ReadNullableString(reader, "requirement_kind"),
                ApplicableRoles = Jsonb.Read<string[]>(reader, "applicable_roles"),
                PrerequisiteStatuses = Jsonb.Read<Dictionary<string, string>>(reader, "prerequisite_statuses"),
                EventFamilyStatuses = Jsonb.Read<Dictionary<string, string>>(reader, "event_family_statuses"),
                CollectedCheckpoint = Jsonb.Read<SourceCheckpoint>(reader, "collected_checkpoint"),
                AcknowledgedCheckpoint = Jsonb.Read<SourceCheckpoint>(reader, "acknowledged_checkpoint"),
                Details = ReadStringDictionary(reader, "details")
            };
            results.Add(report with { Status = SourceHealthRules.EffectiveStatus(report, evaluatedAt) });
        }

        return results;
    }

    private static BoundedSourceHealthCollectionState State<T>(IReadOnlyCollection<T> rows, int limit) =>
        new(Math.Min(rows.Count, limit), rows.Count > limit);

    private static async Task<IReadOnlySet<string>> LoadActiveCoverageExceptionsAsync(
        NpgsqlConnection connection,
        string agentId,
        string? hostname,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select distinct source_id
            from coverage_exceptions
            where (agent_id = @agent_id or (agent_id is null and (hostname is null or hostname = @hostname)))
              and (expires_at is null or expires_at > now());
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("hostname", string.IsNullOrWhiteSpace(hostname) ? string.Empty : hostname);
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(reader.GetString(reader.GetOrdinal("source_id")));
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

    private static decimal? ReadNullableDecimal(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetDecimal(ordinal);
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
