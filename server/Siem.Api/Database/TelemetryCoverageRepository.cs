using System.Text.Json;
using Challenger.Siem.Api.Coverage;
using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed class TelemetryCoverageRepository(
    NpgsqlDataSource dataSource,
    SourceHealthRepository sourceHealth,
    AlertRepository alerts)
{
    private static readonly IReadOnlyList<string> WindowsInventorySnapshotTypes = new[]
    {
        "host_identity",
        "network",
        "local_users_groups",
        "services_drivers",
        "scheduled_tasks_autoruns",
        "installed_software",
        "patches_features",
        "defender_firewall_bitlocker_policy",
        "audit_policy",
        "windows_role_detection"
    };

    private static readonly IReadOnlyList<string> LinuxInventorySnapshotTypes = new[]
    {
        "linux_host_identity",
        "linux_users",
        "linux_groups",
        "linux_services",
        "linux_units",
        "linux_timers",
        "linux_packages",
        "linux_available_updates",
        "linux_interfaces",
        "linux_listeners",
        "linux_mounts",
        "linux_firewall",
        "linux_ssh",
        "linux_mandatory_access_control",
        "linux_secure_boot",
        "linux_agent_integrity"
    };

    public async Task<TelemetryCoverageResponse> AssessAsync(
        string? agentId,
        WindowsCoverageLevel targetLevel,
        int lookbackHours,
        CancellationToken cancellationToken)
    {
        var clampedLookbackHours = Math.Clamp(lookbackHours, 1, 168);
        var lookbackEnd = DateTimeOffset.UtcNow;
        var lookbackStart = lookbackEnd.AddHours(-clampedLookbackHours);
        var agents = await LoadAgentsAsync(agentId, cancellationToken);
        var rules = await alerts.GetRulesAsync(cancellationToken);
        var results = new List<AgentTelemetryCoverage>();

        foreach (var agent in agents)
        {
            var sourceResponse = await sourceHealth.SearchAsync(agent.AgentId, targetLevel, cancellationToken);
            var sources = sourceResponse.Sources;
            var summary = sourceResponse.Summaries.FirstOrDefault()
                ?? TelemetryCoverageEvaluator.CreateSummary(agent.AgentId, agent.Hostname, 0, null, sources, targetLevel);
            var platform = summary.Platform ?? agent.Platform;
            summary = summary with
            {
                Platform = platform,
                HostTimezone = summary.HostTimezone ?? agent.HostTimezone
            };
            var eventCountsBySource = await LoadRecentEventCountsBySourceAsync(agent.AgentId, lookbackStart, lookbackEnd, cancellationToken);
            var recentEventCount = eventCountsBySource.Values.Sum();
            var sourceCoverage = sources
                .Select(source => ToSourceCoverage(agent.AgentId, source, lookbackStart, eventCountsBySource, agent.HostTimezone))
                .ToArray();
            var inventory = await LoadInventoryStatusesAsync(agent.AgentId, platform, lookbackStart, cancellationToken);
            var inventoryByType = inventory.ToDictionary(item => item.SnapshotType, StringComparer.OrdinalIgnoreCase);
            var detectionPrerequisites = string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
                ? Array.Empty<DetectionPrerequisiteTelemetryStatus>()
                : TelemetryCoverageEvaluator.EvaluateDetectionPrerequisites(rules, sourceCoverage, inventoryByType, targetLevel);
            var alertStatusCounts = await LoadAlertStatusCountsAsync(agent.AgentId, lookbackStart, cancellationToken);
            var newAlertCount = alertStatusCounts.GetValueOrDefault(AlertStatuses.New);
            var activeGraphCount = await CountActiveGraphsAsync(agent.AgentId, cancellationToken);
            var expectedSourceCount = string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
                ? LinuxTelemetrySourceCatalog.ExpectedFor(targetLevel).Count
                : WindowsTelemetrySourceCatalog.ExpectedFor(targetLevel).Count;
            var reportedSourceCount = CountReportedSources(sources);
            var sourceStatusCounts = sourceCoverage
                .GroupBy(source => source.Status, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
            var gaps = BuildGaps(summary, recentEventCount, expectedSourceCount, reportedSourceCount, inventory, detectionPrerequisites);

            results.Add(new AgentTelemetryCoverage
            {
                AgentId = agent.AgentId,
                Hostname = agent.Hostname,
                Platform = platform,
                AgentStatus = agent.Status,
                LastSeen = agent.LastSeen,
                HostTimezone = agent.HostTimezone,
                TargetLevel = targetLevel,
                CurrentLevel = summary.CurrentLevel,
                OverallStatus = summary.OverallStatus,
                RecentEventCount = recentEventCount,
                ExpectedSourceCount = expectedSourceCount,
                ReportedSourceCount = reportedSourceCount,
                SourceStatusCounts = sourceStatusCounts,
                QueueMetrics = summary.QueueMetrics,
                ResourceMetrics = summary.ResourceMetrics,
                MissingMandatorySources = summary.MissingMandatorySources,
                StaleSources = summary.StaleSources,
                ErrorSources = summary.ErrorSources,
                DegradedSources = summary.DegradedSources,
                PermissionDeniedSources = summary.PermissionDeniedSources,
                UnsupportedSources = summary.UnsupportedSources,
                ExceptedSources = summary.ExceptedSources,
                NotApplicableSources = summary.NotApplicableSources,
                NewAlertCount = newAlertCount,
                AlertStatusCounts = alertStatusCounts,
                ActiveGraphCount = activeGraphCount,
                Sources = sourceCoverage,
                Inventory = inventory,
                DetectionPrerequisites = detectionPrerequisites,
                Gaps = gaps
            });
        }

        return new TelemetryCoverageResponse
        {
            GeneratedAt = lookbackEnd,
            LookbackStart = lookbackStart,
            LookbackEnd = lookbackEnd,
            LookbackHours = clampedLookbackHours,
            TargetLevel = targetLevel,
            Agents = results
        };
    }

    private async Task<IReadOnlyList<AgentRecord>> LoadAgentsAsync(string? agentId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select agent_id, hostname, status, last_seen, host_timezone, coalesce(platform, 'windows') as platform
            from agents
            """;
        if (string.IsNullOrWhiteSpace(agentId))
        {
            command.CommandText += " where status = 'active'";
        }
        else
        {
            command.CommandText += " where agent_id = @agent_id";
            command.Parameters.AddWithValue("agent_id", agentId);
        }

        command.CommandText += " order by last_seen desc, agent_id asc limit 100;";
        var results = new List<AgentRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AgentRecord(
                reader.GetString(reader.GetOrdinal("agent_id")),
                reader.GetString(reader.GetOrdinal("hostname")),
                reader.GetString(reader.GetOrdinal("status")),
                ReadDateTimeOffset(reader, "last_seen"),
                Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone"),
                reader.GetString(reader.GetOrdinal("platform"))));
        }

        return results;
    }

    private async Task<IReadOnlyDictionary<string, int>> LoadRecentEventCountsBySourceAsync(
        string agentId,
        DateTimeOffset lookbackStart,
        DateTimeOffset lookbackEnd,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select source_id, channel, count(*)::int as event_count
            from events
            where agent_id = @agent_id
              and event_time >= @lookback_start
              and event_time <= @lookback_end
            group by source_id, channel;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("lookback_start", lookbackStart.ToUniversalTime());
        command.Parameters.AddWithValue("lookback_end", lookbackEnd.ToUniversalTime());
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var sourceIdOrdinal = reader.GetOrdinal("source_id");
            var channelOrdinal = reader.GetOrdinal("channel");
            var sourceId = reader.IsDBNull(sourceIdOrdinal) ? null : reader.GetString(sourceIdOrdinal);
            if (sourceId is null && !reader.IsDBNull(channelOrdinal))
            {
                var channel = reader.GetString(channelOrdinal);
                sourceId = WindowsTelemetrySourceCatalog.FindByChannel(channel)?.SourceId ?? Slug(channel);
            }
            if (sourceId is not null)
            {
                counts[sourceId] = counts.GetValueOrDefault(sourceId) + reader.GetInt32(reader.GetOrdinal("event_count"));
            }
        }

        return counts;
    }

    private async Task<IReadOnlyList<InventoryTelemetryStatus>> LoadInventoryStatusesAsync(
        string agentId,
        string platform,
        DateTimeOffset lookbackStart,
        CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select distinct on (snapshot_type)
                snapshot_type,
                collected_at,
                host_timezone,
                jsonb_array_length(items) as item_count,
                summary
            from asset_inventory_snapshots
            where agent_id = @agent_id
            order by snapshot_type, collected_at desc;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        var latest = new Dictionary<string, InventorySnapshotRecord>(StringComparer.OrdinalIgnoreCase);
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var snapshotType = reader.GetString(reader.GetOrdinal("snapshot_type"));
                latest[snapshotType] = new InventorySnapshotRecord(
                    snapshotType,
                    ReadDateTimeOffset(reader, "collected_at"),
                    Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone"),
                    reader.GetInt32(reader.GetOrdinal("item_count")),
                    ReadStringDictionary(reader, "summary"));
            }
        }

        var expectedTypes = string.Equals(platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
            ? LinuxInventorySnapshotTypes
            : WindowsInventorySnapshotTypes;
        return expectedTypes
            .Select(type => ToInventoryStatus(agentId, type, latest.GetValueOrDefault(type), lookbackStart))
            .ToArray();
    }

    private async Task<IReadOnlyDictionary<string, int>> LoadAlertStatusCountsAsync(string agentId, DateTimeOffset lookbackStart, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select status, count(*)::int as alert_count
            from alerts
            where agent_id = @agent_id
              and created_at >= @lookback_start
            group by status;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("lookback_start", lookbackStart.ToUniversalTime());
        var results = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results[reader.GetString(reader.GetOrdinal("status"))] = reader.GetInt32(reader.GetOrdinal("alert_count"));
        }

        return results;
    }

    private async Task<int> CountActiveGraphsAsync(string agentId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select count(distinct g.graph_id)::int
            from investigation_graphs g
            join investigation_graph_nodes n on n.graph_id = g.graph_id
            where g.status = 'active'
              and n.status = 'active'
              and n.reference_kind = 'agent'
              and n.reference_id = @agent_id;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }

    private static SourceTelemetryCoverage ToSourceCoverage(
        string agentId,
        SourceHealthReport source,
        DateTimeOffset lookbackStart,
        IReadOnlyDictionary<string, int> eventCountsBySource,
        HostTimezoneMetadata? fallbackTimezone)
    {
        var recentCount = eventCountsBySource.GetValueOrDefault(source.SourceId);
        return new SourceTelemetryCoverage
        {
            SourceId = source.SourceId,
            DisplayName = source.DisplayName,
            Channel = source.Channel ?? string.Empty,
            Platform = source.Platform,
            SourceKind = source.SourceKind,
            SourceNamespace = source.SourceNamespace,
            Applicability = source.Applicability,
            ApplicabilityReason = source.ApplicabilityReason,
            Requirement = source.Requirement,
            ApplicableRoles = source.ApplicableRoles,
            PrerequisiteStatuses = source.PrerequisiteStatuses,
            EventFamilyStatuses = source.EventFamilyStatuses,
            CoverageLevel = source.CoverageLevel,
            Required = source.Required,
            Enabled = source.Enabled,
            Reported = IsReportedByAgent(source),
            Status = source.Status,
            LastEventTime = source.LastEventTime,
            ObservedAt = source.ObservedAt,
            HostTimezone = source.HostTimezone ?? fallbackTimezone,
            SilenceSeconds = source.SilenceSeconds,
            EventRatePerMinute = source.EventRatePerMinute,
            GapCount = source.GapCount,
            TransitionState = source.TransitionState,
            TransitionedAt = source.TransitionedAt,
            SourceVersion = source.SourceVersion,
            ConfigHash = source.ConfigHash,
            Details = source.Details,
            RecentEventCount = recentCount,
            Reason = SourceReason(source, recentCount),
            EventSearchUrl = source.SourceId is { Length: > 0 } && source.SourceKind is not null
                ? $"/events?agent_id={Uri.EscapeDataString(agentId)}&source_id={Uri.EscapeDataString(source.SourceId)}&from={Uri.EscapeDataString(lookbackStart.ToString("O"))}"
                : $"/events?agent_id={Uri.EscapeDataString(agentId)}&channel={Uri.EscapeDataString(source.Channel ?? string.Empty)}&from={Uri.EscapeDataString(lookbackStart.ToString("O"))}",
            SourceHealthUrl = $"/agents/detail?agent_id={Uri.EscapeDataString(agentId)}"
        };
    }

    private static InventoryTelemetryStatus ToInventoryStatus(
        string agentId,
        string snapshotType,
        InventorySnapshotRecord? snapshot,
        DateTimeOffset lookbackStart)
    {
        var url = string.Equals(snapshotType, "audit_policy", StringComparison.OrdinalIgnoreCase)
            ? $"/audit-policy?agent_id={Uri.EscapeDataString(agentId)}"
            : $"/api/v1/inventory?agent_id={Uri.EscapeDataString(agentId)}&snapshot_type={Uri.EscapeDataString(snapshotType)}";

        if (snapshot is null)
        {
            return new InventoryTelemetryStatus
            {
                SnapshotType = snapshotType,
                Status = SourceHealthStatuses.Missing,
                Reason = "Expected inventory snapshot has not been reported.",
                Url = url
            };
        }

        if (snapshot.CollectedAt < lookbackStart)
        {
            return new InventoryTelemetryStatus
            {
                SnapshotType = snapshotType,
                Status = SourceHealthStatuses.Stale,
                LatestCollectedAt = snapshot.CollectedAt,
                HostTimezone = snapshot.HostTimezone,
                ItemCount = snapshot.ItemCount,
                Reason = "Latest inventory snapshot is older than the validation lookback.",
                Url = url
            };
        }

        if (snapshot.Summary.TryGetValue("state", out var collectionState)
            && !string.Equals(collectionState, "success", StringComparison.Ordinal))
        {
            var (status, reason) = collectionState switch
            {
                "not_applicable" => (SourceHealthStatuses.NotApplicable, "Inventory source is not applicable to this host."),
                "permission_denied" => (SourceHealthStatuses.PermissionDenied, "Inventory source access was denied."),
                "unavailable" => (SourceHealthStatuses.Missing, "Inventory source or prerequisite is unavailable."),
                "timeout" => (SourceHealthStatuses.Degraded, "Inventory source exceeded its bounded collection deadline."),
                "malformed" => (SourceHealthStatuses.Error, "Inventory source returned malformed bounded data."),
                _ => (SourceHealthStatuses.Degraded, "Inventory source reported an unknown collection state.")
            };
            return new InventoryTelemetryStatus
            {
                SnapshotType = snapshotType,
                Status = status,
                LatestCollectedAt = snapshot.CollectedAt,
                HostTimezone = snapshot.HostTimezone,
                ItemCount = snapshot.ItemCount,
                Reason = reason,
                Url = url
            };
        }

        if (string.Equals(snapshotType, "audit_policy", StringComparison.OrdinalIgnoreCase)
            && snapshot.Summary.TryGetValue("drift_count", out var driftText)
            && int.TryParse(driftText, out var driftCount)
            && driftCount > 0)
        {
            return new InventoryTelemetryStatus
            {
                SnapshotType = snapshotType,
                Status = SourceHealthStatuses.Error,
                LatestCollectedAt = snapshot.CollectedAt,
                HostTimezone = snapshot.HostTimezone,
                ItemCount = snapshot.ItemCount,
                Reason = $"Audit-policy snapshot reports {driftCount} drifted required setting(s).",
                Url = url
            };
        }

        return new InventoryTelemetryStatus
        {
            SnapshotType = snapshotType,
            Status = SourceHealthStatuses.Healthy,
            LatestCollectedAt = snapshot.CollectedAt,
            HostTimezone = snapshot.HostTimezone,
            ItemCount = snapshot.ItemCount,
            Reason = "Recent bounded inventory snapshot is available.",
            Url = url
        };
    }

    private static IReadOnlyList<string> BuildGaps(
        CoverageSummary summary,
        int recentEventCount,
        int expectedSourceCount,
        int reportedSourceCount,
        IReadOnlyList<InventoryTelemetryStatus> inventory,
        IReadOnlyList<DetectionPrerequisiteTelemetryStatus> detectionPrerequisites)
    {
        var gaps = new List<string>();
        if (reportedSourceCount <= 1 && expectedSourceCount > 1)
        {
            gaps.Add($"Only {reportedSourceCount} source-health row(s) have been reported for {expectedSourceCount} expected source(s).");
        }

        if (summary.MissingMandatorySources > 0)
        {
            gaps.Add($"{summary.MissingMandatorySources} mandatory source(s) are missing or disabled.");
        }

        if (summary.StaleSources > 0)
        {
            gaps.Add($"{summary.StaleSources} source(s) are stale.");
        }

        if (summary.ErrorSources > 0)
        {
            gaps.Add($"{summary.ErrorSources} source(s) report collection errors or gap/clear indicators.");
        }

        if (summary.PermissionDeniedSources > 0)
        {
            gaps.Add($"{summary.PermissionDeniedSources} source(s) report permission-denied access.");
        }

        if (summary.DegradedSources > 0)
        {
            gaps.Add($"{summary.DegradedSources} source(s) report degraded or uncertain coverage.");
        }

        if (summary.UnsupportedSources > 0)
        {
            gaps.Add($"{summary.UnsupportedSources} source(s) are explicitly unsupported by the current collector set.");
        }

        if (recentEventCount == 0)
        {
            gaps.Add("No recent normalized events were observed for this agent in the validation lookback.");
        }

        var missingInventory = inventory.Count(item => string.Equals(item.Status, SourceHealthStatuses.Missing, StringComparison.OrdinalIgnoreCase));
        if (missingInventory > 0)
        {
            gaps.Add($"{missingInventory} expected inventory/audit-policy snapshot type(s) are missing.");
        }

        var detectionMissing = detectionPrerequisites.Count(item => string.Equals(item.Status, TelemetryCoverageEvaluator.StatusMissingPrerequisites, StringComparison.OrdinalIgnoreCase));
        var detectionUnknown = detectionPrerequisites.Count(item => string.Equals(item.Status, TelemetryCoverageEvaluator.StatusUnknown, StringComparison.OrdinalIgnoreCase));
        if (detectionMissing > 0 || detectionUnknown > 0)
        {
            gaps.Add($"{detectionMissing} detection rule(s) have missing prerequisites and {detectionUnknown} have unknown recent-event validation.");
        }

        return gaps;
    }

    private static int CountReportedSources(IReadOnlyList<SourceHealthReport> sources) =>
        sources.Count(IsReportedByAgent);

    private static bool IsReportedByAgent(SourceHealthReport source) =>
        !source.Details.TryGetValue("reported_by_agent", out var reported)
        || string.Equals(reported, "true", StringComparison.OrdinalIgnoreCase);

    private static string SourceReason(SourceHealthReport source, int recentCount)
    {
        if (string.Equals(source.Status, SourceHealthStatuses.Excepted, StringComparison.OrdinalIgnoreCase))
        {
            return "Active coverage exception marks this source as excepted.";
        }

        if (!IsReportedByAgent(source))
        {
            return "Expected source has not been reported by the agent source-health heartbeat.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase) && recentCount == 0)
        {
            return "Source health is healthy, but no normalized events for this source arrived in the lookback.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase))
        {
            return "Source health is healthy and recent normalized events were observed.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Stale, StringComparison.OrdinalIgnoreCase))
        {
            return "Source health is stale for the validation freshness window.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Error, StringComparison.OrdinalIgnoreCase))
        {
            return "Source reports a collection error, event-log gap, clear, or bookmark issue.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.PermissionDenied, StringComparison.OrdinalIgnoreCase))
        {
            return "Source access is permission denied; no privilege expansion was attempted.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Unsupported, StringComparison.OrdinalIgnoreCase))
        {
            return "Source is explicitly unsupported by the current collector set.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Degraded, StringComparison.OrdinalIgnoreCase))
        {
            return "Source coverage is degraded or applicability remains uncertain.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.NotApplicable, StringComparison.OrdinalIgnoreCase))
        {
            return "Source is explicitly not applicable to the declared host role or platform.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Disabled, StringComparison.OrdinalIgnoreCase))
        {
            return "Source is disabled according to agent source-health.";
        }

        if (string.Equals(source.Status, SourceHealthStatuses.Missing, StringComparison.OrdinalIgnoreCase))
        {
            return "Source is missing according to agent source-health.";
        }

        return "Source status is available for review.";
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

    private static string Slug(string value)
    {
        var chars = value.ToLowerInvariant().Select(ch => char.IsLetterOrDigit(ch) ? ch : '-').ToArray();
        return new string(chars).Trim('-');
    }

    private sealed record AgentRecord(string AgentId, string Hostname, string Status, DateTimeOffset LastSeen, HostTimezoneMetadata? HostTimezone, string Platform);

    private sealed record InventorySnapshotRecord(
        string SnapshotType,
        DateTimeOffset CollectedAt,
        HostTimezoneMetadata? HostTimezone,
        int ItemCount,
        IReadOnlyDictionary<string, string> Summary);
}
