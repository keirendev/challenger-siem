using System.Globalization;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Contracts.V2;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record StoreEventsResult(
    int Accepted,
    int Duplicates,
    IReadOnlyList<Guid> AcceptedEventIds,
    IReadOnlyList<Guid> DuplicateEventIds);

public sealed record StorageQuotaThreshold(int Percent, long Bytes, string State);

public sealed record ManagedStorageAccounting(
    long TableBytes,
    long IndexBytes,
    long TotalBytes,
    long EventRows,
    DateTimeOffset MeasuredAt,
    long CapacityBytes,
    decimal UsedPercent,
    string WarningState,
    IReadOnlyList<StorageQuotaThreshold> WarningThresholds,
    DateTimeOffset? OldestEventTime,
    DateTimeOffset? NewestEventTime,
    long? OldestEventAgeSeconds,
    string RetentionLagState,
    long? RetentionLagSeconds,
    IReadOnlyList<ManagedTelemetryTableAccounting> ManagedTables,
    string AccountingMode);

public sealed record EventSearchPage(IReadOnlyList<EventEnvelope> Events, EventSearchPageInfo Page, IReadOnlyList<EventSearchFilterSummary> ActiveFilters, string ResultScope, string RedactionNotice);

public sealed record EventTimelineQueryResult(IReadOnlyList<EventTimelineBucket> Buckets, int BucketSeconds);

public sealed record EventExportResult(byte[] Content, string FileName, int Rows, int BoundedLimit);

public sealed class EventRepository(NpgsqlDataSource dataSource)
{
    private static readonly string[] EventInsertParameterNames =
    [
        "event_id", "agent_id", "hostname", "source", "platform", "source_id", "event_code", "facility", "unit",
        "checkpoint_json", "deduplication_json", "data_handling_json", "event_time", "host_timezone", "severity", "message",
        "raw_json", "event_category", "event_action", "normalized_json", "user_name", "target_user_name", "process_image",
        "process_command_line", "source_ip", "destination_ip", "service_name", "file_path", "registry_key"
    ];

    public async Task<StoreEventsResult> StoreEventsAsync(IngestBatchRequest batch, CancellationToken cancellationToken)
    {
        if (batch.Events.Count == 0)
        {
            return new StoreEventsResult(0, 0, Array.Empty<Guid>(), Array.Empty<Guid>());
        }
        if (batch.Events.Count > ContractLimits.MaxIngestEventsPerBatch)
        {
            throw new ArgumentOutOfRangeException(nameof(batch),
                $"Event storage batch exceeds the {ContractLimits.MaxIngestEventsPerBatch}-event contract limit.");
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var requestedEventIds = batch.Events.Select(item => item.EventId).Distinct().ToArray();
        var preexistingIds = new HashSet<Guid>();
        await using (var lookup = connection.CreateCommand())
        {
            lookup.Transaction = transaction;
            lookup.CommandText = """
                select event_id
                from events
                where agent_id = @agent_id
                  and event_id = any(@event_ids);
                """;
            lookup.Parameters.AddWithValue("agent_id", batch.AgentId);
            lookup.Parameters.AddWithValue("event_ids", requestedEventIds);
            await using var reader = await lookup.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                preexistingIds.Add(reader.GetGuid(0));
            }
        }

        var pendingEvents = batch.Events.Where(item => !preexistingIds.Contains(item.EventId)).ToArray();
        var insertedIds = new HashSet<Guid>();
        if (pendingEvents.Length > 0)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;

            var sql = new StringBuilder("""
                insert into events (
                    event_id, agent_id, hostname, source,
                    platform, source_id, event_code, facility, unit, checkpoint_json, deduplication_json, data_handling_json,
                    event_time, host_timezone, severity, message, raw_json, event_category, event_action, normalized_json,
                    user_name, target_user_name, process_image, process_command_line, source_ip, destination_ip, service_name,
                    file_path, registry_key
                )
                values
                """);
            for (var index = 0; index < pendingEvents.Length; index++)
            {
                if (index > 0) sql.Append(',');
                sql.AppendLine();
                sql.Append('(');
                sql.AppendJoin(',', EventInsertParameterNames.Select(name => $"@{name}_{index}"));
                sql.Append(')');
                AddEventInsertParameters(command, pendingEvents[index], index);
            }
            sql.AppendLine();
            sql.Append("""
                on conflict (agent_id, event_id) do nothing
                returning event_id;
                """);
            command.CommandText = sql.ToString();

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                insertedIds.Add(reader.GetGuid(0));
            }
        }
        await transaction.CommitAsync(cancellationToken);

        var acceptedEventIds = new List<Guid>();
        var duplicateEventIds = new List<Guid>();
        foreach (var envelope in batch.Events)
        {
            if (insertedIds.Remove(envelope.EventId)) acceptedEventIds.Add(envelope.EventId);
            else duplicateEventIds.Add(envelope.EventId);
        }

        return new StoreEventsResult(acceptedEventIds.Count, duplicateEventIds.Count, acceptedEventIds, duplicateEventIds);
    }

    public async Task<IReadOnlyList<EventEnvelope>> SearchEventsAsync(EventSearchQuery query, CancellationToken cancellationToken, int offset = 0)
    {
        var page = await SearchEventsPageAsync(query with { Cursor = null }, null, cancellationToken, offset);
        return page.Events;
    }

    public async Task<EventSearchPage> SearchEventsPageForServiceAsync(EventSearchQuery query, string role, CancellationToken cancellationToken)
    {
        var roleQuery = query.ForRole(role);
        var page = await SearchEventsPageAsync(roleQuery, role, cancellationToken);
        var filtered = page.Events.Select(item => ServiceEventPolicy.Apply(item, role)).ToArray();
        const string redaction = "service_full_record";
        return page with { Events = filtered, RedactionNotice = redaction };
    }

    public async Task<IReadOnlyList<EventEnvelope>> SearchEventsForServiceAsync(EventSearchQuery query, string role, CancellationToken cancellationToken, int offset = 0)
    {
        var page = await SearchEventsPageAsync(query.ForRole(role) with { Cursor = null }, role, cancellationToken, offset);
        return page.Events.Select(item => ServiceEventPolicy.Apply(item, role)).ToArray();
    }

    public async Task<EventTimelineQueryResult> GetTimelineAsync(EventSearchQuery query, string role, CancellationToken cancellationToken)
    {
        var roleQuery = query.ForRole(role);
        var where = new List<string>();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        AddSearchPredicates(where, command, roleQuery, includeCursor: false);
        var bucketSeconds = Math.Clamp(roleQuery.BucketSeconds, 60, 86400);
        command.Parameters.AddWithValue("bucket_seconds", bucketSeconds);
        var sql = new StringBuilder("""
            select
                to_timestamp(floor(extract(epoch from event_time) / @bucket_seconds) * @bucket_seconds) at time zone 'utc' as bucket_start,
                severity,
                source,
                count(*)::bigint as event_count,
                array_remove(array_agg(distinct coalesce(host_timezone->>'id', host_timezone->>'display_name', host_timezone->>'utc_offset_minutes')), null) as timezone_labels
            from events
            """);
        if (where.Count > 0)
        {
            sql.Append(" where ");
            sql.Append(string.Join(" and ", where));
        }
        sql.Append(" group by bucket_start, severity, source order by bucket_start asc, severity, source limit 500;");
        command.CommandText = sql.ToString();
        var results = new List<EventTimelineBucket>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var start = ReadDateTimeOffset(reader, "bucket_start");
            var labels = reader.IsDBNull(reader.GetOrdinal("timezone_labels")) ? Array.Empty<string>() : reader.GetFieldValue<string[]>(reader.GetOrdinal("timezone_labels"));
            results.Add(new EventTimelineBucket
            {
                StartUtc = start,
                EndUtc = start.AddSeconds(bucketSeconds),
                Severity = ReadNullableString(reader, "severity"),
                Source = ReadNullableString(reader, "source"),
                Count = reader.GetInt64(reader.GetOrdinal("event_count")),
                HostTimezoneLabels = labels.Take(8).ToArray()
            });
        }
        return new EventTimelineQueryResult(results, bucketSeconds);
    }

    public async Task<IReadOnlyList<EventEnvelope>> SearchGlobalEventsForServiceAsync(string searchText, int limit, string role, CancellationToken cancellationToken, int offset = 0)
    {
        var trimmed = searchText.Trim();
        if (trimmed.Length == 0)
        {
            return Array.Empty<EventEnvelope>();
        }

        var normalizedLimit = Math.Clamp(limit, 1, EventSearchQuery.MaxLimit);
        var clampedOffset = Math.Max(0, offset);
        var canReviewSensitive = ServiceAuthorization.HasPermission(role, ServicePermission.ReviewSensitive);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("term", trimmed);
        command.Parameters.AddWithValue("like_term", $"%{EscapeLike(trimmed)}%");
        command.Parameters.AddWithValue("limit", normalizedLimit);
        command.Parameters.AddWithValue("offset", clampedOffset);

        var predicates = new List<string>
        {
            "agent_id ilike @like_term escape '\\'",
            "hostname ilike @like_term escape '\\'",
            "source ilike @like_term escape '\\'",
            "coalesce(platform, '') ilike @like_term escape '\\'",
            "coalesce(source_id, '') ilike @like_term escape '\\'",
            "coalesce(event_code, '') ilike @like_term escape '\\'",
            "coalesce(facility, '') ilike @like_term escape '\\'",
            "coalesce(unit, '') ilike @like_term escape '\\'"
        };

        if (canReviewSensitive)
        {
            predicates.Add("message ilike @like_term escape '\\'");
            predicates.Add("raw_json::text ilike @like_term escape '\\'");
            predicates.Add("normalized_json::text ilike @like_term escape '\\'");
        }

        var sql = new StringBuilder(SelectEventSql);
        sql.Append(" where (");
        sql.Append(string.Join(" or ", predicates));
        sql.Append(") order by event_time desc, id desc limit @limit offset @offset;");
        command.CommandText = sql.ToString();

        var results = new List<EventEnvelope>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ServiceEventPolicy.Apply(ReadEventEnvelope(reader), role));
        }

        return results;
    }

    public async Task<EventEnvelope?> GetEventForServiceAsync(string agentId, Guid eventId, string role, CancellationToken cancellationToken)
    {
        var item = await GetEventAsync(agentId, eventId, cancellationToken);
        return item is null ? null : ServiceEventPolicy.Apply(item, role);
    }

    public async Task<EventEnvelope?> GetEventAsync(string agentId, Guid eventId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = SelectEventSql + """

            where agent_id = @agent_id
              and event_id = @event_id
            limit 1;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("event_id", eventId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadEventEnvelope(reader) : null;
    }

    public async Task<IReadOnlyList<EventEnvelope>> LoadStoredEventsAsync(
        string agentId,
        IEnumerable<Guid> eventIds,
        CancellationToken cancellationToken)
    {
        var boundedIds = eventIds.Distinct().Take(ContractLimits.MaxIngestEventsPerBatch).ToArray();
        if (boundedIds.Length == 0)
        {
            return Array.Empty<EventEnvelope>();
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = SelectEventSql + """

            where agent_id = @agent_id
              and event_id = any(@event_ids)
            order by event_time asc, id asc
            limit @max_events;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        command.Parameters.AddWithValue("event_ids", boundedIds);
        command.Parameters.AddWithValue("max_events", ContractLimits.MaxIngestEventsPerBatch);

        var stored = new List<EventEnvelope>(boundedIds.Length);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            stored.Add(ReadEventEnvelope(reader));
        }

        return stored;
    }

    public async Task<IReadOnlyList<SavedEventSearchRecord>> ListSavedSearchesAsync(Guid serviceId, string role, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select saved_search_id, name, description, visibility, version, query_json, columns_json, created_at, updated_at, owner_username
            from saved_event_searches
            order by updated_at desc, name asc
            limit 100;
            """;
        var results = new List<SavedEventSearchRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(ApplySavedSearchRolePolicy(ReadSavedSearch(reader), role));
        }
        return results;
    }

    public async Task<SavedEventSearchRecord?> GetSavedSearchAsync(Guid id, Guid serviceId, bool canUseShared, string role, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select saved_search_id, name, description, visibility, version, query_json, columns_json, created_at, updated_at, owner_username
            from saved_event_searches
            where saved_search_id = @id
            limit 1;
            """;
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? ApplySavedSearchRolePolicy(ReadSavedSearch(reader), role)
            : null;
    }

    public async Task<SavedEventSearchRecord> SaveSearchAsync(SavedEventSearchRequest request, Guid serviceId, string serviceName, bool canShare, CancellationToken cancellationToken, Guid? existingId = null)
    {
        ValidateSavedSearchRequest(request, canShare);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var queryJson = JsonSerializer.Serialize(request.Query, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var columnsJson = JsonSerializer.Serialize(request.Columns.Take(16).ToArray(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (existingId.HasValue)
        {
            command.CommandText = """
                update saved_event_searches
                set name = @name, description = @description, visibility = @visibility, query_json = @query_json::jsonb, columns_json = @columns_json::jsonb,
                    version = version + 1, updated_at = now()
                where saved_search_id = @id and (@expected_version is null or version = @expected_version)
                returning saved_search_id, name, description, visibility, version, query_json, columns_json, created_at, updated_at, owner_username;
                """;
            command.Parameters.AddWithValue("id", existingId.Value);
            command.Parameters.AddWithValue("expected_version", request.ExpectedVersion.HasValue ? request.ExpectedVersion.Value : DBNull.Value);
        }
        else
        {
            command.CommandText = """
                insert into saved_event_searches(saved_search_id, owner_username, name, description, visibility, version, query_json, columns_json)
                values(@id, @owner_username, @name, @description, @visibility, 1, @query_json::jsonb, @columns_json::jsonb)
                returning saved_search_id, name, description, visibility, version, query_json, columns_json, created_at, updated_at, owner_username;
                """;
            command.Parameters.AddWithValue("id", Guid.NewGuid());
        }
        command.Parameters.AddWithValue("owner_username", serviceName);
        command.Parameters.AddWithValue("name", request.Name.Trim());
        command.Parameters.AddWithValue("description", string.IsNullOrWhiteSpace(request.Description) ? DBNull.Value : request.Description.Trim());
        command.Parameters.AddWithValue("visibility", request.Visibility);
        command.Parameters.AddWithValue("query_json", queryJson);
        command.Parameters.AddWithValue("columns_json", columnsJson);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) throw new InvalidOperationException("Saved search was not written; the expected version may be stale.");
        return ReadSavedSearch(reader);
    }

    public async Task<bool> DeleteSavedSearchAsync(Guid id, Guid serviceId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "delete from saved_event_searches where saved_search_id = @id;";
        command.Parameters.AddWithValue("id", id);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<EventExportResult> ExportCsvForServiceAsync(EventSearchQuery query, string role, CancellationToken cancellationToken)
    {
        var exportQuery = query.ForRole(role) with { Limit = Math.Clamp(query.Limit, 1, EventSearchQuery.MaxExportLimit), Cursor = null };
        var page = await SearchEventsPageAsync(exportQuery, role, cancellationToken, offset: 0, maxLimit: EventSearchQuery.MaxExportLimit);
        var rows = page.Events.Select(item => ServiceEventPolicy.Apply(item, role)).ToArray();
        var builder = new StringBuilder();
        builder.AppendLine("event_time_utc,ingest_time_utc,agent_id,hostname,platform,source,source_id,facility,unit,event_code,severity,category,action,outcome,message");
        foreach (var item in rows)
        {
            builder.AppendCsv(TimeCsv(item.EventTime));
            builder.AppendCsv(TimeCsv(item.IngestTime));
            builder.AppendCsv(item.AgentId);
            builder.AppendCsv(item.Hostname);
            builder.AppendCsv(item.Platform);
            builder.AppendCsv(item.Source);
            builder.AppendCsv(item.SourceId);
            builder.AppendCsv(item.Facility);
            builder.AppendCsv(item.Unit);
            builder.AppendCsv(item.EventCode);
            builder.AppendCsv(item.Severity);
            builder.AppendCsv(item.Normalized?.Category);
            builder.AppendCsv(item.Normalized?.Action);
            builder.AppendCsv(item.Normalized?.Outcome);
            builder.AppendCsv(item.Message, endOfRow: true);
        }
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        return new EventExportResult(Encoding.UTF8.GetBytes(builder.ToString()), $"challenger-siem-events-{timestamp}.csv", rows.Length, exportQuery.Limit);
    }

    private async Task<EventSearchPage> SearchEventsPageAsync(EventSearchQuery query, string? role, CancellationToken cancellationToken, int offset = 0, int maxLimit = EventSearchQuery.MaxLimit)
    {
        var where = new List<string>();
        var limit = Math.Clamp(query.Limit, 1, maxLimit);
        var fetchLimit = Math.Min(limit + 1, maxLimit + 1);
        var clampedOffset = Math.Max(0, offset);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        AddSearchPredicates(where, command, query, includeCursor: offset == 0);
        command.Parameters.AddWithValue("limit", fetchLimit);
        command.Parameters.AddWithValue("offset", clampedOffset);

        var sql = new StringBuilder(SelectEventSql);
        if (where.Count > 0)
        {
            sql.Append(" where ");
            sql.Append(string.Join(" and ", where));
        }

        sql.Append(" order by event_time desc, id desc limit @limit offset @offset;");
        command.CommandText = sql.ToString();

        var rows = new List<(long RowId, EventEnvelope Envelope)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add((reader.GetInt64(reader.GetOrdinal("id")), ReadEventEnvelope(reader)));
        }

        var hasNext = rows.Count > limit;
        var visibleRows = rows.Take(limit).ToArray();
        var nextCursor = hasNext && visibleRows.Length > 0
            ? EventSearchCursor.Encode(visibleRows[^1].Envelope.EventTime, visibleRows[^1].RowId)
            : null;
        return new EventSearchPage(
            visibleRows.Select(item => item.Envelope).ToArray(),
            new EventSearchPageInfo { Limit = limit, Returned = visibleRows.Length, HasNext = hasNext, NextCursor = nextCursor },
            query.ActiveFilterSummaries(),
            BuildResultScope(query, limit, role),
            "server_role_policy_applied");
    }

    private static void AddSearchPredicates(List<string> where, NpgsqlCommand command, EventSearchQuery query, bool includeCursor)
    {
        AddTextFilter(where, command, "hostname", "hostname", query.Hostname, exact: true);
        AddTextFilter(where, command, "agent_id", "agent_id", query.AgentId, exact: true);
        AddTextFilter(where, command, "source", "source", query.Source, exact: true);
        AddTextFilter(where, command, "platform", "platform", query.Platform, exact: true);
        AddTextFilter(where, command, "source_id", "source_id", query.SourceId, exact: true);
        AddTextFilter(where, command, "event_code", "event_code", query.EventCode, exact: true);
        AddTextFilter(where, command, "facility", "facility", query.Facility, exact: true);
        AddTextFilter(where, command, "unit", "unit", query.Unit, exact: true);
        AddTextFilter(where, command, "severity", "severity", query.Severity, exact: true);
        AddTextFilter(where, command, "event_category", "category", query.Category, exact: true);
        AddTextFilter(where, command, "event_action", "action", query.Action, exact: true);
        AddTextFilter(where, command, "normalized_json->>'outcome'", "outcome", query.Outcome, exact: true);
        AddTextFilter(where, command, "user_name", "user_name", query.UserName, exact: false);
        AddFallbackTextFilter(where, command, "process_image", "normalized_json->'process'->>'executable'", "process_image", query.ProcessImage, exact: false);
        AddFallbackTextFilter(where, command, "process_command_line", "normalized_json->'process'->>'command_line'", "process_command_line", query.ProcessCommandLine, exact: false);
        AddFallbackTextFilter(where, command, "source_ip", "normalized_json->'network'->>'source_ip'", "source_ip", query.SourceIp, exact: true);
        AddFallbackTextFilter(where, command, "destination_ip", "normalized_json->'network'->>'destination_ip'", "destination_ip", query.DestinationIp, exact: true);
        AddFallbackTextFilter(where, command, "normalized_json->>'source_port'", "normalized_json->'network'->>'source_port'", "source_port", query.SourcePort, exact: true);
        AddFallbackTextFilter(where, command, "normalized_json->>'destination_port'", "normalized_json->'network'->>'destination_port'", "destination_port", query.DestinationPort, exact: true);
        AddFallbackTextFilter(where, command, "normalized_json->>'protocol'", "normalized_json->'network'->>'protocol'", "protocol", query.Protocol, exact: true);
        AddTextFilter(where, command, "service_name", "service_name", query.ServiceName, exact: false);
        AddFallbackTextFilter(where, command, "file_path", "normalized_json->'file'->>'path'", "file_path", query.FilePath, exact: false);
        AddTextFilter(where, command, "registry_key", "registry_key", query.RegistryKey, exact: false);
        AddTextFilter(where, command, "normalized_json->>'package_name'", "package_name", query.PackageName, exact: true);

        if (query.From.HasValue)
        {
            where.Add("event_time >= @from");
            command.Parameters.AddWithValue("from", query.From.Value.ToUniversalTime());
        }
        if (query.To.HasValue)
        {
            where.Add("event_time <= @to");
            command.Parameters.AddWithValue("to", query.To.Value.ToUniversalTime());
        }
        if (!string.IsNullOrWhiteSpace(query.Keyword))
        {
            where.Add("(message ilike @keyword escape '\\' or raw_json::text ilike @keyword escape '\\' or normalized_json::text ilike @keyword escape '\\')");
            command.Parameters.AddWithValue("keyword", $"%{EscapeLike(query.Keyword.Trim())}%");
        }
        if (!string.IsNullOrWhiteSpace(query.NetworkIp))
        {
            where.Add("(source_ip = @network_ip or destination_ip = @network_ip or normalized_json->'network'->>'source_ip' = @network_ip or normalized_json->'network'->>'destination_ip' = @network_ip)");
            command.Parameters.AddWithValue("network_ip", query.NetworkIp.Trim());
        }
        if (!string.IsNullOrWhiteSpace(query.EntityType) && !string.IsNullOrWhiteSpace(query.EntityValue))
        {
            where.Add("normalized_json @> @entity_json::jsonb");
            command.Parameters.AddWithValue("entity_json", JsonSerializer.Serialize(new { entities = new[] { new { type = query.EntityType, value = query.EntityValue } } }));
        }
        if (!string.IsNullOrWhiteSpace(query.DetectionRuleId))
        {
            where.Add("exists (select 1 from alert_evidence ae join alerts a on a.alert_id = ae.alert_id where ae.agent_id = events.agent_id and ae.event_id = events.event_id and a.rule_id = @detection_rule_id)");
            command.Parameters.AddWithValue("detection_rule_id", query.DetectionRuleId.Trim());
        }
        if (includeCursor && EventSearchCursor.TryDecode(query.Cursor) is { } cursor)
        {
            where.Add("(event_time, id) < (@cursor_event_time, @cursor_id)");
            command.Parameters.AddWithValue("cursor_event_time", cursor.EventTime.ToUniversalTime());
            command.Parameters.AddWithValue("cursor_id", cursor.RowId);
        }
    }

    private const string SelectEventSql = """
            select
                id,
                event_id,
                agent_id,
                hostname,
                source,
                platform, source_id, event_code, facility, unit, checkpoint_json, deduplication_json, data_handling_json,
                event_time,
                host_timezone,
                ingest_time,
                severity,
                message,
                raw_json,
                normalized_json
            from events
            """;

    private static string BuildResultScope(EventSearchQuery query, int limit, string? role)
    {
        var filterCount = query.ActiveFilterSummaries().Count;
        var range = query.From.HasValue || query.To.HasValue ? "bounded UTC range" : "all retained UTC event time";
        var roleText = string.IsNullOrWhiteSpace(role) ? "service" : role;
        return $"{filterCount} active filters over {range}; newest first; limit {limit}; role {roleText}.";
    }

    private static string EscapeLike(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);

    private static void ValidateSavedSearchRequest(SavedEventSearchRequest request, bool canShare)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 80)
        {
            throw new ArgumentException("Saved search name is required and must be 80 characters or fewer.");
        }
        if (!SavedEventSearchVisibility.IsValid(request.Visibility))
        {
            throw new ArgumentException("Saved search visibility must be private or shared.");
        }
        if (request.Visibility == SavedEventSearchVisibility.Shared && !canShare)
        {
            throw new UnauthorizedAccessException("Only analysts, detection engineers, and admins may create shared saved searches.");
        }
        if (request.Query.Count > 40 || request.Query.Any(item => item.Key.Length > 64 || item.Value.Length > 512))
        {
            throw new ArgumentException("Saved search query metadata is too large.");
        }
    }

    private static SavedEventSearchRecord ReadSavedSearch(NpgsqlDataReader reader)
    {
        var queryJson = reader.GetString(reader.GetOrdinal("query_json"));
        var columnsJson = reader.GetString(reader.GetOrdinal("columns_json"));
        return new SavedEventSearchRecord
        {
            SavedSearchId = reader.GetGuid(reader.GetOrdinal("saved_search_id")),
            Name = reader.GetString(reader.GetOrdinal("name")),
            Description = ReadNullableString(reader, "description"),
            Visibility = reader.GetString(reader.GetOrdinal("visibility")),
            Version = reader.GetInt32(reader.GetOrdinal("version")),
            Query = JsonSerializer.Deserialize<Dictionary<string, string>>(queryJson, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? new Dictionary<string, string>(StringComparer.Ordinal),
            Columns = JsonSerializer.Deserialize<string[]>(columnsJson, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? Array.Empty<string>(),
            CreatedAt = ReadDateTimeOffset(reader, "created_at"),
            UpdatedAt = ReadDateTimeOffset(reader, "updated_at"),
            CreatedBy = ReadNullableString(reader, "owner_username")
        };
    }

    private static SavedEventSearchRecord ApplySavedSearchRolePolicy(SavedEventSearchRecord saved, string role) =>
        saved with { Query = EventSearchQuery.SavedQueryForRole(saved.Query, role) };

    private static string TimeCsv(DateTimeOffset? value) => value?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;

    private static EventEnvelope ReadEventEnvelope(NpgsqlDataReader reader)
    {
        var rawJson = reader.GetString(reader.GetOrdinal("raw_json"));
        using var rawDocument = JsonDocument.Parse(rawJson);
        var normalized = ReadNormalized(reader);

        return new EventEnvelope
        {
            EventId = reader.GetGuid(reader.GetOrdinal("event_id")),
            AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
            Hostname = reader.GetString(reader.GetOrdinal("hostname")),
            Source = reader.GetString(reader.GetOrdinal("source")),
            Platform = ReadNullableString(reader, "platform"),
            SourceId = ReadNullableString(reader, "source_id"),
            EventCode = ReadNullableString(reader, "event_code"),
            Facility = ReadNullableString(reader, "facility"),
            Unit = ReadNullableString(reader, "unit"),
            Checkpoint = Jsonb.Read<SourceCheckpoint>(reader, "checkpoint_json"),
            Deduplication = Jsonb.Read<EventDeduplicationMetadata>(reader, "deduplication_json"),
            DataHandling = Jsonb.Read<DataHandlingMetadata>(reader, "data_handling_json"),
            EventTime = ReadDateTimeOffset(reader, "event_time"),
            HostTimezone = Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone"),
            IngestTime = ReadDateTimeOffset(reader, "ingest_time"),
            Severity = reader.GetString(reader.GetOrdinal("severity")),
            Message = reader.GetString(reader.GetOrdinal("message")),
            Normalized = normalized,
            Raw = rawDocument.RootElement.Clone()
        };
    }

    public async Task<ManagedStorageAccounting> GetManagedStorageAccountingAsync(long capacityBytes, CancellationToken cancellationToken, int targetRetentionDays = 30)
    {
        var boundedCapacityBytes = Math.Clamp(capacityBytes, 1024, ManagedRetentionOptions.HardManagedCapacityBytes);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select * from (
                select 'events' as table_name, count(*)::bigint as row_count, coalesce(sum(pg_column_size(events.*)),0)::bigint as live_bytes,
                       pg_relation_size('public.events')::bigint as relation_bytes, pg_indexes_size('public.events')::bigint as index_bytes,
                       pg_total_relation_size('public.events')::bigint as total_relation_bytes,
                       min(event_time) as oldest_time, max(event_time) as newest_time
                from events
                union all
                select 'agent_heartbeats', count(*)::bigint, coalesce(sum(pg_column_size(agent_heartbeats.*)),0)::bigint,
                       pg_relation_size('public.agent_heartbeats')::bigint, pg_indexes_size('public.agent_heartbeats')::bigint,
                       pg_total_relation_size('public.agent_heartbeats')::bigint,
                       min(heartbeat_time), max(heartbeat_time)
                from agent_heartbeats
                union all
                select 'asset_inventory_snapshots', count(*)::bigint, coalesce(sum(pg_column_size(asset_inventory_snapshots.*)),0)::bigint,
                       pg_relation_size('public.asset_inventory_snapshots')::bigint, pg_indexes_size('public.asset_inventory_snapshots')::bigint,
                       pg_total_relation_size('public.asset_inventory_snapshots')::bigint,
                       min(collected_at), max(collected_at)
                from asset_inventory_snapshots
                union all
                select 'ingestion_errors', count(*)::bigint, coalesce(sum(pg_column_size(ingestion_errors.*)),0)::bigint,
                       pg_relation_size('public.ingestion_errors')::bigint, pg_indexes_size('public.ingestion_errors')::bigint,
                       pg_total_relation_size('public.ingestion_errors')::bigint,
                       min(error_time), max(error_time)
                from ingestion_errors
            ) managed
            order by table_name;
            """;
        return await ReadManagedStorageAccountingAsync(
            command, boundedCapacityBytes, targetRetentionDays, "exact_live_rows", cancellationToken);
    }

    public async Task<ManagedStorageAccounting> GetManagedStorageAccountingEstimateAsync(
        long capacityBytes,
        CancellationToken cancellationToken,
        int targetRetentionDays = 30)
    {
        var boundedCapacityBytes = Math.Clamp(capacityBytes, 1024, ManagedRetentionOptions.HardManagedCapacityBytes);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select * from (
                select 'events' as table_name,
                       coalesce((select n_live_tup::bigint from pg_stat_user_tables where schemaname = 'public' and relname = 'events'), 0) as row_count,
                       pg_table_size('public.events')::bigint as live_bytes,
                       pg_relation_size('public.events')::bigint as relation_bytes,
                       pg_indexes_size('public.events')::bigint as index_bytes,
                       pg_total_relation_size('public.events')::bigint as total_relation_bytes,
                       (select event_time from events order by event_time asc limit 1) as oldest_time,
                       (select event_time from events order by event_time desc limit 1) as newest_time
                union all
                select 'agent_heartbeats',
                       coalesce((select n_live_tup::bigint from pg_stat_user_tables where schemaname = 'public' and relname = 'agent_heartbeats'), 0),
                       pg_table_size('public.agent_heartbeats')::bigint,
                       pg_relation_size('public.agent_heartbeats')::bigint,
                       pg_indexes_size('public.agent_heartbeats')::bigint,
                       pg_total_relation_size('public.agent_heartbeats')::bigint,
                       min(heartbeat_time), max(heartbeat_time)
                from agent_heartbeats
                union all
                select 'asset_inventory_snapshots',
                       coalesce((select n_live_tup::bigint from pg_stat_user_tables where schemaname = 'public' and relname = 'asset_inventory_snapshots'), 0),
                       pg_table_size('public.asset_inventory_snapshots')::bigint,
                       pg_relation_size('public.asset_inventory_snapshots')::bigint,
                       pg_indexes_size('public.asset_inventory_snapshots')::bigint,
                       pg_total_relation_size('public.asset_inventory_snapshots')::bigint,
                       min(collected_at), max(collected_at)
                from asset_inventory_snapshots
                union all
                select 'ingestion_errors',
                       coalesce((select n_live_tup::bigint from pg_stat_user_tables where schemaname = 'public' and relname = 'ingestion_errors'), 0),
                       pg_table_size('public.ingestion_errors')::bigint,
                       pg_relation_size('public.ingestion_errors')::bigint,
                       pg_indexes_size('public.ingestion_errors')::bigint,
                       pg_total_relation_size('public.ingestion_errors')::bigint,
                       min(error_time), max(error_time)
                from ingestion_errors
            ) managed
            order by table_name;
            """;
        return await ReadManagedStorageAccountingAsync(
            command, boundedCapacityBytes, targetRetentionDays, "catalog_estimate", cancellationToken);
    }

    private static async Task<ManagedStorageAccounting> ReadManagedStorageAccountingAsync(
        NpgsqlCommand command,
        long boundedCapacityBytes,
        int targetRetentionDays,
        string accountingMode,
        CancellationToken cancellationToken)
    {
        var tables = new List<ManagedTelemetryTableAccounting>();
        DateTimeOffset? oldest = null;
        DateTimeOffset? newest = null;
        long eventRows = 0;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var tableName = reader.GetString(0);
            var rowCount = reader.GetInt64(1);
            var liveBytes = reader.GetInt64(2);
            var relationBytes = reader.GetInt64(3);
            var indexBytes = reader.GetInt64(4);
            var totalRelationBytes = reader.GetInt64(5);
            tables.Add(new ManagedTelemetryTableAccounting(tableName, rowCount, liveBytes, relationBytes, indexBytes, totalRelationBytes));
            if (tableName == "events") eventRows = rowCount;
            oldest = MinDateTime(oldest, ReadNullableDateTimeOffset(reader, "oldest_time"));
            newest = MaxDateTime(newest, ReadNullableDateTimeOffset(reader, "newest_time"));
        }

        var tableBytes = tables.Sum(item => item.LiveBytes);
        var indexTotalBytes = tables.Sum(item => item.IndexBytes);
        var totalBytes = tableBytes + indexTotalBytes;
        var measuredAt = DateTimeOffset.UtcNow;
        var targetRetentionSeconds = Math.Clamp(targetRetentionDays, 1, 3650) * 24L * 60 * 60;
        var retentionLagSeconds = oldest.HasValue ? Math.Max(0, (long)Math.Floor((measuredAt - oldest.Value).TotalSeconds) - targetRetentionSeconds) : (long?)null;
        var retentionLagState = retentionLagSeconds is null or <= 0 ? "within_target" : "expired_telemetry_present";
        return new(
            tableBytes,
            indexTotalBytes,
            totalBytes,
            eventRows,
            measuredAt,
            boundedCapacityBytes,
            CalculateUsedPercent(totalBytes, boundedCapacityBytes),
            CalculateStorageWarningState(totalBytes, boundedCapacityBytes),
            BuildStorageThresholds(boundedCapacityBytes),
            oldest,
            newest,
            oldest.HasValue ? Math.Max(0, (long)Math.Floor((measuredAt - oldest.Value).TotalSeconds)) : null,
            retentionLagState,
            retentionLagSeconds,
            tables,
            accountingMode);
    }

    public static string CalculateStorageWarningState(long totalBytes, long capacityBytes)
    {
        if (capacityBytes <= 0) return "unknown";
        var percent = CalculateUsedPercent(totalBytes, capacityBytes);
        return percent >= 100 ? "over_capacity"
            : percent >= 95 ? "critical_95"
            : percent >= 85 ? "warning_85"
            : percent >= 70 ? "warning_70"
            : "normal";
    }

    public static IReadOnlyList<StorageQuotaThreshold> BuildStorageThresholds(long capacityBytes) => new[]
    {
        new StorageQuotaThreshold(70, capacityBytes * 70 / 100, "warning_70"),
        new StorageQuotaThreshold(85, capacityBytes * 85 / 100, "warning_85"),
        new StorageQuotaThreshold(95, capacityBytes * 95 / 100, "critical_95"),
        new StorageQuotaThreshold(100, capacityBytes, "over_capacity")
    };

    private static decimal CalculateUsedPercent(long totalBytes, long capacityBytes) => capacityBytes <= 0
        ? 0
        : Math.Round(totalBytes * 100m / capacityBytes, 3, MidpointRounding.AwayFromZero);

    private static DateTimeOffset? MinDateTime(DateTimeOffset? left, DateTimeOffset? right) => !left.HasValue ? right : !right.HasValue ? left : left.Value <= right.Value ? left : right;
    private static DateTimeOffset? MaxDateTime(DateTimeOffset? left, DateTimeOffset? right) => !left.HasValue ? right : !right.HasValue ? left : left.Value >= right.Value ? left : right;

    private static string? ReadNullableString(NpgsqlDataReader reader, string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetString(reader.GetOrdinal(name));
    private static int? ReadNullableInt32(NpgsqlDataReader reader, string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetInt32(reader.GetOrdinal(name));
    private static long? ReadNullableInt64(NpgsqlDataReader reader, string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? null : reader.GetInt64(reader.GetOrdinal(name));

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

    private static void AddTextFilter(List<string> where, NpgsqlCommand command, string column, string parameterName, string? value, bool exact)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (exact)
        {
            where.Add($"{column} = @{parameterName}");
            command.Parameters.AddWithValue(parameterName, value.Trim());
        }
        else
        {
            where.Add($"{column} ilike @{parameterName} escape '\\'");
            command.Parameters.AddWithValue(parameterName, $"%{EscapeLike(value.Trim())}%");
        }
    }

    private static void AddFallbackTextFilter(
        List<string> where,
        NpgsqlCommand command,
        string indexedExpression,
        string legacyFallbackExpression,
        string parameterName,
        string? value,
        bool exact)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (exact)
        {
            where.Add($"({indexedExpression} = @{parameterName} or ({indexedExpression} is null and {legacyFallbackExpression} = @{parameterName}))");
            command.Parameters.AddWithValue(parameterName, value.Trim());
        }
        else
        {
            where.Add($"({indexedExpression} ilike @{parameterName} escape '\\' or ({indexedExpression} is null and {legacyFallbackExpression} ilike @{parameterName} escape '\\'))");
            command.Parameters.AddWithValue(parameterName, $"%{EscapeLike(value.Trim())}%");
        }
    }

    private static void AddEventInsertParameters(NpgsqlCommand command, EventEnvelope envelope, int index)
    {
        var suffix = $"_{index}";
        command.Parameters.AddWithValue($"event_id{suffix}", envelope.EventId);
        command.Parameters.AddWithValue($"agent_id{suffix}", envelope.AgentId);
        command.Parameters.AddWithValue($"hostname{suffix}", envelope.Hostname);
        command.Parameters.AddWithValue($"source{suffix}", envelope.Source);
        command.Parameters.AddWithValue($"platform{suffix}", DbValue(envelope.Platform));
        command.Parameters.AddWithValue($"source_id{suffix}", DbValue(envelope.SourceId));
        command.Parameters.AddWithValue($"event_code{suffix}", DbValue(envelope.EventCode));
        command.Parameters.AddWithValue($"facility{suffix}", DbValue(envelope.Facility));
        command.Parameters.AddWithValue($"unit{suffix}", DbValue(envelope.Unit));
        Jsonb.Add(command, $"checkpoint_json{suffix}", envelope.Checkpoint);
        Jsonb.Add(command, $"deduplication_json{suffix}", envelope.Deduplication);
        Jsonb.Add(command, $"data_handling_json{suffix}", envelope.DataHandling);
        command.Parameters.AddWithValue($"event_time{suffix}", envelope.EventTime.ToUniversalTime());
        Jsonb.Add(command, $"host_timezone{suffix}", envelope.HostTimezone);
        command.Parameters.AddWithValue($"severity{suffix}", envelope.Severity);
        command.Parameters.AddWithValue($"message{suffix}", envelope.Message);

        var rawParameter = command.Parameters.Add($"raw_json{suffix}", NpgsqlDbType.Jsonb);
        rawParameter.Value = envelope.Raw.ValueKind == JsonValueKind.Undefined ? "{}" : envelope.Raw.GetRawText();
        command.Parameters.AddWithValue($"event_category{suffix}", DbValue(envelope.Normalized?.Category));
        command.Parameters.AddWithValue($"event_action{suffix}", DbValue(envelope.Normalized?.Action));
        var normalizedParameter = command.Parameters.Add($"normalized_json{suffix}", NpgsqlDbType.Jsonb);
        normalizedParameter.Value = envelope.Normalized is null
            ? DBNull.Value
            : JsonSerializer.Serialize(envelope.Normalized, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        command.Parameters.AddWithValue($"user_name{suffix}", DbValue(envelope.Normalized?.UserName));
        command.Parameters.AddWithValue($"target_user_name{suffix}", DbValue(envelope.Normalized?.TargetUserName));
        command.Parameters.AddWithValue($"process_image{suffix}", DbValue(envelope.Normalized?.ProcessImage ?? envelope.Normalized?.Process?.Executable));
        command.Parameters.AddWithValue($"process_command_line{suffix}", DbValue(Truncate(envelope.Normalized?.ProcessCommandLine ?? envelope.Normalized?.Process?.CommandLine, 4096)));
        command.Parameters.AddWithValue($"source_ip{suffix}", DbValue(envelope.Normalized?.SourceIp ?? envelope.Normalized?.Network?.SourceIp));
        command.Parameters.AddWithValue($"destination_ip{suffix}", DbValue(envelope.Normalized?.DestinationIp ?? envelope.Normalized?.Network?.DestinationIp));
        command.Parameters.AddWithValue($"service_name{suffix}", DbValue(envelope.Normalized?.ServiceName));
        command.Parameters.AddWithValue($"file_path{suffix}", DbValue(envelope.Normalized?.FilePath ?? envelope.Normalized?.File?.Path));
        command.Parameters.AddWithValue($"registry_key{suffix}", DbValue(envelope.Normalized?.RegistryKey));
    }

    private static object DbValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? DBNull.Value : value;
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private static NormalizedEventFields? ReadNormalized(NpgsqlDataReader reader)
    {
        var ordinal = reader.GetOrdinal("normalized_json");
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }

        return JsonSerializer.Deserialize<NormalizedEventFields>(reader.GetString(ordinal), new JsonSerializerOptions(JsonSerializerDefaults.Web));
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
}

internal static class EventCsvWriterExtensions
{
    public static void AppendCsv(this StringBuilder builder, string? value, bool endOfRow = false)
    {
        var safe = EventCsvValueSanitizer.Sanitize(value);
        builder.Append('"');
        builder.Append(safe.Replace("\"", "\"\"", StringComparison.Ordinal));
        builder.Append('"');
        builder.Append(endOfRow ? Environment.NewLine : ',');
    }
}

internal static class EventCsvValueSanitizer
{
    public static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sanitized = value.ReplaceLineEndings(" ").Trim();
        if (sanitized.Length > 2000) sanitized = sanitized[..2000];
        if (sanitized.StartsWith('=') || sanitized.StartsWith('+') || sanitized.StartsWith('-') || sanitized.StartsWith('@')
            || sanitized.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || sanitized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            sanitized = "'" + sanitized;
        }
        return sanitized;
    }
}
