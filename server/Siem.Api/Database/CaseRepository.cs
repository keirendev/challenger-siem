using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record BoundedCaseCollectionState(int Returned, bool Truncated);

public sealed record BoundedCaseDetailResult(
    CaseDetailRecord Case,
    int NestedLimit,
    int ReturnedNestedRecords,
    bool Truncated,
    IReadOnlyDictionary<string, BoundedCaseCollectionState> Collections);

public sealed class CaseRepository(NpgsqlDataSource dataSource)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<CaseSummaryRecord>> ListAsync(string? status, string? owner, CancellationToken cancellationToken, int limit = 100, int offset = 0)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(status) && !string.Equals(status, "all", StringComparison.OrdinalIgnoreCase))
        {
            where.Add("c.status = @status");
            command.Parameters.AddWithValue("status", status.Trim().ToLowerInvariant());
        }
        if (!string.IsNullOrWhiteSpace(owner))
        {
            where.Add("c.owner = @owner");
            command.Parameters.AddWithValue("owner", owner.Trim());
        }
        command.CommandText = CaseSummarySql + (where.Count == 0 ? string.Empty : " where " + string.Join(" and ", where)) + " order by c.last_activity_at desc limit @limit offset @offset;";
        command.Parameters.AddWithValue("limit", Math.Clamp(limit, 1, 100));
        command.Parameters.AddWithValue("offset", Math.Max(0, offset));
        var results = new List<CaseSummaryRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(ReadSummary(reader));
        return results;
    }

    public async Task<CaseDetailRecord?> GetAsync(Guid caseId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var detail = await LoadDetailAsync(connection, caseId, cancellationToken);
        if (detail is null) return null;
        return detail with
        {
            Alerts = await LoadAlertsAsync(connection, caseId, cancellationToken),
            Entities = await LoadEntitiesAsync(connection, caseId, cancellationToken),
            Graphs = await LoadGraphsAsync(connection, caseId, cancellationToken),
            Evidence = await LoadEvidenceAsync(connection, caseId, cancellationToken),
            Notes = await LoadNotesAsync(connection, caseId, cancellationToken),
            Activity = await LoadActivitiesAsync(connection, caseId, cancellationToken)
        };
    }

    public async Task<BoundedCaseDetailResult?> GetBoundedAsync(Guid caseId, int nestedLimit, CancellationToken cancellationToken)
    {
        if (nestedLimit is < 1 or > 100)
        {
            throw new ArgumentException("Nested case record limit must be between 1 and 100.", nameof(nestedLimit));
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var detail = await LoadDetailAsync(connection, caseId, cancellationToken);
        if (detail is null) return null;

        var fetchLimit = nestedLimit + 1;
        var alerts = await LoadAlertsAsync(connection, caseId, cancellationToken, fetchLimit);
        var entities = await LoadEntitiesAsync(connection, caseId, cancellationToken, fetchLimit);
        var graphs = await LoadGraphsAsync(connection, caseId, cancellationToken, fetchLimit);
        var evidence = await LoadEvidenceAsync(connection, caseId, cancellationToken, fetchLimit);
        var notes = await LoadNotesAsync(connection, caseId, cancellationToken, fetchLimit);
        var activity = await LoadActivitiesAsync(connection, caseId, cancellationToken, fetchLimit);
        var collections = new Dictionary<string, BoundedCaseCollectionState>(StringComparer.Ordinal)
        {
            ["alerts"] = State(alerts, nestedLimit),
            ["entities"] = State(entities, nestedLimit),
            ["graphs"] = State(graphs, nestedLimit),
            ["evidence"] = State(evidence, nestedLimit),
            ["notes"] = State(notes, nestedLimit),
            ["activity"] = State(activity, nestedLimit)
        };
        var bounded = detail with
        {
            Alerts = alerts.Take(nestedLimit).ToArray(),
            Entities = entities.Take(nestedLimit).ToArray(),
            Graphs = graphs.Take(nestedLimit).ToArray(),
            Evidence = evidence.Take(nestedLimit).ToArray(),
            Notes = notes.Take(nestedLimit).ToArray(),
            Activity = activity.Take(nestedLimit).ToArray()
        };
        var returned = collections.Values.Sum(item => item.Returned);
        return new BoundedCaseDetailResult(
            bounded,
            nestedLimit,
            returned,
            collections.Values.Any(item => item.Truncated),
            collections);
    }

    public async Task<CaseDetailRecord> CreateAsync(CaseCreateRequest request, string actor, CancellationToken cancellationToken)
    {
        var title = AlertRepository.BoundRequired(request.Title, 1, 160, "Case title");
        var description = AlertRepository.BoundOptional(request.Description, 4000, "Case description");
        var owner = AlertRepository.BoundOptional(request.Owner, 96, "Owner");
        var severity = NormalizeSeverity(request.Severity);
        var priority = NormalizePriority(request.Priority);
        AlertRepository.ValidateIdempotency(request.IdempotencyKey);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!string.IsNullOrWhiteSpace(request.IdempotencyKey))
        {
            var existingId = await FindCaseByIdempotencyAsync(connection, request.IdempotencyKey!, cancellationToken);
            if (existingId.HasValue) return (await GetAsync(existingId.Value, cancellationToken))!;
        }
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var caseId = Guid.NewGuid();
        var caseKey = await NextCaseKeyAsync(connection, transaction, cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into cases(case_id, case_key, title, description, owner, severity, priority, status, idempotency_key, last_actor, last_action)
                values(@case_id, @case_key, @title, @description, @owner, @severity, @priority, 'open', @idempotency_key, @actor, 'create');
                """;
            command.Parameters.AddWithValue("case_id", caseId);
            command.Parameters.AddWithValue("case_key", caseKey);
            command.Parameters.AddWithValue("title", title);
            command.Parameters.AddWithValue("description", (object?)description ?? DBNull.Value);
            command.Parameters.AddWithValue("owner", (object?)owner ?? DBNull.Value);
            command.Parameters.AddWithValue("severity", severity);
            command.Parameters.AddWithValue("priority", priority);
            command.Parameters.AddWithValue("idempotency_key", (object?)request.IdempotencyKey ?? DBNull.Value);
            command.Parameters.AddWithValue("actor", BoundActor(actor));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await AddCaseActivityAsync(connection, transaction, caseId, "create", actor, null, "open", "Created case.", request.IdempotencyKey, cancellationToken);
        foreach (var alertId in request.AlertIds.Distinct().Take(25))
        {
            await LinkAlertInternalAsync(connection, transaction, caseId, alertId, "primary", actor, cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return (await GetAsync(caseId, cancellationToken))!;
    }

    public async Task<CaseDetailRecord?> UpdateAsync(Guid caseId, CaseMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateExpectedVersion(request.ExpectedVersion);
        var title = AlertRepository.BoundOptional(request.Title, 160, "Case title");
        var description = AlertRepository.BoundOptional(request.Description, 4000, "Case description");
        var severity = request.Severity is null ? null : NormalizeSeverity(request.Severity);
        var priority = request.Priority is null ? null : NormalizePriority(request.Priority);
        var owner = AlertRepository.BoundOptional(request.Owner, 96, "Owner");
        return await MutateAsync(caseId, request.ExpectedVersion, "update", actor, request.IdempotencyKey,
            "title = coalesce(@title, title), description = coalesce(@description, description), owner = coalesce(@owner, owner), severity = coalesce(@severity, severity), priority = coalesce(@priority, priority)",
            command => { command.Parameters.AddWithValue("title", (object?)title ?? DBNull.Value); command.Parameters.AddWithValue("description", (object?)description ?? DBNull.Value); command.Parameters.AddWithValue("owner", (object?)owner ?? DBNull.Value); command.Parameters.AddWithValue("severity", (object?)severity ?? DBNull.Value); command.Parameters.AddWithValue("priority", (object?)priority ?? DBNull.Value); },
            "Updated case metadata.", null, cancellationToken);
    }

    public async Task<CaseDetailRecord?> SetStatusAsync(Guid caseId, CaseMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateExpectedVersion(request.ExpectedVersion);
        var status = NormalizeStatus(request.Status, allowClosed: false);
        return await MutateAsync(caseId, request.ExpectedVersion, "status", actor, request.IdempotencyKey,
            "status = @status", command => command.Parameters.AddWithValue("status", status), $"Changed case status to {status}.", status, cancellationToken);
    }

    public async Task<CaseDetailRecord?> AssignAsync(Guid caseId, CaseMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateExpectedVersion(request.ExpectedVersion);
        var owner = AlertRepository.BoundRequired(request.Owner, 1, 96, "Owner");
        return await MutateAsync(caseId, request.ExpectedVersion, "assign", actor, request.IdempotencyKey,
            "owner = @owner", command => command.Parameters.AddWithValue("owner", owner), $"Assigned case to {owner}.", null, cancellationToken);
    }

    public async Task<CaseDetailRecord?> CloseAsync(Guid caseId, CaseMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateExpectedVersion(request.ExpectedVersion);
        if (!request.Confirm) throw new ArgumentException("Case closure requires explicit confirmation.");
        var disposition = AlertRepository.NormalizeDisposition(request.Disposition, required: true)!;
        var summary = AlertRepository.BoundRequired(request.ClosureSummary, 8, 4000, "Closure summary");
        var criteria = AlertRepository.BoundOptional(request.ClosureCriteria, 4000, "Closure criteria");
        return await MutateAsync(caseId, request.ExpectedVersion, "close", actor, request.IdempotencyKey,
            "status = 'closed', disposition = @disposition, closure_summary = @summary, closure_criteria = @criteria, coverage_gap_acknowledged = @coverage, closed_at = now()",
            command => { command.Parameters.AddWithValue("disposition", disposition); command.Parameters.AddWithValue("summary", summary); command.Parameters.AddWithValue("criteria", (object?)criteria ?? DBNull.Value); command.Parameters.AddWithValue("coverage", request.CoverageGapAcknowledged); },
            $"Closed case with disposition {disposition}.", "closed", cancellationToken);
    }

    public async Task<CaseDetailRecord?> ReopenAsync(Guid caseId, CaseMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateExpectedVersion(request.ExpectedVersion);
        return await MutateAsync(caseId, request.ExpectedVersion, "reopen", actor, request.IdempotencyKey,
            "status = 'investigating', reopened_at = now()", _ => { }, "Reopened case for investigation.", "investigating", cancellationToken);
    }

    public async Task<CaseDetailRecord?> AddNoteAsync(Guid caseId, CaseNoteRequest request, string actor, CancellationToken cancellationToken)
    {
        var body = AlertRepository.BoundRequired(request.Body, 1, 4000, "Note body");
        AlertRepository.ValidateIdempotency(request.IdempotencyKey);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!await CaseExistsAsync(connection, caseId, cancellationToken)) return null;
        if (!string.IsNullOrWhiteSpace(request.IdempotencyKey) && await HasCaseActivityAsync(connection, caseId, request.IdempotencyKey!, cancellationToken)) return await GetAsync(caseId, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "insert into case_notes(note_id, case_id, body, created_by) values(@note_id, @case_id, @body, @actor);";
            command.Parameters.AddWithValue("note_id", Guid.NewGuid());
            command.Parameters.AddWithValue("case_id", caseId);
            command.Parameters.AddWithValue("body", body);
            command.Parameters.AddWithValue("actor", BoundActor(actor));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await TouchCaseAsync(connection, transaction, caseId, actor, "note", cancellationToken);
        await AddCaseActivityAsync(connection, transaction, caseId, "note", actor, null, null, "Added analyst note.", request.IdempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(caseId, cancellationToken);
    }

    public async Task<CaseDetailRecord?> LinkAlertAsync(Guid caseId, CaseAlertRequest request, string actor, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateIdempotency(request.IdempotencyKey);
        var relationship = BoundRelationship(request.Relationship);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!await CaseExistsAsync(connection, caseId, cancellationToken)) return null;
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await LinkAlertInternalAsync(connection, transaction, caseId, request.AlertId, relationship, actor, cancellationToken);
        await TouchCaseAsync(connection, transaction, caseId, actor, "link_alert", cancellationToken);
        await AddCaseActivityAsync(connection, transaction, caseId, "link_alert", actor, null, null, "Linked alert to case.", request.IdempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(caseId, cancellationToken);
    }

    public async Task<CaseDetailRecord?> LinkEntityAsync(Guid caseId, CaseEntityRequest request, string actor, CancellationToken cancellationToken)
    {
        var type = AlertRepository.BoundRequired(request.EntityType, 1, 64, "Entity type");
        var value = AlertRepository.BoundRequired(request.EntityValue, 1, 512, "Entity value");
        var relationship = AlertRepository.BoundRequired(request.Relationship, 1, 64, "Relationship");
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!await CaseExistsAsync(connection, caseId, cancellationToken)) return null;
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "insert into case_entities(case_entity_id, case_id, entity_type, entity_value, relationship, created_by) values(@id, @case_id, @type, @value, @relationship, @actor);";
            command.Parameters.AddWithValue("id", Guid.NewGuid()); command.Parameters.AddWithValue("case_id", caseId); command.Parameters.AddWithValue("type", type); command.Parameters.AddWithValue("value", value); command.Parameters.AddWithValue("relationship", relationship); command.Parameters.AddWithValue("actor", BoundActor(actor));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await TouchCaseAsync(connection, transaction, caseId, actor, "link_entity", cancellationToken);
        await AddCaseActivityAsync(connection, transaction, caseId, "link_entity", actor, null, null, "Linked related entity.", request.IdempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(caseId, cancellationToken);
    }

    public async Task<CaseDetailRecord?> LinkGraphAsync(Guid caseId, CaseGraphRequest request, string actor, CancellationToken cancellationToken)
    {
        var relationship = AlertRepository.BoundRequired(request.Relationship, 1, 64, "Relationship");
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!await CaseExistsAsync(connection, caseId, cancellationToken)) return null;
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "insert into case_graphs(case_id, graph_id, relationship, created_by) values(@case_id, @graph_id, @relationship, @actor) on conflict(case_id, graph_id) do update set relationship = excluded.relationship;";
            command.Parameters.AddWithValue("case_id", caseId); command.Parameters.AddWithValue("graph_id", request.GraphId); command.Parameters.AddWithValue("relationship", relationship); command.Parameters.AddWithValue("actor", BoundActor(actor));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await TouchCaseAsync(connection, transaction, caseId, actor, "link_graph", cancellationToken);
        await AddCaseActivityAsync(connection, transaction, caseId, "link_graph", actor, null, null, "Linked investigation graph.", request.IdempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(caseId, cancellationToken);
    }

    public async Task<CaseDetailRecord?> LinkEvidenceAsync(Guid caseId, CaseEvidenceRequest request, string actor, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!await CaseExistsAsync(connection, caseId, cancellationToken)) return null;
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into case_evidence(case_evidence_id, case_id, alert_id, agent_id, event_id, event_time, host_timezone, evidence_kind, summary, created_by)
                select @id, @case_id, @alert_id, @agent_id, @event_id, coalesce(ae.event_time, e.event_time), coalesce(ae.host_timezone, e.host_timezone),
                       case when ae.event_id is null then 'event' else 'alert_evidence' end,
                       coalesce(@summary, ae.summary, left(concat_ws(' ', e.source_id, e.event_code, e.event_category, e.event_action), 500), 'Evidence identity retained; underlying telemetry missing.'), @actor
                from (select 1) seed
                left join alert_evidence ae on ae.agent_id = @agent_id and ae.event_id = @event_id and (@alert_id is null or ae.alert_id = @alert_id)
                left join events e on e.agent_id = @agent_id and e.event_id = @event_id
                on conflict(case_id, agent_id, event_id) do nothing;
                """;
            command.Parameters.AddWithValue("id", Guid.NewGuid()); command.Parameters.AddWithValue("case_id", caseId); command.Parameters.AddWithValue("alert_id", request.AlertId.HasValue ? request.AlertId.Value : DBNull.Value); command.Parameters.AddWithValue("agent_id", AlertRepository.BoundRequired(request.AgentId, 1, 128, "Agent ID")); command.Parameters.AddWithValue("event_id", request.EventId); command.Parameters.AddWithValue("summary", (object?)AlertRepository.BoundOptional(request.Summary, 1000, "Evidence summary") ?? DBNull.Value); command.Parameters.AddWithValue("actor", BoundActor(actor));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await TouchCaseAsync(connection, transaction, caseId, actor, "link_evidence", cancellationToken);
        await AddCaseActivityAsync(connection, transaction, caseId, "link_evidence", actor, null, null, "Linked evidence identity to case.", request.IdempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(caseId, cancellationToken);
    }

    private async Task<CaseDetailRecord?> MutateAsync(Guid caseId, int expectedVersion, string action, string actor, string? idempotencyKey, string setSql, Action<NpgsqlCommand> addParameters, string summary, string? toStatus, CancellationToken cancellationToken)
    {
        AlertRepository.ValidateIdempotency(idempotencyKey);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!string.IsNullOrWhiteSpace(idempotencyKey) && await HasCaseActivityAsync(connection, caseId, idempotencyKey!, cancellationToken)) return await GetAsync(caseId, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        string? fromStatus;
        await using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = "select status from cases where case_id = @case_id and version = @expected_version for update;";
            read.Parameters.AddWithValue("case_id", caseId); read.Parameters.AddWithValue("expected_version", expectedVersion);
            fromStatus = await read.ExecuteScalarAsync(cancellationToken) as string;
            if (fromStatus is null) { await transaction.RollbackAsync(cancellationToken); return null; }
        }
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"update cases set {setSql}, version = version + 1, updated_at = now(), last_activity_at = now(), last_actor = @actor, last_action = @action where case_id = @case_id and version = @expected_version;";
            command.Parameters.AddWithValue("case_id", caseId); command.Parameters.AddWithValue("expected_version", expectedVersion); command.Parameters.AddWithValue("actor", BoundActor(actor)); command.Parameters.AddWithValue("action", action);
            addParameters(command);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await AddCaseActivityAsync(connection, transaction, caseId, action, actor, fromStatus, toStatus, summary, idempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAsync(caseId, cancellationToken);
    }

    private const string CaseSummarySql = """
        select c.case_id, c.case_key, c.title, c.owner, c.severity, c.priority, c.status, c.disposition, c.version, c.created_at, c.updated_at, c.last_activity_at,
               coalesce(a.alert_count, 0)::int as alert_count, coalesce(e.evidence_count, 0)::int as evidence_count
        from cases c
        left join lateral (select count(*)::int as alert_count from case_alerts where case_id = c.case_id) a on true
        left join lateral (select count(*)::int as evidence_count from case_evidence where case_id = c.case_id) e on true
        """;
    private const string CaseDetailSql = """
        select c.case_id, c.case_key, c.title, c.description, c.owner, c.severity, c.priority, c.status, c.disposition, c.closure_summary, c.closure_criteria, c.coverage_gap_acknowledged,
               c.version, c.created_at, c.updated_at, c.closed_at, c.reopened_at, c.last_activity_at,
               coalesce(a.alert_count, 0)::int as alert_count, coalesce(e.evidence_count, 0)::int as evidence_count
        from cases c
        left join lateral (select count(*)::int as alert_count from case_alerts where case_id = c.case_id) a on true
        left join lateral (select count(*)::int as evidence_count from case_evidence where case_id = c.case_id) e on true
        """;

    private static CaseSummaryRecord ReadSummary(NpgsqlDataReader reader) => new()
    {
        CaseId = reader.GetGuid(reader.GetOrdinal("case_id")), CaseKey = reader.GetString(reader.GetOrdinal("case_key")), Title = reader.GetString(reader.GetOrdinal("title")), Owner = ReadNullableString(reader, "owner"), Severity = reader.GetString(reader.GetOrdinal("severity")), Priority = reader.GetString(reader.GetOrdinal("priority")), Status = reader.GetString(reader.GetOrdinal("status")), Disposition = ReadNullableString(reader, "disposition"), Version = reader.GetInt32(reader.GetOrdinal("version")), CreatedAt = ReadTime(reader, "created_at"), UpdatedAt = ReadTime(reader, "updated_at"), LastActivityAt = ReadTime(reader, "last_activity_at"), AlertCount = reader.GetInt32(reader.GetOrdinal("alert_count")), EvidenceCount = reader.GetInt32(reader.GetOrdinal("evidence_count"))
    };

    private static CaseDetailRecord ReadDetail(NpgsqlDataReader reader) => new()
    {
        CaseId = reader.GetGuid(reader.GetOrdinal("case_id")), CaseKey = reader.GetString(reader.GetOrdinal("case_key")), Title = reader.GetString(reader.GetOrdinal("title")), Description = ReadNullableString(reader, "description"), Owner = ReadNullableString(reader, "owner"), Severity = reader.GetString(reader.GetOrdinal("severity")), Priority = reader.GetString(reader.GetOrdinal("priority")), Status = reader.GetString(reader.GetOrdinal("status")), Disposition = ReadNullableString(reader, "disposition"), ClosureSummary = ReadNullableString(reader, "closure_summary"), ClosureCriteria = ReadNullableString(reader, "closure_criteria"), CoverageGapAcknowledged = reader.GetBoolean(reader.GetOrdinal("coverage_gap_acknowledged")), Version = reader.GetInt32(reader.GetOrdinal("version")), CreatedAt = ReadTime(reader, "created_at"), UpdatedAt = ReadTime(reader, "updated_at"), ClosedAt = ReadNullableTime(reader, "closed_at"), ReopenedAt = ReadNullableTime(reader, "reopened_at"), LastActivityAt = ReadTime(reader, "last_activity_at"), AlertCount = reader.GetInt32(reader.GetOrdinal("alert_count")), EvidenceCount = reader.GetInt32(reader.GetOrdinal("evidence_count"))
    };

    private static async Task<CaseDetailRecord?> LoadDetailAsync(NpgsqlConnection connection, Guid caseId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = CaseDetailSql + " where c.case_id = @case_id;";
        command.Parameters.AddWithValue("case_id", caseId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadDetail(reader) : null;
    }

    private static async Task<IReadOnlyList<CaseAlertLinkRecord>> LoadAlertsAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct, int? limit = null)
    {
        await using var q = c.CreateCommand(); q.CommandText = "select a.alert_id, a.title, a.status, a.severity, ca.relationship from case_alerts ca join alerts a on a.alert_id=ca.alert_id where ca.case_id=@case_id order by ca.created_at desc"; q.Parameters.AddWithValue("case_id", caseId); AddOptionalLimit(q, limit);
        var rows = new List<CaseAlertLinkRecord>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) rows.Add(new() { AlertId = r.GetGuid(0), Title = r.GetString(1), Status = r.GetString(2), Severity = r.GetString(3), Relationship = r.GetString(4) }); return rows;
    }
    private static async Task<IReadOnlyList<CaseEntityRecord>> LoadEntitiesAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct, int? limit = null)
    {
        await using var q = c.CreateCommand(); q.CommandText = "select case_entity_id, entity_type, entity_value, relationship from case_entities where case_id=@case_id order by created_at desc"; q.Parameters.AddWithValue("case_id", caseId); AddOptionalLimit(q, limit);
        var rows = new List<CaseEntityRecord>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) rows.Add(new() { CaseEntityId = r.GetGuid(0), EntityType = r.GetString(1), EntityValue = r.GetString(2), Relationship = r.GetString(3) }); return rows;
    }
    private static async Task<IReadOnlyList<CaseGraphLinkRecord>> LoadGraphsAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct, int? limit = null)
    {
        await using var q = c.CreateCommand(); q.CommandText = "select g.graph_id, g.title, g.status, cg.relationship from case_graphs cg join investigation_graphs g on g.graph_id=cg.graph_id where cg.case_id=@case_id order by cg.created_at desc"; q.Parameters.AddWithValue("case_id", caseId); AddOptionalLimit(q, limit);
        var rows = new List<CaseGraphLinkRecord>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) rows.Add(new() { GraphId = r.GetGuid(0), Title = r.GetString(1), Status = r.GetString(2), Relationship = r.GetString(3) }); return rows;
    }
    private static async Task<IReadOnlyList<CaseEvidenceRecord>> LoadEvidenceAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct, int? limit = null)
    {
        await using var q = c.CreateCommand(); q.CommandText = """
            select ce.case_evidence_id, ce.alert_id, ce.agent_id, ce.event_id, ce.event_time, ce.host_timezone, ce.evidence_kind, ce.summary,
                   case when e.event_id is not null then 'telemetry_retained' when mre.event_id is not null then 'telemetry_removed_by_retention' else 'underlying_telemetry_missing' end as telemetry_retention_state
            from case_evidence ce
            left join events e on e.agent_id=ce.agent_id and e.event_id=ce.event_id
            left join managed_retention_removed_events mre on mre.agent_id=ce.agent_id and mre.event_id=ce.event_id
            where ce.case_id=@case_id order by ce.created_at desc
            """; q.Parameters.AddWithValue("case_id", caseId); AddOptionalLimit(q, limit);
        var rows = new List<CaseEvidenceRecord>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) rows.Add(new() { CaseEvidenceId = r.GetGuid(r.GetOrdinal("case_evidence_id")), AlertId = ReadNullableGuid(r, "alert_id"), AgentId = r.GetString(r.GetOrdinal("agent_id")), EventId = r.GetGuid(r.GetOrdinal("event_id")), EventTime = ReadNullableTime(r, "event_time"), HostTimezone = Jsonb.Read<HostTimezoneMetadata>(r, "host_timezone"), EvidenceKind = r.GetString(r.GetOrdinal("evidence_kind")), Summary = r.GetString(r.GetOrdinal("summary")), TelemetryRetentionState = r.GetString(r.GetOrdinal("telemetry_retention_state")) }); return rows;
    }
    private static async Task<IReadOnlyList<CaseNoteRecord>> LoadNotesAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct, int? limit = null)
    {
        await using var q = c.CreateCommand(); q.CommandText = "select note_id, created_at, created_by, body from case_notes where case_id=@case_id order by created_at desc"; q.Parameters.AddWithValue("case_id", caseId); AddRequiredLimit(q, limit ?? 100);
        var rows = new List<CaseNoteRecord>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) rows.Add(new() { NoteId = r.GetGuid(0), CreatedAt = ReadTime(r, "created_at"), CreatedBy = ReadNullableString(r, "created_by"), Body = r.GetString(3) }); return rows;
    }
    private static async Task<IReadOnlyList<CaseActivityRecord>> LoadActivitiesAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct, int? limit = null)
    {
        await using var q = c.CreateCommand(); q.CommandText = "select activity_id, occurred_at, actor, action, from_status, to_status, summary from case_activities where case_id=@case_id order by occurred_at desc"; q.Parameters.AddWithValue("case_id", caseId); AddRequiredLimit(q, limit ?? 100);
        var rows = new List<CaseActivityRecord>(); await using var r = await q.ExecuteReaderAsync(ct); while (await r.ReadAsync(ct)) rows.Add(new() { ActivityId = r.GetGuid(0), OccurredAt = ReadTime(r, "occurred_at"), Actor = ReadNullableString(r, "actor"), Action = r.GetString(r.GetOrdinal("action")), FromStatus = ReadNullableString(r, "from_status"), ToStatus = ReadNullableString(r, "to_status"), Summary = r.GetString(r.GetOrdinal("summary")) }); return rows;
    }

    private static BoundedCaseCollectionState State<T>(IReadOnlyCollection<T> rows, int limit) =>
        new(Math.Min(rows.Count, limit), rows.Count > limit);

    private static void AddOptionalLimit(NpgsqlCommand command, int? limit)
    {
        if (limit.HasValue)
        {
            AddRequiredLimit(command, limit.Value);
            return;
        }

        command.CommandText += ";";
    }

    private static void AddRequiredLimit(NpgsqlCommand command, int limit)
    {
        command.CommandText += " limit @nested_limit;";
        command.Parameters.AddWithValue("nested_limit", limit);
    }

    private static async Task<Guid?> FindCaseByIdempotencyAsync(NpgsqlConnection c, string key, CancellationToken ct)
    {
        await using var q = c.CreateCommand();
        q.CommandText = "select case_id from cases where idempotency_key = @key limit 1;";
        q.Parameters.AddWithValue("key", key);
        var value = await q.ExecuteScalarAsync(ct);
        return value is Guid id ? id : null;
    }

    private static async Task<string> NextCaseKeyAsync(NpgsqlConnection c, NpgsqlTransaction t, CancellationToken ct)
    {
        await using var q = c.CreateCommand(); q.Transaction = t; q.CommandText = "select 'CASE-' || to_char(now(), 'YYYY') || '-' || lpad((count(*) + 1)::text, 6, '0') from cases where created_at >= date_trunc('year', now());"; return (string)(await q.ExecuteScalarAsync(ct) ?? $"CASE-{DateTimeOffset.UtcNow:yyyy}-000001");
    }
    private static async Task LinkAlertInternalAsync(NpgsqlConnection c, NpgsqlTransaction t, Guid caseId, Guid alertId, string relationship, string actor, CancellationToken ct)
    {
        await using var q = c.CreateCommand(); q.Transaction = t; q.CommandText = "insert into case_alerts(case_id, alert_id, relationship, created_by) values(@case_id,@alert_id,@relationship,@actor) on conflict(case_id, alert_id) do update set relationship=excluded.relationship;"; q.Parameters.AddWithValue("case_id", caseId); q.Parameters.AddWithValue("alert_id", alertId); q.Parameters.AddWithValue("relationship", relationship); q.Parameters.AddWithValue("actor", BoundActor(actor)); await q.ExecuteNonQueryAsync(ct);
    }
    private static async Task TouchCaseAsync(NpgsqlConnection c, NpgsqlTransaction t, Guid caseId, string actor, string action, CancellationToken ct)
    {
        await using var q = c.CreateCommand(); q.Transaction = t; q.CommandText = "update cases set updated_at=now(), last_activity_at=now(), last_actor=@actor, last_action=@action where case_id=@case_id;"; q.Parameters.AddWithValue("case_id", caseId); q.Parameters.AddWithValue("actor", BoundActor(actor)); q.Parameters.AddWithValue("action", action); await q.ExecuteNonQueryAsync(ct);
    }
    private static async Task AddCaseActivityAsync(NpgsqlConnection c, NpgsqlTransaction t, Guid caseId, string action, string actor, string? fromStatus, string? toStatus, string summary, string? idempotencyKey, CancellationToken ct)
    {
        await using var q = c.CreateCommand(); q.Transaction = t; q.CommandText = "insert into case_activities(activity_id, case_id, actor, action, from_status, to_status, summary, idempotency_key) values(@id,@case_id,@actor,@action,@from,@to,@summary,@key) on conflict do nothing;"; q.Parameters.AddWithValue("id", Guid.NewGuid()); q.Parameters.AddWithValue("case_id", caseId); q.Parameters.AddWithValue("actor", BoundActor(actor)); q.Parameters.AddWithValue("action", action); q.Parameters.AddWithValue("from", (object?)fromStatus ?? DBNull.Value); q.Parameters.AddWithValue("to", (object?)toStatus ?? DBNull.Value); q.Parameters.AddWithValue("summary", AlertRepository.BoundRequired(summary, 1, 1000, "Activity summary")); q.Parameters.AddWithValue("key", (object?)idempotencyKey ?? DBNull.Value); await q.ExecuteNonQueryAsync(ct);
    }
    private static async Task<bool> HasCaseActivityAsync(NpgsqlConnection c, Guid caseId, string key, CancellationToken ct) { await using var q = c.CreateCommand(); q.CommandText = "select exists(select 1 from case_activities where case_id=@case_id and idempotency_key=@key);"; q.Parameters.AddWithValue("case_id", caseId); q.Parameters.AddWithValue("key", key); return (bool)(await q.ExecuteScalarAsync(ct) ?? false); }
    private static async Task<bool> CaseExistsAsync(NpgsqlConnection c, Guid caseId, CancellationToken ct) { await using var q = c.CreateCommand(); q.CommandText = "select exists(select 1 from cases where case_id=@case_id);"; q.Parameters.AddWithValue("case_id", caseId); return (bool)(await q.ExecuteScalarAsync(ct) ?? false); }

    public static string NormalizeStatus(string? status, bool allowClosed) { var v = (status ?? string.Empty).Trim().ToLowerInvariant(); var allowed = allowClosed ? new[] { CaseStatuses.Draft, CaseStatuses.Open, CaseStatuses.Investigating, CaseStatuses.PendingExternal, CaseStatuses.Contained, CaseStatuses.Resolved, CaseStatuses.Closed } : new[] { CaseStatuses.Draft, CaseStatuses.Open, CaseStatuses.Investigating, CaseStatuses.PendingExternal, CaseStatuses.Contained, CaseStatuses.Resolved }; if (!allowed.Contains(v, StringComparer.Ordinal)) throw new ArgumentException("Case status value is not recognized for this transition."); return v; }
    public static string NormalizeSeverity(string? severity) { var v = (severity ?? DetectionSeverities.Medium).Trim().ToLowerInvariant(); var allowed = new[] { DetectionSeverities.Informational, DetectionSeverities.Low, DetectionSeverities.Medium, DetectionSeverities.High, DetectionSeverities.Critical }; if (!allowed.Contains(v, StringComparer.Ordinal)) throw new ArgumentException("Severity value is not recognized."); return v; }
    public static string NormalizePriority(string? priority) { var v = (priority ?? CasePriorities.Normal).Trim().ToLowerInvariant(); var allowed = new[] { CasePriorities.Low, CasePriorities.Normal, CasePriorities.High, CasePriorities.Urgent }; if (!allowed.Contains(v, StringComparer.Ordinal)) throw new ArgumentException("Priority value is not recognized."); return v; }
    private static string BoundRelationship(string? relationship) { var v = (relationship ?? "related").Trim().ToLowerInvariant(); var allowed = new[] { "primary", "related", "duplicate_of", "derived_from" }; if (!allowed.Contains(v, StringComparer.Ordinal)) throw new ArgumentException("Alert relationship value is not recognized."); return v; }
    private static string BoundActor(string actor) => AlertRepository.BoundOptional(actor, 96, "Actor") ?? "operator";
    private static string? ReadNullableString(NpgsqlDataReader r, string n) { var i = r.GetOrdinal(n); return r.IsDBNull(i) ? null : r.GetString(i); }
    private static Guid? ReadNullableGuid(NpgsqlDataReader r, string n) { var i = r.GetOrdinal(n); return r.IsDBNull(i) ? null : r.GetGuid(i); }
    private static DateTimeOffset ReadTime(NpgsqlDataReader r, string n) { var value = r.GetValue(r.GetOrdinal(n)); return value switch { DateTimeOffset dto => dto.ToUniversalTime(), DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)), _ => throw new InvalidOperationException("Timestamp column was invalid.") }; }
    private static DateTimeOffset? ReadNullableTime(NpgsqlDataReader r, string n) { var i = r.GetOrdinal(n); if (r.IsDBNull(i)) return null; var value = r.GetValue(i); return value switch { DateTimeOffset dto => dto.ToUniversalTime(), DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)), _ => null }; }
}
