using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Api.Detections;
using Challenger.Siem.Contracts.V1;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed class AlertRepository(NpgsqlDataSource dataSource)
{
    public async Task<IReadOnlyList<AlertRecord>> SearchAlertsAsync(string? status, CancellationToken cancellationToken, int limit = 500, int offset = 0)
    {
        var clampedLimit = Math.Clamp(limit, 1, 500);
        var clampedOffset = Math.Max(0, offset);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select alert_id, rule_id, rule_version, title, severity, confidence, status, owner, version, updated_at,
                   acknowledged_at, triaged_at, suppressed_at, suppressed_until, suppression_reason, disposition,
                   closed_at, closure_summary, reopened_at, last_activity_at, agent_id, hostname, created_at, summary, affected_entities
            from alerts
            """;
        if (!string.IsNullOrWhiteSpace(status))
        {
            command.CommandText += " where status = @status";
            command.Parameters.AddWithValue("status", status);
        }

        command.Parameters.AddWithValue("limit", clampedLimit);
        command.Parameters.AddWithValue("offset", clampedOffset);
        command.CommandText += " order by created_at desc limit @limit offset @offset;";
        var alerts = new List<AlertRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            alerts.Add(ReadAlert(reader, Array.Empty<AlertEvidenceRecord>()));
        }

        return alerts;
    }

    public async Task<AlertRecord?> GetAlertAsync(Guid alertId, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        AlertRecord? alert = null;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                select alert_id, rule_id, rule_version, title, severity, confidence, status, owner, version, updated_at,
                       acknowledged_at, triaged_at, suppressed_at, suppressed_until, suppression_reason, disposition,
                       closed_at, closure_summary, reopened_at, last_activity_at, agent_id, hostname, created_at, summary, affected_entities
                from alerts
                where alert_id = @alert_id
                limit 1;
                """;
            command.Parameters.AddWithValue("alert_id", alertId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                alert = ReadAlert(reader, Array.Empty<AlertEvidenceRecord>());
            }
        }

        if (alert is null)
        {
            return null;
        }

        var evidence = await LoadEvidenceAsync(connection, alertId, cancellationToken);
        var cases = await LoadCaseLinksAsync(connection, alertId, cancellationToken);
        var activity = await LoadActivityAsync(connection, alertId, cancellationToken);
        return alert with { Evidence = evidence, Cases = cases, Activity = activity };
    }

    public async Task<AlertRecord?> AssignAsync(Guid alertId, AlertMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        ValidateExpectedVersion(request.ExpectedVersion);
        var owner = BoundOptional(request.Owner, 96, "Owner");
        if (owner is null) throw new ArgumentException("Owner is required.");
        return await MutateAlertAsync(alertId, request.ExpectedVersion, "assign", actor, request.IdempotencyKey,
            "owner = @owner", command => command.Parameters.AddWithValue("owner", owner),
            $"Assigned alert to {owner}.", null, cancellationToken);
    }

    public async Task<AlertRecord?> AcknowledgeAsync(Guid alertId, AlertMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        ValidateExpectedVersion(request.ExpectedVersion);
        return await MutateAlertAsync(alertId, request.ExpectedVersion, "acknowledge", actor, request.IdempotencyKey,
            "status = 'acknowledged', acknowledged_at = coalesce(acknowledged_at, now())", _ => { },
            "Acknowledged alert for triage.", "acknowledged", cancellationToken);
    }

    public async Task<AlertRecord?> SetStatusAsync(Guid alertId, AlertMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        ValidateExpectedVersion(request.ExpectedVersion);
        var status = NormalizeAlertStatus(request.Status);
        return await MutateAlertAsync(alertId, request.ExpectedVersion, "status", actor, request.IdempotencyKey,
            "status = @status, triaged_at = case when @status in ('triaged','investigating','escalated','contained','resolved') then coalesce(triaged_at, now()) else triaged_at end",
            command => command.Parameters.AddWithValue("status", status),
            $"Changed alert status to {status}.", status, cancellationToken);
    }

    public async Task<AlertRecord?> SuppressAsync(Guid alertId, AlertMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        ValidateExpectedVersion(request.ExpectedVersion);
        var reason = BoundRequired(request.Reason, 8, 1000, "Suppression reason");
        if (request.SuppressedUntil.HasValue && request.SuppressedUntil.Value <= DateTimeOffset.UtcNow.AddMinutes(-1))
        {
            throw new ArgumentException("Suppression expiry must be in the future when provided.");
        }
        return await MutateAlertAsync(alertId, request.ExpectedVersion, "suppress", actor, request.IdempotencyKey,
            "status = 'suppressed', suppressed_at = now(), suppressed_until = @until, suppression_reason = @reason",
            command => { command.Parameters.AddWithValue("until", request.SuppressedUntil.HasValue ? request.SuppressedUntil.Value.ToUniversalTime() : DBNull.Value); command.Parameters.AddWithValue("reason", reason); },
            "Suppressed alert with bounded analyst reason.", "suppressed", cancellationToken);
    }

    public async Task<AlertRecord?> CloseAsync(Guid alertId, AlertMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        ValidateExpectedVersion(request.ExpectedVersion);
        var disposition = NormalizeDisposition(request.Disposition, required: true);
        var summary = BoundRequired(request.Summary, 8, 2000, "Closure summary");
        return await MutateAlertAsync(alertId, request.ExpectedVersion, "close", actor, request.IdempotencyKey,
            "status = 'closed', disposition = @disposition, closure_summary = @summary, closed_at = now()",
            command => { command.Parameters.AddWithValue("disposition", disposition!); command.Parameters.AddWithValue("summary", summary); },
            $"Closed alert with disposition {disposition}.", "closed", cancellationToken);
    }

    public async Task<AlertRecord?> ReopenAsync(Guid alertId, AlertMutationRequest request, string actor, CancellationToken cancellationToken)
    {
        ValidateExpectedVersion(request.ExpectedVersion);
        return await MutateAlertAsync(alertId, request.ExpectedVersion, "reopen", actor, request.IdempotencyKey,
            "status = 'investigating', reopened_at = now(), closed_at = null",
            _ => { }, "Reopened alert for investigation.", "investigating", cancellationToken);
    }

    private async Task<AlertRecord?> MutateAlertAsync(Guid alertId, int expectedVersion, string action, string actor, string? idempotencyKey,
        string setSql, Action<NpgsqlCommand> addParameters, string activitySummary, string? toStatus, CancellationToken cancellationToken)
    {
        ValidateIdempotency(idempotencyKey);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        if (!string.IsNullOrWhiteSpace(idempotencyKey) && await HasAlertActivityAsync(connection, alertId, idempotencyKey!, cancellationToken))
        {
            return await GetAlertAsync(alertId, cancellationToken);
        }

        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        string? fromStatus;
        await using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = "select status from alerts where alert_id = @alert_id and version = @expected_version for update;";
            read.Parameters.AddWithValue("alert_id", alertId);
            read.Parameters.AddWithValue("expected_version", expectedVersion);
            fromStatus = await read.ExecuteScalarAsync(cancellationToken) as string;
            if (fromStatus is null)
            {
                await transaction.RollbackAsync(cancellationToken);
                return null;
            }
        }
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"""
                update alerts
                set {setSql}, version = version + 1, updated_at = now(), last_activity_at = now(), last_actor = @actor, last_action = @action
                where alert_id = @alert_id and version = @expected_version;
                """;
            command.Parameters.AddWithValue("alert_id", alertId);
            command.Parameters.AddWithValue("expected_version", expectedVersion);
            command.Parameters.AddWithValue("actor", BoundOptional(actor, 96, "Actor") ?? "operator");
            command.Parameters.AddWithValue("action", action);
            addParameters(command);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await AddAlertActivityAsync(connection, transaction, alertId, action, actor, fromStatus, toStatus, activitySummary, idempotencyKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetAlertAsync(alertId, cancellationToken);
    }

    public async Task<IReadOnlyList<DetectionRuleMetadata>> GetRulesAsync(CancellationToken cancellationToken)
    {
        await EnsureBuiltInRulesAsync(cancellationToken);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select rule_id, version, name, description, severity, confidence, category, required_sources, required_fields, mitre_attack,
                   tactics, correlation_window_seconds, suppression_keys, false_positive_notes, response_guidance, enabled
            from detection_rules
            order by category asc, rule_id asc, version desc;
            """;
        var results = new List<DetectionRuleMetadata>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new DetectionRuleMetadata
            {
                RuleId = reader.GetString(reader.GetOrdinal("rule_id")),
                Version = reader.GetInt32(reader.GetOrdinal("version")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                Description = reader.GetString(reader.GetOrdinal("description")),
                Severity = reader.GetString(reader.GetOrdinal("severity")),
                Confidence = reader.GetString(reader.GetOrdinal("confidence")),
                Category = reader.GetString(reader.GetOrdinal("category")),
                RequiredSources = reader.GetFieldValue<string[]>(reader.GetOrdinal("required_sources")),
                RequiredFields = reader.GetFieldValue<string[]>(reader.GetOrdinal("required_fields")),
                MitreAttack = reader.GetFieldValue<string[]>(reader.GetOrdinal("mitre_attack")),
                Tactics = reader.GetFieldValue<string[]>(reader.GetOrdinal("tactics")),
                CorrelationWindowSeconds = reader.GetInt32(reader.GetOrdinal("correlation_window_seconds")),
                SuppressionKeys = reader.GetFieldValue<string[]>(reader.GetOrdinal("suppression_keys")),
                FalsePositiveNotes = reader.GetString(reader.GetOrdinal("false_positive_notes")),
                ResponseGuidance = reader.GetString(reader.GetOrdinal("response_guidance")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled"))
            });
        }

        return results;
    }

    public async Task EnsureBuiltInRulesAsync(CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        foreach (var rule in DetectionRuleCatalog.BuiltInRules)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                insert into detection_rules (
                    rule_id, version, name, description, severity, confidence, category, required_sources, required_fields, mitre_attack,
                    tactics, correlation_window_seconds, suppression_keys, false_positive_notes, response_guidance, enabled)
                values (
                    @rule_id, @version, @name, @description, @severity, @confidence, @category, @required_sources, @required_fields, @mitre_attack,
                    @tactics, @correlation_window_seconds, @suppression_keys, @false_positive_notes, @response_guidance, @enabled)
                on conflict (rule_id, version) do update set
                    name = excluded.name,
                    description = excluded.description,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    category = excluded.category,
                    required_sources = excluded.required_sources,
                    required_fields = excluded.required_fields,
                    mitre_attack = excluded.mitre_attack,
                    tactics = excluded.tactics,
                    correlation_window_seconds = excluded.correlation_window_seconds,
                    suppression_keys = excluded.suppression_keys,
                    false_positive_notes = excluded.false_positive_notes,
                    response_guidance = excluded.response_guidance,
                    enabled = excluded.enabled;
                """;
            command.Parameters.AddWithValue("rule_id", rule.RuleId);
            command.Parameters.AddWithValue("version", rule.Version);
            command.Parameters.AddWithValue("name", rule.Name);
            command.Parameters.AddWithValue("description", rule.Description);
            command.Parameters.AddWithValue("severity", rule.Severity);
            command.Parameters.AddWithValue("confidence", rule.Confidence);
            command.Parameters.AddWithValue("category", rule.Category);
            command.Parameters.AddWithValue("required_sources", rule.RequiredSources.ToArray());
            command.Parameters.AddWithValue("required_fields", rule.RequiredFields.ToArray());
            command.Parameters.AddWithValue("mitre_attack", rule.MitreAttack.ToArray());
            command.Parameters.AddWithValue("tactics", rule.Tactics.ToArray());
            command.Parameters.AddWithValue("correlation_window_seconds", rule.CorrelationWindowSeconds);
            command.Parameters.AddWithValue("suppression_keys", rule.SuppressionKeys.ToArray());
            command.Parameters.AddWithValue("false_positive_notes", rule.FalsePositiveNotes);
            command.Parameters.AddWithValue("response_guidance", rule.ResponseGuidance);
            command.Parameters.AddWithValue("enabled", rule.Enabled);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public async Task RunLinuxDetectionsAsync(
        IngestBatchRequest batch,
        IReadOnlyCollection<Guid> acceptedEventIds,
        DetectionEngine engine,
        CancellationToken cancellationToken)
    {
        if (acceptedEventIds.Count == 0)
        {
            return;
        }

        var accepted = batch.Events
            .Where(envelope => acceptedEventIds.Contains(envelope.EventId))
            .Take(500)
            .ToArray();
        if (accepted.Length == 0)
        {
            return;
        }

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var disabledRules = await LoadDisabledDetectionRulesAsync(connection, cancellationToken);
        foreach (var group in accepted.GroupBy(envelope => envelope.AgentId, StringComparer.Ordinal))
        {
            var sourceHealth = await LoadDetectionSourceHealthAsync(connection, group.Key, cancellationToken);
            foreach (var envelope in group)
            {
                foreach (var evaluation in engine.EvaluateLinux(envelope, sourceHealth))
                {
                    if (disabledRules.Contains((evaluation.Rule.RuleId, evaluation.Rule.Version)) || !evaluation.Matched || !evaluation.PrerequisitesMet)
                    {
                        continue;
                    }

                    var evidenceIds = await ResolveEvidenceEventIdsAsync(connection, envelope, evaluation.Rule, cancellationToken);
                    if (evidenceIds.Count == 0)
                    {
                        continue;
                    }

                    await InsertDetectionAlertAsync(connection, envelope, evaluation, evidenceIds, cancellationToken);
                }
            }
        }
    }

    private static async Task<IReadOnlySet<(string RuleId, int Version)>> LoadDisabledDetectionRulesAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select rule_id, version
            from detection_rule_management
            where not enabled or lifecycle_state in ('disabled', 'deprecated');
            """;
        var results = new HashSet<(string, int)>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add((reader.GetString(0), reader.GetInt32(1)));
        }

        return results;
    }

    private static async Task<IReadOnlyDictionary<string, SourceHealthReport>> LoadDetectionSourceHealthAsync(
        NpgsqlConnection connection,
        string agentId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select source_id, status, prerequisite_statuses, event_family_statuses, gap_detected, cleared_detected,
                   bookmark_gap_detected, dropped_events, transition_state, details
            from source_health
            where agent_id = @agent_id;
            """;
        command.Parameters.AddWithValue("agent_id", agentId);
        var results = new Dictionary<string, SourceHealthReport>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var sourceId = reader.GetString(reader.GetOrdinal("source_id"));
            results[sourceId] = new SourceHealthReport
            {
                SourceId = sourceId,
                Status = reader.GetString(reader.GetOrdinal("status")),
                PrerequisiteStatuses = Jsonb.Read<Dictionary<string, string>>(reader, "prerequisite_statuses"),
                EventFamilyStatuses = Jsonb.Read<Dictionary<string, string>>(reader, "event_family_statuses"),
                GapDetected = reader.GetBoolean(reader.GetOrdinal("gap_detected")),
                ClearedDetected = reader.GetBoolean(reader.GetOrdinal("cleared_detected")),
                BookmarkGapDetected = reader.GetBoolean(reader.GetOrdinal("bookmark_gap_detected")),
                DroppedEvents = ReadNullableInt64(reader, "dropped_events"),
                TransitionState = ReadNullableString(reader, "transition_state"),
                Details = ReadStringDictionary(reader, "details")
            };
        }

        return results;
    }

    private static async Task<IReadOnlyList<Guid>> ResolveEvidenceEventIdsAsync(
        NpgsqlConnection connection,
        EventEnvelope envelope,
        DetectionRuleMetadata rule,
        CancellationToken cancellationToken)
    {
        return rule.RuleId switch
        {
            "auth.bruteforce.linux" => await QueryLinuxAuthenticationFailuresAsync(connection, envelope, rule.CorrelationWindowSeconds, minimumFailures: 5, cancellationToken),
            "auth.success-after-failures.linux" => await QueryLinuxSuccessAfterFailuresAsync(connection, envelope, rule.CorrelationWindowSeconds, minimumFailures: 3, cancellationToken),
            _ => new[] { envelope.EventId }
        };
    }

    private static async Task<IReadOnlyList<Guid>> QueryLinuxAuthenticationFailuresAsync(
        NpgsqlConnection connection,
        EventEnvelope envelope,
        int windowSeconds,
        int minimumFailures,
        CancellationToken cancellationToken)
    {
        var ids = await QueryLinuxAuthenticationEventsAsync(
            connection,
            envelope,
            windowSeconds,
            outcome: "failure",
            beforeOnly: false,
            cancellationToken);
        return ids.Count >= minimumFailures ? ids : Array.Empty<Guid>();
    }

    private static async Task<IReadOnlyList<Guid>> QueryLinuxSuccessAfterFailuresAsync(
        NpgsqlConnection connection,
        EventEnvelope envelope,
        int windowSeconds,
        int minimumFailures,
        CancellationToken cancellationToken)
    {
        var failures = await QueryLinuxAuthenticationEventsAsync(
            connection,
            envelope,
            windowSeconds,
            outcome: "failure",
            beforeOnly: true,
            cancellationToken);
        if (failures.Count < minimumFailures)
        {
            return Array.Empty<Guid>();
        }

        return failures.Concat(new[] { envelope.EventId }).Distinct().Take(20).ToArray();
    }

    private static async Task<IReadOnlyList<Guid>> QueryLinuxAuthenticationEventsAsync(
        NpgsqlConnection connection,
        EventEnvelope envelope,
        int windowSeconds,
        string outcome,
        bool beforeOnly,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        var window = TimeSpan.FromSeconds(Math.Clamp(windowSeconds, 60, 604800));
        command.CommandText = """
            select event_id
            from events
            where agent_id = @agent_id
              and platform = 'linux'
              and source_id = any(@source_ids)
              and event_time >= @start_time
              and event_time <= @end_time
              and event_category = 'authentication'
              and event_action = 'authenticate'
              and normalized_json->>'outcome' = @outcome
              and (@source_ip is null or source_ip = @source_ip)
              and (@target_user_name is null or target_user_name = @target_user_name)
            order by event_time desc
            limit 20;
            """;
        var end = beforeOnly ? envelope.EventTime.AddTicks(-1) : envelope.EventTime.Add(window);
        command.Parameters.AddWithValue("agent_id", envelope.AgentId);
        command.Parameters.AddWithValue("source_ids", new[] { LinuxTelemetrySourceIds.LoginSession, LinuxTelemetrySourceIds.Ssh });
        command.Parameters.AddWithValue("start_time", envelope.EventTime.Subtract(window).ToUniversalTime());
        command.Parameters.AddWithValue("end_time", end.ToUniversalTime());
        command.Parameters.AddWithValue("outcome", outcome);
        command.Parameters.AddWithValue("source_ip", string.IsNullOrWhiteSpace(envelope.Normalized?.SourceIp) ? DBNull.Value : envelope.Normalized.SourceIp);
        command.Parameters.AddWithValue("target_user_name", string.IsNullOrWhiteSpace(envelope.Normalized?.TargetUserName) ? DBNull.Value : envelope.Normalized.TargetUserName);

        var results = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(reader.GetGuid(reader.GetOrdinal("event_id")));
        }

        return results;
    }

    private static async Task InsertDetectionAlertAsync(
        NpgsqlConnection connection,
        EventEnvelope envelope,
        DetectionEvaluationResult evaluation,
        IReadOnlyList<Guid> evidenceIds,
        CancellationToken cancellationToken)
    {
        var rule = evaluation.Rule;
        var alertId = ComputeDeterministicAlertId(rule, envelope, evaluation.SuppressionKey);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                insert into alerts (alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary, affected_entities)
                values (@alert_id, @rule_id, @rule_version, @title, @severity, @confidence, 'new', @agent_id, @hostname, @summary, @affected_entities)
                on conflict (alert_id) do nothing;
                """;
            command.Parameters.AddWithValue("alert_id", alertId);
            command.Parameters.AddWithValue("rule_id", rule.RuleId);
            command.Parameters.AddWithValue("rule_version", rule.Version);
            command.Parameters.AddWithValue("title", rule.Name);
            command.Parameters.AddWithValue("severity", rule.Severity);
            command.Parameters.AddWithValue("confidence", evaluation.EffectiveConfidence);
            command.Parameters.AddWithValue("agent_id", envelope.AgentId);
            command.Parameters.AddWithValue("hostname", envelope.Hostname);
            command.Parameters.AddWithValue("summary", BuildAlertSummary(evaluation, evidenceIds.Count));
            command.Parameters.AddWithValue("affected_entities", JsonSerializer.Serialize(BuildAffectedEntities(rule, envelope), new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var evidence = connection.CreateCommand())
        {
            evidence.CommandText = """
                insert into alert_evidence (alert_id, agent_id, event_id, event_time, channel, windows_event_id, host_timezone, summary)
                select @alert_id, e.agent_id, e.event_id, e.event_time, e.channel, e.windows_event_id, e.host_timezone,
                       left(concat_ws(' ', e.source_id, e.event_code, e.event_category, e.event_action), 500)
                from events e
                where e.agent_id = @agent_id and e.event_id = any(@event_ids)
                on conflict (alert_id, agent_id, event_id) do nothing;
                """;
            evidence.Parameters.AddWithValue("alert_id", alertId);
            evidence.Parameters.AddWithValue("agent_id", envelope.AgentId);
            evidence.Parameters.AddWithValue("event_ids", evidenceIds.Distinct().Take(20).ToArray());
            await evidence.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static string BuildAlertSummary(DetectionEvaluationResult evaluation, int evidenceCount)
    {
        return $"{evaluation.Rule.Name}; confidence={evaluation.EffectiveConfidence}; evidence_events={evidenceCount}; {evaluation.Reason}. Missing or degraded prerequisite telemetry is treated as a visibility gap, not proof of no threat.";
    }

    private static IReadOnlyList<EventEntity> BuildAffectedEntities(DetectionRuleMetadata rule, EventEnvelope envelope)
    {
        var entities = new List<EventEntity>();
        foreach (var key in rule.SuppressionKeys.Concat(rule.RequiredFields).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (key.Contains("command_line", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = DetectionEngine.FieldValue(envelope, key);
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            entities.Add(new EventEntity
            {
                Type = key,
                Value = value.Length > 256 ? value[..256] : value,
                Role = "detection_context"
            });
            if (entities.Count >= 10)
            {
                break;
            }
        }

        return entities;
    }

    private static Guid ComputeDeterministicAlertId(DetectionRuleMetadata rule, EventEnvelope envelope, string suppressionKey)
    {
        var window = Math.Max(rule.CorrelationWindowSeconds, 60);
        var bucket = envelope.EventTime.ToUnixTimeSeconds() / window * window;
        var material = $"{rule.RuleId}\u001f{rule.Version}\u001f{envelope.AgentId}\u001f{suppressionKey}\u001f{bucket}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }

    private static async Task<bool> HasAlertActivityAsync(NpgsqlConnection connection, Guid alertId, string idempotencyKey, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select exists(select 1 from alert_activities where alert_id = @alert_id and idempotency_key = @idempotency_key);";
        command.Parameters.AddWithValue("alert_id", alertId);
        command.Parameters.AddWithValue("idempotency_key", idempotencyKey);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }

    private static async Task AddAlertActivityAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid alertId, string action, string actor,
        string? fromStatus, string? toStatus, string summary, string? idempotencyKey, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            insert into alert_activities(activity_id, alert_id, actor, action, from_status, to_status, summary, idempotency_key)
            values(@activity_id, @alert_id, @actor, @action, @from_status, @to_status, @summary, @idempotency_key)
            on conflict do nothing;
            """;
        command.Parameters.AddWithValue("activity_id", Guid.NewGuid());
        command.Parameters.AddWithValue("alert_id", alertId);
        command.Parameters.AddWithValue("actor", (object?)BoundOptional(actor, 96, "Actor") ?? DBNull.Value);
        command.Parameters.AddWithValue("action", action);
        command.Parameters.AddWithValue("from_status", (object?)fromStatus ?? DBNull.Value);
        command.Parameters.AddWithValue("to_status", (object?)toStatus ?? DBNull.Value);
        command.Parameters.AddWithValue("summary", BoundRequired(summary, 1, 1000, "Activity summary"));
        command.Parameters.AddWithValue("idempotency_key", (object?)idempotencyKey ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<IReadOnlyList<AlertCaseLinkRecord>> LoadCaseLinksAsync(NpgsqlConnection connection, Guid alertId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select c.case_id, c.case_key, c.title, c.status, ca.relationship
            from case_alerts ca
            join cases c on c.case_id = ca.case_id
            where ca.alert_id = @alert_id
            order by c.updated_at desc
            limit 50;
            """;
        command.Parameters.AddWithValue("alert_id", alertId);
        var results = new List<AlertCaseLinkRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AlertCaseLinkRecord
            {
                CaseId = reader.GetGuid(reader.GetOrdinal("case_id")),
                CaseKey = reader.GetString(reader.GetOrdinal("case_key")),
                Title = reader.GetString(reader.GetOrdinal("title")),
                Status = reader.GetString(reader.GetOrdinal("status")),
                Relationship = reader.GetString(reader.GetOrdinal("relationship"))
            });
        }
        return results;
    }

    private static async Task<IReadOnlyList<AlertActivityRecord>> LoadActivityAsync(NpgsqlConnection connection, Guid alertId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select activity_id, occurred_at, actor, action, from_status, to_status, summary from alert_activities where alert_id = @alert_id order by occurred_at desc limit 100;";
        command.Parameters.AddWithValue("alert_id", alertId);
        var results = new List<AlertActivityRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AlertActivityRecord
            {
                ActivityId = reader.GetGuid(reader.GetOrdinal("activity_id")),
                OccurredAt = ReadDateTimeOffset(reader, "occurred_at"),
                Actor = ReadNullableString(reader, "actor"),
                Action = reader.GetString(reader.GetOrdinal("action")),
                FromStatus = ReadNullableString(reader, "from_status"),
                ToStatus = ReadNullableString(reader, "to_status"),
                Summary = reader.GetString(reader.GetOrdinal("summary"))
            });
        }
        return results;
    }

    public static string NormalizeAlertStatus(string? status)
    {
        var value = (status ?? string.Empty).Trim().ToLowerInvariant();
        var allowed = new[] { AlertStatuses.Triaged, AlertStatuses.Investigating, AlertStatuses.Escalated, AlertStatuses.Contained, AlertStatuses.Resolved };
        if (!allowed.Contains(value, StringComparer.Ordinal)) throw new ArgumentException("Alert status transition must be triaged, investigating, escalated, contained, or resolved.");
        return value;
    }

    public static string? NormalizeDisposition(string? disposition, bool required)
    {
        if (string.IsNullOrWhiteSpace(disposition))
        {
            if (required) throw new ArgumentException("Disposition is required.");
            return null;
        }
        var value = disposition.Trim().ToLowerInvariant();
        var allowed = new[] { AlertDispositions.TruePositive, AlertDispositions.FalsePositive, AlertDispositions.Duplicate, AlertDispositions.Benign, AlertDispositions.AuthorizedActivity, AlertDispositions.RetentionLimited, AlertDispositions.Unknown };
        if (!allowed.Contains(value, StringComparer.Ordinal)) throw new ArgumentException("Disposition value is not recognized.");
        return value;
    }

    public static void ValidateExpectedVersion(int expectedVersion)
    {
        if (expectedVersion < 1) throw new ArgumentException("expected_version must be positive.");
    }

    public static void ValidateIdempotency(string? idempotencyKey)
    {
        if (idempotencyKey is null) return;
        var value = idempotencyKey.Trim();
        if (value.Length is < 8 or > 128 || value.Any(char.IsControl)) throw new ArgumentException("idempotency_key must be 8-128 printable characters.");
    }

    public static string BoundRequired(string? value, int min, int max, string fieldName)
    {
        var bounded = BoundOptional(value, max, fieldName);
        if (bounded is null || bounded.Length < min) throw new ArgumentException($"{fieldName} is required and must be at least {min} characters.");
        return bounded;
    }

    public static string? BoundOptional(string? value, int max, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        if (trimmed.Length > max || trimmed.Any(char.IsControl)) throw new ArgumentException($"{fieldName} must be bounded and printable.");
        return trimmed;
    }

    private static AlertRecord ReadAlert(NpgsqlDataReader reader, IReadOnlyList<AlertEvidenceRecord> evidence)
    {
        return new AlertRecord
        {
            AlertId = reader.GetGuid(reader.GetOrdinal("alert_id")),
            RuleId = reader.GetString(reader.GetOrdinal("rule_id")),
            RuleVersion = reader.GetInt32(reader.GetOrdinal("rule_version")),
            Title = reader.GetString(reader.GetOrdinal("title")),
            Severity = reader.GetString(reader.GetOrdinal("severity")),
            Confidence = reader.GetString(reader.GetOrdinal("confidence")),
            Status = reader.GetString(reader.GetOrdinal("status")),
            Owner = ReadNullableString(reader, "owner"),
            Version = reader.GetInt32(reader.GetOrdinal("version")),
            UpdatedAt = ReadNullableDateTimeOffset(reader, "updated_at"),
            AcknowledgedAt = ReadNullableDateTimeOffset(reader, "acknowledged_at"),
            TriagedAt = ReadNullableDateTimeOffset(reader, "triaged_at"),
            SuppressedAt = ReadNullableDateTimeOffset(reader, "suppressed_at"),
            SuppressedUntil = ReadNullableDateTimeOffset(reader, "suppressed_until"),
            SuppressionReason = ReadNullableString(reader, "suppression_reason"),
            Disposition = ReadNullableString(reader, "disposition"),
            ClosedAt = ReadNullableDateTimeOffset(reader, "closed_at"),
            ClosureSummary = ReadNullableString(reader, "closure_summary"),
            ReopenedAt = ReadNullableDateTimeOffset(reader, "reopened_at"),
            LastActivityAt = ReadNullableDateTimeOffset(reader, "last_activity_at"),
            AgentId = ReadNullableString(reader, "agent_id"),
            Hostname = ReadNullableString(reader, "hostname"),
            CreatedAt = ReadDateTimeOffset(reader, "created_at"),
            Summary = reader.GetString(reader.GetOrdinal("summary")),
            AffectedEntities = ReadEntities(reader.GetString(reader.GetOrdinal("affected_entities"))),
            Evidence = evidence
        };
    }

    private static async Task<IReadOnlyList<AlertEvidenceRecord>> LoadEvidenceAsync(NpgsqlConnection connection, Guid alertId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select
                ae.agent_id,
                ae.event_id,
                ae.event_time,
                coalesce(ae.host_timezone, e.host_timezone) as host_timezone,
                ae.channel,
                ae.windows_event_id,
                ae.summary,
                case
                    when e.event_id is not null then 'telemetry_retained'
                    when mre.event_id is not null then 'telemetry_removed_by_retention'
                    else 'underlying_telemetry_missing'
                end as telemetry_retention_state
            from alert_evidence ae
            left join events e on e.agent_id = ae.agent_id and e.event_id = ae.event_id
            left join managed_retention_removed_events mre on mre.agent_id = ae.agent_id and mre.event_id = ae.event_id
            where ae.alert_id = @alert_id
            order by ae.event_time desc nulls last, ae.id asc;
            """;
        command.Parameters.AddWithValue("alert_id", alertId);
        var results = new List<AlertEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AlertEvidenceRecord
            {
                AgentId = reader.GetString(reader.GetOrdinal("agent_id")),
                EventId = reader.GetGuid(reader.GetOrdinal("event_id")),
                EventTime = ReadNullableDateTimeOffset(reader, "event_time"),
                HostTimezone = Jsonb.Read<HostTimezoneMetadata>(reader, "host_timezone"),
                Channel = ReadNullableString(reader, "channel"),
                WindowsEventId = ReadNullableInt32(reader, "windows_event_id"),
                Summary = reader.GetString(reader.GetOrdinal("summary")),
                TelemetryRetentionState = reader.GetString(reader.GetOrdinal("telemetry_retention_state"))
            });
        }

        return results;
    }

    private static IReadOnlyList<EventEntity> ReadEntities(string json)
    {
        return JsonSerializer.Deserialize<IReadOnlyList<EventEntity>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? Array.Empty<EventEntity>();
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

    private static long? ReadNullableInt64(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    }

    private static int? ReadNullableInt32(NpgsqlDataReader reader, string columnName)
    {
        var ordinal = reader.GetOrdinal(columnName);
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static DateTimeOffset ReadDateTimeOffset(NpgsqlDataReader reader, string columnName)
    {
        var value = reader.GetValue(reader.GetOrdinal(columnName));
        return value switch
        {
            DateTimeOffset dateTimeOffset => dateTimeOffset.ToUniversalTime(),
            DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
            _ => throw new InvalidOperationException("Column did not contain a timestamp value.")
        };
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
