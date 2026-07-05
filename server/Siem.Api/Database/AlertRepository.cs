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
            select alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, created_at, summary, affected_entities
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
                select alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, created_at, summary, affected_entities
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
        return alert with { Evidence = evidence };
    }

    public async Task<IReadOnlyList<DetectionRuleMetadata>> GetRulesAsync(CancellationToken cancellationToken)
    {
        await EnsureBuiltInRulesAsync(cancellationToken);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select rule_id, version, name, description, severity, confidence, category, required_sources, required_fields, mitre_attack, enabled
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
                insert into detection_rules (rule_id, version, name, description, severity, confidence, category, required_sources, required_fields, mitre_attack, enabled)
                values (@rule_id, @version, @name, @description, @severity, @confidence, @category, @required_sources, @required_fields, @mitre_attack, @enabled)
                on conflict (rule_id, version) do update set
                    name = excluded.name,
                    description = excluded.description,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    category = excluded.category,
                    required_sources = excluded.required_sources,
                    required_fields = excluded.required_fields,
                    mitre_attack = excluded.mitre_attack,
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
            command.Parameters.AddWithValue("enabled", rule.Enabled);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
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
            select agent_id, event_id, event_time, channel, windows_event_id, summary
            from alert_evidence
            where alert_id = @alert_id
            order by event_time desc nulls last, id asc;
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
                Channel = ReadNullableString(reader, "channel"),
                WindowsEventId = ReadNullableInt32(reader, "windows_event_id"),
                Summary = reader.GetString(reader.GetOrdinal("summary"))
            });
        }

        return results;
    }

    private static IReadOnlyList<EventEntity> ReadEntities(string json)
    {
        return JsonSerializer.Deserialize<IReadOnlyList<EventEntity>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? Array.Empty<EventEntity>();
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
