using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Contracts.V1;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record DetectionRuleManagementRecord(
    DetectionRuleMetadata Rule,
    bool EffectiveEnabled,
    string LifecycleState,
    string ValidationStatus,
    string TuningNotes,
    string SuppressionNotes,
    int SettingsVersion,
    DateTimeOffset? UpdatedAt,
    string? UpdatedBy,
    string PrerequisiteState,
    string ConfidenceImpact,
    IReadOnlyList<DetectionPrerequisiteStatus> Prerequisites,
    IReadOnlyList<string> SyntheticTests);

public sealed record DetectionPrerequisiteStatus(
    string SourceId,
    long Healthy,
    long Degraded,
    long Missing,
    string EffectiveState);

public sealed record DetectionRuleSettingsRequest(
    int ExpectedVersion,
    bool Enabled,
    string LifecycleState,
    string ValidationStatus,
    string? TuningNotes,
    string? SuppressionNotes,
    string ConfirmImpact);

public sealed class DetectionManagementRepository(NpgsqlDataSource dataSource)
{
    private static readonly IReadOnlySet<string> LifecycleStates = new HashSet<string>(StringComparer.Ordinal)
        { "catalog", "draft", "review", "test_failed", "test_passed", "staged", "active", "deprecated", "disabled" };
    private static readonly IReadOnlySet<string> ValidationStatuses = new HashSet<string>(StringComparer.Ordinal)
        { "not_run", "synthetic_passed", "synthetic_failed", "skipped_with_reason" };

    public async Task<IReadOnlyList<DetectionRuleManagementRecord>> ListAsync(IReadOnlyList<DetectionRuleMetadata> rules, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var settings = await LoadSettingsAsync(connection, cancellationToken);
        var prerequisites = await LoadPrerequisiteCountsAsync(connection, cancellationToken);
        return rules
            .OrderBy(rule => rule.Category, StringComparer.Ordinal)
            .ThenBy(rule => rule.RuleId, StringComparer.Ordinal)
            .Select(rule => BuildRecord(rule, settings.GetValueOrDefault((rule.RuleId, rule.Version)), prerequisites))
            .ToArray();
    }

    public async Task<DetectionRuleManagementRecord?> GetAsync(IReadOnlyList<DetectionRuleMetadata> rules, string ruleId, int version, CancellationToken cancellationToken)
    {
        var records = await ListAsync(rules.Where(rule => string.Equals(rule.RuleId, ruleId, StringComparison.Ordinal) && rule.Version == version).ToArray(), cancellationToken);
        return records.FirstOrDefault();
    }

    public async Task<DetectionRuleManagementRecord?> UpdateSettingsAsync(
        IReadOnlyList<DetectionRuleMetadata> rules,
        string ruleId,
        int version,
        DetectionRuleSettingsRequest request,
        string actor,
        HttpContext context,
        SecurityAuditRepository audit,
        CancellationToken cancellationToken)
    {
        var rule = rules.FirstOrDefault(item => string.Equals(item.RuleId, ruleId, StringComparison.Ordinal) && item.Version == version);
        if (rule is null)
        {
            throw new KeyNotFoundException("Detection rule version was not found.");
        }

        ValidateRequest(request);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var existing = await LoadSettingAsync(connection, transaction, ruleId, version, cancellationToken);
        var expected = Math.Max(1, request.ExpectedVersion);
        if ((existing?.SettingsVersion ?? 1) != expected)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var previousJson = existing is null ? null : JsonSerializer.Serialize(existing, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var nextVersion = expected + 1;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into detection_rule_management(rule_id, version, enabled, lifecycle_state, validation_status, tuning_notes, suppression_notes, updated_by, updated_at, settings_version)
                values(@rule_id, @version, @enabled, @lifecycle_state, @validation_status, @tuning_notes, @suppression_notes, @updated_by, now(), @settings_version)
                on conflict(rule_id, version) do update set
                    enabled = excluded.enabled,
                    lifecycle_state = excluded.lifecycle_state,
                    validation_status = excluded.validation_status,
                    tuning_notes = excluded.tuning_notes,
                    suppression_notes = excluded.suppression_notes,
                    updated_by = excluded.updated_by,
                    updated_at = now(),
                    settings_version = excluded.settings_version;
                """;
            command.Parameters.AddWithValue("rule_id", ruleId);
            command.Parameters.AddWithValue("version", version);
            command.Parameters.AddWithValue("enabled", request.Enabled);
            command.Parameters.AddWithValue("lifecycle_state", request.LifecycleState);
            command.Parameters.AddWithValue("validation_status", request.ValidationStatus);
            command.Parameters.AddWithValue("tuning_notes", BoundOptional(request.TuningNotes, 2000));
            command.Parameters.AddWithValue("suppression_notes", BoundOptional(request.SuppressionNotes, 2000));
            command.Parameters.AddWithValue("updated_by", actor);
            command.Parameters.AddWithValue("settings_version", nextVersion);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var history = connection.CreateCommand())
        {
            history.Transaction = transaction;
            history.CommandText = """
                insert into detection_rule_management_history(rule_id, version, changed_by, action, previous_settings, new_settings)
                values(@rule_id, @version, @changed_by, 'settings.update', @previous::jsonb, @new::jsonb);
                """;
            history.Parameters.AddWithValue("rule_id", ruleId);
            history.Parameters.AddWithValue("version", version);
            history.Parameters.AddWithValue("changed_by", actor);
            history.Parameters.Add("previous", NpgsqlDbType.Jsonb).Value = previousJson is null ? DBNull.Value : previousJson;
            history.Parameters.Add("new", NpgsqlDbType.Jsonb).Value = JsonSerializer.Serialize(new
            {
                request.Enabled,
                request.LifecycleState,
                request.ValidationStatus,
                tuning_notes = BoundOptional(request.TuningNotes, 2000),
                suppression_notes = BoundOptional(request.SuppressionNotes, 2000),
                settings_version = nextVersion
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            await history.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name,
            "detection_rule.settings.update", "success", "detection_rule", $"{ruleId}@{version}", context,
            new Dictionary<string, object?>
            {
                ["enabled"] = request.Enabled,
                ["lifecycle_state"] = request.LifecycleState,
                ["validation_status"] = request.ValidationStatus,
                ["settings_version"] = nextVersion
            }, cancellationToken);

        return await GetAsync(rules, ruleId, version, cancellationToken);
    }

    private static void ValidateRequest(DetectionRuleSettingsRequest request)
    {
        if (!LifecycleStates.Contains(request.LifecycleState))
        {
            throw new ArgumentException("Lifecycle state is not valid for detection rules.");
        }
        if (!ValidationStatuses.Contains(request.ValidationStatus))
        {
            throw new ArgumentException("Validation status is not valid for detection rules.");
        }
        if (!string.Equals(request.ConfirmImpact, "CONFIRM DETECTION SERVER CHANGE", StringComparison.Ordinal))
        {
            throw new ArgumentException("Confirmation phrase is required for detection rule changes.");
        }
        ValidateNote(request.TuningNotes, nameof(request.TuningNotes));
        ValidateNote(request.SuppressionNotes, nameof(request.SuppressionNotes));
    }

    private static void ValidateNote(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        if (value.Length > 2000) throw new ArgumentException($"{field} must be 2000 characters or less.");
        var lowered = value.ToLowerInvariant();
        if (lowered.Contains("function(", StringComparison.Ordinal)
            || lowered.Contains("eval(", StringComparison.Ordinal)
            || lowered.Contains("<script", StringComparison.Ordinal)
            || lowered.Contains("=>", StringComparison.Ordinal)
            || lowered.Contains("authorization:", StringComparison.Ordinal)
            || lowered.Contains("password=", StringComparison.Ordinal)
            || lowered.Contains("api_token", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{field} accepts notes only; code, expressions, and secret-shaped values are not accepted.");
        }
    }

    private static DetectionRuleManagementRecord BuildRecord(
        DetectionRuleMetadata rule,
        RuleSetting? setting,
        IReadOnlyDictionary<string, SourceCounts> prerequisiteCounts)
    {
        var prerequisites = rule.RequiredSources.Select(source =>
        {
            var counts = prerequisiteCounts.GetValueOrDefault(source, SourceCounts.Empty);
            var state = counts.Missing > 0 ? "missing"
                : counts.Degraded > 0 ? "degraded"
                : counts.Healthy > 0 ? "healthy"
                : "unknown";
            return new DetectionPrerequisiteStatus(source, counts.Healthy, counts.Degraded, counts.Missing, state);
        }).ToArray();
        var prerequisiteState = prerequisites.Any(item => item.EffectiveState == "missing") ? "missing"
            : prerequisites.Any(item => item.EffectiveState == "degraded" || item.EffectiveState == "unknown") ? "degraded"
            : prerequisites.Length == 0 ? "none" : "healthy";
        var enabled = setting?.Enabled ?? rule.Enabled;
        var lifecycle = setting?.LifecycleState ?? (enabled ? "active" : "disabled");
        var confidenceImpact = prerequisiteState switch
        {
            "missing" => "suppressed until required source evidence exists",
            "degraded" => "confidence lowered where source health is stale, degraded, or unknown",
            "healthy" => "catalog confidence applies",
            _ => "no prerequisite source declared"
        };

        return new DetectionRuleManagementRecord(
            rule,
            enabled && lifecycle is not "disabled" and not "deprecated",
            lifecycle,
            setting?.ValidationStatus ?? "synthetic_passed",
            setting?.TuningNotes ?? string.Empty,
            setting?.SuppressionNotes ?? string.Empty,
            setting?.SettingsVersion ?? 1,
            setting?.UpdatedAt,
            setting?.UpdatedBy,
            prerequisiteState,
            confidenceImpact,
            prerequisites,
            new[] { "synthetic catalog validation", "bounded prerequisite regression", "no arbitrary code execution" });
    }

    private static async Task<Dictionary<(string RuleId, int Version), RuleSetting>> LoadSettingsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select rule_id, version, enabled, lifecycle_state, validation_status, tuning_notes, suppression_notes, updated_by, updated_at, settings_version from detection_rule_management;";
        var results = new Dictionary<(string, int), RuleSetting>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var setting = ReadSetting(reader);
            results[(setting.RuleId, setting.Version)] = setting;
        }
        return results;
    }

    private static async Task<RuleSetting?> LoadSettingAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string ruleId, int version, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "select rule_id, version, enabled, lifecycle_state, validation_status, tuning_notes, suppression_notes, updated_by, updated_at, settings_version from detection_rule_management where rule_id=@rule_id and version=@version for update;";
        command.Parameters.AddWithValue("rule_id", ruleId);
        command.Parameters.AddWithValue("version", version);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSetting(reader) : null;
    }

    private static async Task<IReadOnlyDictionary<string, SourceCounts>> LoadPrerequisiteCountsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select source_id,
                   count(*) filter (where status in ('healthy', 'excepted'))::bigint as healthy,
                   count(*) filter (where status in ('stale', 'degraded'))::bigint as degraded,
                   count(*) filter (where status in ('missing', 'disabled', 'permission_denied', 'unsupported', 'error', 'not_applicable'))::bigint as missing
            from source_health
            group by source_id;
            """;
        var results = new Dictionary<string, SourceCounts>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results[reader.GetString(0)] = new SourceCounts(reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
        }
        return results;
    }

    private static RuleSetting ReadSetting(NpgsqlDataReader reader) => new(
        reader.GetString(reader.GetOrdinal("rule_id")),
        reader.GetInt32(reader.GetOrdinal("version")),
        reader.GetBoolean(reader.GetOrdinal("enabled")),
        reader.GetString(reader.GetOrdinal("lifecycle_state")),
        reader.GetString(reader.GetOrdinal("validation_status")),
        reader.GetString(reader.GetOrdinal("tuning_notes")),
        reader.GetString(reader.GetOrdinal("suppression_notes")),
        reader.IsDBNull(reader.GetOrdinal("updated_by")) ? null : reader.GetString(reader.GetOrdinal("updated_by")),
        ReadDateTimeOffset(reader, "updated_at"),
        reader.GetInt32(reader.GetOrdinal("settings_version")));

    private static DateTimeOffset? ReadDateTimeOffset(NpgsqlDataReader reader, string column)
    {
        var ordinal = reader.GetOrdinal(column);
        if (reader.IsDBNull(ordinal)) return null;
        var value = reader.GetValue(ordinal);
        return value switch
        {
            DateTimeOffset dto => dto.ToUniversalTime(),
            DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
            _ => null
        };
    }

    private static string BoundOptional(string? value, int max) => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim()[..Math.Min(value.Trim().Length, max)];

    private sealed record RuleSetting(string RuleId, int Version, bool Enabled, string LifecycleState, string ValidationStatus, string TuningNotes, string SuppressionNotes, string? UpdatedBy, DateTimeOffset? UpdatedAt, int SettingsVersion);
    private sealed record SourceCounts(long Healthy, long Degraded, long Missing)
    {
        public static readonly SourceCounts Empty = new(0, 0, 0);
    }
}
