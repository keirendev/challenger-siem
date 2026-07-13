using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Configuration;
using Npgsql;

namespace Challenger.Siem.Api.Database;

public sealed record AdminOperatorRecord(Guid OperatorId, string Username, string DisplayName, string Role, bool Enabled, int FailedLoginCount, DateTimeOffset? LockedUntil, DateTimeOffset? LastLoginAt, DateTimeOffset CredentialsChangedAt);
public sealed record AdminSessionRecord(Guid SessionId, string Username, string Role, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt, string? RevokeReason);
public sealed record AdminAuditRecord(long AuditId, DateTimeOffset OccurredAt, string? ActorUsername, string Action, string Outcome, string? TargetType, string? TargetId, string DetailsSummary);
public sealed record AdminSourceState(string SourceId, string DisplayName, string Status, long AgentCount, long Healthy, long Degraded, long Missing, string? ReviewNote, DateTimeOffset? MutedUntil, int SettingsVersion);
public sealed record AdminConfigSettingRecord(string Key, string Value, string EffectiveValue, int Version, DateTimeOffset? UpdatedAt, string? UpdatedBy, string Impact);
public sealed record AdminConfigSettingRequest(string Key, string Value, int ExpectedVersion, string ConfirmImpact);
public sealed record AdminSourceSettingRequest(string SourceId, string DisplayName, string? ReviewNote, DateTimeOffset? MutedUntil, int ExpectedVersion, string ConfirmImpact);

public sealed record AdminOverviewResponse(
    IReadOnlyList<AdminOperatorRecord> Operators,
    IReadOnlyList<AdminSessionRecord> Sessions,
    IReadOnlyList<AdminSourceState> Sources,
    IReadOnlyList<AdminConfigSettingRecord> Settings,
    IReadOnlyList<AdminAuditRecord> AuditEvents);

public sealed class AdminRepository(NpgsqlDataSource dataSource)
{
    public async Task<AdminOverviewResponse> GetOverviewAsync(ManagedRetentionOptions configured, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        return new AdminOverviewResponse(
            await LoadOperatorsAsync(connection, cancellationToken),
            await LoadSessionsAsync(connection, cancellationToken),
            await LoadSourcesAsync(connection, cancellationToken),
            await LoadSettingsAsync(connection, configured, cancellationToken),
            await LoadAuditAsync(connection, cancellationToken));
    }

    public async Task<ManagedRetentionOptions> GetEffectiveRetentionOptionsAsync(ManagedRetentionOptions configured, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "select setting_key, setting_value from server_config_settings;";
        var effective = Clone(configured);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ApplySetting(effective, reader.GetString(0), reader.GetString(1));
        }
        return effective;
    }

    public async Task<AdminConfigSettingRecord?> UpdateSettingAsync(AdminConfigSettingRequest request, string actor, HttpContext context, SecurityAuditRepository audit, ManagedRetentionOptions configured, CancellationToken cancellationToken)
    {
        ValidateSetting(request);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var currentVersion = await ReadSettingVersionAsync(connection, transaction, request.Key, cancellationToken) ?? 1;
        if (currentVersion != Math.Max(1, request.ExpectedVersion))
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        var nextVersion = currentVersion + 1;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into server_config_settings(setting_key, setting_value, updated_by, updated_at, version)
                values(@key, @value, @updated_by, now(), @version)
                on conflict(setting_key) do update set setting_value=excluded.setting_value, updated_by=excluded.updated_by, updated_at=now(), version=excluded.version;
                """;
            command.Parameters.AddWithValue("key", request.Key);
            command.Parameters.AddWithValue("value", request.Value.Trim());
            command.Parameters.AddWithValue("updated_by", actor);
            command.Parameters.AddWithValue("version", nextVersion);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name,
            "admin.config.update", "success", "server_config", request.Key, context,
            new Dictionary<string, object?> { ["setting_key"] = request.Key, ["version"] = nextVersion, ["impact"] = ImpactFor(request.Key, request.Value) }, cancellationToken);
        return (await LoadSettingsAsync(connection, configured, cancellationToken)).FirstOrDefault(item => item.Key == request.Key);
    }

    public async Task<AdminSourceState?> UpdateSourceSettingAsync(AdminSourceSettingRequest request, string actor, HttpContext context, SecurityAuditRepository audit, CancellationToken cancellationToken)
    {
        ValidateSourceSetting(request);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var currentVersion = await ReadSourceVersionAsync(connection, transaction, request.SourceId, cancellationToken) ?? 1;
        if (currentVersion != Math.Max(1, request.ExpectedVersion))
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        var nextVersion = currentVersion + 1;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                insert into source_review_settings(source_id, display_name, review_note, muted_until, updated_by, updated_at, version)
                values(@source_id, @display_name, @review_note, @muted_until, @updated_by, now(), @version)
                on conflict(source_id) do update set display_name=excluded.display_name, review_note=excluded.review_note, muted_until=excluded.muted_until, updated_by=excluded.updated_by, updated_at=now(), version=excluded.version;
                """;
            command.Parameters.AddWithValue("source_id", request.SourceId.Trim());
            command.Parameters.AddWithValue("display_name", request.DisplayName.Trim());
            command.Parameters.AddWithValue("review_note", (request.ReviewNote ?? string.Empty).Trim());
            command.Parameters.AddWithValue("muted_until", request.MutedUntil.HasValue ? request.MutedUntil.Value.ToUniversalTime() : DBNull.Value);
            command.Parameters.AddWithValue("updated_by", actor);
            command.Parameters.AddWithValue("version", nextVersion);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        await audit.RecordAsync(OperatorAuthentication.OperatorId(context.User), context.User.Identity?.Name,
            "admin.source_review.update", "success", "source", request.SourceId, context,
            new Dictionary<string, object?> { ["version"] = nextVersion, ["muted_until_set"] = request.MutedUntil.HasValue }, cancellationToken);
        return (await LoadSourcesAsync(connection, cancellationToken)).FirstOrDefault(item => item.SourceId == request.SourceId);
    }

    private static async Task<IReadOnlyList<AdminOperatorRecord>> LoadOperatorsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select operator_id, username, display_name, role, enabled, failed_login_count, locked_until, last_login_at, credentials_changed_at from operators order by username asc limit 200;";
        var results = new List<AdminOperatorRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new AdminOperatorRecord(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetBoolean(4), reader.GetInt32(5), ReadNullableTime(reader, 6), ReadNullableTime(reader, 7), ReadTime(reader, 8)));
        }
        return results;
    }

    private static async Task<IReadOnlyList<AdminSessionRecord>> LoadSessionsAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select s.session_id, o.username, o.role, s.created_at, s.expires_at, s.revoked_at, s.revoke_reason
            from operator_sessions s join operators o on o.operator_id=s.operator_id
            order by s.created_at desc limit 200;
            """;
        var results = new List<AdminSessionRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(new AdminSessionRecord(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), ReadTime(reader, 3), ReadTime(reader, 4), ReadNullableTime(reader, 5), reader.IsDBNull(6) ? null : reader.GetString(6)));
        return results;
    }

    private static async Task<IReadOnlyList<AdminSourceState>> LoadSourcesAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            select sh.source_id, max(sh.display_name) as display_name,
                   case when count(*) filter (where sh.status in ('missing','disabled','permission_denied','unsupported','error')) > 0 then 'missing'
                        when count(*) filter (where sh.status in ('stale','degraded')) > 0 then 'degraded'
                        when count(*) filter (where sh.status='healthy') > 0 then 'healthy' else 'unknown' end as status,
                   count(distinct sh.agent_id)::bigint as agent_count,
                   count(*) filter (where sh.status in ('healthy','excepted'))::bigint as healthy,
                   count(*) filter (where sh.status in ('stale','degraded'))::bigint as degraded,
                   count(*) filter (where sh.status in ('missing','disabled','permission_denied','unsupported','error','not_applicable'))::bigint as missing,
                   s.review_note, s.muted_until, coalesce(s.version, 1) as settings_version
            from source_health sh
            left join source_review_settings s on s.source_id = sh.source_id
            group by sh.source_id, s.review_note, s.muted_until, s.version
            order by status asc, sh.source_id asc limit 200;
            """;
        var results = new List<AdminSourceState>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(new AdminSourceState(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3), reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6), reader.IsDBNull(7) ? null : reader.GetString(7), ReadNullableTime(reader, 8), reader.GetInt32(9)));
        return results;
    }

    private static async Task<IReadOnlyList<AdminConfigSettingRecord>> LoadSettingsAsync(NpgsqlConnection connection, ManagedRetentionOptions configured, CancellationToken cancellationToken)
    {
        var keys = new[]
        {
            ("retention.target_days", configured.TargetRetentionDays.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("retention.managed_capacity_bytes", configured.ManagedCapacityBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ("retention.max_batches_per_run", configured.MaxBatchesPerRun.ToString(System.Globalization.CultureInfo.InvariantCulture))
        };
        await using var command = connection.CreateCommand();
        command.CommandText = "select setting_key, setting_value, version, updated_at, updated_by from server_config_settings;";
        var configuredMap = keys.ToDictionary(item => item.Item1, item => item.Item2, StringComparer.Ordinal);
        var overrides = new Dictionary<string, (string Value, int Version, DateTimeOffset? UpdatedAt, string? UpdatedBy)>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) overrides[reader.GetString(0)] = (reader.GetString(1), reader.GetInt32(2), ReadNullableTime(reader, 3), reader.IsDBNull(4) ? null : reader.GetString(4));
        return keys.Select(item =>
        {
            var has = overrides.TryGetValue(item.Item1, out var overrideValue);
            var effective = has ? overrideValue.Value : item.Item2;
            return new AdminConfigSettingRecord(item.Item1, has ? overrideValue.Value : string.Empty, effective, has ? overrideValue.Version : 1, has ? overrideValue.UpdatedAt : null, has ? overrideValue.UpdatedBy : null, ImpactFor(item.Item1, effective));
        }).ToArray();
    }

    private static async Task<IReadOnlyList<AdminAuditRecord>> LoadAuditAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "select audit_id, occurred_at, actor_username, action, outcome, target_type, target_id, left(details::text, 500) from security_audit_events order by occurred_at desc limit 200;";
        var results = new List<AdminAuditRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(new AdminAuditRecord(reader.GetInt64(0), ReadTime(reader, 1), reader.IsDBNull(2) ? null : reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6), reader.GetString(7)));
        return results;
    }

    private static async Task<int?> ReadSettingVersionAsync(NpgsqlConnection c, NpgsqlTransaction t, string key, CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "select version from server_config_settings where setting_key=@key for update;"; command.Parameters.AddWithValue("key", key);
        var value = await command.ExecuteScalarAsync(ct); return value is null ? null : Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<int?> ReadSourceVersionAsync(NpgsqlConnection c, NpgsqlTransaction t, string sourceId, CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "select version from source_review_settings where source_id=@source_id for update;"; command.Parameters.AddWithValue("source_id", sourceId);
        var value = await command.ExecuteScalarAsync(ct); return value is null ? null : Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void ValidateSetting(AdminConfigSettingRequest request)
    {
        if (!string.Equals(request.ConfirmImpact, "CONFIRM SERVER CONFIG CHANGE", StringComparison.Ordinal)) throw new ArgumentException("Confirmation phrase is required for server configuration changes.");
        if (request.Key == "retention.target_days" && (!int.TryParse(request.Value, out var days) || days is < 1 or > 3650)) throw new ArgumentException("Retention target days must be between 1 and 3650.");
        if (request.Key == "retention.managed_capacity_bytes" && (!long.TryParse(request.Value, out var bytes) || bytes < 1024 || bytes > ManagedRetentionOptions.HardManagedCapacityBytes)) throw new ArgumentException("Managed capacity must be between 1024 bytes and the hard 100 GiB ceiling.");
        if (request.Key == "retention.max_batches_per_run" && (!int.TryParse(request.Value, out var batches) || batches is < 1 or > 1000)) throw new ArgumentException("Retention max batches per run must be between 1 and 1000.");
        if (request.Key is not ("retention.target_days" or "retention.managed_capacity_bytes" or "retention.max_batches_per_run")) throw new ArgumentException("Setting key is not admin-editable.");
    }

    private static void ValidateSourceSetting(AdminSourceSettingRequest request)
    {
        if (!string.Equals(request.ConfirmImpact, "CONFIRM SOURCE REVIEW CHANGE", StringComparison.Ordinal)) throw new ArgumentException("Confirmation phrase is required for source review changes.");
        if (string.IsNullOrWhiteSpace(request.SourceId) || request.SourceId.Length > 128) throw new ArgumentException("Source ID is required and must be 128 characters or less.");
        if (string.IsNullOrWhiteSpace(request.DisplayName) || request.DisplayName.Length > 128) throw new ArgumentException("Display name is required and must be 128 characters or less.");
        if ((request.ReviewNote?.Length ?? 0) > 1000) throw new ArgumentException("Review note must be 1000 characters or less.");
        if ((request.ReviewNote ?? string.Empty).Contains("api_token", StringComparison.OrdinalIgnoreCase) || (request.ReviewNote ?? string.Empty).Contains("password", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Review note must not contain secret-shaped values.");
    }

    private static ManagedRetentionOptions Clone(ManagedRetentionOptions source) => new()
    {
        Enabled = source.Enabled,
        HostedServiceEnabled = source.HostedServiceEnabled,
        TargetRetentionDays = source.TargetRetentionDays,
        ManagedCapacityBytes = source.ManagedCapacityBytes,
        CleanupBatchSize = source.CleanupBatchSize,
        MaxBatchesPerRun = source.MaxBatchesPerRun,
        EmergencyTargetPercent = source.EmergencyTargetPercent,
        HostedServiceIntervalMinutes = source.HostedServiceIntervalMinutes,
        AdvisoryLockKey = source.AdvisoryLockKey
    };

    private static void ApplySetting(ManagedRetentionOptions options, string key, string value)
    {
        if (key == "retention.target_days" && int.TryParse(value, out var days)) options.TargetRetentionDays = days;
        if (key == "retention.managed_capacity_bytes" && long.TryParse(value, out var bytes)) options.ManagedCapacityBytes = bytes;
        if (key == "retention.max_batches_per_run" && int.TryParse(value, out var batches)) options.MaxBatchesPerRun = batches;
    }

    private static string ImpactFor(string key, string value) => key switch
    {
        "retention.target_days" => $"Managed telemetry older than {value} day(s) is eligible during execute runs; protected tables are unchanged.",
        "retention.managed_capacity_bytes" => $"Managed telemetry capacity warning and emergency cleanup ceiling become {value} bytes; hard 100 GiB cap remains.",
        "retention.max_batches_per_run" => $"Execute retention runs may process up to {value} bounded batches per invocation.",
        _ => "No host policy or endpoint collection settings are changed."
    };

    private static DateTimeOffset ReadTime(NpgsqlDataReader reader, int ordinal) => ToTime(reader.GetValue(ordinal));
    private static DateTimeOffset? ReadNullableTime(NpgsqlDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : ToTime(reader.GetValue(ordinal));
    private static DateTimeOffset ToTime(object value) => value switch
    {
        DateTimeOffset dto => dto.ToUniversalTime(),
        DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
        _ => throw new InvalidOperationException("Expected timestamp value.")
    };
}
