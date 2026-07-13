using System.Text.Json;
using Challenger.Siem.Api.Auth;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed record OperatorIdentity(Guid OperatorId, string Username, string DisplayName, string Role, bool Enabled,
    int FailedLoginCount, DateTimeOffset? LockedUntil, string PasswordHash, string? ApiTokenHash, DateTimeOffset CredentialsChangedAt);
public sealed record OperatorSession(Guid SessionId, OperatorIdentity Operator, DateTimeOffset ExpiresAt);
public sealed record LoginResult(string Status, OperatorSession? Session, string? SessionToken);

public sealed class OperatorRepository(NpgsqlDataSource dataSource, OperatorPasswordHasher passwordHasher)
{
    public const int LockoutAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);

    public async Task<LoginResult> AuthenticatePasswordAsync(string username, string password, CancellationToken cancellationToken)
    {
        var normalized = NormalizeUsername(username);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var identity = await FindByUsernameAsync(connection, transaction, normalized, cancellationToken);
        if (identity is null || !identity.Enabled)
        {
            await transaction.CommitAsync(cancellationToken);
            return new("invalid", null, null);
        }
        if (identity.LockedUntil is { } locked && locked > DateTimeOffset.UtcNow)
        {
            await transaction.CommitAsync(cancellationToken);
            return new("locked", null, null);
        }
        if (!passwordHasher.Verify(password, identity.PasswordHash))
        {
            await using var failure = connection.CreateCommand(); failure.Transaction = transaction;
            failure.CommandText = "update operators set failed_login_count=failed_login_count+1, locked_until=case when failed_login_count+1 >= @attempts then now()+@duration else null end, updated_at=now() where operator_id=@id;";
            failure.Parameters.AddWithValue("attempts", LockoutAttempts); failure.Parameters.AddWithValue("duration", LockoutDuration); failure.Parameters.AddWithValue("id", identity.OperatorId);
            await failure.ExecuteNonQueryAsync(cancellationToken); await transaction.CommitAsync(cancellationToken);
            return new(identity.FailedLoginCount + 1 >= LockoutAttempts ? "locked" : "invalid", null, null);
        }
        var token = OperatorSecrets.Generate(); var tokenHash = OperatorSecrets.Hash(token); var sessionId = Guid.NewGuid(); var expires = DateTimeOffset.UtcNow.Add(SessionLifetime);
        await using var success = connection.CreateCommand(); success.Transaction = transaction;
        success.CommandText = "update operators set failed_login_count=0, locked_until=null, last_login_at=now(), updated_at=now() where operator_id=@id; insert into operator_sessions(session_id,operator_id,token_hash,expires_at) values(@sid,@id,@hash,@expires);";
        success.Parameters.AddWithValue("id", identity.OperatorId); success.Parameters.AddWithValue("sid", sessionId); success.Parameters.AddWithValue("hash", tokenHash); success.Parameters.AddWithValue("expires", expires);
        await success.ExecuteNonQueryAsync(cancellationToken); await transaction.CommitAsync(cancellationToken);
        return new("success", new(sessionId, identity with { FailedLoginCount = 0, LockedUntil = null }, expires), token);
    }

    public async Task<OperatorSession?> ValidateSessionAsync(string token, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "select s.session_id,s.expires_at,o.* from operator_sessions s join operators o on o.operator_id=s.operator_id where s.token_hash=@hash and s.revoked_at is null and s.expires_at>now() and o.enabled and o.credentials_changed_at<=s.created_at;";
        command.Parameters.AddWithValue("hash", OperatorSecrets.Hash(token)); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(reader.GetGuid(reader.GetOrdinal("session_id")), ReadOperator(reader), ReadTime(reader,"expires_at"));
    }

    public async Task<OperatorIdentity?> AuthenticateApiTokenAsync(string token, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = "select * from operators where api_token_hash=@hash and enabled and (locked_until is null or locked_until<=now());";
        command.Parameters.AddWithValue("hash", OperatorSecrets.Hash(token)); await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadOperator(reader) : null;
    }

    public async Task<OperatorIdentity> CreateAsync(string username, string displayName, string role, string password, bool requireEmpty, CancellationToken cancellationToken)
    {
        ValidateRole(role); var normalized = NormalizeUsername(username); var hash = passwordHasher.Hash(password);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken); await using var command = connection.CreateCommand();
        command.CommandText = requireEmpty
            ? "insert into operators(operator_id,username,normalized_username,display_name,role,password_hash) select @id,@username,@normalized,@display,@role,@hash where not exists(select 1 from operators) returning *;"
            : "insert into operators(operator_id,username,normalized_username,display_name,role,password_hash) values(@id,@username,@normalized,@display,@role,@hash) returning *;";
        command.Parameters.AddWithValue("id", Guid.NewGuid()); command.Parameters.AddWithValue("username", username.Trim()); command.Parameters.AddWithValue("normalized", normalized); command.Parameters.AddWithValue("display", displayName.Trim()); command.Parameters.AddWithValue("role", role); command.Parameters.AddWithValue("hash", hash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) throw new InvalidOperationException("Bootstrap is allowed only when no operator exists."); return ReadOperator(reader);
    }

    public async Task<bool> VerifyPasswordAsync(Guid id, string password, CancellationToken cancellationToken)
    {
        await using var connection=await dataSource.OpenConnectionAsync(cancellationToken); await using var command=connection.CreateCommand();
        command.CommandText="select password_hash from operators where operator_id=@id and enabled;"; command.Parameters.AddWithValue("id",id);
        var hash=await command.ExecuteScalarAsync(cancellationToken) as string; return hash is not null && passwordHasher.Verify(password,hash);
    }

    public async Task ChangePasswordAsync(Guid id, string password, bool unlock, CancellationToken cancellationToken)
    {
        var hash=passwordHasher.Hash(password); await using var connection=await dataSource.OpenConnectionAsync(cancellationToken); await using var transaction=await connection.BeginTransactionAsync(cancellationToken);
        await using(var command=connection.CreateCommand()){command.Transaction=transaction; command.CommandText="update operators set password_hash=@hash,password_changed_at=now(),credentials_changed_at=now(),failed_login_count=case when @unlock then 0 else failed_login_count end,locked_until=case when @unlock then null else locked_until end,updated_at=now() where operator_id=@id; update operator_sessions set revoked_at=now(),revoke_reason='credentials_changed' where operator_id=@id and revoked_at is null;"; command.Parameters.AddWithValue("hash",hash);command.Parameters.AddWithValue("unlock",unlock);command.Parameters.AddWithValue("id",id); await command.ExecuteNonQueryAsync(cancellationToken);} await transaction.CommitAsync(cancellationToken);
    }

    public async Task<string> RotateApiTokenAsync(Guid id, CancellationToken cancellationToken)
    { var token=OperatorSecrets.Generate(); await using var connection=await dataSource.OpenConnectionAsync(cancellationToken);await using var command=connection.CreateCommand();command.CommandText="update operators set api_token_hash=@hash,credentials_changed_at=now(),updated_at=now() where operator_id=@id; update operator_sessions set revoked_at=now(),revoke_reason='credentials_changed' where operator_id=@id and revoked_at is null;";command.Parameters.AddWithValue("hash",OperatorSecrets.Hash(token));command.Parameters.AddWithValue("id",id);await command.ExecuteNonQueryAsync(cancellationToken);return token; }
    public async Task RevokeSessionAsync(string token,string reason,CancellationToken cancellationToken){await using var c=await dataSource.OpenConnectionAsync(cancellationToken);await using var q=c.CreateCommand();q.CommandText="update operator_sessions set revoked_at=coalesce(revoked_at,now()),revoke_reason=coalesce(revoke_reason,@reason) where token_hash=@hash;";q.Parameters.AddWithValue("reason",reason);q.Parameters.AddWithValue("hash",OperatorSecrets.Hash(token));await q.ExecuteNonQueryAsync(cancellationToken);}
    public async Task<OperatorIdentity?> FindByUsernameAsync(string username,CancellationToken ct){await using var c=await dataSource.OpenConnectionAsync(ct);return await FindByUsernameAsync(c,null,NormalizeUsername(username),ct);}

    private static async Task<OperatorIdentity?> FindByUsernameAsync(NpgsqlConnection c,NpgsqlTransaction? t,string normalized,CancellationToken ct){await using var q=c.CreateCommand();q.Transaction=t;q.CommandText="select * from operators where normalized_username=@username for update;";q.Parameters.AddWithValue("username",normalized);await using var r=await q.ExecuteReaderAsync(ct);return await r.ReadAsync(ct)?ReadOperator(r):null;}
    private static OperatorIdentity ReadOperator(NpgsqlDataReader r)=>new(r.GetGuid(r.GetOrdinal("operator_id")),r.GetString(r.GetOrdinal("username")),r.GetString(r.GetOrdinal("display_name")),r.GetString(r.GetOrdinal("role")),r.GetBoolean(r.GetOrdinal("enabled")),r.GetInt32(r.GetOrdinal("failed_login_count")),ReadNullableTime(r,"locked_until"),r.GetString(r.GetOrdinal("password_hash")),ReadNullable(r,"api_token_hash"),ReadTime(r,"credentials_changed_at"));
    private static string? ReadNullable(NpgsqlDataReader r,string n){var i=r.GetOrdinal(n);return r.IsDBNull(i)?null:r.GetString(i);} private static DateTimeOffset? ReadNullableTime(NpgsqlDataReader r,string n){var i=r.GetOrdinal(n);return r.IsDBNull(i)?null:ReadTime(r,n);} private static DateTimeOffset ReadTime(NpgsqlDataReader r,string n)=>new(r.GetDateTime(r.GetOrdinal(n)),TimeSpan.Zero);
    public static string NormalizeUsername(string value){var v=value?.Trim()??"";if(v.Length is <3 or >64 || v.Any(ch=>!(char.IsLetterOrDigit(ch)||ch is '.' or '_' or '-')))throw new ArgumentException("Username must be 3-64 letters, numbers, dots, underscores, or hyphens.");return v.ToUpperInvariant();}
    public static void ValidateRole(string role){if(!OperatorRoles.All.Contains(role))throw new ArgumentException("Role must be viewer, analyst, detection-engineer, or admin.");}
}

public sealed class SecurityAuditRepository(NpgsqlDataSource dataSource)
{
    private const int MaxActorChars = 64;
    private const int MaxTargetChars = 128;
    private const int MaxRequestChars = 128;
    private const int MaxDetailJsonChars = 4000;

    public async Task RecordAsync(Guid? operatorId,string? username,string action,string outcome,string? targetType,string? targetId,HttpContext? context,IReadOnlyDictionary<string,object?>? details,CancellationToken ct)
    {
        await using var c=await dataSource.OpenConnectionAsync(ct);
        await using var q=c.CreateCommand();
        q.CommandText="insert into security_audit_events(operator_id,actor_username,action,outcome,target_type,target_id,request_id,remote_address_hash,details) values(@id,@user,@action,@outcome,@type,@target,@request,@remote,@details);";
        q.Parameters.AddWithValue("id",operatorId.HasValue?operatorId.Value:DBNull.Value);
        q.Parameters.AddWithValue("user",(object?)BoundActorUsername(username)??DBNull.Value);
        q.Parameters.AddWithValue("action",BoundText(action,96) ?? "unknown");
        q.Parameters.AddWithValue("outcome",outcome);
        q.Parameters.AddWithValue("type",(object?)BoundText(targetType,64)??DBNull.Value);
        q.Parameters.AddWithValue("target",(object?)BoundText(targetId,MaxTargetChars)??DBNull.Value);
        q.Parameters.AddWithValue("request",(object?)BoundText(context?.TraceIdentifier,MaxRequestChars)??DBNull.Value);
        var remote=context?.Connection.RemoteIpAddress?.ToString();
        q.Parameters.AddWithValue("remote",remote is null?DBNull.Value:OperatorSecrets.Hash(remote));
        var detailJson = BoundDetailJson(details);
        var p=q.Parameters.Add("details",NpgsqlDbType.Jsonb);
        p.Value=detailJson;
        await q.ExecuteNonQueryAsync(ct);
    }

    internal static string? BoundActorUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username)) return null;
        var trimmed = username.Trim();
        // Never persist raw invalid/oversized login identifiers or credential-shaped input.
        if (trimmed.Length is < 3 or > MaxActorChars
            || trimmed.Any(char.IsControl)
            || trimmed.Contains(':', StringComparison.Ordinal)
            || trimmed.Contains(' ', StringComparison.Ordinal)
            || trimmed.Contains('\t', StringComparison.Ordinal))
        {
            return "invalid_identifier:" + OperatorSecrets.Hash(trimmed)[..16];
        }

        return trimmed;
    }

    private static string? BoundText(string? value, int maxChars)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        return trimmed.Length <= maxChars ? trimmed : trimmed[..maxChars];
    }

    private static string BoundDetailJson(IReadOnlyDictionary<string, object?>? details)
    {
        var json = JsonSerializer.Serialize(details ?? new Dictionary<string, object?>());
        if (json.Length <= MaxDetailJsonChars) return json;
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["truncated"] = true,
            ["original_length"] = json.Length
        });
    }
}
