using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace Challenger.Siem.Api.Database;

public sealed class SecurityAuditRepository(NpgsqlDataSource dataSource)
{
    private const int MaxActorChars = 64;
    private const int MaxDetailJsonChars = 4000;

    public async Task RecordAsync(Guid? actorId, string? actorName, string action, string outcome, string? targetType, string? targetId, HttpContext? context, IReadOnlyDictionary<string, object?>? details, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "insert into security_audit_events(actor_id,actor_name,action,outcome,target_type,target_id,request_id,remote_address_hash,details) values(@id,@name,@action,@outcome,@type,@target,@request,@remote,@details);";
        command.Parameters.AddWithValue("id", actorId.HasValue ? actorId.Value : DBNull.Value);
        command.Parameters.AddWithValue("name", (object?)BoundActorName(actorName) ?? DBNull.Value);
        command.Parameters.AddWithValue("action", Bound(action, 96) ?? "unknown");
        command.Parameters.AddWithValue("outcome", outcome);
        command.Parameters.AddWithValue("type", (object?)Bound(targetType, 64) ?? DBNull.Value);
        command.Parameters.AddWithValue("target", (object?)Bound(targetId, 128) ?? DBNull.Value);
        command.Parameters.AddWithValue("request", (object?)Bound(context?.TraceIdentifier, 128) ?? DBNull.Value);
        var remote = context?.Connection.RemoteIpAddress?.ToString();
        command.Parameters.AddWithValue("remote", remote is null ? DBNull.Value : Hash(remote));
        command.Parameters.Add("details", NpgsqlDbType.Jsonb).Value = BoundDetails(details);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    internal static string? BoundActorName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        if (trimmed.Length is < 3 or > MaxActorChars || trimmed.Any(char.IsControl) || trimmed.Contains(':') || trimmed.Any(char.IsWhiteSpace))
        {
            return "invalid_identifier:" + Hash(trimmed)[..16];
        }
        return trimmed;
    }

    private static string? Bound(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        return trimmed.Length <= max ? trimmed : trimmed[..max];
    }

    private static string BoundDetails(IReadOnlyDictionary<string, object?>? details)
    {
        var json = JsonSerializer.Serialize(details ?? new Dictionary<string, object?>());
        return json.Length <= MaxDetailJsonChars
            ? json
            : JsonSerializer.Serialize(new { truncated = true, original_length = json.Length });
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
