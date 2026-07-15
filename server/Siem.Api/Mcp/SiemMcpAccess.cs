using System.Security.Cryptography;
using System.Text;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;

namespace Challenger.Siem.Api.Mcp;

public sealed record SiemMcpAuditSummary(
    int RowCount,
    bool Truncated,
    string Redaction,
    string DataClassification = "operator_sensitive");

public sealed class SiemMcpAccess(
    IHttpContextAccessor httpContextAccessor,
    SecurityAuditRepository audit)
{
    public string Role
    {
        get
        {
            var context = RequiredContext();
            return OperatorAuthorization.Role(context.User)
                ?? throw new InvalidOperationException("Authenticated MCP operator role is unavailable.");
        }
    }

    public bool IsAdmin => string.Equals(Role, OperatorRoles.Admin, StringComparison.Ordinal);

    public void RequireAdmin()
    {
        if (!IsAdmin)
        {
            throw new UnauthorizedAccessException("This MCP operation requires an admin operator token.");
        }
    }

    public async Task<T> ExecuteReadAsync<T>(
        string capability,
        string? targetType,
        string? targetId,
        Func<CancellationToken, Task<T>> action,
        Func<T, SiemMcpAuditSummary> summarize,
        CancellationToken cancellationToken)
    {
        var context = RequiredContext();
        try
        {
            var result = await action(cancellationToken);
            var summary = summarize(result);
            await RecordAsync(context, capability, "success", targetType, targetId, summary, null, cancellationToken);
            return result;
        }
        catch (UnauthorizedAccessException)
        {
            await RecordAsync(context, capability, "denied", targetType, targetId, null, "role_denied", CancellationToken.None);
            throw;
        }
        catch (ArgumentException)
        {
            await RecordAsync(context, capability, "failure", targetType, targetId, null, "invalid_request", CancellationToken.None);
            throw;
        }
        catch (KeyNotFoundException)
        {
            await RecordAsync(context, capability, "failure", targetType, targetId, null, "not_found", CancellationToken.None);
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await RecordAsync(context, capability, "failure", targetType, targetId, null, "cancelled", CancellationToken.None);
            throw;
        }
        catch
        {
            await RecordAsync(context, capability, "failure", targetType, targetId, null, "execution_error", CancellationToken.None);
            throw;
        }
    }

    private HttpContext RequiredContext()
    {
        var context = httpContextAccessor.HttpContext;
        if (context?.User.Identity?.IsAuthenticated != true)
        {
            throw new InvalidOperationException("Authenticated MCP operator context is unavailable.");
        }

        return context;
    }

    private Task RecordAsync(
        HttpContext context,
        string capability,
        string outcome,
        string? targetType,
        string? targetId,
        SiemMcpAuditSummary? summary,
        string? reason,
        CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, object?>
        {
            ["transport"] = "streamable_http",
            ["read_only"] = true,
            ["row_count"] = summary?.RowCount,
            ["truncated"] = summary?.Truncated,
            ["redaction"] = summary?.Redaction,
            ["data_classification"] = summary?.DataClassification,
            ["reason"] = reason
        };
        return audit.RecordAsync(
            OperatorAuthentication.OperatorId(context.User),
            context.User.Identity?.Name,
            $"mcp.tool.{capability}",
            outcome,
            targetType,
            targetId,
            context,
            details,
            cancellationToken);
    }
}

public static class SiemMcpValidation
{
    public const int MaxReadRows = 100;
    public const int MaxLookbackHours = 168;

    public static int Range(int value, int minimum, int maximum, string name)
    {
        if (value < minimum || value > maximum)
        {
            throw new ArgumentException($"{name} must be between {minimum} and {maximum}.", name);
        }

        return value;
    }

    public static string Required(string? value, int maximumLength, string name)
    {
        var result = Optional(value, maximumLength, name);
        return result ?? throw new ArgumentException($"{name} is required.", name);
    }

    public static string? Optional(string? value, int maximumLength, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length > maximumLength || trimmed.Any(char.IsControl))
        {
            throw new ArgumentException($"{name} must be {maximumLength} characters or less and contain no control characters.", name);
        }

        return trimmed;
    }

    public static Guid Guid(string? value, string name)
    {
        if (!System.Guid.TryParse(value, out var result))
        {
            throw new ArgumentException($"{name} must be a valid UUID.", name);
        }

        return result;
    }

    public static string PromptIdentifier(string? value, int maximumLength, string name)
    {
        var result = Required(value, maximumLength, name);
        if (result.Any(character => !(character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-' or '_' or '.' or ':' or '@')))
        {
            throw new ArgumentException(
                $"{name} must use only ASCII letters, numbers, hyphens, underscores, dots, colons, or at signs in prompt arguments.",
                name);
        }

        return result;
    }

    public static string? AuditIdentifier(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length <= maximumLength && trimmed.All(IsSafeAuditIdentifierCharacter))
        {
            return trimmed;
        }

        return HashAuditValue(trimmed);
    }

    public static string? AuditGuidIdentifier(string? value) =>
        System.Guid.TryParse(value, out var parsed)
            ? parsed.ToString()
            : string.IsNullOrWhiteSpace(value)
                ? null
                : HashAuditValue(value.Trim());

    private static string HashAuditValue(string value)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(digest).ToLowerInvariant()}";
    }

    private static bool IsSafeAuditIdentifierCharacter(char character) => character is
        >= 'a' and <= 'z'
        or >= 'A' and <= 'Z'
        or >= '0' and <= '9'
        or '-' or '_' or '.' or ':' or '@';
}
