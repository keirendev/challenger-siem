using System.Security.Cryptography;
using System.Text;

namespace Challenger.Siem.Api.Auth;

public sealed class TokenService
{
    public string GenerateAgentToken()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    public string HashToken(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hash);
    }

    public bool FixedTimeEquals(string expected, string? actual)
    {
        if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(actual))
        {
            return false;
        }

        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(actual));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }

    public string? GetBearerToken(HttpContext context)
    {
        var header = context.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = header[prefix.Length..].Trim();
        return token.Length == 0 ? null : token;
    }

    public bool HasOperatorAccess(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true) return false;
        var role = OperatorAuthorization.Role(context.User);
        var path = context.Request.Path.Value ?? string.Empty;
        var permission = path.StartsWith("/api/v1/operators/me/", StringComparison.Ordinal) ? OperatorPermission.ReviewMetadata
            : path.StartsWith("/api/v1/soc-agent", StringComparison.Ordinal) ? OperatorPermission.UseSocAgent
            : path.StartsWith("/api/v1/graphs", StringComparison.Ordinal) ? OperatorPermission.ManageInvestigations
            : path.StartsWith("/api/v1/cases", StringComparison.Ordinal) ? OperatorPermission.ManageInvestigations
            : path.StartsWith("/api/v1/alerts", StringComparison.Ordinal) && context.Request.Method != HttpMethods.Get ? OperatorPermission.ManageInvestigations
            : path.StartsWith("/api/v1/storage/", StringComparison.Ordinal) ? OperatorPermission.ManageAgents
            : path == "/api/v1/inventory" ? OperatorPermission.ManageAgents
            : context.Request.Method == HttpMethods.Get
                ? OperatorPermission.ReviewMetadata
            : OperatorPermission.ManageOperators;
        return OperatorAuthorization.HasPermission(role, permission);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
