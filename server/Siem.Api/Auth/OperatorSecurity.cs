using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Auth;

public static class OperatorRoles
{
    public const string Viewer = "viewer";
    public const string Analyst = "analyst";
    public const string DetectionEngineer = "detection-engineer";
    public const string Admin = "admin";
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
        { Viewer, Analyst, DetectionEngineer, Admin };
}

public enum OperatorPermission
{
    ReviewMetadata,
    ReviewSensitive,
    UseSocAgent,
    ManageInvestigations,
    ManageDetections,
    ManageAgents,
    ManageOperators,
    ReviewAudit
}

public static class OperatorAuthorization
{
    public static bool HasPermission(string? role, OperatorPermission permission) => role switch
    {
        OperatorRoles.Viewer => permission == OperatorPermission.ReviewMetadata,
        OperatorRoles.Analyst => permission is OperatorPermission.ReviewMetadata or OperatorPermission.ReviewSensitive
            or OperatorPermission.UseSocAgent or OperatorPermission.ManageInvestigations,
        OperatorRoles.DetectionEngineer => permission is OperatorPermission.ReviewMetadata or OperatorPermission.ReviewSensitive
            or OperatorPermission.UseSocAgent or OperatorPermission.ManageInvestigations or OperatorPermission.ManageDetections,
        OperatorRoles.Admin => true,
        _ => false
    };

    public static string? Role(System.Security.Claims.ClaimsPrincipal principal) =>
        principal.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
}

public sealed class OperatorPasswordHasher
{
    private const int Iterations = 210_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public string Hash(string password)
    {
        ValidatePassword(password);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashBytes);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string encoded)
    {
        try
        {
            var parts = encoded.Split('$');
            if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out var iterations)) return false;
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException) { return false; }
    }

    public static void ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 14 || password.Length > 256
            || !password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit)
            || !password.Any(ch => !char.IsLetterOrDigit(ch)))
            throw new ArgumentException("Password must be 14-256 characters and include upper, lower, number, and symbol characters.");
    }
}

public static class OperatorSecrets
{
    public static string Generate() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string Hash(string value) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

public static class AlertFieldPolicy
{
    public static AlertRecord Apply(AlertRecord source, string role) => role == OperatorRoles.Admin ? source : source with
    {
        Summary = "[redacted: sensitive alert context]",
        AffectedEntities = Array.Empty<EventEntity>(),
        Evidence = source.Evidence.Select(item => item with { Summary = "[redacted: sensitive evidence context]" }).ToArray()
    };
}

public static class EventFieldPolicy
{
    private static readonly JsonElement Empty = JsonDocument.Parse("{}").RootElement.Clone();

    public static EventEnvelope Apply(EventEnvelope source, string role)
    {
        if (role == OperatorRoles.Admin) return source;
        var canReview = OperatorAuthorization.HasPermission(role, OperatorPermission.ReviewSensitive);
        return source with
        {
            Message = canReview ? "[redacted: sensitive event text]" : "[restricted]",
            Raw = Empty,
            Normalized = source.Normalized is null ? null : source.Normalized with
            {
                UserName = null, UserSid = null, TargetUserName = null,
                ProcessId = null, ParentProcessId = null, ProcessImage = null, ParentProcessImage = null, ProcessCommandLine = null,
                SourceIp = null, SourcePort = null, DestinationIp = null, DestinationPort = null,
                FilePath = null, RegistryKey = null, ObjectName = null,
                User = null, Network = null,
                Process = source.Normalized.Process is null ? null : source.Normalized.Process with { CommandLine = null, Executable = null },
                File = null, Entities = Array.Empty<EventEntity>(), Labels = new Dictionary<string,string>()
            }
        };
    }
}
