using System.Text.RegularExpressions;
using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Mcp;

public static partial class SiemMcpInventoryPolicy
{
    private const string Redacted = "<redacted>";

    private static readonly string[] SensitiveKeyFragments =
    {
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "authorization",
        "cookie",
        "sessionid",
        "sessiontoken",
        "privatekey",
        "connectionstring",
        "apikey",
        "clientsecret",
        "enrollmenttoken",
        "agenttoken",
        "accesskey",
        "secretkey"
    };

    public static IReadOnlyDictionary<string, string> RedactMap(IReadOnlyDictionary<string, string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var redacted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in values)
        {
            redacted[item.Key] = IsSensitiveKey(item.Key) ? Redacted : RedactText(item.Value);
        }

        return redacted;
    }

    public static InventoryItem RedactItem(InventoryItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        return item with
        {
            Kind = RedactText(item.Kind),
            Name = RedactText(item.Name),
            Status = item.Status is null ? null : RedactText(item.Status),
            Identity = item.Identity is null ? null : RedactText(item.Identity),
            Metadata = RedactMap(item.Metadata)
        };
    }

    public static string RedactText(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var redacted = SocAgentTextSafety.RedactSecrets(value);
        redacted = PrivateKeyPattern().Replace(redacted, Redacted);
        redacted = JsonWebTokenPattern().Replace(redacted, Redacted);
        redacted = ProviderCredentialPattern().Replace(redacted, Redacted);
        redacted = CloudAccessKeyPattern().Replace(redacted, Redacted);
        redacted = BasicAuthorizationPattern().Replace(redacted, "Basic <redacted>");
        return UserInfoPattern().Replace(redacted, "${scheme}<redacted>@");
    }

    private static bool IsSensitiveKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        var normalized = new string(key.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
        return normalized == "pwd" || SensitiveKeyFragments.Any(normalized.Contains);
    }

    [GeneratedRegex("-----BEGIN [^-\\r\\n]*PRIVATE KEY-----.*?-----END [^-\\r\\n]*PRIVATE KEY-----", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex PrivateKeyPattern();

    [GeneratedRegex("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b", RegexOptions.CultureInvariant)]
    private static partial Regex JsonWebTokenPattern();

    [GeneratedRegex("\\b(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{16,}\\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProviderCredentialPattern();

    [GeneratedRegex("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b", RegexOptions.CultureInvariant)]
    private static partial Regex CloudAccessKeyPattern();

    [GeneratedRegex("\\bBasic\\s+[A-Za-z0-9+/]{8,}={0,2}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BasicAuthorizationPattern();

    [GeneratedRegex("(?<scheme>[a-z][a-z0-9+.-]*://)[^\\s/@:]+:[^\\s/@]+@", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserInfoPattern();
}
