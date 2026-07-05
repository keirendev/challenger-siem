using System.Globalization;
using System.Text.Json;

namespace Challenger.Siem.Api.SocAgent;

internal sealed record SocAgentDelegatedAuthFileResult
{
    public string Status { get; init; } = "auth_required";
    public string OperatorMessage { get; init; } = string.Empty;
    public bool RequiresConnection { get; init; } = true;
    public string? ConnectLabel { get; init; } = "View delegated auth setup";
    public string? CredentialSource { get; init; } = "configured delegated auth file";
    public DateTimeOffset? ExpiresAt { get; init; }
    public string? RefreshStatus { get; init; }
    public string? AccessToken { get; init; }

    public bool CanUseCredential => string.Equals(Status, "connected", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(AccessToken);
}

internal static class SocAgentDelegatedAuthFileLoader
{
    private static readonly HashSet<string> AllowedCredentialTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "delegated_bearer",
        "oauth_access_token",
        "openai_api_bearer",
        "official_openai_api",
        "official_provider_bearer"
    };

    private static readonly HashSet<string> AllowedIssuerHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "auth.openai.com",
        "login.openai.com",
        "platform.openai.com",
        "api.openai.com"
    };

    public static SocAgentDelegatedAuthFileResult Load(
        SocAgentOptions options,
        IConfiguration configuration,
        bool includeSecret,
        DateTimeOffset? checkedAt = null)
    {
        var path = FirstConfigured(
            options.AuthFilePath,
            configuration["SocAgent:AuthFilePath"],
            configuration["SocAgent:DelegatedAuthFilePath"],
            configuration["SOC_AGENT_AUTH_FILE"]);

        if (string.IsNullOrWhiteSpace(path))
        {
            return AuthRequired("Delegated auth-file mode is selected, but no server-side auth file path is configured. Configure SocAgent:AuthFilePath with an ignored local file or an operator-managed secret path.");
        }

        var providerKey = FirstConfigured(
            options.AuthFileProviderKey,
            configuration["SocAgent:AuthFileProviderKey"],
            configuration["SOC_AGENT_AUTH_FILE_PROVIDER_KEY"]) ?? "openai";

        if (!TryResolveSafePath(path, out var fullPath))
        {
            return ProviderError("The configured delegated auth file path is not an ignored/local auth-file path or operator-managed secret path. Move the file under .local/, use an auth.json-style ignored filename, or configure a path outside the repository.");
        }

        if (!File.Exists(fullPath))
        {
            return AuthRequired("The configured delegated auth file was not found. Reconnect or create the server-side auth file outside source control.");
        }

        JsonDocument document;
        try
        {
            using var stream = File.OpenRead(fullPath);
            document = JsonDocument.Parse(stream);
        }
        catch (UnauthorizedAccessException)
        {
            return AuthRequired("The configured delegated auth file could not be read by the SIEM server. Fix file permissions without exposing provider credentials.");
        }
        catch (IOException)
        {
            return AuthRequired("The configured delegated auth file could not be read by the SIEM server. Reconnect or retry after the file is available.");
        }
        catch (JsonException)
        {
            return AuthRequired("The configured delegated auth file is not valid JSON for the supported minimal credential schema. Recreate it from the documented placeholder format.");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Unsupported("The delegated auth file does not use the supported minimal providers object schema.");
            }

            if (!TryGetObjectProperty(root, out var providers, "providers") || providers.ValueKind != JsonValueKind.Object)
            {
                return Unsupported("The delegated auth file must contain a providers object with an explicit provider entry. Browser session exports and consumer website auth bundles are not supported.");
            }

            if (!TryGetObjectProperty(providers, out var entry, providerKey) || entry.ValueKind != JsonValueKind.Object)
            {
                return AuthRequired("The delegated auth file does not contain the configured provider entry. Verify SocAgent:AuthFileProviderKey and reconnect using a supported credential file.");
            }

            var providerName = GetString(entry, "provider", "provider_name", "providerName");
            if (!string.IsNullOrWhiteSpace(providerName)
                && !providerName.Equals("OpenAI", StringComparison.OrdinalIgnoreCase)
                && !providerName.Equals("ChatGPT", StringComparison.OrdinalIgnoreCase))
            {
                return Unsupported("The delegated auth file provider entry is not supported by this Challenger SIEM build. No external calls will be attempted.");
            }

            var credentialType = GetString(entry, "auth_type", "authType", "credential_type", "credentialType");
            if (string.IsNullOrWhiteSpace(credentialType) || !AllowedCredentialTypes.Contains(credentialType.Trim()))
            {
                return Unsupported("The delegated auth file does not declare a supported official OpenAI API bearer credential type. No unofficial browser/session credentials will be used.");
            }

            var tokenType = GetString(entry, "token_type", "tokenType");
            if (string.IsNullOrWhiteSpace(tokenType) || !tokenType.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                return Unsupported("The delegated auth file token type is unsupported. Only bearer access tokens for the official provider API are accepted.");
            }

            var accessToken = GetString(entry, "access_token", "accessToken");
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return AuthRequired("The delegated auth file does not contain an access token for the configured provider entry. Reconnect using the supported server-side credential file format.");
            }

            var audience = GetString(entry, "audience", "resource", "token_audience", "tokenAudience");
            if (!IsOfficialOpenAiAudience(audience))
            {
                return Unsupported("The delegated auth file does not declare the official OpenAI API audience. No external calls will be attempted with unsupported delegated credentials.");
            }

            var issuer = GetString(entry, "issuer", "iss");
            if (!string.IsNullOrWhiteSpace(issuer) && !IsAllowedIssuer(issuer))
            {
                return Unsupported("The delegated auth file issuer is not on the official provider allowlist. No external calls will be attempted.");
            }

            if (!TryGetExpiresAt(entry, out var expiresAt))
            {
                return AuthRequired("The delegated auth file must include an access-token expiry so Challenger SIEM can fail closed before stale credentials are used.");
            }

            var refreshTokenPresent = !string.IsNullOrWhiteSpace(GetString(entry, "refresh_token", "refreshToken"));
            var refreshStatus = refreshTokenPresent ? "not_supported" : "not_configured";
            var now = checkedAt ?? DateTimeOffset.UtcNow;
            var skewSeconds = Math.Clamp(options.AuthFileExpirySkewSeconds, 0, 3600);
            if (expiresAt <= now.AddSeconds(skewSeconds))
            {
                return new SocAgentDelegatedAuthFileResult
                {
                    Status = refreshTokenPresent ? "refresh_failed" : "expired",
                    OperatorMessage = refreshTokenPresent
                        ? "The delegated auth file access token is expired or near expiry, and this build has no configured official refresh flow. Reconnect and replace the server-side auth file."
                        : "The delegated auth file access token is expired or near expiry. Reconnect and replace the server-side auth file.",
                    RequiresConnection = true,
                    ConnectLabel = "Reconnect delegated provider auth",
                    CredentialSource = "configured delegated auth file",
                    ExpiresAt = expiresAt,
                    RefreshStatus = refreshStatus
                };
            }

            return new SocAgentDelegatedAuthFileResult
            {
                Status = "connected",
                OperatorMessage = "Server-side delegated auth-file credentials are available for the official OpenAI API. Browser clients never receive provider tokens or raw auth-file metadata.",
                RequiresConnection = false,
                ConnectLabel = null,
                CredentialSource = "configured delegated auth file",
                ExpiresAt = expiresAt,
                RefreshStatus = refreshStatus,
                AccessToken = includeSecret ? accessToken.Trim() : null
            };
        }
    }

    private static SocAgentDelegatedAuthFileResult AuthRequired(string message)
    {
        return new SocAgentDelegatedAuthFileResult
        {
            Status = "auth_required",
            OperatorMessage = message,
            RequiresConnection = true,
            ConnectLabel = "Review delegated auth setup"
        };
    }

    private static SocAgentDelegatedAuthFileResult Unsupported(string message)
    {
        return new SocAgentDelegatedAuthFileResult
        {
            Status = "unsupported_delegated_auth",
            OperatorMessage = message,
            RequiresConnection = true,
            ConnectLabel = "Review supported delegated auth setup"
        };
    }

    private static SocAgentDelegatedAuthFileResult ProviderError(string message)
    {
        return new SocAgentDelegatedAuthFileResult
        {
            Status = "provider_error",
            OperatorMessage = message,
            RequiresConnection = true,
            ConnectLabel = "Review provider configuration"
        };
    }

    private static string? FirstConfigured(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return null;
    }

    private static bool TryResolveSafePath(string configuredPath, out string fullPath)
    {
        fullPath = string.Empty;
        string? repoRoot;
        try
        {
            var currentDirectory = Directory.GetCurrentDirectory();
            repoRoot = FindRepositoryRoot(currentDirectory);
            var expanded = Environment.ExpandEnvironmentVariables(configuredPath.Trim());
            fullPath = Path.IsPathRooted(expanded)
                ? Path.GetFullPath(expanded)
                : Path.GetFullPath(expanded, repoRoot ?? currentDirectory);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        if (repoRoot is null || !IsSubPathOf(fullPath, repoRoot))
        {
            return true;
        }

        var relative = Path.GetRelativePath(repoRoot, fullPath).Replace(Path.DirectorySeparatorChar, '/');
        return relative.StartsWith(".local/", StringComparison.OrdinalIgnoreCase)
            || relative.Contains("/.local/", StringComparison.OrdinalIgnoreCase)
            || IsIgnoredAuthFileName(Path.GetFileName(relative));
    }

    private static string? FindRepositoryRoot(string startDirectory)
    {
        var directory = new DirectoryInfo(startDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static bool IsSubPathOf(string path, string root)
    {
        var normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return normalizedPath.Equals(normalizedRoot, comparison)
            || normalizedPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, comparison)
            || normalizedPath.StartsWith(normalizedRoot + Path.AltDirectorySeparatorChar, comparison);
    }

    private static bool IsIgnoredAuthFileName(string fileName)
    {
        return fileName.Equals("auth.json", StringComparison.OrdinalIgnoreCase)
            || (fileName.StartsWith("auth.", StringComparison.OrdinalIgnoreCase) && fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            || fileName.EndsWith(".auth.json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetObjectProperty(JsonElement parent, out JsonElement value, params string[] names)
    {
        if (parent.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in parent.EnumerateObject())
            {
                foreach (var name in names)
                {
                    if (property.NameEquals(name) || property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    {
                        value = property.Value;
                        return true;
                    }
                }
            }
        }

        value = default;
        return false;
    }

    private static string? GetString(JsonElement parent, params string[] names)
    {
        if (!TryGetObjectProperty(parent, out var value, names))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString()?.Trim() : null;
    }

    private static bool TryGetExpiresAt(JsonElement parent, out DateTimeOffset expiresAt)
    {
        var raw = GetString(parent, "expires_at", "expiresAt", "expires_on", "expiresOn");
        if (!string.IsNullOrWhiteSpace(raw)
            && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out expiresAt))
        {
            return true;
        }

        if (TryGetObjectProperty(parent, out var epoch, "expires_at_epoch", "expiresAtEpoch")
            && epoch.ValueKind == JsonValueKind.Number
            && epoch.TryGetInt64(out var seconds))
        {
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }

        expiresAt = default;
        return false;
    }

    private static bool IsOfficialOpenAiAudience(string? audience)
    {
        if (string.IsNullOrWhiteSpace(audience))
        {
            return false;
        }

        return audience.Trim().Equals("https://api.openai.com", StringComparison.OrdinalIgnoreCase)
            || audience.Trim().Equals("https://api.openai.com/v1", StringComparison.OrdinalIgnoreCase)
            || audience.Trim().Equals("api.openai.com", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAllowedIssuer(string issuer)
    {
        if (!Uri.TryCreate(issuer.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        return string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && AllowedIssuerHosts.Contains(uri.Host);
    }
}
