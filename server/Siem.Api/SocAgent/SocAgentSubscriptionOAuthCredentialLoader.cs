using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Challenger.Siem.Api.SocAgent;

internal sealed record SocAgentSubscriptionOAuthResult
{
    public string Status { get; init; } = "auth_required";
    public string OperatorMessage { get; init; } = string.Empty;
    public bool RequiresConnection { get; init; } = true;
    public string? ConnectLabel { get; init; } = "Review ChatGPT subscription OAuth setup";
    public string? CredentialSource { get; init; } = "configured ChatGPT subscription OAuth file";
    public DateTimeOffset? ExpiresAt { get; init; }
    public string? RefreshStatus { get; init; }
    public string? ScopeStatus { get; init; }
    public string? EntitlementStatus { get; init; }
    public string ProviderPath { get; init; } = "chatgpt_subscription_oauth";
    public string AuthFileMode { get; init; } = "subscription_oauth";
    public string SetupPriority { get; init; } = "primary";
    public string? AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public string? TokenEndpoint { get; init; }
    public string? ClientId { get; init; }
    public string? AccountId { get; init; }
    public string? FilePath { get; init; }
    public string? ProviderKey { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RequiredScopes { get; init; } = Array.Empty<string>();

    public bool CanUseCredential => string.Equals(Status, "connected", StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(AccessToken);

    public bool ShouldRefresh(DateTimeOffset? now = null)
    {
        return string.Equals(RefreshStatus, "refresh_required", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(RefreshToken)
            && !string.IsNullOrWhiteSpace(TokenEndpoint)
            && !string.IsNullOrWhiteSpace(FilePath)
            && !string.IsNullOrWhiteSpace(ProviderKey)
            && ExpiresAt.HasValue
            && ExpiresAt.Value > (now ?? DateTimeOffset.UtcNow);
    }
}

internal static class SocAgentSubscriptionOAuthCredentialLoader
{
    private static readonly HashSet<string> AllowedCredentialTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "subscription_oauth",
        "subscription-oauth",
        "chatgpt_subscription_oauth",
        "chatgpt-subscription-oauth",
        "chatgpt_oauth",
        "oauth_subscription",
        "oauth_access_token",
        "oauth"
    };

    private static readonly HashSet<string> AllowedIssuerHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "auth.openai.com",
        "login.openai.com",
        "platform.openai.com",
        "api.openai.com"
    };

    private static readonly HashSet<string> AllowedRefreshHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "auth.openai.com",
        "login.openai.com",
        "platform.openai.com"
    };

    public static SocAgentSubscriptionOAuthResult Load(
        SocAgentOptions options,
        IConfiguration configuration,
        bool includeSecret,
        DateTimeOffset? checkedAt = null)
    {
        var path = FirstConfigured(
            options.SubscriptionAuthFilePath,
            configuration["SocAgent:SubscriptionAuthFilePath"],
            configuration["SocAgent:ChatGptSubscriptionAuthFilePath"],
            configuration["SocAgent:ChatGptAuthFilePath"],
            configuration["CHATGPT_SUBSCRIPTION_AUTH_FILE"],
            configuration["CHATGPT_AUTH_FILE"],
            UsesSubscriptionOAuth(options.AuthMode) ? options.AuthFilePath : null,
            UsesSubscriptionOAuth(options.AuthMode) ? configuration["SocAgent:AuthFilePath"] : null,
            options.SubscriptionUsePiAuthFile ? configuration["SocAgent:SubscriptionPiAuthFilePath"] : null,
            options.SubscriptionUsePiAuthFile ? configuration["PI_AGENT_AUTH_FILE"] : null,
            options.SubscriptionUsePiAuthFile ? options.SubscriptionPiAuthFilePath : null);

        if (string.IsNullOrWhiteSpace(path))
        {
            return AuthRequired("ChatGPT subscription OAuth mode is selected, but no server-side auth file path is configured. Configure SocAgent:SubscriptionAuthFilePath with an ignored local file or an operator-managed secret path.");
        }

        var providerKey = FirstConfigured(
            options.SubscriptionAuthFileProviderKey,
            configuration["SocAgent:SubscriptionAuthFileProviderKey"],
            configuration["SocAgent:ChatGptSubscriptionAuthFileProviderKey"],
            configuration["CHATGPT_SUBSCRIPTION_AUTH_FILE_PROVIDER_KEY"],
            UsesSubscriptionOAuth(options.AuthMode) ? options.AuthFileProviderKey : null,
            options.SubscriptionUsePiAuthFile ? configuration["SocAgent:SubscriptionPiAuthFileProviderKey"] : null,
            options.SubscriptionUsePiAuthFile ? options.SubscriptionPiAuthFileProviderKey : null) ?? "chatgpt";

        if (!TryResolveSafePath(path, out var fullPath))
        {
            return ProviderError("The configured ChatGPT subscription OAuth auth file path is not an ignored/local auth-file path or operator-managed secret path. Move the file under .local/, use an auth.json-style ignored filename, or configure a path outside the repository.");
        }

        if (!File.Exists(fullPath))
        {
            return AuthRequired("The configured ChatGPT subscription OAuth auth file was not found. Reconnect or create the server-side auth file outside source control.");
        }

        JsonDocument document;
        try
        {
            using var stream = File.OpenRead(fullPath);
            document = JsonDocument.Parse(stream);
        }
        catch (UnauthorizedAccessException)
        {
            return AuthRequired("The configured ChatGPT subscription OAuth auth file could not be read by the SIEM server. Fix file permissions without exposing provider credentials.");
        }
        catch (IOException)
        {
            return AuthRequired("The configured ChatGPT subscription OAuth auth file could not be read by the SIEM server. Reconnect or retry after the file is available.");
        }
        catch (JsonException)
        {
            return AuthRequired("The configured ChatGPT subscription OAuth auth file is not valid JSON for the supported credential schema. Recreate it from the documented placeholder format.");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Unsupported("The ChatGPT subscription OAuth auth file must be a JSON object with an explicit provider entry. Browser session archives are not supported.");
            }

            if (!TryFindCredentialEntry(root, providerKey, out var entry, out var entryKey))
            {
                return AuthRequired("The ChatGPT subscription OAuth auth file does not contain the configured provider entry. Verify SocAgent:SubscriptionAuthFileProviderKey and reconnect using a supported credential file.");
            }

            var isPiAuthJson = IsPiAuthCredential(entry, entryKey);
            var credentialSource = isPiAuthJson ? "Pi auth.json OpenAI Codex OAuth credential" : "configured ChatGPT subscription OAuth file";
            var providerPath = isPiAuthJson ? "pi_auth_json_openai_codex" : "chatgpt_subscription_oauth";
            var authFileMode = isPiAuthJson ? "pi_auth_json" : "subscription_oauth";

            var providerName = GetString(entry, "provider", "provider_name", "providerName", "name");
            if (!isPiAuthJson
                && !string.IsNullOrWhiteSpace(providerName)
                && !providerName.Equals("ChatGPT", StringComparison.OrdinalIgnoreCase)
                && !providerName.Equals("OpenAI", StringComparison.OrdinalIgnoreCase)
                && !providerName.Equals("OpenAI ChatGPT", StringComparison.OrdinalIgnoreCase))
            {
                return Unsupported("The subscription OAuth auth file provider entry is not supported by this Challenger SIEM build. No external calls will be attempted.");
            }

            var credentialType = GetString(entry, "auth_type", "authType", "credential_type", "credentialType", "type");
            if (!isPiAuthJson && (string.IsNullOrWhiteSpace(credentialType) || !AllowedCredentialTypes.Contains(credentialType.Trim())))
            {
                return Unsupported("The auth file does not declare a supported ChatGPT subscription OAuth credential type. Browser cookies, profiles, and session replay exports are not supported.");
            }

            var tokenType = GetString(entry, "token_type", "tokenType");
            if (!isPiAuthJson && !string.IsNullOrWhiteSpace(tokenType) && !tokenType.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                return Unsupported("The ChatGPT subscription OAuth token type is unsupported. Only bearer access tokens from an official OAuth flow are accepted.");
            }

            var accessToken = GetString(entry, "access_token", "accessToken", "accessTokenValue", "access");
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return AuthRequired("The ChatGPT subscription OAuth auth file does not contain an access token for the configured provider entry. Reconnect using a supported server-side credential file format.");
            }

            var audience = GetString(entry, "audience", "resource", "token_audience", "tokenAudience", "aud");
            if (!isPiAuthJson && !IsOfficialOpenAiAudience(audience))
            {
                return Unsupported("The ChatGPT subscription OAuth credential does not declare the official OpenAI API audience for model invocation. Challenger SIEM will not attempt consumer-web or unofficial endpoints.");
            }

            var issuer = GetString(entry, "issuer", "iss");
            if (!string.IsNullOrWhiteSpace(issuer) && !IsAllowedIssuer(issuer))
            {
                return Unsupported("The ChatGPT subscription OAuth credential issuer is not on the official provider allowlist. No external calls will be attempted.");
            }

            if (!TryGetExpiresAt(entry, out var expiresAt))
            {
                return AuthRequired("The ChatGPT subscription OAuth credential must include an access-token expiry so Challenger SIEM can fail closed before stale credentials are used.");
            }

            var requiredScopes = ParseRequiredScopes(options, configuration);
            var scopes = GetScopes(entry);
            if (!isPiAuthJson && !HasRequiredScopes(scopes, requiredScopes))
            {
                return new SocAgentSubscriptionOAuthResult
                {
                    Status = "scope_missing",
                    OperatorMessage = "The ChatGPT subscription OAuth credential is missing the required model-invocation scope. Reconnect through an official flow that grants the documented scope; no external call will be attempted.",
                    RequiresConnection = true,
                    ConnectLabel = "Reconnect ChatGPT subscription OAuth",
                    CredentialSource = credentialSource,
                    ExpiresAt = expiresAt,
                    RefreshStatus = RefreshTokenStatus(entry, options, configuration, expiresAt, checkedAt),
                    ScopeStatus = "model_scope_missing",
                    EntitlementStatus = "not_checked",
                    FilePath = fullPath,
                    ProviderKey = entryKey,
                    Scopes = scopes,
                    RequiredScopes = requiredScopes
                };
            }

            var entitlementStatus = isPiAuthJson ? "not_checked" : NormalizeEntitlementStatus(entry);
            if (string.Equals(entitlementStatus, "unsupported", StringComparison.OrdinalIgnoreCase))
            {
                return new SocAgentSubscriptionOAuthResult
                {
                    Status = "unsupported_subscription_oauth",
                    OperatorMessage = "The ChatGPT subscription OAuth credential indicates that model invocation is unsupported for this application. No external call will be attempted.",
                    RequiresConnection = true,
                    ConnectLabel = "Review supported ChatGPT subscription OAuth setup",
                    CredentialSource = credentialSource,
                    ExpiresAt = expiresAt,
                    RefreshStatus = RefreshTokenStatus(entry, options, configuration, expiresAt, checkedAt),
                    ScopeStatus = isPiAuthJson ? "pi_auth_json" : "model_scope_present",
                    EntitlementStatus = entitlementStatus,
                    ProviderPath = providerPath,
                    AuthFileMode = authFileMode,
                    FilePath = fullPath,
                    ProviderKey = entryKey,
                    Scopes = scopes,
                    RequiredScopes = requiredScopes
                };
            }

            if (string.Equals(entitlementStatus, "plan_limited", StringComparison.OrdinalIgnoreCase))
            {
                return new SocAgentSubscriptionOAuthResult
                {
                    Status = "plan_limited",
                    OperatorMessage = "The ChatGPT subscription OAuth credential does not currently have a plan or entitlement that permits model invocation for this application. No external call will be attempted.",
                    RequiresConnection = false,
                    ConnectLabel = null,
                    CredentialSource = credentialSource,
                    ExpiresAt = expiresAt,
                    RefreshStatus = RefreshTokenStatus(entry, options, configuration, expiresAt, checkedAt),
                    ScopeStatus = isPiAuthJson ? "pi_auth_json" : "model_scope_present",
                    EntitlementStatus = entitlementStatus,
                    ProviderPath = providerPath,
                    AuthFileMode = authFileMode,
                    FilePath = fullPath,
                    ProviderKey = entryKey,
                    Scopes = scopes,
                    RequiredScopes = requiredScopes
                };
            }

            var refreshToken = GetString(entry, "refresh_token", "refreshToken", "refresh");
            var accountId = GetAccountId(entry, accessToken);
            var tokenEndpoint = isPiAuthJson ? null : ResolveTokenEndpoint(entry, options, configuration);
            var now = checkedAt ?? DateTimeOffset.UtcNow;
            var skewSeconds = Math.Clamp(options.AuthFileExpirySkewSeconds, 0, 3600);
            var refreshStatus = isPiAuthJson
                ? (string.IsNullOrWhiteSpace(refreshToken) ? "not_configured" : "pi_managed")
                : RefreshTokenStatus(entry, options, configuration, expiresAt, checkedAt);
            if (expiresAt <= now)
            {
                return new SocAgentSubscriptionOAuthResult
                {
                    Status = "expired",
                    OperatorMessage = "The ChatGPT subscription OAuth access token is expired. Reconnect or refresh the server-side auth file through the official provider flow before external calls are attempted.",
                    RequiresConnection = true,
                    ConnectLabel = "Reconnect ChatGPT subscription OAuth",
                    CredentialSource = credentialSource,
                    ExpiresAt = expiresAt,
                    RefreshStatus = refreshStatus,
                    ScopeStatus = isPiAuthJson ? "pi_auth_json" : "model_scope_present",
                    EntitlementStatus = entitlementStatus,
                    ProviderPath = providerPath,
                    AuthFileMode = authFileMode,
                    FilePath = fullPath,
                    ProviderKey = entryKey,
                    Scopes = scopes,
                    RequiredScopes = requiredScopes
                };
            }

            if (!isPiAuthJson
                && expiresAt <= now.AddSeconds(skewSeconds)
                && (string.IsNullOrWhiteSpace(refreshToken) || string.IsNullOrWhiteSpace(tokenEndpoint)))
            {
                return new SocAgentSubscriptionOAuthResult
                {
                    Status = string.IsNullOrWhiteSpace(refreshToken) ? "expired" : "refresh_failed",
                    OperatorMessage = string.IsNullOrWhiteSpace(refreshToken)
                        ? "The ChatGPT subscription OAuth access token is near expiry and no refresh token is present. Reconnect and replace the server-side auth file."
                        : "The ChatGPT subscription OAuth access token is near expiry, but no official allowlisted refresh endpoint is configured. Reconnect and replace the server-side auth file.",
                    RequiresConnection = true,
                    ConnectLabel = "Reconnect ChatGPT subscription OAuth",
                    CredentialSource = credentialSource,
                    ExpiresAt = expiresAt,
                    RefreshStatus = refreshStatus,
                    ScopeStatus = isPiAuthJson ? "pi_auth_json" : "model_scope_present",
                    EntitlementStatus = entitlementStatus,
                    ProviderPath = providerPath,
                    AuthFileMode = authFileMode,
                    FilePath = fullPath,
                    ProviderKey = entryKey,
                    Scopes = scopes,
                    RequiredScopes = requiredScopes
                };
            }

            return new SocAgentSubscriptionOAuthResult
            {
                Status = "connected",
                OperatorMessage = isPiAuthJson
                    ? "Pi auth.json OpenAI Codex OAuth credentials are available server-side. Challenger SIEM will use the ChatGPT Codex Responses backend for the configured model; browser clients never receive provider tokens, account identifiers, raw auth-file metadata, or full auth-file paths."
                    : "Server-side ChatGPT subscription OAuth credentials are available for an official OpenAI API model path. Browser clients never receive provider tokens, account identifiers, raw auth-file metadata, or full auth-file paths.",
                RequiresConnection = false,
                ConnectLabel = null,
                CredentialSource = credentialSource,
                ExpiresAt = expiresAt,
                RefreshStatus = refreshStatus,
                ScopeStatus = isPiAuthJson ? "pi_auth_json" : "model_scope_present",
                EntitlementStatus = entitlementStatus,
                ProviderPath = providerPath,
                AuthFileMode = authFileMode,
                AccessToken = includeSecret ? accessToken.Trim() : null,
                RefreshToken = includeSecret ? refreshToken?.Trim() : null,
                TokenEndpoint = tokenEndpoint,
                ClientId = includeSecret ? GetString(entry, "client_id", "clientId") : null,
                AccountId = includeSecret ? accountId : null,
                FilePath = fullPath,
                ProviderKey = entryKey,
                Scopes = scopes,
                RequiredScopes = requiredScopes
            };
        }
    }

    public static async Task<SocAgentSubscriptionOAuthResult> RefreshAsync(
        SocAgentSubscriptionOAuthResult credential,
        SocAgentOptions options,
        HttpClient httpClient,
        CancellationToken cancellationToken)
    {
        if (!credential.ShouldRefresh())
        {
            return credential;
        }

        if (!Uri.TryCreate(credential.TokenEndpoint, UriKind.Absolute, out var endpoint) || !IsAllowedRefreshEndpoint(endpoint.ToString()))
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth refresh endpoint is not on the official provider allowlist. No external model call was attempted.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var formFields = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("refresh_token", credential.RefreshToken!.Trim())
        };
        if (!string.IsNullOrWhiteSpace(credential.ClientId))
        {
            formFields.Add(new KeyValuePair<string, string>("client_id", credential.ClientId.Trim()));
        }

        if (credential.RequiredScopes.Count > 0)
        {
            formFields.Add(new KeyValuePair<string, string>("scope", string.Join(' ', credential.RequiredScopes)));
        }

        request.Content = new FormUrlEncodedContent(formFields);

        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth refresh request could not be completed safely. Reconnect the server-side auth file or use local fallback.",
                ex);
        }

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The official provider rejected the ChatGPT subscription OAuth refresh request. Reconnect the server-side auth file or use local fallback.");
        }

        JsonDocument document;
        try
        {
            document = await JsonDocument.ParseAsync(responseStream, cancellationToken: cancellationToken);
        }
        catch (JsonException ex)
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth refresh response could not be parsed safely.",
                ex);
        }

        using (document)
        {
            var root = document.RootElement;
            var accessToken = GetString(root, "access_token", "accessToken");
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new SocAgentModelProviderException(
                    "refresh_failed",
                    "The ChatGPT subscription OAuth refresh response did not include an access token.");
            }

            var tokenType = GetString(root, "token_type", "tokenType");
            if (!string.IsNullOrWhiteSpace(tokenType) && !tokenType.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                throw new SocAgentModelProviderException(
                    "refresh_failed",
                    "The ChatGPT subscription OAuth refresh response returned an unsupported token type.");
            }

            var expiresAt = TryGetExpiresAt(root, out var parsedExpiresAt)
                ? parsedExpiresAt
                : DateTimeOffset.UtcNow.AddSeconds(GetInt(root, "expires_in", "expiresIn") ?? 3600);
            if (expiresAt <= DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(options.AuthFileExpirySkewSeconds, 0, 3600)))
            {
                throw new SocAgentModelProviderException(
                    "refresh_failed",
                    "The ChatGPT subscription OAuth refresh response returned an access token that is already expired or too close to expiry.");
            }

            var scopes = GetScopes(root);
            if (scopes.Count == 0)
            {
                scopes = credential.Scopes;
            }

            if (!HasRequiredScopes(scopes, credential.RequiredScopes))
            {
                throw new SocAgentModelProviderException(
                    "scope_missing",
                    "The refreshed ChatGPT subscription OAuth credential is missing the required model-invocation scope.");
            }

            var refreshToken = GetString(root, "refresh_token", "refreshToken") ?? credential.RefreshToken;
            PersistRefreshedCredential(credential, accessToken.Trim(), refreshToken, expiresAt, scopes);
            return credential with
            {
                Status = "connected",
                OperatorMessage = "Server-side ChatGPT subscription OAuth credentials were refreshed through an official provider endpoint. Browser clients never receive provider tokens.",
                AccessToken = accessToken.Trim(),
                RefreshToken = refreshToken,
                ExpiresAt = expiresAt,
                RefreshStatus = "refreshed",
                Scopes = scopes,
                ScopeStatus = "model_scope_present"
            };
        }
    }

    private static SocAgentSubscriptionOAuthResult AuthRequired(string message)
    {
        return new SocAgentSubscriptionOAuthResult
        {
            Status = "auth_required",
            OperatorMessage = message,
            RequiresConnection = true,
            ConnectLabel = "Review ChatGPT subscription OAuth setup"
        };
    }

    private static SocAgentSubscriptionOAuthResult Unsupported(string message)
    {
        return new SocAgentSubscriptionOAuthResult
        {
            Status = "unsupported_subscription_oauth",
            OperatorMessage = message,
            RequiresConnection = true,
            ConnectLabel = "Review supported ChatGPT subscription OAuth setup"
        };
    }

    private static SocAgentSubscriptionOAuthResult ProviderError(string message)
    {
        return new SocAgentSubscriptionOAuthResult
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

    private static bool UsesSubscriptionOAuth(string? authMode)
    {
        if (string.IsNullOrWhiteSpace(authMode))
        {
            return false;
        }

        return authMode.Trim().Equals("subscriptionoauth", StringComparison.OrdinalIgnoreCase)
            || authMode.Trim().Equals("subscription_oauth", StringComparison.OrdinalIgnoreCase)
            || authMode.Trim().Equals("subscription-oauth", StringComparison.OrdinalIgnoreCase)
            || authMode.Trim().Equals("chatgpt_subscription_oauth", StringComparison.OrdinalIgnoreCase)
            || authMode.Trim().Equals("chatgpt-subscription-oauth", StringComparison.OrdinalIgnoreCase)
            || authMode.Trim().Equals("chatgptoauth", StringComparison.OrdinalIgnoreCase)
            || authMode.Trim().Equals("chatgpt-oauth", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryResolveSafePath(string configuredPath, out string fullPath)
    {
        fullPath = string.Empty;
        string? repoRoot;
        try
        {
            var currentDirectory = Directory.GetCurrentDirectory();
            repoRoot = FindRepositoryRoot(currentDirectory);
            var expanded = ExpandHomeDirectory(Environment.ExpandEnvironmentVariables(configuredPath.Trim()));
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
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, ".git")))
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

    private static string ExpandHomeDirectory(string path)
    {
        if (path.Equals("~", StringComparison.Ordinal))
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        if (path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal))
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[2..]);
        }

        return path;
    }

    private static bool IsPiAuthCredential(JsonElement entry, string entryKey)
    {
        var type = GetString(entry, "auth_type", "authType", "credential_type", "credentialType", "type");
        return entryKey.Equals("openai-codex", StringComparison.OrdinalIgnoreCase)
            && (string.IsNullOrWhiteSpace(type) || string.Equals(type, "oauth", StringComparison.OrdinalIgnoreCase))
            && TryGetObjectProperty(entry, out _, "access")
            && TryGetObjectProperty(entry, out _, "refresh")
            && TryGetObjectProperty(entry, out _, "expires");
    }

    private static bool TryFindCredentialEntry(JsonElement root, string providerKey, out JsonElement entry, out string entryKey)
    {
        var hasProviders = TryGetObjectProperty(root, out var providers, "providers") && providers.ValueKind == JsonValueKind.Object;
        if (hasProviders && TryGetObjectProperty(providers, out entry, providerKey) && entry.ValueKind == JsonValueKind.Object)
        {
            entryKey = providerKey;
            return true;
        }

        if (TryGetObjectProperty(root, out entry, providerKey) && entry.ValueKind == JsonValueKind.Object)
        {
            entryKey = providerKey;
            return true;
        }

        foreach (var fallback in new[] { "openai-codex", "chatgpt", "openai" })
        {
            if (TryGetObjectProperty(root, out entry, fallback) && entry.ValueKind == JsonValueKind.Object)
            {
                entryKey = fallback;
                return true;
            }
        }

        if (hasProviders)
        {
            foreach (var fallback in new[] { "openai-codex", "chatgpt", "openai" })
            {
                if (TryGetObjectProperty(providers, out entry, fallback) && entry.ValueKind == JsonValueKind.Object)
                {
                    entryKey = fallback;
                    return true;
                }
            }
        }

        if (LooksLikeSubscriptionEntry(root))
        {
            entry = root;
            entryKey = providerKey;
            return true;
        }

        entry = default;
        entryKey = providerKey;
        return false;
    }

    private static bool LooksLikeSubscriptionEntry(JsonElement root)
    {
        return root.ValueKind == JsonValueKind.Object
            && TryGetObjectProperty(root, out _, "access_token", "accessToken", "access")
            && (TryGetObjectProperty(root, out _, "auth_type", "authType", "credential_type", "credentialType", "type")
                || TryGetObjectProperty(root, out _, "provider", "provider_name", "providerName", "name"));
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

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString()?.Trim(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    private static string? GetAccountId(JsonElement entry, string accessToken)
    {
        var direct = GetString(entry, "accountId", "account_id", "chatgpt_account_id", "chatgptAccountId");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct.Trim();
        }

        if (TryGetObjectProperty(entry, out var account, "account") && account.ValueKind == JsonValueKind.Object)
        {
            var nested = GetString(account, "id", "accountId", "account_id", "chatgpt_account_id");
            if (!string.IsNullOrWhiteSpace(nested))
            {
                return nested.Trim();
            }
        }

        using var payload = DecodeJwtPayload(accessToken);
        if (payload is null)
        {
            return null;
        }

        if (TryGetObjectProperty(payload.RootElement, out var auth, "https://api.openai.com/auth")
            && auth.ValueKind == JsonValueKind.Object)
        {
            return GetString(auth, "chatgpt_account_id", "account_id", "accountId");
        }

        return null;
    }

    private static JsonDocument? DecodeJwtPayload(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            var padding = payload.Length % 4;
            if (padding > 0)
            {
                payload = payload.PadRight(payload.Length + (4 - padding), '=');
            }

            var bytes = Convert.FromBase64String(payload);
            return JsonDocument.Parse(Encoding.UTF8.GetString(bytes));
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    private static int? GetInt(JsonElement parent, params string[] names)
    {
        if (!TryGetObjectProperty(parent, out var value, names))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        if (value.ValueKind == JsonValueKind.String
            && int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number))
        {
            return number;
        }

        return null;
    }

    private static DateTimeOffset FromUnixSecondsOrMilliseconds(long value)
    {
        return value > 10_000_000_000
            ? DateTimeOffset.FromUnixTimeMilliseconds(value)
            : DateTimeOffset.FromUnixTimeSeconds(value);
    }

    private static bool TryGetExpiresAt(JsonElement parent, out DateTimeOffset expiresAt)
    {
        if (TryGetObjectProperty(parent, out var rawValue, "expires_at", "expiresAt", "expires_on", "expiresOn", "expiry", "expires"))
        {
            if (rawValue.ValueKind == JsonValueKind.String)
            {
                var raw = rawValue.GetString();
                if (!string.IsNullOrWhiteSpace(raw)
                    && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out expiresAt))
                {
                    return true;
                }

                if (!string.IsNullOrWhiteSpace(raw)
                    && long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var rawSeconds))
                {
                    expiresAt = FromUnixSecondsOrMilliseconds(rawSeconds);
                    return true;
                }
            }

            if (rawValue.ValueKind == JsonValueKind.Number && rawValue.TryGetInt64(out var seconds))
            {
                expiresAt = FromUnixSecondsOrMilliseconds(seconds);
                return true;
            }
        }

        if (TryGetObjectProperty(parent, out var epoch, "expires_at_epoch", "expiresAtEpoch")
            && epoch.ValueKind == JsonValueKind.Number
            && epoch.TryGetInt64(out var epochSeconds))
        {
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(epochSeconds);
            return true;
        }

        expiresAt = default;
        return false;
    }

    private static IReadOnlyList<string> ParseRequiredScopes(SocAgentOptions options, IConfiguration configuration)
    {
        var configured = FirstConfigured(
            options.SubscriptionRequiredScopes,
            configuration["SocAgent:SubscriptionRequiredScopes"],
            configuration["SocAgent:ChatGptSubscriptionRequiredScopes"]);
        if (string.IsNullOrWhiteSpace(configured))
        {
            return new[] { "model.request" };
        }

        return configured.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<string> GetScopes(JsonElement entry)
    {
        var values = new List<string>();
        if (TryGetObjectProperty(entry, out var scopeValue, "scope", "scopes"))
        {
            if (scopeValue.ValueKind == JsonValueKind.String)
            {
                values.AddRange((scopeValue.GetString() ?? string.Empty).Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
            else if (scopeValue.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in scopeValue.EnumerateArray())
                {
                    if (element.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(element.GetString()))
                    {
                        values.Add(element.GetString()!.Trim());
                    }
                }
            }
        }

        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool HasRequiredScopes(IReadOnlyList<string> scopes, IReadOnlyList<string> requiredScopes)
    {
        if (requiredScopes.Count == 0)
        {
            return true;
        }

        var set = new HashSet<string>(scopes, StringComparer.OrdinalIgnoreCase);
        return requiredScopes.All(set.Contains);
    }

    private static string NormalizeEntitlementStatus(JsonElement entry)
    {
        var raw = GetString(entry, "entitlement_status", "entitlementStatus", "plan_status", "planStatus", "model_entitlement", "modelEntitlement");
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "not_checked";
        }

        var normalized = raw.Trim().ToLowerInvariant().Replace('-', '_');
        return normalized switch
        {
            "active" or "available" or "entitled" or "ok" or "connected" or "true" => "available",
            "missing" or "none" or "limited" or "plan_limited" or "budget_limited" or "quota_exhausted" or "not_entitled" or "false" => "plan_limited",
            "unsupported" => "unsupported",
            _ => "not_checked"
        };
    }

    private static string RefreshTokenStatus(JsonElement entry, SocAgentOptions options, IConfiguration configuration, DateTimeOffset expiresAt, DateTimeOffset? checkedAt)
    {
        var refreshToken = GetString(entry, "refresh_token", "refreshToken");
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return "not_configured";
        }

        var endpoint = ResolveTokenEndpoint(entry, options, configuration);
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return "not_supported";
        }

        var now = checkedAt ?? DateTimeOffset.UtcNow;
        var skewSeconds = Math.Clamp(options.AuthFileExpirySkewSeconds, 0, 3600);
        return expiresAt <= now.AddSeconds(skewSeconds) && expiresAt > now
            ? "refresh_required"
            : "available";
    }

    private static string? ResolveTokenEndpoint(JsonElement entry, SocAgentOptions options, IConfiguration configuration)
    {
        var candidate = FirstConfigured(
            GetString(entry, "token_endpoint", "tokenEndpoint", "refresh_endpoint", "refreshEndpoint"),
            options.SubscriptionTokenEndpoint,
            configuration["SocAgent:SubscriptionTokenEndpoint"],
            configuration["SocAgent:ChatGptSubscriptionTokenEndpoint"]);
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        return IsAllowedRefreshEndpoint(candidate) ? candidate.Trim() : null;
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

    private static bool IsAllowedRefreshEndpoint(string endpoint)
    {
        return Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && AllowedRefreshHosts.Contains(uri.Host)
            && (uri.AbsolutePath.Equals("/oauth/token", StringComparison.OrdinalIgnoreCase)
                || uri.AbsolutePath.Equals("/oauth2/token", StringComparison.OrdinalIgnoreCase)
                || uri.AbsolutePath.Equals("/v1/oauth/token", StringComparison.OrdinalIgnoreCase));
    }

    private static void PersistRefreshedCredential(
        SocAgentSubscriptionOAuthResult credential,
        string accessToken,
        string? refreshToken,
        DateTimeOffset expiresAt,
        IReadOnlyList<string> scopes)
    {
        if (string.IsNullOrWhiteSpace(credential.FilePath) || string.IsNullOrWhiteSpace(credential.ProviderKey))
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth credential file could not be updated safely after refresh.");
        }

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(File.ReadAllText(credential.FilePath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth credential file could not be reopened safely after refresh.",
                ex);
        }

        if (root is not JsonObject rootObject)
        {
            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth credential file changed to an unsupported shape during refresh.");
        }

        var entry = FindMutableEntry(rootObject, credential.ProviderKey);
        entry["access_token"] = accessToken;
        if (!string.IsNullOrWhiteSpace(refreshToken))
        {
            entry["refresh_token"] = refreshToken;
        }

        entry["token_type"] = "Bearer";
        entry["expires_at"] = expiresAt.ToString("O", CultureInfo.InvariantCulture);
        entry["scope"] = string.Join(' ', scopes);
        entry["updated_at"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

        var directory = Path.GetDirectoryName(credential.FilePath) ?? Directory.GetCurrentDirectory();
        var tempPath = Path.Combine(directory, $".{Path.GetFileName(credential.FilePath)}.{Guid.NewGuid():N}.tmp");
        var options = new JsonSerializerOptions { WriteIndented = true };
        try
        {
            File.WriteAllText(tempPath, rootObject.ToJsonString(options));
            TryRestrictFileMode(tempPath);
            File.Move(tempPath, credential.FilePath, overwrite: true);
            TryRestrictFileMode(credential.FilePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (IOException)
            {
                // Ignore cleanup failure; do not expose paths or tokens in the operator-facing error.
            }

            throw new SocAgentModelProviderException(
                "refresh_failed",
                "The ChatGPT subscription OAuth credential file could not be updated atomically after refresh.",
                ex);
        }
    }

    private static JsonObject FindMutableEntry(JsonObject rootObject, string providerKey)
    {
        if (rootObject["providers"] is JsonObject providers)
        {
            if (providers[providerKey] is JsonObject configured)
            {
                return configured;
            }

            foreach (var fallback in new[] { "chatgpt", "openai" })
            {
                if (providers[fallback] is JsonObject fallbackEntry)
                {
                    return fallbackEntry;
                }
            }
        }

        return rootObject;
    }

    private static void TryRestrictFileMode(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Best effort only; caller still keeps the file under ignored/local or operator-managed paths.
        }
    }
}
