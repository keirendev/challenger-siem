using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.SocAgent;

public sealed record SocAgentSubscriptionOAuthConnectResult(
    bool Succeeded,
    string Status,
    string OperatorSafeMessage);

public sealed record SocAgentSubscriptionOAuthDisconnectResult(
    bool Succeeded,
    bool Removed,
    string Status,
    string OperatorSafeMessage);

public sealed class SocAgentSubscriptionOAuthConnectException(
    string status,
    string operatorSafeMessage,
    Exception? innerException = null) : Exception(operatorSafeMessage, innerException)
{
    public string Status { get; } = status;
    public string OperatorSafeMessage { get; } = operatorSafeMessage;
}

public interface ISocAgentOAuthOperatorSessionValidator
{
    Task<OperatorSession?> ValidateAsync(string sessionToken, CancellationToken cancellationToken);
}

internal sealed class SocAgentOAuthOperatorSessionValidator(OperatorRepository operators)
    : ISocAgentOAuthOperatorSessionValidator
{
    public Task<OperatorSession?> ValidateAsync(string sessionToken, CancellationToken cancellationToken) =>
        operators.ValidateSessionAsync(sessionToken, cancellationToken);
}

public sealed class SocAgentSubscriptionOAuthConnectService(
    HttpClient httpClient,
    IOptions<SocAgentOptions> options,
    IConfiguration configuration,
    IDataProtectionProvider dataProtectionProvider,
    ISocAgentOAuthOperatorSessionValidator operatorSessions,
    ILogger<SocAgentSubscriptionOAuthConnectService> logger)
{
    private const string CorrelationCookieName = ".ChallengerSiem.SocAgentOAuth";
    private const int MaxTokenResponseBytes = 256 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private static readonly HashSet<string> AllowedAuthorizationHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "auth.openai.com",
        "login.openai.com",
        "platform.openai.com"
    };
    private static readonly HashSet<string> AllowedTokenHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "auth.openai.com",
        "login.openai.com",
        "platform.openai.com"
    };

    private readonly SocAgentOptions options = options.Value;
    private readonly IDataProtector protector = dataProtectionProvider.CreateProtector("Challenger.Siem.SocAgent.SubscriptionOAuth.v1");

    public bool CanStartInteractiveConnect()
    {
        return options.SubscriptionConnectEnabled
            && IsSubscriptionOAuth(options.AuthMode)
            && !string.IsNullOrWhiteSpace(ResolveClientId())
            && !string.IsNullOrWhiteSpace(ResolveAuthFilePath())
            && TryResolveSafeAuthFilePath(out _, out _, out _);
    }

    public bool CanDisconnectDedicatedCredential()
    {
        if (!IsSubscriptionOAuth(options.AuthMode)
            || !TryResolveSafeAuthFilePath(out var authFilePath, out var providerKey, out _)
            || !File.Exists(authFilePath))
        {
            return false;
        }

        try
        {
            var rootObject = JsonNode.Parse(File.ReadAllText(authFilePath)) as JsonObject;
            if (rootObject?["providers"] is not JsonObject providers)
            {
                return false;
            }

            var configuredEntry = providers.FirstOrDefault(item =>
                item.Key.Equals(providerKey, StringComparison.OrdinalIgnoreCase));
            return configuredEntry.Value is JsonObject entry && IsDedicatedSubscriptionEntry(entry);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    public Uri CreateAuthorizationUri(HttpContext context, string? returnUrl = null)
    {
        var initiator = RequireInitiatingAdminSession(context);

        if (!options.SubscriptionConnectEnabled)
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "auth_required",
                "ChatGPT subscription OAuth connect is disabled. Ask an admin to enable it with official server-side OAuth client settings.");
        }

        if (!IsSubscriptionOAuth(options.AuthMode))
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                "ChatGPT subscription OAuth connect requires SocAgent:AuthMode=SubscriptionOAuth.");
        }

        var authUrl = ResolveAuthorizationUrl();
        if (authUrl is null)
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                "ChatGPT subscription OAuth connect is not configured with an official authorization URL.");
        }

        var clientId = ResolveClientId();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "auth_required",
                "ChatGPT subscription OAuth connect requires a server-side client ID configured outside source control.");
        }

        if (!TryResolveSafeAuthFilePath(out _, out _, out var pathError))
        {
            throw new SocAgentSubscriptionOAuthConnectException("provider_error", pathError);
        }

        var state = CreateBase64UrlRandom(32);
        var codeVerifier = CreateBase64UrlRandom(64);
        var codeChallenge = WebEncoders.Base64UrlEncode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(codeVerifier)));
        var redirectUri = ResolveRedirectUri(context);
        var correlation = new OAuthCorrelationState(
            state,
            codeVerifier,
            ReturnUrl: SafeReturnUrl(returnUrl) ?? "/soc-agent",
            IssuedAt: DateTimeOffset.UtcNow,
            RedirectUri: redirectUri,
            InitiatorOperatorId: initiator.OperatorId,
            InitiatorSessionToken: initiator.SessionToken);
        var protectedValue = protector.Protect(JsonSerializer.Serialize(correlation, JsonOptions));
        context.Response.Cookies.Append(CorrelationCookieName, protectedValue, CreateCorrelationCookieOptions(context));

        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId.Trim(),
            ["redirect_uri"] = redirectUri,
            ["scope"] = ResolveScopes(),
            ["state"] = state,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };
        var audience = ResolveAudience();
        if (!string.IsNullOrWhiteSpace(audience))
        {
            query["audience"] = audience;
        }

        return new Uri(QueryHelpers.AddQueryString(authUrl.ToString(), query));
    }

    public async Task<SocAgentSubscriptionOAuthConnectResult> CompleteAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var state = context.Request.Query["state"].FirstOrDefault();
        var correlation = ReadAndClearCorrelationCookie(context);
        if (correlation is null
            || string.IsNullOrWhiteSpace(state)
            || !FixedTimeEquals(correlation.State, state))
        {
            return new SocAgentSubscriptionOAuthConnectResult(
                false,
                "auth_required",
                "The ChatGPT subscription OAuth state check failed. Start a new connection from the soc-agent page.");
        }

        if (!await IsValidInitiatingAdminSessionAsync(context, correlation, cancellationToken))
        {
            return new SocAgentSubscriptionOAuthConnectResult(
                false,
                "auth_required",
                "The ChatGPT subscription OAuth connection is no longer associated with the initiating admin session. Start a new connection from the soc-agent page.");
        }

        var lifetime = TimeSpan.FromMinutes(Math.Clamp(options.SubscriptionStateLifetimeMinutes, 1, 60));
        if (correlation.IssuedAt.Add(lifetime) < DateTimeOffset.UtcNow)
        {
            return new SocAgentSubscriptionOAuthConnectResult(
                false,
                "expired",
                "The ChatGPT subscription OAuth connection attempt expired. Start a new connection from the soc-agent page.");
        }

        var providerError = context.Request.Query["error"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(providerError))
        {
            logger.LogWarning("ChatGPT subscription OAuth provider returned an authorization error mapped to auth_required.");
            return new SocAgentSubscriptionOAuthConnectResult(
                false,
                "auth_required",
                "The provider did not complete ChatGPT subscription OAuth authorization. Reconnect using the official provider flow.");
        }

        var code = context.Request.Query["code"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(code))
        {
            return new SocAgentSubscriptionOAuthConnectResult(
                false,
                "auth_required",
                "The ChatGPT subscription OAuth callback did not include the required authorization response.");
        }

        if (!TryResolveSafeAuthFilePath(out var authFilePath, out var providerKey, out var pathError))
        {
            return new SocAgentSubscriptionOAuthConnectResult(false, "provider_error", pathError);
        }

        var tokenEndpoint = ResolveTokenEndpoint();
        if (tokenEndpoint is null)
        {
            return new SocAgentSubscriptionOAuthConnectResult(
                false,
                "provider_error",
                "ChatGPT subscription OAuth connect is not configured with an official token endpoint.");
        }

        var token = await ExchangeCodeAsync(tokenEndpoint, code, correlation, cancellationToken);
        PersistCredential(authFilePath, providerKey, token, tokenEndpoint);
        logger.LogInformation("ChatGPT subscription OAuth credentials were stored in the configured server-side auth file without exposing provider secrets to the browser.");
        return new SocAgentSubscriptionOAuthConnectResult(
            true,
            "connected",
            "ChatGPT subscription OAuth connected. Credentials were stored server-side and were not exposed to the browser.");
    }

    public Task<SocAgentSubscriptionOAuthDisconnectResult> DisconnectAsync(
        bool confirmed,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!confirmed)
        {
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "confirmation_required",
                message: "Confirm ChatGPT subscription OAuth disconnect before removing the dedicated server-side credential entry.");
        }

        if (!IsSubscriptionOAuth(options.AuthMode))
        {
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "provider_error",
                message: "ChatGPT subscription OAuth disconnect is unavailable because subscription OAuth mode is not configured. No credential entries were modified.");
        }

        if (!TryResolveSafeAuthFilePath(out var authFilePath, out var providerKey, out _))
        {
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "provider_error",
                message: "ChatGPT subscription OAuth disconnect requires a dedicated allowed SIEM credential target. Shared Codex-managed credentials were not modified.");
        }

        if (!File.Exists(authFilePath))
        {
            return DisconnectResult(
                succeeded: true,
                removed: false,
                status: "not_connected",
                message: "ChatGPT subscription OAuth is already disconnected for the dedicated SIEM credential entry.");
        }

        JsonObject rootObject;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            rootObject = JsonNode.Parse(File.ReadAllText(authFilePath)) as JsonObject
                ?? throw new JsonException("The subscription OAuth credential root must be a JSON object.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            logger.LogWarning("The dedicated ChatGPT subscription OAuth credential file could not be read safely during disconnect.");
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "provider_error",
                message: "The dedicated ChatGPT subscription OAuth credential file could not be read safely. No credential entries were modified.");
        }

        var providersNode = rootObject["providers"];
        if (providersNode is null)
        {
            return DisconnectResult(
                succeeded: true,
                removed: false,
                status: "not_connected",
                message: "ChatGPT subscription OAuth is already disconnected for the dedicated SIEM credential entry.");
        }

        if (providersNode is not JsonObject providers)
        {
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "provider_error",
                message: "The dedicated ChatGPT subscription OAuth credential file has an unsupported providers structure. No credential entries were modified.");
        }

        var configuredEntry = providers.FirstOrDefault(item =>
            item.Key.Equals(providerKey, StringComparison.OrdinalIgnoreCase));
        if (configuredEntry.Key is null)
        {
            return DisconnectResult(
                succeeded: true,
                removed: false,
                status: "not_connected",
                message: "ChatGPT subscription OAuth is already disconnected for the dedicated SIEM credential entry.");
        }

        if (configuredEntry.Value is not JsonObject entry || !IsDedicatedSubscriptionEntry(entry))
        {
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "unsupported_subscription_oauth",
                message: "The configured credential entry is not a dedicated ChatGPT subscription OAuth entry. Shared or unsupported credentials were not modified.");
        }

        providers.Remove(configuredEntry.Key);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            WriteAuthFileAtomically(
                authFilePath,
                rootObject,
                "The ChatGPT subscription OAuth credential file could not be updated atomically during disconnect. No credential contents were exposed.");
        }
        catch (SocAgentSubscriptionOAuthConnectException)
        {
            logger.LogWarning("The dedicated ChatGPT subscription OAuth credential entry could not be removed atomically.");
            return DisconnectResult(
                succeeded: false,
                removed: false,
                status: "provider_error",
                message: "ChatGPT subscription OAuth could not be disconnected safely. No credential contents were exposed.");
        }

        logger.LogInformation("ChatGPT subscription OAuth disconnected by removing only the dedicated SIEM credential entry.");
        return DisconnectResult(
            succeeded: true,
            removed: true,
            status: "disconnected",
            message: "ChatGPT subscription OAuth disconnected. Only the dedicated SIEM credential entry was removed; other credential data was preserved.");
    }

    public string CompleteReturnUrl(SocAgentSubscriptionOAuthConnectResult result)
    {
        var parameter = result.Succeeded ? "oauth_status" : "oauth_error";
        return QueryHelpers.AddQueryString("/soc-agent", parameter, result.OperatorSafeMessage);
    }

    private async Task<TokenExchangeResult> ExchangeCodeAsync(
        Uri tokenEndpoint,
        string code,
        OAuthCorrelationState correlation,
        CancellationToken cancellationToken)
    {
        var clientId = ResolveClientId();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "auth_required",
                "ChatGPT subscription OAuth connect requires a server-side client ID configured outside source control.");
        }

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code.Trim()),
            new("redirect_uri", correlation.RedirectUri),
            new("client_id", clientId.Trim()),
            new("code_verifier", correlation.CodeVerifier),
        };
        var clientSecret = ResolveClientSecret();
        if (!string.IsNullOrWhiteSpace(clientSecret))
        {
            form.Add(new KeyValuePair<string, string>("client_secret", clientSecret.Trim()));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form)
        };
        request.Headers.Accept.ParseAdd("application/json");

        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                "The ChatGPT subscription OAuth token exchange could not reach the official provider endpoint.",
                ex);
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning(
                "ChatGPT subscription OAuth token exchange failed with provider status {StatusCode}.",
                (int)response.StatusCode);
            return response.StatusCode switch
            {
                System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden => throw new SocAgentSubscriptionOAuthConnectException(
                    "auth_failed",
                    "The provider rejected the ChatGPT subscription OAuth authorization code. Start a new connection or verify server-side OAuth client configuration."),
                _ => throw new SocAgentSubscriptionOAuthConnectException(
                    "provider_error",
                    "The provider did not complete the ChatGPT subscription OAuth token exchange. No provider response body was exposed.")
            };
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var document = await ParseTokenResponseAsync(stream, cancellationToken);

        using (document)
        {
            var root = document.RootElement;
            var accessToken = GetString(root, "access_token", "accessToken");
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new SocAgentSubscriptionOAuthConnectException(
                    "auth_required",
                    "The ChatGPT subscription OAuth token response did not contain an access token.");
            }

            var tokenType = GetString(root, "token_type", "tokenType");
            if (!string.IsNullOrWhiteSpace(tokenType) && !tokenType.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                throw new SocAgentSubscriptionOAuthConnectException(
                    "unsupported_subscription_oauth",
                    "The ChatGPT subscription OAuth token response returned an unsupported token type.");
            }

            var expiresAt = TryGetExpiresAt(root, out var parsedExpiresAt)
                ? parsedExpiresAt
                : DateTimeOffset.UtcNow.AddSeconds(GetInt(root, "expires_in", "expiresIn") ?? 3600);
            var scope = GetScope(root);
            var requiredScopes = ResolveScopes().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (!HasRequiredScopes(scope, requiredScopes))
            {
                throw new SocAgentSubscriptionOAuthConnectException(
                    "scope_missing",
                    "The ChatGPT subscription OAuth token response did not include the required model-invocation scope. No external model calls will be attempted.");
            }

            return new TokenExchangeResult(
                AccessToken: accessToken.Trim(),
                RefreshToken: GetString(root, "refresh_token", "refreshToken"),
                ExpiresAt: expiresAt,
                Scope: scope,
                TokenType: "Bearer");
        }
    }

    private static async Task<JsonDocument> ParseTokenResponseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var readBuffer = ArrayPool<byte>.Shared.Rent(8192);
        var responseBuffer = new ArrayBufferWriter<byte>();
        try
        {
            while (true)
            {
                var bytesRead = await stream.ReadAsync(
                    readBuffer.AsMemory(0, readBuffer.Length),
                    cancellationToken);
                if (bytesRead == 0)
                {
                    break;
                }

                if (responseBuffer.WrittenCount > MaxTokenResponseBytes - bytesRead)
                {
                    throw new SocAgentSubscriptionOAuthConnectException(
                        "provider_error",
                        "The ChatGPT subscription OAuth token response exceeded its safety limit.");
                }

                responseBuffer.Write(readBuffer.AsSpan(0, bytesRead));
            }

            return JsonDocument.Parse(responseBuffer.WrittenMemory);
        }
        catch (JsonException ex)
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                "The ChatGPT subscription OAuth token response could not be parsed safely.",
                ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readBuffer);
            ArrayPool<byte>.Shared.Return(readBuffer);
        }
    }

    private void PersistCredential(string authFilePath, string providerKey, TokenExchangeResult token, Uri tokenEndpoint)
    {
        if (!SocAgentSubscriptionOAuthCredentialLoader.HasSafeCredentialFileAncestors(authFilePath))
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                "The ChatGPT subscription OAuth credential path became unsafe before it could be updated.");
        }

        var directory = Path.GetDirectoryName(authFilePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (!SocAgentSubscriptionOAuthCredentialLoader.HasSafeCredentialFileAncestors(authFilePath))
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                "The ChatGPT subscription OAuth credential path became unsafe before it could be updated.");
        }

        JsonObject rootObject;
        if (File.Exists(authFilePath))
        {
            try
            {
                rootObject = JsonNode.Parse(File.ReadAllText(authFilePath)) as JsonObject ?? new JsonObject();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                throw new SocAgentSubscriptionOAuthConnectException(
                    "provider_error",
                    "The configured ChatGPT subscription OAuth auth file could not be updated safely. Reconnect after fixing server-side file access.",
                    ex);
            }
        }
        else
        {
            rootObject = new JsonObject();
        }

        var providers = rootObject["providers"] as JsonObject;
        if (providers is null)
        {
            providers = new JsonObject();
            rootObject["providers"] = providers;
        }

        var entry = new JsonObject
        {
            ["provider"] = "ChatGPT",
            ["auth_type"] = "subscription_oauth",
            ["token_type"] = token.TokenType,
            ["access_token"] = token.AccessToken,
            ["expires_at"] = token.ExpiresAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            ["audience"] = ResolveAudience(),
            ["issuer"] = ResolveIssuer(),
            ["scope"] = token.Scope,
            ["token_endpoint"] = tokenEndpoint.ToString(),
            ["entitlement_status"] = "not_checked",
            ["connected_at"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrWhiteSpace(token.RefreshToken))
        {
            entry["refresh_token"] = token.RefreshToken.Trim();
        }

        providers[providerKey] = entry;
        WriteAuthFileAtomically(
            authFilePath,
            rootObject,
            "The ChatGPT subscription OAuth auth file could not be updated atomically. No provider secrets were exposed to the browser.");
    }

    private static void WriteAuthFileAtomically(
        string authFilePath,
        JsonObject rootObject,
        string operatorSafeFailureMessage)
    {
        if (!SocAgentSubscriptionOAuthCredentialLoader.HasSafeCredentialFileAncestors(authFilePath))
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                operatorSafeFailureMessage);
        }

        var tempPath = Path.Combine(
            Path.GetDirectoryName(authFilePath) ?? Directory.GetCurrentDirectory(),
            $".{Path.GetFileName(authFilePath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(tempPath, rootObject.ToJsonString(JsonOptions));
            TryRestrictFileMode(tempPath);
            if (!SocAgentSubscriptionOAuthCredentialLoader.HasSafeCredentialFileAncestors(authFilePath))
            {
                throw new SocAgentSubscriptionOAuthConnectException(
                    "provider_error",
                    operatorSafeFailureMessage);
            }

            File.Move(tempPath, authFilePath, overwrite: true);
            TryRestrictFileMode(authFilePath);
        }
        catch (SocAgentSubscriptionOAuthConnectException)
        {
            TryDeleteTempFile(tempPath);
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDeleteTempFile(tempPath);
            throw new SocAgentSubscriptionOAuthConnectException(
                "provider_error",
                operatorSafeFailureMessage,
                ex);
        }
    }

    private OAuthCorrelationState? ReadAndClearCorrelationCookie(HttpContext context)
    {
        var cookieOptions = CreateCorrelationCookieOptions(context);
        context.Response.Cookies.Delete(CorrelationCookieName, cookieOptions);
        if (!context.Request.Cookies.TryGetValue(CorrelationCookieName, out var protectedValue)
            || string.IsNullOrWhiteSpace(protectedValue))
        {
            return null;
        }

        try
        {
            var json = protector.Unprotect(protectedValue);
            return JsonSerializer.Deserialize<OAuthCorrelationState>(json, JsonOptions);
        }
        catch (Exception ex) when (ex is JsonException or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static OAuthInitiator RequireInitiatingAdminSession(HttpContext context)
    {
        var operatorId = OperatorAuthentication.OperatorId(context.User);
        var sessionToken = context.User.FindFirst(OperatorAuthentication.SessionTokenClaim)?.Value;
        if (context.User.Identity?.IsAuthenticated != true
            || !string.Equals(OperatorAuthorization.Role(context.User), OperatorRoles.Admin, StringComparison.Ordinal)
            || !operatorId.HasValue
            || string.IsNullOrWhiteSpace(sessionToken)
            || sessionToken.Length > 512)
        {
            throw new SocAgentSubscriptionOAuthConnectException(
                "auth_required",
                "ChatGPT subscription OAuth connect requires an authenticated admin browser session.");
        }

        return new OAuthInitiator(operatorId.Value, sessionToken);
    }

    private async Task<bool> IsValidInitiatingAdminSessionAsync(
        HttpContext context,
        OAuthCorrelationState correlation,
        CancellationToken cancellationToken)
    {
        if (correlation.InitiatorOperatorId == Guid.Empty
            || string.IsNullOrWhiteSpace(correlation.InitiatorSessionToken)
            || correlation.InitiatorSessionToken.Length > 512)
        {
            return false;
        }

        OperatorSession? session;
        try
        {
            session = await operatorSessions.ValidateAsync(correlation.InitiatorSessionToken, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("The initiating admin session could not be validated during the ChatGPT subscription OAuth callback.");
            return false;
        }

        if (session is null
            || session.Operator.OperatorId != correlation.InitiatorOperatorId
            || !string.Equals(session.Operator.Role, OperatorRoles.Admin, StringComparison.Ordinal))
        {
            return false;
        }

        // The operator cookie is SameSite=Strict, so an official cross-site OAuth callback may
        // arrive without it. When a principal is present, require it to be the exact initiating
        // browser session as an additional defense against account switching mid-flow.
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return true;
        }

        var currentOperatorId = OperatorAuthentication.OperatorId(context.User);
        var currentSessionToken = context.User.FindFirst(OperatorAuthentication.SessionTokenClaim)?.Value;
        return currentOperatorId == correlation.InitiatorOperatorId
            && !string.IsNullOrWhiteSpace(currentSessionToken)
            && FixedTimeEquals(correlation.InitiatorSessionToken, currentSessionToken);
    }

    private CookieOptions CreateCorrelationCookieOptions(HttpContext context)
    {
        return new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = TimeSpan.FromMinutes(Math.Clamp(options.SubscriptionStateLifetimeMinutes, 1, 60)),
            Path = "/soc-agent/oauth"
        };
    }

    private Uri? ResolveAuthorizationUrl()
    {
        var candidate = FirstConfigured(
            options.SubscriptionAuthorizationUrl,
            configuration["SocAgent:SubscriptionAuthorizationUrl"],
            configuration["SocAgent:ChatGptSubscriptionAuthorizationUrl"]);
        return IsAllowedAuthorizationEndpoint(candidate) ? new Uri(candidate!.Trim()) : null;
    }

    private Uri? ResolveTokenEndpoint()
    {
        var candidate = FirstConfigured(
            options.SubscriptionTokenEndpoint,
            configuration["SocAgent:SubscriptionTokenEndpoint"],
            configuration["SocAgent:ChatGptSubscriptionTokenEndpoint"]);
        return IsAllowedTokenEndpoint(candidate) ? new Uri(candidate!.Trim()) : null;
    }

    private string? ResolveAuthFilePath()
    {
        return FirstConfigured(
            options.SubscriptionAuthFilePath,
            configuration["SocAgent:SubscriptionAuthFilePath"],
            configuration["SocAgent:ChatGptSubscriptionAuthFilePath"],
            configuration["CHATGPT_SUBSCRIPTION_AUTH_FILE"],
            configuration["CHATGPT_AUTH_FILE"]);
    }

    private string ResolveProviderKey()
    {
        return FirstConfigured(
            options.SubscriptionAuthFileProviderKey,
            configuration["SocAgent:SubscriptionAuthFileProviderKey"],
            configuration["SocAgent:ChatGptSubscriptionAuthFileProviderKey"],
            configuration["CHATGPT_SUBSCRIPTION_AUTH_FILE_PROVIDER_KEY"]) ?? "chatgpt";
    }

    private string? ResolveClientId()
    {
        return FirstConfigured(
            options.SubscriptionClientId,
            configuration["SocAgent:SubscriptionClientId"],
            configuration["SocAgent:ChatGptSubscriptionClientId"],
            configuration["CHATGPT_SUBSCRIPTION_CLIENT_ID"]);
    }

    private string? ResolveClientSecret()
    {
        return FirstConfigured(
            options.SubscriptionClientSecret,
            configuration["SocAgent:SubscriptionClientSecret"],
            configuration["SocAgent:ChatGptSubscriptionClientSecret"],
            configuration["CHATGPT_SUBSCRIPTION_CLIENT_SECRET"]);
    }

    private string ResolveScopes()
    {
        return FirstConfigured(
            options.SubscriptionRequiredScopes,
            configuration["SocAgent:SubscriptionRequiredScopes"],
            configuration["SocAgent:ChatGptSubscriptionRequiredScopes"]) ?? "model.request";
    }

    private string ResolveAudience()
    {
        return FirstConfigured(
            options.SubscriptionOAuthAudience,
            configuration["SocAgent:SubscriptionOAuthAudience"],
            configuration["SocAgent:ChatGptSubscriptionOAuthAudience"]) ?? "https://api.openai.com/v1";
    }

    private string ResolveIssuer()
    {
        return FirstConfigured(
            options.SubscriptionIssuer,
            configuration["SocAgent:SubscriptionIssuer"],
            configuration["SocAgent:ChatGptSubscriptionIssuer"]) ?? "https://auth.openai.com/";
    }

    private string ResolveRedirectUri(HttpContext context)
    {
        var configured = FirstConfigured(
            options.SubscriptionRedirectUri,
            configuration["SocAgent:SubscriptionRedirectUri"],
            configuration["SocAgent:ChatGptSubscriptionRedirectUri"]);
        if (!string.IsNullOrWhiteSpace(configured)
            && Uri.TryCreate(configured, UriKind.Absolute, out var configuredUri)
            && (string.Equals(configuredUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || IsLocalHttpUri(configuredUri)))
        {
            return configuredUri.ToString();
        }

        var path = string.IsNullOrWhiteSpace(options.SubscriptionRedirectPath)
            ? "/soc-agent/oauth/callback"
            : options.SubscriptionRedirectPath.Trim();
        if (!path.StartsWith('/'))
        {
            path = "/" + path;
        }

        return $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{path}";
    }

    private bool TryResolveSafeAuthFilePath(out string fullPath, out string providerKey, out string errorMessage)
    {
        providerKey = ResolveProviderKey();
        fullPath = string.Empty;
        errorMessage = string.Empty;
        var configuredPath = ResolveAuthFilePath();
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            errorMessage = "ChatGPT subscription OAuth connect requires SocAgent:SubscriptionAuthFilePath to point at an ignored local file or operator-managed secret path.";
            return false;
        }

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
            errorMessage = "The configured ChatGPT subscription OAuth auth file path is invalid.";
            return false;
        }

        if (IsReservedCodexCredentialTarget(providerKey))
        {
            errorMessage = "ChatGPT subscription OAuth connect will not write to the reserved Codex-managed provider entry. Use the SIEM-managed ChatGPT login, or configure a dedicated ignored SocAgent:SubscriptionAuthFilePath for the advanced OAuth-file flow.";
            return false;
        }

        if (IsGlobalManagedCredentialPath(fullPath))
        {
            errorMessage = "ChatGPT subscription OAuth connect will not read or write global Codex or Pi credential state. Configure a dedicated ignored SocAgent:SubscriptionAuthFilePath for the advanced OAuth-file flow.";
            return false;
        }

        if (!SocAgentSubscriptionOAuthCredentialLoader.HasSafeCredentialFileAncestors(fullPath))
        {
            errorMessage = "ChatGPT subscription OAuth connect requires a credential path with no linked or reparse-point directory ancestors.";
            return false;
        }

        if (File.Exists(fullPath))
        {
            try
            {
                var fileInfo = new FileInfo(fullPath);
                fileInfo.Refresh();
                if (fileInfo.LinkTarget is not null
                    || (fileInfo.Attributes & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0)
                {
                    errorMessage = "ChatGPT subscription OAuth connect requires a regular, non-linked dedicated credential file.";
                    return false;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                errorMessage = "The configured ChatGPT subscription OAuth credential target could not be validated safely.";
                return false;
            }
        }

        if (repoRoot is null || !IsSubPathOf(fullPath, repoRoot))
        {
            return true;
        }

        var relative = Path.GetRelativePath(repoRoot, fullPath).Replace(Path.DirectorySeparatorChar, '/');
        var isSafe = relative.StartsWith(".local/", StringComparison.OrdinalIgnoreCase)
            || relative.Contains("/.local/", StringComparison.OrdinalIgnoreCase)
            || IsIgnoredAuthFileName(Path.GetFileName(relative));
        if (!isSafe)
        {
            errorMessage = "The configured ChatGPT subscription OAuth auth file path is not an ignored/local auth-file path or operator-managed secret path.";
        }

        return isSafe;
    }

    private static bool IsAllowedAuthorizationEndpoint(string? endpoint)
    {
        return Uri.TryCreate(endpoint?.Trim(), UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && AllowedAuthorizationHosts.Contains(uri.Host)
            && HasExactOfficialEndpointComponents(uri)
            && (uri.AbsolutePath.Equals("/oauth/authorize", StringComparison.OrdinalIgnoreCase)
                || uri.AbsolutePath.Equals("/oauth2/authorize", StringComparison.OrdinalIgnoreCase)
                || uri.AbsolutePath.Equals("/v1/oauth/authorize", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsAllowedTokenEndpoint(string? endpoint)
    {
        return Uri.TryCreate(endpoint?.Trim(), UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && AllowedTokenHosts.Contains(uri.Host)
            && HasExactOfficialEndpointComponents(uri)
            && (uri.AbsolutePath.Equals("/oauth/token", StringComparison.OrdinalIgnoreCase)
                || uri.AbsolutePath.Equals("/oauth2/token", StringComparison.OrdinalIgnoreCase)
                || uri.AbsolutePath.Equals("/v1/oauth/token", StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasExactOfficialEndpointComponents(Uri uri)
    {
        return uri.IsDefaultPort
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment);
    }

    private static bool IsSubscriptionOAuth(string? authMode)
    {
        if (string.IsNullOrWhiteSpace(authMode))
        {
            return false;
        }

        var normalized = authMode.Trim().Replace('-', '_');
        return normalized.Equals("subscription_oauth", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("subscriptionoauth", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("chatgpt_subscription_oauth", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("chatgpt_oauth", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDedicatedSubscriptionEntry(JsonObject entry)
    {
        var credentialType = GetNodeString(entry, "auth_type", "authType", "credential_type", "credentialType", "type");
        var provider = GetNodeString(entry, "provider", "provider_name", "providerName", "name");
        if (string.IsNullOrWhiteSpace(credentialType) || string.IsNullOrWhiteSpace(provider))
        {
            return false;
        }

        var normalizedType = credentialType.Trim().Replace('-', '_');
        var isSubscriptionType = normalizedType.Equals("subscription_oauth", StringComparison.OrdinalIgnoreCase)
            || normalizedType.Equals("chatgpt_subscription_oauth", StringComparison.OrdinalIgnoreCase)
            || normalizedType.Equals("chatgpt_oauth", StringComparison.OrdinalIgnoreCase)
            || normalizedType.Equals("oauth_subscription", StringComparison.OrdinalIgnoreCase);
        var isChatGptProvider = provider.Equals("ChatGPT", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("OpenAI", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("OpenAI ChatGPT", StringComparison.OrdinalIgnoreCase);
        return isSubscriptionType && isChatGptProvider;
    }

    private static string? GetNodeString(JsonObject parent, params string[] names)
    {
        foreach (var property in parent)
        {
            if (!names.Any(name => property.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                || property.Value is not JsonValue value
                || !value.TryGetValue<string>(out var result))
            {
                continue;
            }

            return result?.Trim();
        }

        return null;
    }

    private static Task<SocAgentSubscriptionOAuthDisconnectResult> DisconnectResult(
        bool succeeded,
        bool removed,
        string status,
        string message)
    {
        return Task.FromResult(new SocAgentSubscriptionOAuthDisconnectResult(succeeded, removed, status, message));
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

    private static string CreateBase64UrlRandom(int bytes)
    {
        var buffer = RandomNumberGenerator.GetBytes(bytes);
        return WebEncoders.Base64UrlEncode(buffer);
    }

    private static bool FixedTimeEquals(string expected, string actual)
    {
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(expected),
            System.Text.Encoding.UTF8.GetBytes(actual));
    }

    private static string? SafeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return null;
        }

        return returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal)
            ? returnUrl
            : null;
    }

    private static bool TryGetExpiresAt(JsonElement parent, out DateTimeOffset expiresAt)
    {
        var raw = GetString(parent, "expires_at", "expiresAt", "expires_on", "expiresOn");
        if (!string.IsNullOrWhiteSpace(raw)
            && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out expiresAt))
        {
            return true;
        }

        expiresAt = default;
        return false;
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

        return value.ValueKind == JsonValueKind.String
            && int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number)
            ? number
            : null;
    }

    private static string GetScope(JsonElement parent)
    {
        if (!TryGetObjectProperty(parent, out var value, "scope", "scopes"))
        {
            return string.Empty;
        }

        if (value.ValueKind == JsonValueKind.String)
        {
            return string.Join(' ', value.GetString()?
                .Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase) ?? Array.Empty<string>());
        }

        if (value.ValueKind == JsonValueKind.Array)
        {
            return string.Join(' ', value.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
                .Select(item => item.GetString()!.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase));
        }

        return string.Empty;
    }

    private static bool HasRequiredScopes(string scope, IReadOnlyList<string> requiredScopes)
    {
        var available = new HashSet<string>(
            scope.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);
        return requiredScopes.Count == 0 || requiredScopes.All(available.Contains);
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

    private static bool IsReservedCodexCredentialTarget(string providerKey)
    {
        return providerKey.Equals("openai-codex", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsGlobalManagedCredentialPath(string path)
    {
        var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return !string.IsNullOrWhiteSpace(userHome)
            && (IsSubPathOf(path, Path.Combine(userHome, ".codex"))
                || IsSubPathOf(path, Path.Combine(userHome, ".pi")));
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

    private static bool IsLocalHttpUri(Uri uri)
    {
        return string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && (string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Host, "::1", StringComparison.OrdinalIgnoreCase));
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
            // Best effort only. The file path is still constrained to ignored/local or operator-managed paths.
        }
    }

    private static void TryDeleteTempFile(string tempPath)
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
            // Best effort cleanup only; do not expose paths or credentials in errors.
        }
    }

    private sealed record OAuthCorrelationState(
        string State,
        string CodeVerifier,
        string ReturnUrl,
        DateTimeOffset IssuedAt,
        string RedirectUri,
        Guid InitiatorOperatorId,
        string InitiatorSessionToken);

    private sealed record OAuthInitiator(Guid OperatorId, string SessionToken);

    private sealed record TokenExchangeResult(
        string AccessToken,
        string? RefreshToken,
        DateTimeOffset ExpiresAt,
        string Scope,
        string TokenType);
}
