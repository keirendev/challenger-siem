using Challenger.Siem.Contracts.V1;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentProviderStatusService(
    IOptions<SocAgentOptions> options,
    IConfiguration configuration)
{
    public SocAgentProviderStatusResponse GetStatus()
    {
        var current = options.Value;
        var provider = NormalizeProvider(current.Provider);
        var authMode = NormalizeAuthMode(current.AuthMode, provider);
        var displayName = DisplayNameFor(current, provider, authMode);

        if (!current.Enabled)
        {
            return Create(
                status: "disabled",
                provider,
                displayName,
                model: current.Model,
                authMode,
                message: "soc-agent is disabled by configuration. Set SocAgent:Enabled=true to enable the local SIEM tool harness.",
                requiresConnection: false,
                connectUrl: null,
                connectLabel: null,
                dataMayLeaveLocalSiem: false);
        }

        if (string.Equals(provider, "Local", StringComparison.OrdinalIgnoreCase))
        {
            return Create(
                status: "local",
                provider: "Local",
                displayName: displayName,
                model: current.Model,
                authMode: "local",
                message: "Using the local deterministic soc-agent provider. Prompts and tool summaries stay inside the SIEM server.",
                requiresConnection: false,
                connectUrl: null,
                connectLabel: null,
                dataMayLeaveLocalSiem: false,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        if (!IsSupportedExternalProvider(provider))
        {
            return Create(
                status: "provider_error",
                provider,
                displayName,
                model: current.Model,
                authMode,
                message: "The configured external provider is not supported by this Challenger SIEM build. No external calls will be attempted.",
                requiresConnection: true,
                connectUrl: "/soc-agent",
                connectLabel: "Review provider configuration",
                dataMayLeaveLocalSiem: true,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        if (!current.ExternalCallsEnabled)
        {
            return Create(
                status: "provider_not_configured",
                provider,
                displayName,
                model: current.Model,
                authMode,
                message: "An external ChatGPT/OpenAI provider is selected, but external model calls are disabled. Configure ChatGPT subscription OAuth or another official server-side provider mode before data leaves the local SIEM.",
                requiresConnection: true,
                connectUrl: SafeSetupUrl(current, authMode),
                connectLabel: IsSubscriptionOAuth(authMode) ? "Review ChatGPT subscription OAuth setup" : "Open official provider setup",
                dataMayLeaveLocalSiem: true,
                providerPath: IsSubscriptionOAuth(authMode) ? "chatgpt_subscription_oauth" : null,
                authFileMode: IsSubscriptionOAuth(authMode) ? "subscription_oauth" : null,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        if (IsSubscriptionOAuth(authMode))
        {
            return CreateSubscriptionOAuthStatus(current, provider, displayName);
        }

        if (string.Equals(authMode, "delegated_file", StringComparison.OrdinalIgnoreCase))
        {
            return CreateDelegatedFileStatus(current, provider, displayName);
        }

        if (string.Equals(authMode, "delegated", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(current.AuthorizationUrl))
            {
                return Create(
                    status: "auth_required",
                    provider,
                    displayName,
                    model: current.Model,
                    authMode,
                    message: "Delegated ChatGPT/OpenAI authentication is selected, but no official authorization URL is configured. Ask an admin to configure a supported OAuth/OIDC/PKCE flow; do not paste ChatGPT passwords into the SIEM.",
                    requiresConnection: true,
                    connectUrl: SafeSetupUrl(current, authMode),
                    connectLabel: "View official provider setup",
                    dataMayLeaveLocalSiem: true,
                    setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
            }

            var authorizationUrl = SafeAuthorizationUrl(current.AuthorizationUrl);
            if (authorizationUrl is null)
            {
                return Create(
                    status: "provider_error",
                    provider,
                    displayName,
                    model: current.Model,
                    authMode,
                    message: "Delegated provider authentication is configured with a URL that is not on the official provider allowlist. No external calls will be attempted.",
                    requiresConnection: true,
                    connectUrl: SafeSetupUrl(current, authMode),
                    connectLabel: "View official provider setup",
                    dataMayLeaveLocalSiem: true,
                    setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
            }

            return Create(
                status: "auth_required",
                provider,
                displayName,
                model: current.Model,
                authMode,
                message: "Delegated provider authentication is required. The connect action uses only the configured official provider authorization URL.",
                requiresConnection: true,
                connectUrl: authorizationUrl,
                connectLabel: "Connect with official provider login",
                dataMayLeaveLocalSiem: true,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        if (!HasServerSideApiKey(current))
        {
            return Create(
                status: "provider_not_configured",
                provider,
                displayName,
                model: current.Model,
                authMode: "api_key",
                message: "Server-side OpenAI API credentials are not configured. Operators cannot enter provider passwords or tokens in the SIEM page; an admin must configure official provider credentials outside source control.",
                requiresConnection: true,
                connectUrl: SafeSetupUrl(current, "api_key"),
                connectLabel: "Open official provider setup",
                dataMayLeaveLocalSiem: true,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        if (!UsesOfficialOpenAiEndpoint(current))
        {
            return Create(
                status: "provider_error",
                provider,
                displayName,
                model: current.Model,
                authMode: "api_key",
                message: "OpenAI provider mode must use the official https://api.openai.com/v1/chat/completions endpoint. No external calls will be attempted with the configured endpoint.",
                requiresConnection: true,
                connectUrl: SafeSetupUrl(current, "api_key"),
                connectLabel: "View official provider setup",
                dataMayLeaveLocalSiem: true,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        if (current.DailyBudgetUsd.HasValue && current.DailyBudgetUsd.Value <= 0m)
        {
            return Create(
                status: "budget_limited",
                provider,
                displayName,
                model: current.Model,
                authMode: "api_key",
                message: "Server-side official provider credentials are configured, but the configured daily budget is exhausted or set to zero. External calls will not be attempted until the budget setting is raised.",
                requiresConnection: false,
                connectUrl: null,
                connectLabel: null,
                dataMayLeaveLocalSiem: true,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        return Create(
            status: "connected",
            provider,
            displayName,
            model: current.Model,
            authMode: "api_key",
            message: "Server-side official provider credentials are configured. Provider calls remain server-side and browser clients never receive provider tokens.",
            requiresConnection: false,
            connectUrl: null,
            connectLabel: null,
            dataMayLeaveLocalSiem: true,
            setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
    }

    private SocAgentProviderStatusResponse CreateSubscriptionOAuthStatus(SocAgentOptions current, string provider, string displayName)
    {
        if (!UsesOfficialOpenAiEndpoint(current))
        {
            return Create(
                status: "provider_error",
                provider,
                displayName,
                model: current.Model,
                authMode: "subscription_oauth",
                message: "ChatGPT subscription OAuth mode must use the official https://api.openai.com/v1/chat/completions model endpoint when model invocation is permitted. No external calls will be attempted with the configured endpoint.",
                requiresConnection: true,
                connectUrl: SafeSetupUrl(current, "subscription_oauth"),
                connectLabel: "View ChatGPT subscription OAuth setup",
                dataMayLeaveLocalSiem: true,
                providerPath: "chatgpt_subscription_oauth",
                authFileMode: "subscription_oauth",
                setupPriority: "primary");
        }

        var fileStatus = SocAgentSubscriptionOAuthCredentialLoader.Load(current, configuration, includeSecret: false);
        if (string.Equals(fileStatus.Status, "connected", StringComparison.OrdinalIgnoreCase)
            && current.DailyBudgetUsd.HasValue
            && current.DailyBudgetUsd.Value <= 0m)
        {
            return Create(
                status: "budget_limited",
                provider,
                displayName,
                model: current.Model,
                authMode: "subscription_oauth",
                message: "ChatGPT subscription OAuth credentials are configured, but the configured daily budget is exhausted or set to zero. External calls will not be attempted until the budget setting is raised.",
                requiresConnection: false,
                connectUrl: null,
                connectLabel: null,
                dataMayLeaveLocalSiem: true,
                credentialSource: fileStatus.CredentialSource,
                expiresAt: fileStatus.ExpiresAt,
                refreshStatus: fileStatus.RefreshStatus,
                providerPath: fileStatus.ProviderPath,
                authFileMode: fileStatus.AuthFileMode,
                setupPriority: fileStatus.SetupPriority,
                scopeStatus: fileStatus.ScopeStatus,
                entitlementStatus: fileStatus.EntitlementStatus);
        }

        return Create(
            status: fileStatus.Status,
            provider,
            displayName,
            model: current.Model,
            authMode: "subscription_oauth",
            message: fileStatus.OperatorMessage,
            requiresConnection: fileStatus.RequiresConnection,
            connectUrl: fileStatus.RequiresConnection ? SafeSetupUrl(current, "subscription_oauth") : null,
            connectLabel: fileStatus.ConnectLabel,
            dataMayLeaveLocalSiem: true,
            credentialSource: fileStatus.CredentialSource,
            expiresAt: fileStatus.ExpiresAt,
            refreshStatus: fileStatus.RefreshStatus,
            providerPath: fileStatus.ProviderPath,
            authFileMode: fileStatus.AuthFileMode,
            setupPriority: fileStatus.SetupPriority,
            scopeStatus: fileStatus.ScopeStatus,
            entitlementStatus: fileStatus.EntitlementStatus);
    }

    private SocAgentProviderStatusResponse CreateDelegatedFileStatus(SocAgentOptions current, string provider, string displayName)
    {
        if (!UsesOfficialOpenAiEndpoint(current))
        {
            return Create(
                status: "provider_error",
                provider,
                displayName,
                model: current.Model,
                authMode: "delegated_file",
                message: "Delegated auth-file mode must use the official https://api.openai.com/v1/chat/completions endpoint. No external calls will be attempted with the configured endpoint.",
                requiresConnection: true,
                connectUrl: SafeSetupUrl(current, "delegated_file"),
                connectLabel: "View official provider setup",
                dataMayLeaveLocalSiem: true,
                setupPriority: NormalizePreferredExternalAuthMode(current.PreferredExternalAuthMode));
        }

        var fileStatus = SocAgentDelegatedAuthFileLoader.Load(current, configuration, includeSecret: false);
        if (string.Equals(fileStatus.Status, "connected", StringComparison.OrdinalIgnoreCase)
            && current.DailyBudgetUsd.HasValue
            && current.DailyBudgetUsd.Value <= 0m)
        {
            return Create(
                status: "budget_limited",
                provider,
                displayName,
                model: current.Model,
                authMode: "delegated_file",
                message: "Server-side delegated auth-file credentials are configured, but the configured daily budget is exhausted or set to zero. External calls will not be attempted until the budget setting is raised.",
                requiresConnection: false,
                connectUrl: null,
                connectLabel: null,
                dataMayLeaveLocalSiem: true,
                credentialSource: fileStatus.CredentialSource,
                expiresAt: fileStatus.ExpiresAt,
                refreshStatus: fileStatus.RefreshStatus,
                providerPath: "delegated_file",
                authFileMode: "delegated_file",
                setupPriority: "advanced");
        }

        return Create(
            status: fileStatus.Status,
            provider,
            displayName,
            model: current.Model,
            authMode: "delegated_file",
            message: fileStatus.OperatorMessage,
            requiresConnection: fileStatus.RequiresConnection,
            connectUrl: fileStatus.RequiresConnection ? SafeSetupUrl(current, "delegated_file") : null,
            connectLabel: fileStatus.ConnectLabel,
            dataMayLeaveLocalSiem: true,
            credentialSource: fileStatus.CredentialSource,
            expiresAt: fileStatus.ExpiresAt,
            refreshStatus: fileStatus.RefreshStatus,
            providerPath: "delegated_file",
            authFileMode: "delegated_file",
            setupPriority: "advanced");
    }

    private bool HasServerSideApiKey(SocAgentOptions current)
    {
        return !string.IsNullOrWhiteSpace(current.OpenAiApiKey)
            || !string.IsNullOrWhiteSpace(configuration["SocAgent:OpenAiApiKey"])
            || !string.IsNullOrWhiteSpace(configuration["OpenAI:ApiKey"])
            || !string.IsNullOrWhiteSpace(configuration["OPENAI_API_KEY"]);
    }

    private static SocAgentProviderStatusResponse Create(
        string status,
        string provider,
        string displayName,
        string model,
        string authMode,
        string message,
        bool requiresConnection,
        string? connectUrl,
        string? connectLabel,
        bool dataMayLeaveLocalSiem,
        string? credentialSource = null,
        DateTimeOffset? expiresAt = null,
        string? refreshStatus = null,
        string? providerPath = null,
        string? authFileMode = null,
        string? setupPriority = null,
        string? scopeStatus = null,
        string? entitlementStatus = null)
    {
        return new SocAgentProviderStatusResponse
        {
            Status = status,
            Provider = provider,
            DisplayName = displayName,
            Model = model,
            AuthMode = authMode,
            Message = message,
            RequiresConnection = requiresConnection,
            ConnectUrl = connectUrl,
            ConnectLabel = connectLabel,
            DataMayLeaveLocalSiem = dataMayLeaveLocalSiem,
            CredentialSource = credentialSource,
            ExpiresAt = expiresAt,
            RefreshStatus = refreshStatus,
            ProviderPath = providerPath,
            AuthFileMode = authFileMode,
            SetupPriority = setupPriority,
            ScopeStatus = scopeStatus,
            EntitlementStatus = entitlementStatus,
            CheckedAt = DateTimeOffset.UtcNow
        };
    }

    private static string NormalizeProvider(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return "Local";
        }

        return provider.Trim() switch
        {
            var value when value.Equals("chatgpt", StringComparison.OrdinalIgnoreCase) => "ChatGPT",
            var value when value.Equals("openai", StringComparison.OrdinalIgnoreCase) => "OpenAI",
            var value when value.Equals("local", StringComparison.OrdinalIgnoreCase) => "Local",
            var value => value
        };
    }

    private static string NormalizeAuthMode(string? authMode, string provider)
    {
        if (string.Equals(provider, "Local", StringComparison.OrdinalIgnoreCase))
        {
            return "local";
        }

        if (string.IsNullOrWhiteSpace(authMode) || string.Equals(authMode, "local", StringComparison.OrdinalIgnoreCase))
        {
            return "api_key";
        }

        return authMode.Trim().ToLowerInvariant().Replace('-', '_') switch
        {
            "oauth" => "delegated",
            "oidc" => "delegated",
            "pkce" => "delegated",
            "delegated" => "delegated",
            "delegated_file" => "delegated_file",
            "delegatedfile" => "delegated_file",
            "auth_file" => "delegated_file",
            "subscriptionoauth" => "subscription_oauth",
            "subscription_oauth" => "subscription_oauth",
            "chatgpt_subscription_oauth" => "subscription_oauth",
            "chatgptoauth" => "subscription_oauth",
            "chatgpt_oauth" => "subscription_oauth",
            "api_key" => "api_key",
            "apikey" => "api_key",
            var value => value
        };
    }

    private static bool IsSupportedExternalProvider(string provider)
    {
        return provider.Equals("OpenAI", StringComparison.OrdinalIgnoreCase)
            || provider.Equals("ChatGPT", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSubscriptionOAuth(string authMode)
    {
        return string.Equals(authMode, "subscription_oauth", StringComparison.OrdinalIgnoreCase);
    }

    private static string DisplayNameFor(SocAgentOptions options, string provider, string authMode)
    {
        var configured = options.ProviderDisplayName?.Trim();
        if (!string.IsNullOrWhiteSpace(configured)
            && (!string.Equals(configured, "Local soc-agent", StringComparison.OrdinalIgnoreCase)
                || string.Equals(provider, "Local", StringComparison.OrdinalIgnoreCase)))
        {
            return configured;
        }

        if (string.Equals(provider, "Local", StringComparison.OrdinalIgnoreCase))
        {
            return "Local soc-agent";
        }

        return IsSubscriptionOAuth(authMode)
            ? "ChatGPT subscription OAuth"
            : "OpenAI ChatGPT";
    }

    private static string NormalizePreferredExternalAuthMode(string? preferred)
    {
        return NormalizeAuthMode(string.IsNullOrWhiteSpace(preferred) ? "SubscriptionOAuth" : preferred, "OpenAI") switch
        {
            "subscription_oauth" => "primary:subscription_oauth",
            "api_key" => "primary:api_key",
            "delegated_file" => "primary:delegated_file",
            var value => $"primary:{value}"
        };
    }

    private static bool UsesOfficialOpenAiEndpoint(SocAgentOptions options)
    {
        var baseUrl = string.IsNullOrWhiteSpace(options.OpenAiBaseUrl)
            ? "https://api.openai.com/v1"
            : options.OpenAiBaseUrl.Trim();
        var path = string.IsNullOrWhiteSpace(options.OpenAiChatCompletionsPath)
            ? "chat/completions"
            : options.OpenAiChatCompletionsPath.Trim().TrimStart('/');
        return Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Host, "api.openai.com", StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.AbsolutePath.TrimEnd('/'), "/v1", StringComparison.OrdinalIgnoreCase)
            && string.Equals(path, "chat/completions", StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeSetupUrl(SocAgentOptions options, string authMode)
    {
        if (IsSubscriptionOAuth(authMode))
        {
            return SafeOfficialProviderUrl(options.SubscriptionProviderSetupUrl, setupUrl: true) ?? "https://help.openai.com/";
        }

        return SafeOfficialProviderUrl(options.ProviderSetupUrl, setupUrl: true) ?? "https://platform.openai.com/api-keys";
    }

    private static string? SafeAuthorizationUrl(string? url)
    {
        return SafeOfficialProviderUrl(url, setupUrl: false);
    }

    private static string? SafeOfficialProviderUrl(string? url, bool setupUrl)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var allowedHosts = setupUrl
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "platform.openai.com",
                "help.openai.com",
                "openai.com",
                "chatgpt.com",
                "chat.openai.com"
            }
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "auth.openai.com",
                "login.openai.com",
                "platform.openai.com",
                "chatgpt.com",
                "chat.openai.com"
            };
        return allowedHosts.Contains(uri.Host) ? uri.ToString() : null;
    }
}
