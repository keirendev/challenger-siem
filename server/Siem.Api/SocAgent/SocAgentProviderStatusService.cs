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
        var displayName = string.IsNullOrWhiteSpace(current.ProviderDisplayName)
            ? provider
            : current.ProviderDisplayName.Trim();

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
                displayName: string.IsNullOrWhiteSpace(current.ProviderDisplayName) ? "Local soc-agent" : displayName,
                model: current.Model,
                authMode: "local",
                message: "Using the local deterministic soc-agent provider. Prompts and tool summaries stay inside the SIEM server.",
                requiresConnection: false,
                connectUrl: null,
                connectLabel: null,
                dataMayLeaveLocalSiem: false);
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
                dataMayLeaveLocalSiem: true);
        }

        if (!current.ExternalCallsEnabled)
        {
            return Create(
                status: "provider_not_configured",
                provider,
                displayName,
                model: current.Model,
                authMode,
                message: "An external ChatGPT/OpenAI provider is selected, but external model calls are disabled. Configure an official server-side provider mode before data leaves the local SIEM.",
                requiresConnection: true,
                connectUrl: SafeSetupUrl(current.ProviderSetupUrl),
                connectLabel: "Open official provider setup",
                dataMayLeaveLocalSiem: true);
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
                    connectUrl: SafeSetupUrl(current.ProviderSetupUrl),
                    connectLabel: "View official provider setup",
                    dataMayLeaveLocalSiem: true);
            }

            return Create(
                status: "auth_required",
                provider,
                displayName,
                model: current.Model,
                authMode,
                message: "Delegated provider authentication is required. The connect action uses only the configured official provider authorization URL.",
                requiresConnection: true,
                connectUrl: current.AuthorizationUrl,
                connectLabel: "Connect with official provider login",
                dataMayLeaveLocalSiem: true);
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
                connectUrl: SafeSetupUrl(current.ProviderSetupUrl),
                connectLabel: "Open official provider setup",
                dataMayLeaveLocalSiem: true);
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
            dataMayLeaveLocalSiem: true);
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
        bool dataMayLeaveLocalSiem)
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
            var value when value.Equals("chatgpt", StringComparison.OrdinalIgnoreCase) => "OpenAI",
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

        return authMode.Trim().ToLowerInvariant() switch
        {
            "oauth" => "delegated",
            "oidc" => "delegated",
            "pkce" => "delegated",
            "delegated" => "delegated",
            "api-key" => "api_key",
            "apikey" => "api_key",
            "api_key" => "api_key",
            var value => value
        };
    }

    private static bool IsSupportedExternalProvider(string provider)
    {
        return provider.Equals("OpenAI", StringComparison.OrdinalIgnoreCase);
    }

    private static string? SafeSetupUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return "https://platform.openai.com/api-keys";
        }

        return url.Trim();
    }
}
