namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentOptions
{
    public const string SectionName = "SocAgent";

    public bool Enabled { get; set; } = true;
    public string Provider { get; set; } = "Local";
    public string ProviderDisplayName { get; set; } = "Local soc-agent";
    public string AuthMode { get; set; } = "Local";
    public string Model { get; set; } = "soc-agent-local-v1";
    public string? ReasoningEffort { get; set; } = "medium";
    public string[] ReasoningEfforts { get; set; } = ["low", "medium", "high"];
    public List<SocAgentConfiguredModelOption> ModelOptions { get; set; } = [];
    public string LocalFallbackProvider { get; set; } = "LocalFallback";
    public string LocalFallbackModel { get; set; } = "soc-agent-local-v1";
    public bool FallbackToLocalWhenUnavailable { get; set; } = true;
    public bool ExternalCallsEnabled { get; set; }
    public string PreferredExternalAuthMode { get; set; } = "CodexAppServer";
    public string? ProviderSetupUrl { get; set; } = "https://platform.openai.com/api-keys";
    public string? SubscriptionProviderSetupUrl { get; set; } = "https://help.openai.com/";
    public string? AuthorizationUrl { get; set; }
    public string? AuthFilePath { get; set; }
    public string AuthFileProviderKey { get; set; } = "openai";
    public string? SubscriptionAuthFilePath { get; set; }
    public string SubscriptionAuthFileProviderKey { get; set; } = "chatgpt";
    public string SubscriptionRequiredScopes { get; set; } = "model.request";
    public string? SubscriptionTokenEndpoint { get; set; } = "https://auth.openai.com/oauth/token";
    public bool SubscriptionConnectEnabled { get; set; }
    public string? SubscriptionAuthorizationUrl { get; set; } = "https://auth.openai.com/oauth/authorize";
    public string SubscriptionRedirectPath { get; set; } = "/soc-agent/oauth/callback";
    public string? SubscriptionRedirectUri { get; set; }
    public string? SubscriptionClientId { get; set; }
    public string? SubscriptionClientSecret { get; set; }
    public string SubscriptionOAuthAudience { get; set; } = "https://api.openai.com/v1";
    public string SubscriptionIssuer { get; set; } = "https://auth.openai.com/";
    public int SubscriptionStateLifetimeMinutes { get; set; } = 10;
    public int AuthFileExpirySkewSeconds { get; set; } = 300;
    public string? OpenAiApiKey { get; set; }
    public string OpenAiBaseUrl { get; set; } = "https://api.openai.com/v1";
    public string OpenAiChatCompletionsPath { get; set; } = "chat/completions";
    public string ChatGptCodexResponsesUrl { get; set; } = "https://chatgpt.com/backend-api/codex/responses";
    public int MaxProviderOutputTokens { get; set; } = 1200;
    public int RequestTimeoutSeconds { get; set; } = 30;
    public int MaxRetries { get; set; } = 1;
    public int MaxToolCalls { get; set; } = 8;
    public int MaxPromptCharacters { get; set; } = 4000;
    public int MaxResultCharacters { get; set; } = 20000;
    public int MaxChatMessages { get; set; } = 50;
    public int MaxEvents { get; set; } = 5;
    public int MaxAgents { get; set; } = 10;
    public int MaxAlerts { get; set; } = 10;
    public bool RequireApprovalForMutations { get; set; } = true;
    public decimal? DailyBudgetUsd { get; set; }
}

public sealed class SocAgentConfiguredModelOption
{
    public string Model { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string[] ReasoningEfforts { get; set; } = [];
    public string? DefaultReasoningEffort { get; set; }
}
