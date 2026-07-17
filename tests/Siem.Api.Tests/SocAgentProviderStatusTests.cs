using Challenger.Siem.Api.SocAgent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentProviderStatusTests
{
    [Fact]
    public void LocalProviderStatusDoesNotRequireExternalConnection()
    {
        var service = CreateService(new SocAgentOptions { Provider = "Local", Model = "soc-agent-local-test" });

        var status = service.GetStatus();

        Assert.Equal("local", status.Status);
        Assert.Equal("Local", status.Provider);
        Assert.False(status.RequiresConnection);
        Assert.False(status.DataMayLeaveLocalSiem);
    }

    [Fact]
    public void LocalModelCatalogSuppressesReasoningEffortForEveryAllowedModel()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "Local",
            Model = "soc-agent-local-test",
            ReasoningEffort = "high",
            ReasoningEfforts = ["low", "high"],
            ModelOptions =
            [
                new SocAgentConfiguredModelOption
                {
                    Model = "soc-agent-local-alt",
                    DisplayName = "Local alternate",
                    ReasoningEfforts = ["medium"],
                    DefaultReasoningEffort = "medium"
                }
            ]
        });

        var status = service.GetStatus();

        Assert.Equal("soc-agent-local-test", status.Model);
        Assert.Null(status.ReasoningEffort);
        Assert.Equal(2, status.ModelOptions.Count);
        Assert.All(status.ModelOptions, option =>
        {
            Assert.Empty(option.ReasoningEfforts);
            Assert.Null(option.DefaultReasoningEffort);
        });
        Assert.Equal(
            new SocAgentExecutionSelection("soc-agent-local-alt", null),
            SocAgentModelCatalog.Resolve(status, "soc-agent-local-alt", null));
        var localEffortError = Assert.Throws<SocAgentSelectionException>(() => SocAgentModelCatalog.Resolve(status, "soc-agent-local-alt", "high"));
        Assert.Equal("reasoning_effort", localEffortError.Field);
    }

    [Fact]
    public void ExternalModelCatalogNormalizesAllowlistAndRejectsUnknownSelections()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "ApiKey",
            Model = "gpt-default",
            ReasoningEffort = "MEDIUM",
            ReasoningEfforts = ["medium", "LOW", "unsupported", "medium"],
            ModelOptions =
            [
                new SocAgentConfiguredModelOption
                {
                    Model = "gpt-selected",
                    DisplayName = "  GPT selected  ",
                    ReasoningEfforts = ["HIGH", "low", "unsupported", "high"],
                    DefaultReasoningEffort = "HIGH"
                },
                new SocAgentConfiguredModelOption
                {
                    Model = "bad model id",
                    ReasoningEfforts = ["low"]
                },
                new SocAgentConfiguredModelOption
                {
                    Model = "GPT-SELECTED",
                    ReasoningEfforts = ["minimal"]
                }
            ],
            ExternalCallsEnabled = true,
            OpenAiApiKey = "fake-openai-api-key-for-tests"
        });

        var status = service.GetStatus();

        Assert.Equal("gpt-default", status.Model);
        Assert.Equal("medium", status.ReasoningEffort);
        Assert.Equal(2, status.ModelOptions.Count);
        var defaultOption = Assert.Single(status.ModelOptions, option => option.Model == "gpt-default");
        Assert.Equal(["medium", "low"], defaultOption.ReasoningEfforts);
        Assert.Equal("medium", defaultOption.DefaultReasoningEffort);
        var selectedOption = Assert.Single(status.ModelOptions, option => option.Model == "gpt-selected");
        Assert.Equal("GPT selected", selectedOption.DisplayName);
        Assert.Equal(["high", "low"], selectedOption.ReasoningEfforts);
        Assert.Equal("high", selectedOption.DefaultReasoningEffort);

        Assert.Equal(
            new SocAgentExecutionSelection("gpt-selected", "high"),
            SocAgentModelCatalog.Resolve(status, "GPT-SELECTED", null));
        Assert.Equal(
            new SocAgentExecutionSelection("gpt-selected", "low"),
            SocAgentModelCatalog.Resolve(status, "gpt-selected", "LOW"));
        Assert.False(SocAgentModelCatalog.Supports(status, "not-allowlisted", "low"));
        Assert.False(SocAgentModelCatalog.Supports(status, "gpt-selected", "medium"));
        var modelError = Assert.Throws<SocAgentSelectionException>(() => SocAgentModelCatalog.Resolve(status, "not-allowlisted", "low"));
        Assert.Equal("model", modelError.Field);
        var effortError = Assert.Throws<SocAgentSelectionException>(() => SocAgentModelCatalog.Resolve(status, "gpt-selected", "medium"));
        Assert.Equal("reasoning_effort", effortError.Field);
    }

    [Fact]
    public void OpenAiProviderWithoutServerSideCredentialsRequiresOfficialSetup()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            ProviderDisplayName = "OpenAI ChatGPT",
            AuthMode = "ApiKey",
            ExternalCallsEnabled = true,
            ProviderSetupUrl = "https://platform.openai.com/api-keys"
        });

        var status = service.GetStatus();

        Assert.Equal("provider_not_configured", status.Status);
        Assert.Equal("OpenAI", status.Provider);
        Assert.Equal("api_key", status.AuthMode);
        Assert.True(status.RequiresConnection);
        Assert.Equal("https://platform.openai.com/api-keys", status.ConnectUrl);
    }

    [Fact]
    public void OpenAiProviderWithServerSideCredentialsReportsConnectedWithoutSecretMaterial()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            ProviderDisplayName = "OpenAI ChatGPT",
            AuthMode = "ApiKey",
            Model = "gpt-test",
            ExternalCallsEnabled = true,
            OpenAiApiKey = "fake-openai-api-key-for-tests"
        });

        var status = service.GetStatus();

        Assert.Equal("connected", status.Status);
        Assert.Equal("OpenAI", status.Provider);
        Assert.False(status.RequiresConnection);
        Assert.True(status.DataMayLeaveLocalSiem);
        Assert.DoesNotContain("fake-openai-api-key", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenAiProviderRejectsNonOfficialApiEndpoint()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "ApiKey",
            ExternalCallsEnabled = true,
            OpenAiApiKey = "fake-openai-api-key-for-tests",
            OpenAiBaseUrl = "https://example.invalid/v1"
        });

        var status = service.GetStatus();

        Assert.Equal("provider_error", status.Status);
        Assert.True(status.RequiresConnection);
        Assert.Contains("official", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenAiProviderWithZeroBudgetReportsBudgetLimited()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "ApiKey",
            ExternalCallsEnabled = true,
            OpenAiApiKey = "fake-openai-api-key-for-tests",
            DailyBudgetUsd = 0m
        });

        var status = service.GetStatus();

        Assert.Equal("budget_limited", status.Status);
        Assert.False(status.RequiresConnection);
        Assert.Contains("budget", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnsafeProviderSetupUrlFallsBackToOfficialSetupUrl()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "ApiKey",
            ExternalCallsEnabled = false,
            ProviderSetupUrl = "https://example.invalid/collect-token"
        });

        var status = service.GetStatus();

        Assert.Equal("provider_not_configured", status.Status);
        Assert.Equal("https://platform.openai.com/api-keys", status.ConnectUrl);
    }

    [Fact]
    public void DelegatedProviderWithoutAuthorizationUrlFailsClosedWithAdminInstructions()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "Delegated",
            ExternalCallsEnabled = true
        });

        var status = service.GetStatus();

        Assert.Equal("auth_required", status.Status);
        Assert.True(status.RequiresConnection);
        Assert.Contains("official", status.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("do not paste ChatGPT passwords", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DelegatedProviderRejectsAuthorizationUrlOutsideOfficialAllowlist()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "Delegated",
            ExternalCallsEnabled = true,
            AuthorizationUrl = "https://example.invalid/oauth/authorize"
        });

        var status = service.GetStatus();

        Assert.Equal("provider_error", status.Status);
        Assert.True(status.RequiresConnection);
        Assert.Contains("allowlist", status.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("https://platform.openai.com/api-keys", status.ConnectUrl);
    }

    [Fact]
    public void DelegatedAuthFileWithSyntheticBearerReportsConnectedWithoutSecrets()
    {
        using var authFile = SyntheticAuthFile.Create(ValidAuthJson("synthetic-delegated-access-token", DateTimeOffset.UtcNow.AddHours(2)));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            ProviderDisplayName = "OpenAI delegated",
            AuthMode = "DelegatedFile",
            Model = "gpt-test",
            ExternalCallsEnabled = true,
            AuthFilePath = authFile.FilePath,
            AuthFileProviderKey = "openai"
        });

        var status = service.GetStatus();

        Assert.Equal("connected", status.Status);
        Assert.Equal("delegated_file", status.AuthMode);
        Assert.Equal("configured delegated auth file", status.CredentialSource);
        Assert.Equal("not_configured", status.RefreshStatus);
        Assert.False(status.RequiresConnection);
        Assert.True(status.DataMayLeaveLocalSiem);
        Assert.NotNull(status.ExpiresAt);
        Assert.DoesNotContain("synthetic-delegated-access-token", status.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(authFile.FilePath, status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SubscriptionOAuthWithSyntheticBundleReportsConnectedWithoutSecrets()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-access-token",
            DateTimeOffset.UtcNow.AddHours(2),
            refreshToken: "synthetic-subscription-refresh-token",
            accountId: "acct_synthetic_private"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            Model = "gpt-test",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            SubscriptionAuthFileProviderKey = "chatgpt"
        });

        var status = service.GetStatus();

        Assert.Equal("connected", status.Status);
        Assert.Equal("ChatGPT", status.Provider);
        Assert.Equal("subscription_oauth", status.AuthMode);
        Assert.Equal("chatgpt_subscription_oauth", status.ProviderPath);
        Assert.Equal("subscription_oauth", status.AuthFileMode);
        Assert.Equal("primary", status.SetupPriority);
        Assert.Equal("model_scope_present", status.ScopeStatus);
        Assert.Equal("available", status.EntitlementStatus);
        Assert.Equal("available", status.RefreshStatus);
        Assert.Equal("configured ChatGPT subscription OAuth file", status.CredentialSource);
        Assert.False(status.RequiresConnection);
        Assert.True(status.DataMayLeaveLocalSiem);
        Assert.DoesNotContain("synthetic-subscription-access-token", status.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-subscription-refresh-token", status.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("acct_synthetic_private", status.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(authFile.FilePath, status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CodexAppServerConnectedReportsManagedStatusWithoutSecretsOrPaths()
    {
        const string syntheticSecret = "synthetic-codex-access-token";
        const string syntheticPath = "/private/synthetic/codex/auth.json";
        var appServer = new FakeCodexAppServerClient(
            new SocAgentCodexAccountStatus(
                IsAvailable: true,
                IsConnected: true,
                State: "connected",
                PlanType: "plus",
                OperatorMessage: "ChatGPT is connected through the SIEM-managed OpenAI Codex login."),
            syntheticSecret,
            syntheticPath);
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "CodexAppServer",
            Model = "gpt-test",
            ExternalCallsEnabled = true
        }, appServer, new SocAgentCodexAppServerOptions { Enabled = true });

        var status = service.GetStatus();

        Assert.Equal("connected", status.Status);
        Assert.Equal("codex_app_server", status.AuthMode);
        Assert.Equal("codex_app_server", status.ProviderPath);
        Assert.Null(status.AuthFileMode);
        Assert.Equal("OpenAI Codex managed", status.CredentialSource);
        Assert.Equal("Codex managed", status.RefreshStatus);
        Assert.Equal("primary:codex_app_server", status.SetupPriority);
        Assert.Equal("plus", status.EntitlementStatus);
        Assert.False(status.RequiresConnection);
        Assert.True(status.DataMayLeaveLocalSiem);
        Assert.DoesNotContain(syntheticSecret, status.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(syntheticPath, status.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("Pi auth", status.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pi_auth_json", status.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://chatgpt.com:444/backend-api/codex/responses")]
    [InlineData("https://operator@chatgpt.com/backend-api/codex/responses")]
    [InlineData("https://chatgpt.com/backend-api/codex/responses?route=other")]
    [InlineData("https://chatgpt.com/backend-api/codex/responses#fragment")]
    [InlineData("https://chatgpt.com/backend-api/codex/responses/")]
    public void CodexAppServerStatusRejectsEveryEndpointRejectedByInvocation(string configuredUrl)
    {
        var appServer = new FakeCodexAppServerClient(
            new SocAgentCodexAccountStatus(
                IsAvailable: true,
                IsConnected: true,
                State: "connected",
                PlanType: "plus",
                OperatorMessage: "ChatGPT is connected."),
            "synthetic-secret-that-must-not-render",
            "/synthetic/path/that/must/not/render");
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "CodexAppServer",
            Model = "gpt-test",
            ExternalCallsEnabled = true,
            ChatGptCodexResponsesUrl = configuredUrl
        }, appServer, new SocAgentCodexAppServerOptions { Enabled = true });

        var status = service.GetStatus();

        Assert.Equal("provider_error", status.Status);
        Assert.Equal("codex_app_server", status.AuthMode);
        Assert.Equal("codex_app_server", status.ProviderPath);
        Assert.True(status.RequiresConnection);
        Assert.Contains("https://chatgpt.com/backend-api/codex/responses", status.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(configuredUrl, status.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, "auth_required", "Log in to ChatGPT")]
    [InlineData(false, "provider_error", "Review ChatGPT login")]
    public void CodexAppServerAuthRequiredOrUnavailableReportsSafeAction(
        bool isAvailable,
        string expectedStatus,
        string expectedConnectLabel)
    {
        const string syntheticSecret = "synthetic-codex-refresh-token";
        const string syntheticPath = "/private/synthetic/codex/auth.json";
        var appServer = new FakeCodexAppServerClient(
            new SocAgentCodexAccountStatus(
                IsAvailable: isAvailable,
                IsConnected: false,
                State: isAvailable ? "auth_required" : "unavailable",
                PlanType: null,
                OperatorMessage: isAvailable
                    ? "ChatGPT login is required."
                    : "The OpenAI Codex login service is unavailable."),
            syntheticSecret,
            syntheticPath);
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "CodexAppServer",
            Model = "gpt-test",
            ExternalCallsEnabled = true
        }, appServer, new SocAgentCodexAppServerOptions { Enabled = true });

        var status = service.GetStatus();

        Assert.Equal(expectedStatus, status.Status);
        Assert.Equal("codex_app_server", status.AuthMode);
        Assert.Equal("codex_app_server", status.ProviderPath);
        Assert.Equal("OpenAI Codex managed", status.CredentialSource);
        Assert.Equal("Codex managed", status.RefreshStatus);
        Assert.True(status.RequiresConnection);
        Assert.Equal("/soc-agent?manage_login=true", status.ConnectUrl);
        Assert.Equal(expectedConnectLabel, status.ConnectLabel);
        Assert.DoesNotContain(syntheticSecret, status.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(syntheticPath, status.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("Pi auth", status.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pi_auth_json", status.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SubscriptionOAuthMissingModelScopeFailsClosed()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-access-token",
            DateTimeOffset.UtcNow.AddHours(2),
            scopes: "openid profile offline_access"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("scope_missing", status.Status);
        Assert.Equal("model_scope_missing", status.ScopeStatus);
        Assert.True(status.RequiresConnection);
        Assert.DoesNotContain("synthetic-subscription-access-token", status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SubscriptionOAuthUnsupportedAudienceFailsClosed()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-access-token",
            DateTimeOffset.UtcNow.AddHours(2),
            audience: "https://chatgpt.com"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("unsupported_subscription_oauth", status.Status);
        Assert.Contains("official OpenAI API audience", status.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(status.RequiresConnection);
    }

    [Fact]
    public void SubscriptionOAuthPlanLimitedFailsClosedWithoutConnectionPrompt()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-access-token",
            DateTimeOffset.UtcNow.AddHours(2),
            entitlementStatus: "plan_limited"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("plan_limited", status.Status);
        Assert.Equal("plan_limited", status.EntitlementStatus);
        Assert.False(status.RequiresConnection);
        Assert.DoesNotContain("synthetic-subscription-access-token", status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SubscriptionOAuthMissingCredentialWithInteractiveConnectReportsLocalConnectAction()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionConnectEnabled = true,
            SubscriptionAuthFilePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "auth.json")
        });

        var status = service.GetStatus();

        Assert.Equal("auth_required", status.Status);
        Assert.Equal("subscription_oauth", status.AuthMode);
        Assert.Equal("/soc-agent/oauth/start", status.ConnectUrl);
        Assert.Equal("Connect ChatGPT subscription OAuth", status.ConnectLabel);
        Assert.True(status.RequiresConnection);
    }

    [Fact]
    public void SubscriptionOAuthUnsupportedEntitlementFailsClosed()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-access-token",
            DateTimeOffset.UtcNow.AddHours(2),
            entitlementStatus: "unsupported"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("unsupported_subscription_oauth", status.Status);
        Assert.Equal("unsupported", status.EntitlementStatus);
        Assert.True(status.RequiresConnection);
        Assert.DoesNotContain("synthetic-subscription-access-token", status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SubscriptionOAuthNearExpiryWithRefreshTokenReportsRefreshRequired()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-access-token",
            DateTimeOffset.UtcNow.AddMinutes(1),
            refreshToken: "synthetic-subscription-refresh-token"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            AuthFileExpirySkewSeconds = 300
        });

        var status = service.GetStatus();

        Assert.Equal("connected", status.Status);
        Assert.Equal("refresh_required", status.RefreshStatus);
        Assert.False(status.RequiresConnection);
        Assert.DoesNotContain("synthetic-subscription-refresh-token", status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DelegatedAuthFileMissingPathFailsClosedWithAuthRequired()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "DelegatedFile",
            ExternalCallsEnabled = true,
            AuthFilePath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"), "auth.json")
        });

        var status = service.GetStatus();

        Assert.Equal("auth_required", status.Status);
        Assert.Equal("delegated_file", status.AuthMode);
        Assert.True(status.RequiresConnection);
        Assert.DoesNotContain(status.ConnectUrl ?? string.Empty, status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DelegatedAuthFileInvalidJsonFailsClosedWithoutRawContent()
    {
        using var authFile = SyntheticAuthFile.Create("{ not-json: synthetic-secret-placeholder }");
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "DelegatedFile",
            ExternalCallsEnabled = true,
            AuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("auth_required", status.Status);
        Assert.Contains("valid JSON", status.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("synthetic-secret-placeholder", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DelegatedAuthFileExpiredRefreshMaterialReportsRefreshFailed()
    {
        using var authFile = SyntheticAuthFile.Create(ValidAuthJson("synthetic-expired-access-token", DateTimeOffset.UtcNow.AddMinutes(-10), refreshToken: "synthetic-refresh-placeholder"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "DelegatedFile",
            ExternalCallsEnabled = true,
            AuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("refresh_failed", status.Status);
        Assert.Equal("not_supported", status.RefreshStatus);
        Assert.True(status.RequiresConnection);
        Assert.DoesNotContain("synthetic-refresh-placeholder", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DelegatedAuthFileUnsupportedAudienceFailsClosed()
    {
        using var authFile = SyntheticAuthFile.Create(ValidAuthJson("synthetic-access-token", DateTimeOffset.UtcNow.AddHours(2), audience: "https://example.invalid"));
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "DelegatedFile",
            ExternalCallsEnabled = true,
            AuthFilePath = authFile.FilePath
        });

        var status = service.GetStatus();

        Assert.Equal("unsupported_delegated_auth", status.Status);
        Assert.Contains("official OpenAI API audience", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DelegatedAuthFilePathInsideRepositoryMustBeIgnoredAuthFileNameOrLocalPath()
    {
        var service = CreateService(new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "DelegatedFile",
            ExternalCallsEnabled = true,
            AuthFilePath = RepositoryFile("server", "Siem.Api", "appsettings.json")
        });

        var status = service.GetStatus();

        Assert.Equal("provider_error", status.Status);
        Assert.Contains("ignored/local", status.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string RepositoryFile(params string[] parts)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln"))) current = current.Parent;
        return Path.Combine(new[] { current?.FullName ?? throw new InvalidOperationException("Repository root not found.") }.Concat(parts).ToArray());
    }

    private static string ValidAuthJson(
        string accessToken,
        DateTimeOffset expiresAt,
        string audience = "https://api.openai.com/v1",
        string? refreshToken = null)
    {
        var refreshLine = refreshToken is null ? string.Empty : $",\n        \"refresh_token\": \"{refreshToken}\"";
        return $$"""
        {
          "providers": {
            "openai": {
              "provider": "OpenAI",
              "auth_type": "delegated_bearer",
              "token_type": "Bearer",
              "access_token": "{{accessToken}}",
              "expires_at": "{{expiresAt:O}}",
              "audience": "{{audience}}",
              "issuer": "https://auth.openai.com/"{{refreshLine}}
            }
          }
        }
        """;
    }

    private static string ValidSubscriptionAuthJson(
        string accessToken,
        DateTimeOffset expiresAt,
        string audience = "https://api.openai.com/v1",
        string scopes = "openid profile offline_access model.request",
        string entitlementStatus = "available",
        string? refreshToken = null,
        string? accountId = null)
    {
        var refreshLine = refreshToken is null ? string.Empty : $",\n        \"refresh_token\": \"{refreshToken}\"";
        var accountLine = accountId is null ? string.Empty : $",\n        \"account\": {{ \"id\": \"{accountId}\", \"email\": \"synthetic@example.invalid\" }}";
        return $$"""
        {
          "providers": {
            "chatgpt": {
              "provider": "ChatGPT",
              "auth_type": "subscription_oauth",
              "token_type": "Bearer",
              "access_token": "{{accessToken}}",
              "expires_at": "{{expiresAt:O}}",
              "audience": "{{audience}}",
              "issuer": "https://auth.openai.com/",
              "scope": "{{scopes}}",
              "token_endpoint": "https://auth.openai.com/oauth/token",
              "entitlement_status": "{{entitlementStatus}}"{{refreshLine}}{{accountLine}}
            }
          }
        }
        """;
    }

    private static SocAgentProviderStatusService CreateService(
        SocAgentOptions options,
        ISocAgentCodexAppServerClient? codexAppServer = null,
        SocAgentCodexAppServerOptions? codexOptions = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        return new SocAgentProviderStatusService(
            Options.Create(options),
            configuration,
            codexAppServer,
            codexOptions is null ? null : Options.Create(codexOptions));
    }

    private sealed class FakeCodexAppServerClient(
        SocAgentCodexAccountStatus accountStatus,
        string syntheticSecret,
        string syntheticCredentialPath) : ISocAgentCodexAppServerClient
    {
        private readonly string syntheticSecret = syntheticSecret;
        private readonly string syntheticCredentialPath = syntheticCredentialPath;

        public SocAgentCodexAccountStatus GetAccountStatus() => accountStatus;

        public SocAgentCodexLoginStatus GetLoginStatus() => new(
            accountStatus.IsAvailable,
            false,
            accountStatus.State,
            null,
            null,
            accountStatus.OperatorMessage);

        public Task<SocAgentCodexLoginStartResult> StartDeviceLoginAsync(CancellationToken cancellationToken)
        {
            _ = syntheticSecret;
            _ = syntheticCredentialPath;
            return Task.FromResult(new SocAgentCodexLoginStartResult(false, GetLoginStatus()));
        }

        public Task<SocAgentCodexLoginCancelResult> CancelDeviceLoginAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new SocAgentCodexLoginCancelResult(false, GetLoginStatus()));
        }
    }

    private sealed class SyntheticAuthFile : IDisposable
    {
        private readonly string directory;

        private SyntheticAuthFile(string directory, string filePath)
        {
            this.directory = directory;
            FilePath = filePath;
        }

        public string FilePath { get; }

        public static SyntheticAuthFile Create(string content)
        {
            var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "challenger-siem-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var filePath = System.IO.Path.Combine(directory, "auth.json");
            File.WriteAllText(filePath, content);
            return new SyntheticAuthFile(directory, filePath);
        }

        public void Dispose()
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
