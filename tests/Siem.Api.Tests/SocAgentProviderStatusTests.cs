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
            AuthFilePath = "server/Siem.Api/appsettings.json"
        });

        var status = service.GetStatus();

        Assert.Equal("provider_error", status.Status);
        Assert.Contains("ignored/local", status.Message, StringComparison.OrdinalIgnoreCase);
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

    private static SocAgentProviderStatusService CreateService(SocAgentOptions options)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        return new SocAgentProviderStatusService(Options.Create(options), configuration);
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
