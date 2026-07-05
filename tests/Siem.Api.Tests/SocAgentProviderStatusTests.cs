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

    private static SocAgentProviderStatusService CreateService(SocAgentOptions options)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        return new SocAgentProviderStatusService(Options.Create(options), configuration);
    }
}
