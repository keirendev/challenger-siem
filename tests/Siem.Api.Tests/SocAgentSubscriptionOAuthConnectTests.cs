using System.Net;
using Challenger.Siem.Api.SocAgent;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentSubscriptionOAuthConnectTests
{
    [Fact]
    public void CreateAuthorizationUriUsesOfficialEndpointPkceAndCorrelationCookie()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath);
        var context = CreateContext();

        var uri = service.CreateAuthorizationUri(context, "/soc-agent");
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);

        Assert.Equal("auth.openai.com", uri.Host);
        Assert.Equal("/oauth/authorize", uri.AbsolutePath);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("synthetic-client-id", query["client_id"]);
        Assert.Equal("http://127.0.0.1:5081/soc-agent/oauth/callback", query["redirect_uri"]);
        Assert.Contains("model.request", query["scope"].ToString(), StringComparison.Ordinal);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.False(string.IsNullOrWhiteSpace(query["code_challenge"]));
        Assert.False(string.IsNullOrWhiteSpace(query["state"]));
        Assert.Contains(".ChallengerSiem.SocAgentOAuth=", context.Response.Headers.SetCookie.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-client-secret", context.Response.Headers.SetCookie.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteAsyncExchangesCodeAndStoresMinimalServerSideCredentialFile()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(request =>
        {
            Assert.Equal(new Uri("https://auth.openai.com/oauth/token"), request.RequestUri);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                {
                  "access_token": "synthetic-connected-access-token",
                  "refresh_token": "synthetic-connected-refresh-token",
                  "token_type": "Bearer",
                  "expires_in": 3600,
                  "scope": "openid profile offline_access model.request",
                  "id_token": "synthetic-id-token-that-must-not-be-stored"
                }
                """)
            };
        }));
        var protector = new EphemeralDataProtectionProvider();
        var service = CreateService(httpClient, authFile.FilePath, protector);
        var startContext = CreateContext();
        var uri = service.CreateAuthorizationUri(startContext, "/soc-agent");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)["state"].ToString();
        var callbackContext = CreateContext($"/soc-agent/oauth/callback?code=synthetic-code&state={Uri.EscapeDataString(state)}");
        callbackContext.Request.Headers.Cookie = ExtractCookieHeader(startContext.Response.Headers.SetCookie.ToString());

        var result = await service.CompleteAsync(callbackContext, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal("connected", result.Status);
        var saved = File.ReadAllText(authFile.FilePath);
        Assert.Contains("synthetic-connected-access-token", saved, StringComparison.Ordinal);
        Assert.Contains("synthetic-connected-refresh-token", saved, StringComparison.Ordinal);
        Assert.Contains("subscription_oauth", saved, StringComparison.Ordinal);
        Assert.Contains("model.request", saved, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-id-token-that-must-not-be-stored", saved, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-client-secret", saved, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateAuthorizationUriRejectsPiAuthJsonWriteTarget()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionPiAuthFilePath = authFile.FilePath;
        });

        var ex = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() => service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));

        Assert.Equal("provider_error", ex.Status);
        Assert.Contains("Pi", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/login", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateAuthorizationUriRejectsNonOfficialAuthorizationEndpoint()
    {
        using var authFile = SyntheticAuthFile.Create();
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var service = CreateService(httpClient, authFile.FilePath, options =>
        {
            options.SubscriptionAuthorizationUrl = "https://example.invalid/oauth/authorize";
        });

        var ex = Assert.Throws<SocAgentSubscriptionOAuthConnectException>(() => service.CreateAuthorizationUri(CreateContext(), "/soc-agent"));

        Assert.Equal("provider_error", ex.Status);
        Assert.Contains("official authorization URL", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    private static SocAgentSubscriptionOAuthConnectService CreateService(
        HttpClient httpClient,
        string authFilePath,
        Action<SocAgentOptions>? configure = null)
    {
        return CreateService(httpClient, authFilePath, new EphemeralDataProtectionProvider(), configure);
    }

    private static SocAgentSubscriptionOAuthConnectService CreateService(
        HttpClient httpClient,
        string authFilePath,
        IDataProtectionProvider protector,
        Action<SocAgentOptions>? configure = null)
    {
        var options = new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionConnectEnabled = true,
            SubscriptionAuthFilePath = authFilePath,
            SubscriptionAuthFileProviderKey = "chatgpt",
            SubscriptionClientId = "synthetic-client-id",
            SubscriptionClientSecret = "synthetic-client-secret",
            SubscriptionAuthorizationUrl = "https://auth.openai.com/oauth/authorize",
            SubscriptionTokenEndpoint = "https://auth.openai.com/oauth/token",
            SubscriptionRequiredScopes = "model.request"
        };
        configure?.Invoke(options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        return new SocAgentSubscriptionOAuthConnectService(
            httpClient,
            Options.Create(options),
            configuration,
            protector,
            NullLogger<SocAgentSubscriptionOAuthConnectService>.Instance);
    }

    private static DefaultHttpContext CreateContext(string target = "/soc-agent")
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("127.0.0.1:5081");
        var parts = target.Split('?', 2);
        context.Request.Path = parts[0];
        if (parts.Length == 2)
        {
            context.Request.QueryString = new QueryString("?" + parts[1]);
        }

        context.Response.Body = new MemoryStream();
        return context;
    }

    private static string ExtractCookieHeader(string setCookie)
    {
        return setCookie.Split(';', 2)[0];
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(responseFactory(request));
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

        public static SyntheticAuthFile Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "challenger-siem-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            return new SyntheticAuthFile(directory, Path.Combine(directory, "auth.json"));
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
