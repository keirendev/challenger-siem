using System.Net;
using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentModelProviderTests
{
    [Fact]
    public async Task OpenAiProviderUsesOfficialEndpointAndRedactsReturnedSecrets()
    {
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            {
              "choices": [
                { "message": { "content": "Provider answer with Bearer abc123 and api_key:should-not-render" } }
              ]
            }
            """)
        }));
        var provider = CreateProvider(httpClient);

        var result = await provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse { Status = "connected", Provider = "OpenAI", Model = "gpt-test" },
            "bounded prompt",
            2000), CancellationToken.None);

        Assert.Equal("OpenAI", result.Provider);
        Assert.Equal("gpt-test", result.Model);
        Assert.Contains("Provider answer", result.Answer, StringComparison.Ordinal);
        Assert.Contains("Bearer <redacted>", result.Answer, StringComparison.Ordinal);
        Assert.Contains("api_key=<redacted>", result.Answer, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(new Uri("https://api.openai.com/v1/chat/completions"), RecordingHandler.LastRequestUri);
        Assert.Equal("Bearer", RecordingHandler.LastAuthorizationScheme);
        Assert.DoesNotContain("fake-openai-api-key-for-tests", RecordingHandler.LastRequestBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenAiProviderUsesDelegatedAuthFileBearerWithoutPuttingSecretInBody()
    {
        using var authFile = SyntheticAuthFile.Create(ValidAuthJson("synthetic-delegated-provider-token", DateTimeOffset.UtcNow.AddHours(2)));
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            {
              "choices": [
                { "message": { "content": "Delegated provider answer" } }
              ]
            }
            """)
        }));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "DelegatedFile",
            ExternalCallsEnabled = true,
            AuthFilePath = authFile.FilePath,
            AuthFileProviderKey = "openai"
        });

        var result = await provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse { Status = "connected", Provider = "OpenAI", Model = "gpt-test", AuthMode = "delegated_file" },
            "bounded prompt",
            2000), CancellationToken.None);

        Assert.Equal("Delegated provider answer", result.Answer);
        Assert.Equal("Bearer", RecordingHandler.LastAuthorizationScheme);
        Assert.Equal("synthetic-delegated-provider-token", RecordingHandler.LastAuthorizationParameter);
        Assert.DoesNotContain("synthetic-delegated-provider-token", RecordingHandler.LastRequestBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenAiProviderUsesPiOpenAiCodexAuthJsonAccessTokenWithoutRefreshOrBodyLeak()
    {
        using var authFile = SyntheticAuthFile.Create(PiOpenAiCodexAuthJson(
            "synthetic-pi-provider-token",
            "synthetic-pi-refresh-token",
            DateTimeOffset.UtcNow.AddMinutes(1)));
        SequencedHandler.Calls.Clear();
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            data: {"type":"response.output_text.delta","delta":"Pi auth provider answer with Bearer abc123"}
            data: {"type":"response.completed"}
            data: [DONE]

            """)
        }));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            SubscriptionAuthFileProviderKey = "openai-codex",
            AuthFileExpirySkewSeconds = 300
        });

        var result = await provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse
            {
                Status = "connected",
                Provider = "ChatGPT",
                Model = "gpt-test",
                AuthMode = "pi_auth_json",
                AuthFileMode = "pi_auth_json",
                ProviderPath = "pi_auth_json_openai_codex"
            },
            "bounded prompt",
            2000), CancellationToken.None);

        Assert.Equal("Pi auth provider answer with Bearer <redacted>", result.Answer);
        Assert.Single(SequencedHandler.Calls);
        Assert.Equal(new Uri("https://chatgpt.com/backend-api/codex/responses"), SequencedHandler.Calls[0].Uri);
        Assert.Equal("Bearer", SequencedHandler.Calls[0].AuthorizationScheme);
        Assert.Equal("synthetic-pi-provider-token", SequencedHandler.Calls[0].AuthorizationParameter);
        Assert.Contains("\"model\":\"gpt-test\"", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
        Assert.Contains("\"stream\":true", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-pi-provider-token", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-pi-refresh-token", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenAiProviderRefreshesSubscriptionOAuthCredentialBeforeModelCall()
    {
        SequencedHandler.Calls.Clear();
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-expiring-subscription-token",
            DateTimeOffset.UtcNow.AddMinutes(1),
            refreshToken: "synthetic-refresh-token"));
        using var httpClient = new HttpClient(new SequencedHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath.Equals("/oauth/token", StringComparison.OrdinalIgnoreCase) == true)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($$"""
                    {
                      "access_token": "synthetic-refreshed-subscription-token",
                      "refresh_token": "synthetic-next-refresh-token",
                      "token_type": "Bearer",
                      "expires_in": 3600,
                      "scope": "openid profile offline_access model.request"
                    }
                    """)
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                {
                  "choices": [
                    { "message": { "content": "Subscription OAuth provider answer" } }
                  ]
                }
                """)
            };
        }));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            AuthFileExpirySkewSeconds = 300
        });

        var result = await provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse { Status = "connected", Provider = "ChatGPT", Model = "gpt-test", AuthMode = "subscription_oauth" },
            "bounded prompt",
            2000), CancellationToken.None);

        Assert.Equal("Subscription OAuth provider answer", result.Answer);
        Assert.Equal(2, SequencedHandler.Calls.Count);
        Assert.Equal(new Uri("https://auth.openai.com/oauth/token"), SequencedHandler.Calls[0].Uri);
        Assert.Equal(new Uri("https://api.openai.com/v1/chat/completions"), SequencedHandler.Calls[1].Uri);
        Assert.Equal("Bearer", SequencedHandler.Calls[1].AuthorizationScheme);
        Assert.Equal("synthetic-refreshed-subscription-token", SequencedHandler.Calls[1].AuthorizationParameter);
        Assert.DoesNotContain("synthetic-refreshed-subscription-token", SequencedHandler.Calls[1].Body, StringComparison.Ordinal);
        Assert.Contains("synthetic-refreshed-subscription-token", File.ReadAllText(authFile.FilePath), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SubscriptionOAuthForbiddenProviderResponseMapsToScopeMissing()
    {
        using var authFile = SyntheticAuthFile.Create(ValidSubscriptionAuthJson(
            "synthetic-subscription-token",
            DateTimeOffset.UtcNow.AddHours(2)));
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("{\"error\":{\"message\":\"synthetic provider scope detail\"}}")
        }));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "SubscriptionOAuth",
            ExternalCallsEnabled = true,
            SubscriptionAuthFilePath = authFile.FilePath,
            MaxRetries = 0
        });

        var ex = await Assert.ThrowsAsync<SocAgentModelProviderException>(() => provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse { Status = "connected", Provider = "ChatGPT", Model = "gpt-test", AuthMode = "subscription_oauth" },
            "bounded prompt",
            2000), CancellationToken.None));

        Assert.Equal("scope_missing", ex.ErrorCode);
        Assert.DoesNotContain("synthetic provider scope detail", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OpenAiProviderMapsRateLimitToSafeErrorCode()
    {
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests)
        {
            Content = new StringContent("{\"error\":{\"message\":\"synthetic rate limit\"}}")
        }));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "ApiKey",
            ExternalCallsEnabled = true,
            OpenAiApiKey = "fake-openai-api-key-for-tests",
            MaxRetries = 0
        });

        var ex = await Assert.ThrowsAsync<SocAgentModelProviderException>(() => provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse { Status = "connected", Provider = "OpenAI", Model = "gpt-test" },
            "bounded prompt",
            2000), CancellationToken.None));

        Assert.Equal("rate_limited", ex.ErrorCode);
        Assert.DoesNotContain("synthetic rate limit", ex.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    private static string ValidAuthJson(string accessToken, DateTimeOffset expiresAt)
    {
        return $$"""
        {
          "providers": {
            "openai": {
              "provider": "OpenAI",
              "auth_type": "delegated_bearer",
              "token_type": "Bearer",
              "access_token": "{{accessToken}}",
              "expires_at": "{{expiresAt:O}}",
              "audience": "https://api.openai.com/v1",
              "issuer": "https://auth.openai.com/"
            }
          }
        }
        """;
    }

    private static string PiOpenAiCodexAuthJson(string accessToken, string refreshToken, DateTimeOffset expiresAt)
    {
        return $$"""
        {
          "openai-codex": {
            "type": "oauth",
            "access": "{{accessToken}}",
            "refresh": "{{refreshToken}}",
            "expires": {{expiresAt.ToUnixTimeMilliseconds()}}
          }
        }
        """;
    }

    private static string ValidSubscriptionAuthJson(string accessToken, DateTimeOffset expiresAt, string? refreshToken = null)
    {
        var refreshLine = refreshToken is null ? string.Empty : $",\n        \"refresh_token\": \"{refreshToken}\"";
        return $$"""
        {
          "providers": {
            "chatgpt": {
              "provider": "ChatGPT",
              "auth_type": "subscription_oauth",
              "token_type": "Bearer",
              "access_token": "{{accessToken}}",
              "expires_at": "{{expiresAt:O}}",
              "audience": "https://api.openai.com/v1",
              "issuer": "https://auth.openai.com/",
              "scope": "openid profile offline_access model.request",
              "token_endpoint": "https://auth.openai.com/oauth/token",
              "entitlement_status": "available"{{refreshLine}}
            }
          }
        }
        """;
    }

    private static OpenAiSocAgentModelProvider CreateProvider(HttpClient httpClient, SocAgentOptions? options = null)
    {
        options ??= new SocAgentOptions
        {
            Provider = "OpenAI",
            AuthMode = "ApiKey",
            ExternalCallsEnabled = true,
            OpenAiApiKey = "fake-openai-api-key-for-tests"
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();
        return new OpenAiSocAgentModelProvider(
            httpClient,
            Options.Create(options),
            configuration,
            NullLogger<OpenAiSocAgentModelProvider>.Instance);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        public static Uri? LastRequestUri { get; private set; }
        public static string? LastAuthorizationScheme { get; private set; }
        public static string? LastAuthorizationParameter { get; private set; }
        public static string LastRequestBody { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            LastAuthorizationScheme = request.Headers.Authorization?.Scheme;
            LastAuthorizationParameter = request.Headers.Authorization?.Parameter;
            LastRequestBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return responseFactory(request);
        }
    }

    private sealed class SequencedHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        public static List<RecordedCall> Calls { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            Calls.Add(new RecordedCall(request.RequestUri, request.Headers.Authorization?.Scheme, request.Headers.Authorization?.Parameter, body));
            return responseFactory(request);
        }
    }

    private sealed record RecordedCall(Uri? Uri, string? AuthorizationScheme, string? AuthorizationParameter, string Body);

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
