using System.Net;
using System.Text.Json;
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
        using var requestBody = JsonDocument.Parse(RecordingHandler.LastRequestBody);
        Assert.Equal("gpt-test", requestBody.RootElement.GetProperty("model").GetString());
        Assert.Equal(0.2d, requestBody.RootElement.GetProperty("temperature").GetDouble());
        Assert.Equal(1200, requestBody.RootElement.GetProperty("max_tokens").GetInt32());
        Assert.False(requestBody.RootElement.TryGetProperty("reasoning_effort", out _));
        Assert.False(requestBody.RootElement.TryGetProperty("max_completion_tokens", out _));
        Assert.Null(result.ReasoningEffort);
    }

    [Fact]
    public async Task OpenAiChatCompletionsUsesSelectedModelAndTopLevelReasoningEffort()
    {
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            {
              "choices": [
                { "message": { "content": "Reasoned provider answer" } }
              ]
            }
            """)
        }));
        var provider = CreateProvider(httpClient);

        var result = await provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse { Status = "connected", Provider = "OpenAI", Model = "gpt-default" },
            "bounded prompt",
            2000,
            "gpt-selected",
            "high"), CancellationToken.None);

        Assert.Equal("gpt-selected", result.Model);
        Assert.Equal("high", result.ReasoningEffort);
        using var requestBody = JsonDocument.Parse(RecordingHandler.LastRequestBody);
        Assert.Equal("gpt-selected", requestBody.RootElement.GetProperty("model").GetString());
        Assert.Equal("high", requestBody.RootElement.GetProperty("reasoning_effort").GetString());
        Assert.Equal(1200, requestBody.RootElement.GetProperty("max_completion_tokens").GetInt32());
        Assert.False(requestBody.RootElement.TryGetProperty("temperature", out _));
        Assert.False(requestBody.RootElement.TryGetProperty("max_tokens", out _));
    }

    [Fact]
    public async Task OpenAiChatCompletionsRejectsOversizedJsonBeforeParsing()
    {
        const string privateTail = "synthetic-private-provider-tail";
        var oversizedAnswer = new string('a', (2 * 1024 * 1024) + 1) + privateTail;
        var responseBody = JsonSerializer.Serialize(new
        {
            choices = new[]
            {
                new { message = new { content = oversizedAnswer } }
            }
        });
        using var httpClient = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseBody)
        }));
        var provider = CreateProvider(httpClient);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(new SocAgentModelProviderRequest(
                new SocAgentProviderStatusResponse { Status = "connected", Provider = "OpenAI", Model = "gpt-test" },
                "bounded prompt",
                2000), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.Contains("safety limit", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(privateTail, exception.OperatorSafeMessage, StringComparison.Ordinal);
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
    public async Task OpenAiProviderUsesCodexCredentialBrokerForBoundedChatGptResponsesWithoutSecretLeak()
    {
        var credentialBroker = new FakeCodexCredentialBroker(
            "synthetic-codex-provider-token",
            "acct_synthetic_codex");
        SequencedHandler.Calls.Clear();
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
            data: {"type":"response.output_text.delta","delta":"Codex managed answer with Bearer abc123 and token=should-not-render"}
            data: {"type":"response.completed"}
            data: [DONE]

            """)
        }));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "CodexAppServer",
            ExternalCallsEnabled = true,
            AuthFileExpirySkewSeconds = 300
        }, credentialBroker, new SocAgentCodexAppServerOptions { Enabled = true });

        var result = await provider.CompleteAsync(new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse
            {
                Status = "connected",
                Provider = "ChatGPT",
                Model = "gpt-test",
                AuthMode = "codex_app_server",
                ProviderPath = "codex_app_server"
            },
            "bounded prompt",
            2000,
            "gpt-reasoning-test",
            "high"), CancellationToken.None);

        Assert.Equal("Codex managed answer with Bearer <redacted> and token=<redacted>", result.Answer);
        Assert.Equal("gpt-reasoning-test", result.Model);
        Assert.Equal("high", result.ReasoningEffort);
        Assert.Equal(1, credentialBroker.CallCount);
        Assert.Single(SequencedHandler.Calls);
        Assert.Equal(new Uri("https://chatgpt.com/backend-api/codex/responses"), SequencedHandler.Calls[0].Uri);
        Assert.Equal("Bearer", SequencedHandler.Calls[0].AuthorizationScheme);
        Assert.Equal("synthetic-codex-provider-token", SequencedHandler.Calls[0].AuthorizationParameter);
        Assert.Equal("acct_synthetic_codex", SequencedHandler.Calls[0].ChatGptAccountId);
        using var requestBody = JsonDocument.Parse(SequencedHandler.Calls[0].Body);
        Assert.Equal("gpt-reasoning-test", requestBody.RootElement.GetProperty("model").GetString());
        Assert.Equal("high", requestBody.RootElement.GetProperty("reasoning").GetProperty("effort").GetString());
        Assert.False(requestBody.RootElement.TryGetProperty("reasoning_effort", out _));
        Assert.False(requestBody.RootElement.TryGetProperty("max_output_tokens", out _));
        Assert.False(requestBody.RootElement.GetProperty("store").GetBoolean());
        Assert.Equal(0, requestBody.RootElement.GetProperty("tools").GetArrayLength());
        Assert.Equal("auto", requestBody.RootElement.GetProperty("tool_choice").GetString());
        Assert.False(requestBody.RootElement.GetProperty("parallel_tool_calls").GetBoolean());
        Assert.Equal("reasoning.encrypted_content", requestBody.RootElement.GetProperty("include")[0].GetString());
        Assert.Equal("challenger-siem-soc-agent", requestBody.RootElement.GetProperty("prompt_cache_key").GetString());
        Assert.Equal("low", requestBody.RootElement.GetProperty("text").GetProperty("verbosity").GetString());
        Assert.False(requestBody.RootElement.TryGetProperty("client_metadata", out _));
        Assert.Equal("bounded prompt", requestBody.RootElement
            .GetProperty("input")[0]
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString());
        Assert.Contains("\"stream\":true", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-codex-provider-token", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
        Assert.DoesNotContain("acct_synthetic_codex", SequencedHandler.Calls[0].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CodexResponsesOmitsReasoningWhenNoEffortIsSelected()
    {
        SequencedHandler.Calls.Clear();
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("data: {\"type\":\"response.output_text.delta\",\"delta\":\"Concise answer\"}\n"
                + "data: {\"type\":\"response.completed\"}\n")
        }));
        var provider = CreateCodexProvider(httpClient);

        var result = await provider.CompleteAsync(CodexRequest(), CancellationToken.None);

        Assert.Equal("Concise answer", result.Answer);
        Assert.Null(result.ReasoningEffort);
        Assert.Single(SequencedHandler.Calls);
        using var requestBody = JsonDocument.Parse(SequencedHandler.Calls[0].Body);
        Assert.False(requestBody.RootElement.TryGetProperty("reasoning", out _));
        Assert.False(requestBody.RootElement.TryGetProperty("max_output_tokens", out _));
        Assert.Equal("auto", requestBody.RootElement.GetProperty("tool_choice").GetString());
        Assert.False(requestBody.RootElement.GetProperty("parallel_tool_calls").GetBoolean());
    }

    [Theory]
    [InlineData("https://chatgpt.com:444/backend-api/codex/responses")]
    [InlineData("https://operator@chatgpt.com/backend-api/codex/responses")]
    [InlineData("https://chatgpt.com/backend-api/codex/responses?route=other")]
    [InlineData("https://chatgpt.com/backend-api/codex/responses#fragment")]
    [InlineData("https://chatgpt.com/backend-api/codex/responses/")]
    public async Task CodexResponsesRejectsAnyNonExactProviderUri(string configuredUrl)
    {
        SequencedHandler.Calls.Clear();
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("data: {\"type\":\"response.completed\"}\n")
        }));
        var provider = CreateCodexProvider(httpClient, configuredUrl);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(CodexRequest(), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.Empty(SequencedHandler.Calls);
    }

    [Fact]
    public async Task CodexResponsesRejectsATruncatedStreamWithoutSuccessfulTerminalEvent()
    {
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial answer\"}\n\ndata: [DONE]\n")
        }));
        var provider = CreateCodexProvider(httpClient);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(CodexRequest(), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.Contains("before successful completion", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("partial answer", exception.OperatorSafeMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("response.failed")]
    [InlineData("response.incomplete")]
    [InlineData("error")]
    public async Task CodexResponsesRejectsExplicitFailureTerminalEvents(string eventType)
    {
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"data: {{\"type\":\"{eventType}\",\"error\":\"synthetic private provider detail\"}}\n")
        }));
        var provider = CreateCodexProvider(httpClient);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(CodexRequest(), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.DoesNotContain("synthetic private provider detail", exception.OperatorSafeMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CodexResponsesRejectsAnOversizedEventLine()
    {
        var oversizedLine = "data: " + new string('x', (128 * 1024) + 1) + "\n";
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(oversizedLine)
        }));
        var provider = CreateCodexProvider(httpClient);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(CodexRequest(), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.Contains("oversized event", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CodexResponsesRejectsAnOversizedCumulativeStream()
    {
        var stream = new System.Text.StringBuilder();
        var ignoredLine = ": " + new string('x', 32 * 1024) + "\n";
        var ignoredLineBytes = System.Text.Encoding.UTF8.GetByteCount(ignoredLine);
        var totalBytes = 0;
        while (totalBytes <= (2 * 1024 * 1024))
        {
            stream.Append(ignoredLine);
            totalBytes += ignoredLineBytes;
        }

        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(stream.ToString())
        }));
        var provider = CreateCodexProvider(httpClient);

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(CodexRequest(), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.Contains("stream exceeded", exception.OperatorSafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CodexResponsesBoundsAccumulatedAnswerWhileStillRequiringCompletion()
    {
        var responseBody = $"data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{new string('a', 200)}\"}}\n"
            + "data: {\"type\":\"response.completed\"}\n";
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseBody)
        }));
        var provider = CreateCodexProvider(httpClient);

        var result = await provider.CompleteAsync(CodexRequest(maxResultCharacters: 32), CancellationToken.None);

        Assert.Equal(32, result.Answer.Length);
        Assert.Equal(new string('a', 32), result.Answer);
    }

    [Fact]
    public async Task CodexAppServerModeFailsClosedWithoutFallingBackToAnotherCredentialSource()
    {
        var credentialBroker = new FakeCodexCredentialBroker(
            "synthetic-codex-provider-token",
            "acct_synthetic_codex");
        SequencedHandler.Calls.Clear();
        using var httpClient = new HttpClient(new SequencedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var provider = CreateProvider(httpClient, new SocAgentOptions
        {
            Provider = "ChatGPT",
            AuthMode = "CodexAppServer",
            ExternalCallsEnabled = true,
            OpenAiApiKey = "synthetic-api-key-that-must-not-be-used",
            SubscriptionAuthFilePath = "/synthetic/path/that/must/not/be-read"
        }, credentialBroker, new SocAgentCodexAppServerOptions { Enabled = false });

        var exception = await Assert.ThrowsAsync<SocAgentModelProviderException>(() =>
            provider.CompleteAsync(new SocAgentModelProviderRequest(
                new SocAgentProviderStatusResponse
                {
                    Status = "provider_error",
                    Provider = "ChatGPT",
                    Model = "gpt-test",
                    AuthMode = "codex_app_server",
                    ProviderPath = "codex_app_server"
                },
                "bounded prompt",
                2000), CancellationToken.None));

        Assert.Equal("provider_error", exception.ErrorCode);
        Assert.Equal(0, credentialBroker.CallCount);
        Assert.Empty(SequencedHandler.Calls);
        Assert.DoesNotContain("synthetic-api-key", exception.OperatorSafeMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("/synthetic/path", exception.OperatorSafeMessage, StringComparison.Ordinal);
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

    private static OpenAiSocAgentModelProvider CreateProvider(
        HttpClient httpClient,
        SocAgentOptions? options = null,
        ISocAgentCodexCredentialBroker? codexCredentialBroker = null,
        SocAgentCodexAppServerOptions? codexOptions = null)
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
            NullLogger<OpenAiSocAgentModelProvider>.Instance,
            codexCredentialBroker,
            codexOptions is null ? null : Options.Create(codexOptions));
    }

    private static OpenAiSocAgentModelProvider CreateCodexProvider(
        HttpClient httpClient,
        string? responsesUrl = null)
    {
        return CreateProvider(
            httpClient,
            new SocAgentOptions
            {
                Provider = "ChatGPT",
                AuthMode = "CodexAppServer",
                ExternalCallsEnabled = true,
                ChatGptCodexResponsesUrl = responsesUrl ?? "https://chatgpt.com/backend-api/codex/responses",
                MaxRetries = 0
            },
            new FakeCodexCredentialBroker("synthetic-codex-provider-token", "acct_synthetic_codex"),
            new SocAgentCodexAppServerOptions { Enabled = true });
    }

    private static SocAgentModelProviderRequest CodexRequest(int maxResultCharacters = 2000)
    {
        return new SocAgentModelProviderRequest(
            new SocAgentProviderStatusResponse
            {
                Status = "connected",
                Provider = "ChatGPT",
                Model = "gpt-test",
                AuthMode = "codex_app_server",
                ProviderPath = "codex_app_server"
            },
            "bounded prompt",
            maxResultCharacters);
    }

    private sealed class FakeCodexCredentialBroker(string accessToken, string? accountId)
        : ISocAgentCodexCredentialBroker
    {
        public int CallCount { get; private set; }

        public Task<SocAgentCodexCredential> GetCredentialAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new SocAgentCodexCredential(accessToken, accountId));
        }
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
            request.Headers.TryGetValues("chatgpt-account-id", out var accountIds);
            Calls.Add(new RecordedCall(
                request.RequestUri,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter,
                accountIds?.SingleOrDefault(),
                body));
            return responseFactory(request);
        }
    }

    private sealed record RecordedCall(
        Uri? Uri,
        string? AuthorizationScheme,
        string? AuthorizationParameter,
        string? ChatGptAccountId,
        string Body);

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
