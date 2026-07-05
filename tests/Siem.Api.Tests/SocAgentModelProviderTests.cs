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
        public static string LastRequestBody { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            LastAuthorizationScheme = request.Headers.Authorization?.Scheme;
            LastRequestBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return responseFactory(request);
        }
    }
}
