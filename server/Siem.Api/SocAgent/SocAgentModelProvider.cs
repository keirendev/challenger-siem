using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.SocAgent;

public interface ISocAgentModelProvider
{
    Task<SocAgentModelProviderResult> CompleteAsync(SocAgentModelProviderRequest request, CancellationToken cancellationToken);
}

public sealed record SocAgentModelProviderRequest(
    SocAgentProviderStatusResponse Status,
    string Prompt,
    int MaxResultCharacters);

public sealed record SocAgentModelProviderResult(
    string Provider,
    string Model,
    string Answer);

public sealed class SocAgentModelProviderException(string errorCode, string operatorSafeMessage, Exception? innerException = null)
    : Exception(operatorSafeMessage, innerException)
{
    public string ErrorCode { get; } = errorCode;

    public string OperatorSafeMessage { get; } = operatorSafeMessage;
}

public sealed class OpenAiSocAgentModelProvider(
    HttpClient httpClient,
    IOptions<SocAgentOptions> options,
    IConfiguration configuration,
    ILogger<OpenAiSocAgentModelProvider> logger) : ISocAgentModelProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SocAgentOptions options = options.Value;

    public async Task<SocAgentModelProviderResult> CompleteAsync(SocAgentModelProviderRequest request, CancellationToken cancellationToken)
    {
        var apiKey = GetApiKey();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new SocAgentModelProviderException(
                "provider_not_configured",
                "Server-side OpenAI API credentials are not configured.");
        }

        var endpoint = CreateChatCompletionsEndpoint();
        var maxRetries = Math.Clamp(options.MaxRetries, 0, 3);
        for (var attempt = 0; attempt <= maxRetries; attempt++)
        {
            using var httpRequest = CreateRequest(endpoint, apiKey, request);
            using var response = await httpClient.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var answer = await ReadAnswerAsync(response, request.MaxResultCharacters, cancellationToken);
                return new SocAgentModelProviderResult(request.Status.Provider, request.Status.Model, answer);
            }

            var errorCode = MapStatusCode(response.StatusCode);
            if (IsRetryable(response.StatusCode) && attempt < maxRetries)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250 * (attempt + 1)), cancellationToken);
                continue;
            }

            logger.LogWarning(
                "soc-agent external provider request failed with status {StatusCode} mapped to {ErrorCode}.",
                (int)response.StatusCode,
                errorCode);
            throw new SocAgentModelProviderException(errorCode, ProviderErrorMessage(errorCode));
        }

        throw new SocAgentModelProviderException("provider_error", "The external provider request did not complete.");
    }

    private HttpRequestMessage CreateRequest(Uri endpoint, string apiKey, SocAgentModelProviderRequest request)
    {
        var payload = new
        {
            model = request.Status.Model,
            messages = new[]
            {
                new
                {
                    role = "system",
                    content = "You are Challenger SIEM soc-agent. Use only the supplied bounded SIEM context, preserve citations, do not request credentials, and never perform mutations."
                },
                new
                {
                    role = "user",
                    content = request.Prompt
                }
            },
            temperature = 0.2,
            max_tokens = Math.Clamp(options.MaxProviderOutputTokens, 128, 4096)
        };

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, JsonOptions), Encoding.UTF8, "application/json")
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        AddOptionalHeader(httpRequest, "OpenAI-Organization", configuration["OpenAI:OrganizationId"] ?? configuration["OPENAI_ORGANIZATION"]);
        AddOptionalHeader(httpRequest, "OpenAI-Project", configuration["OpenAI:ProjectId"] ?? configuration["OPENAI_PROJECT"]);
        return httpRequest;
    }

    private Uri CreateChatCompletionsEndpoint()
    {
        var baseUrl = string.IsNullOrWhiteSpace(options.OpenAiBaseUrl)
            ? "https://api.openai.com/v1"
            : options.OpenAiBaseUrl.Trim();
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)
            || !string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(baseUri.Host, "api.openai.com", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(baseUri.AbsolutePath.TrimEnd('/'), "/v1", StringComparison.OrdinalIgnoreCase))
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The OpenAI API base URL must be the official https://api.openai.com endpoint.");
        }

        var normalizedBase = baseUri.AbsoluteUri.EndsWith("/", StringComparison.Ordinal) ? baseUri : new Uri(baseUri.AbsoluteUri + "/");
        var path = string.IsNullOrWhiteSpace(options.OpenAiChatCompletionsPath)
            ? "chat/completions"
            : options.OpenAiChatCompletionsPath.Trim().TrimStart('/');
        if (!string.Equals(path, "chat/completions", StringComparison.OrdinalIgnoreCase))
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The OpenAI chat completions path must use the official /v1/chat/completions endpoint.");
        }

        return new Uri(normalizedBase, path);
    }

    private async Task<string> ReadAnswerAsync(HttpResponseMessage response, int maxResultCharacters, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;
        if (!root.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array || choices.GetArrayLength() == 0)
        {
            throw new SocAgentModelProviderException("provider_error", "The external provider response did not include a chat completion choice.");
        }

        var first = choices[0];
        if (!first.TryGetProperty("message", out var message)
            || !message.TryGetProperty("content", out var content)
            || content.ValueKind != JsonValueKind.String)
        {
            throw new SocAgentModelProviderException("provider_error", "The external provider response did not include assistant text.");
        }

        var answer = SocAgentTextSafety.RedactSecrets(content.GetString() ?? string.Empty).Trim();
        if (answer.Length == 0)
        {
            throw new SocAgentModelProviderException("provider_error", "The external provider response was empty.");
        }

        return SocAgentTextSafety.Truncate(answer, maxResultCharacters);
    }

    private string? GetApiKey()
    {
        return options.OpenAiApiKey
            ?? configuration["SocAgent:OpenAiApiKey"]
            ?? configuration["OpenAI:ApiKey"]
            ?? configuration["OPENAI_API_KEY"];
    }

    private static void AddOptionalHeader(HttpRequestMessage request, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            request.Headers.TryAddWithoutValidation(name, value.Trim());
        }
    }

    private static bool IsRetryable(HttpStatusCode statusCode)
    {
        var numeric = (int)statusCode;
        return statusCode == HttpStatusCode.TooManyRequests || numeric is >= 500 and <= 599;
    }

    private static string MapStatusCode(HttpStatusCode statusCode)
    {
        return statusCode switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "auth_failed",
            HttpStatusCode.PaymentRequired => "budget_limited",
            HttpStatusCode.TooManyRequests => "rate_limited",
            _ => "provider_error"
        };
    }

    private static string ProviderErrorMessage(string errorCode)
    {
        return errorCode switch
        {
            "auth_failed" => "The external provider rejected the server-side credentials. Ask an admin to rotate or reconnect official provider credentials.",
            "budget_limited" => "The external provider reported that budget or quota is unavailable.",
            "rate_limited" => "The external provider rate limit was reached. Try again later or use local fallback.",
            _ => "The external provider returned an error. No provider secrets were exposed to the browser."
        };
    }
}

internal static partial class SocAgentTextSafety
{
    private static readonly Regex BearerTokenPattern = BearerTokenRegex();
    private static readonly Regex SecretAssignmentPattern = SecretAssignmentRegex();

    public static string RedactSecrets(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var withoutBearer = BearerTokenPattern.Replace(value, "Bearer <redacted>");
        return SecretAssignmentPattern.Replace(withoutBearer, "$1=<redacted>");
    }

    public static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    [GeneratedRegex("Bearer\\s+[A-Za-z0-9._~+/-]+=*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BearerTokenRegex();

    [GeneratedRegex("(?i)(token|password|secret|api[_-]?key)\\s*[:=]\\s*[^\\s,;]+", RegexOptions.CultureInvariant)]
    private static partial Regex SecretAssignmentRegex();
}
