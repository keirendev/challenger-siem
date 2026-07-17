using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
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
    int MaxResultCharacters,
    string? Model = null,
    string? ReasoningEffort = null)
{
    public string EffectiveModel => string.IsNullOrWhiteSpace(Model) ? Status.Model : Model.Trim();
}

public sealed record SocAgentModelProviderResult(
    string Provider,
    string Model,
    string Answer,
    string? ReasoningEffort = null);

public sealed class SocAgentModelProviderException(string errorCode, string operatorSafeMessage, Exception? innerException = null)
    : Exception(operatorSafeMessage, innerException)
{
    public string ErrorCode { get; } = errorCode;

    public string OperatorSafeMessage { get; } = operatorSafeMessage;
}

internal sealed class OpenAiSocAgentModelProvider(
    HttpClient httpClient,
    IOptions<SocAgentOptions> options,
    IConfiguration configuration,
    ILogger<OpenAiSocAgentModelProvider> logger,
    ISocAgentCodexCredentialBroker? codexCredentialBroker = null,
    IOptions<SocAgentCodexAppServerOptions>? codexOptions = null) : ISocAgentModelProvider
{
    private const int MaxProviderJsonResponseBytes = 2 * 1024 * 1024;
    private const int MaxChatGptCodexEventLineBytes = 128 * 1024;
    private const int MaxChatGptCodexStreamBytes = 2 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SocAgentOptions options = options.Value;

    private sealed record ProviderCredential(string AccessToken, string? AccountId);

    public async Task<SocAgentModelProviderResult> CompleteAsync(SocAgentModelProviderRequest request, CancellationToken cancellationToken)
    {
        var credential = await GetBearerCredentialAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(credential?.AccessToken))
        {
            throw new SocAgentModelProviderException(
                "provider_not_configured",
                "Server-side OpenAI API credentials are not configured.");
        }

        var useChatGptCodexResponses = UsesChatGptCodexResponses(request.Status);
        var endpoint = useChatGptCodexResponses
            ? CreateChatGptCodexResponsesEndpoint()
            : CreateChatCompletionsEndpoint();
        var maxRetries = Math.Clamp(options.MaxRetries, 0, 3);
        for (var attempt = 0; attempt <= maxRetries; attempt++)
        {
            using var httpRequest = useChatGptCodexResponses
                ? CreateChatGptCodexRequest(endpoint, credential, request)
                : CreateRequest(endpoint, credential.AccessToken, request);
            using var response = await SendAsync(httpRequest, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var answer = useChatGptCodexResponses
                    ? await ReadChatGptCodexAnswerAsync(response, request.MaxResultCharacters, cancellationToken)
                    : await ReadAnswerAsync(response, request.MaxResultCharacters, cancellationToken);
                return new SocAgentModelProviderResult(
                    request.Status.Provider,
                    request.EffectiveModel,
                    answer,
                    request.ReasoningEffort);
            }

            var errorCode = MapStatusCode(response.StatusCode, request.Status.AuthMode);
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

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            return await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The external provider request timed out. Try again later or use local fallback.",
                ex);
        }
        catch (HttpRequestException ex)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The external provider could not be reached. No provider secrets were exposed to the browser.",
                ex);
        }
    }

    private HttpRequestMessage CreateRequest(Uri endpoint, string bearerCredential, SocAgentModelProviderRequest request)
    {
        var payload = new Dictionary<string, object?>
        {
            ["model"] = request.EffectiveModel,
            ["messages"] = new[]
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
            }
        };
        if (string.IsNullOrWhiteSpace(request.ReasoningEffort))
        {
            payload["temperature"] = 0.2;
            payload["max_tokens"] = Math.Clamp(options.MaxProviderOutputTokens, 128, 4096);
        }
        else
        {
            payload["reasoning_effort"] = request.ReasoningEffort;
            payload["max_completion_tokens"] = Math.Clamp(options.MaxProviderOutputTokens, 128, 4096);
        }

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, JsonOptions), Encoding.UTF8, "application/json")
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerCredential);
        AddOptionalHeader(httpRequest, "OpenAI-Organization", configuration["OpenAI:OrganizationId"] ?? configuration["OPENAI_ORGANIZATION"]);
        AddOptionalHeader(httpRequest, "OpenAI-Project", configuration["OpenAI:ProjectId"] ?? configuration["OPENAI_PROJECT"]);
        return httpRequest;
    }

    private HttpRequestMessage CreateChatGptCodexRequest(Uri endpoint, ProviderCredential credential, SocAgentModelProviderRequest request)
    {
        var payload = new Dictionary<string, object?>
        {
            ["model"] = request.EffectiveModel,
            ["instructions"] = "You are Challenger SIEM soc-agent. Use only the supplied bounded SIEM context, preserve citations, do not request credentials, and never perform mutations.",
            ["input"] = new[]
            {
                new
                {
                    type = "message",
                    role = "user",
                    content = new[]
                    {
                        new
                        {
                            type = "input_text",
                            text = request.Prompt
                        }
                    }
                }
            },
            ["stream"] = true,
            ["store"] = false,
            ["tools"] = Array.Empty<object>(),
            ["tool_choice"] = "auto",
            ["parallel_tool_calls"] = false,
            ["include"] = new[] { "reasoning.encrypted_content" },
            ["prompt_cache_key"] = "challenger-siem-soc-agent",
            ["text"] = new { verbosity = "low" }
        };
        if (!string.IsNullOrWhiteSpace(request.ReasoningEffort))
        {
            payload["reasoning"] = new { effort = request.ReasoningEffort };
        }

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, JsonOptions), Encoding.UTF8, "application/json")
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential.AccessToken);
        httpRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        httpRequest.Headers.TryAddWithoutValidation("chatgpt-account-id", credential.AccountId ?? string.Empty);
        httpRequest.Headers.TryAddWithoutValidation("OpenAI-Beta", "responses=experimental");
        httpRequest.Headers.TryAddWithoutValidation("originator", "codex_cli_rs");
        httpRequest.Headers.TryAddWithoutValidation("session_id", Guid.NewGuid().ToString("D"));
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
            || !baseUri.IsDefaultPort
            || !string.IsNullOrEmpty(baseUri.UserInfo)
            || !string.IsNullOrEmpty(baseUri.Query)
            || !string.IsNullOrEmpty(baseUri.Fragment)
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

    private Uri CreateChatGptCodexResponsesEndpoint()
    {
        if (!SocAgentProviderEndpointPolicy.TryCreateChatGptCodexResponsesEndpoint(
                options.ChatGptCodexResponsesUrl,
                out var uri))
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The ChatGPT Codex Responses URL must use the configured https://chatgpt.com/backend-api/codex/responses endpoint.");
        }

        return uri;
    }

    private async Task<string> ReadAnswerAsync(HttpResponseMessage response, int maxResultCharacters, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await ParseProviderResponseAsync(stream, cancellationToken);
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

    private static async Task<string> ReadChatGptCodexAnswerAsync(HttpResponseMessage response, int maxResultCharacters, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var readBuffer = ArrayPool<byte>.Shared.Rent(8192);
        var lineBuffer = new ArrayBufferWriter<byte>();
        var answer = new StringBuilder();
        var answerLimit = Math.Clamp(maxResultCharacters, 1, 100_000);
        var totalBytes = 0;
        var firstLine = true;
        var completed = false;
        try
        {
            while (!completed)
            {
                var bytesRead = await stream.ReadAsync(
                    readBuffer.AsMemory(0, readBuffer.Length),
                    cancellationToken);
                if (bytesRead == 0)
                {
                    if (lineBuffer.WrittenCount > 0)
                    {
                        completed = ProcessChatGptCodexEventLine(
                            lineBuffer.WrittenMemory,
                            answer,
                            answerLimit,
                            firstLine);
                    }

                    break;
                }

                totalBytes = checked(totalBytes + bytesRead);
                if (totalBytes > MaxChatGptCodexStreamBytes)
                {
                    throw new SocAgentModelProviderException(
                        "provider_error",
                        "The ChatGPT Codex Responses backend stream exceeded its safety limit.");
                }

                var offset = 0;
                while (offset < bytesRead && !completed)
                {
                    var relativeNewLine = readBuffer.AsSpan(offset, bytesRead - offset).IndexOf((byte)'\n');
                    var segmentLength = relativeNewLine < 0 ? bytesRead - offset : relativeNewLine;
                    if (lineBuffer.WrittenCount + segmentLength > MaxChatGptCodexEventLineBytes)
                    {
                        throw new SocAgentModelProviderException(
                            "provider_error",
                            "The ChatGPT Codex Responses backend emitted an oversized event.");
                    }

                    if (segmentLength > 0)
                    {
                        lineBuffer.Write(readBuffer.AsSpan(offset, segmentLength));
                    }

                    offset += segmentLength;
                    if (relativeNewLine < 0)
                    {
                        continue;
                    }

                    completed = ProcessChatGptCodexEventLine(
                        lineBuffer.WrittenMemory,
                        answer,
                        answerLimit,
                        firstLine);
                    firstLine = false;
                    lineBuffer.Clear();
                    offset++;
                }
            }
        }
        catch (OverflowException ex)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The ChatGPT Codex Responses backend stream exceeded its safety limit.",
                ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readBuffer);
            ArrayPool<byte>.Shared.Return(readBuffer);
        }

        if (!completed)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The ChatGPT Codex Responses backend stream ended before successful completion.");
        }

        var sanitized = SocAgentTextSafety.RedactSecrets(answer.ToString()).Trim();
        if (sanitized.Length == 0)
        {
            throw new SocAgentModelProviderException("provider_error", "The ChatGPT Codex Responses backend response was empty.");
        }

        return SocAgentTextSafety.Truncate(sanitized, answerLimit);
    }

    private static bool ProcessChatGptCodexEventLine(
        ReadOnlyMemory<byte> lineBytes,
        StringBuilder answer,
        int answerLimit,
        bool firstLine)
    {
        var lineSpan = lineBytes.Span;
        if (lineSpan.Length > 0 && lineSpan[^1] == (byte)'\r')
        {
            lineSpan = lineSpan[..^1];
        }

        string line;
        try
        {
            line = StrictUtf8.GetString(lineSpan);
        }
        catch (DecoderFallbackException ex)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The external provider stream was not valid UTF-8.",
                ex);
        }

        if (firstLine)
        {
            line = line.TrimStart('\uFEFF');
        }

        if (!line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var data = line[5..].Trim();
        if (data.Length == 0 || string.Equals(data, "[DONE]", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        using var document = ParseProviderEvent(data);
        var root = document.RootElement;
        var eventType = root.TryGetProperty("type", out var typeProperty) && typeProperty.ValueKind == JsonValueKind.String
            ? typeProperty.GetString()
            : null;
        if (string.Equals(eventType, "response.output_text.delta", StringComparison.OrdinalIgnoreCase)
            && root.TryGetProperty("delta", out var delta)
            && delta.ValueKind == JsonValueKind.String)
        {
            var value = delta.GetString() ?? string.Empty;
            var remaining = answerLimit - answer.Length;
            if (remaining > 0 && value.Length > 0)
            {
                answer.Append(value.AsSpan(0, Math.Min(remaining, value.Length)));
            }

            return false;
        }

        if (string.Equals(eventType, "response.completed", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (string.Equals(eventType, "response.failed", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventType, "response.incomplete", StringComparison.OrdinalIgnoreCase)
            || string.Equals(eventType, "error", StringComparison.OrdinalIgnoreCase))
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The ChatGPT Codex Responses backend returned an error. Use local fallback or reconnect the server-side credential.");
        }

        return false;
    }

    private static JsonDocument ParseProviderEvent(string data)
    {
        try
        {
            return JsonDocument.Parse(data);
        }
        catch (JsonException ex)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The external provider stream could not be parsed safely.",
                ex);
        }
    }

    private static async Task<JsonDocument> ParseProviderResponseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var readBuffer = ArrayPool<byte>.Shared.Rent(8192);
        var responseBuffer = new ArrayBufferWriter<byte>();
        try
        {
            while (true)
            {
                var bytesRead = await stream.ReadAsync(
                    readBuffer.AsMemory(0, readBuffer.Length),
                    cancellationToken);
                if (bytesRead == 0)
                {
                    break;
                }

                if (responseBuffer.WrittenCount > MaxProviderJsonResponseBytes - bytesRead)
                {
                    throw new SocAgentModelProviderException(
                        "provider_error",
                        "The external provider response exceeded its safety limit.");
                }

                responseBuffer.Write(readBuffer.AsSpan(0, bytesRead));
            }

            return JsonDocument.Parse(responseBuffer.WrittenMemory);
        }
        catch (JsonException ex)
        {
            throw new SocAgentModelProviderException(
                "provider_error",
                "The external provider response could not be parsed safely.",
                ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readBuffer);
            ArrayPool<byte>.Shared.Return(readBuffer);
        }
    }

    private async Task<ProviderCredential?> GetBearerCredentialAsync(CancellationToken cancellationToken)
    {
        if (UsesCodexAppServer())
        {
            if (codexCredentialBroker is null || codexOptions?.Value.Enabled != true)
            {
                throw new SocAgentModelProviderException(
                    "provider_error",
                    "The SIEM-managed OpenAI Codex login service is unavailable.");
            }

            var credential = await codexCredentialBroker.GetCredentialAsync(cancellationToken);
            return new ProviderCredential(credential.AccessToken, credential.AccountId);
        }

        if (UsesSubscriptionOAuth(options.AuthMode))
        {
            var fileStatus = SocAgentSubscriptionOAuthCredentialLoader.Load(options, configuration, includeSecret: true);
            if (fileStatus.ShouldRefresh())
            {
                fileStatus = await SocAgentSubscriptionOAuthCredentialLoader.RefreshAsync(fileStatus, options, httpClient, cancellationToken);
            }

            if (fileStatus.CanUseCredential)
            {
                return new ProviderCredential(fileStatus.AccessToken!, fileStatus.AccountId);
            }

            throw new SocAgentModelProviderException(fileStatus.Status, fileStatus.OperatorMessage);
        }

        if (UsesDelegatedAuthFile(options.AuthMode))
        {
            var fileStatus = SocAgentDelegatedAuthFileLoader.Load(options, configuration, includeSecret: true);
            if (fileStatus.CanUseCredential)
            {
                return new ProviderCredential(fileStatus.AccessToken!, null);
            }

            throw new SocAgentModelProviderException(fileStatus.Status, fileStatus.OperatorMessage);
        }

        foreach (var candidate in new[]
        {
            options.OpenAiApiKey,
            configuration["SocAgent:OpenAiApiKey"],
            configuration["OpenAI:ApiKey"],
            configuration["OPENAI_API_KEY"]
        })
        {
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                return new ProviderCredential(candidate.Trim(), null);
            }
        }

        return null;
    }

    private static bool UsesSubscriptionOAuth(string? authMode)
    {
        return authMode?.Trim().Equals("subscription_oauth", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("subscription-oauth", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("subscriptionoauth", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("chatgpt_subscription_oauth", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("chatgpt-subscription-oauth", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("chatgpt_oauth", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("chatgpt-oauth", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static bool UsesDelegatedAuthFile(string? authMode)
    {
        return authMode?.Trim().Equals("delegated_file", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("delegated-file", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("delegatedfile", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("auth_file", StringComparison.OrdinalIgnoreCase) == true
            || authMode?.Trim().Equals("auth-file", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static bool UsesChatGptCodexResponses(SocAgentProviderStatusResponse status)
    {
        return string.Equals(status.AuthMode, "codex_app_server", StringComparison.OrdinalIgnoreCase)
            || string.Equals(status.ProviderPath, "codex_app_server", StringComparison.OrdinalIgnoreCase);
    }

    private bool UsesCodexAppServer()
    {
        var authMode = options.AuthMode?.Trim().ToLowerInvariant().Replace('-', '_');
        return authMode is "codexappserver" or "codex_app_server" or "chatgpt_codex";
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

    private static string MapStatusCode(HttpStatusCode statusCode, string? authMode)
    {
        return statusCode switch
        {
            HttpStatusCode.Unauthorized => "auth_failed",
            HttpStatusCode.Forbidden when UsesSubscriptionOAuth(authMode)
                || string.Equals(authMode, "codex_app_server", StringComparison.OrdinalIgnoreCase) => "scope_missing",
            HttpStatusCode.Forbidden => "auth_failed",
            HttpStatusCode.PaymentRequired when UsesSubscriptionOAuth(authMode)
                || string.Equals(authMode, "codex_app_server", StringComparison.OrdinalIgnoreCase) => "plan_limited",
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
            "scope_missing" => "The external provider reported that the server-side OAuth credential lacks the required model-invocation scope.",
            "budget_limited" => "The external provider reported that budget or quota is unavailable.",
            "plan_limited" => "The external provider reported that the subscription plan or entitlement does not permit this model request.",
            "rate_limited" => "The external provider rate limit was reached. Try again later or use local fallback.",
            _ => "The external provider returned an error. No provider secrets were exposed to the browser."
        };
    }
}

internal static class SocAgentProviderEndpointPolicy
{
    private const string ChatGptCodexResponsesUrl = "https://chatgpt.com/backend-api/codex/responses";

    public static bool TryCreateChatGptCodexResponsesEndpoint(string? configuredUrl, out Uri endpoint)
    {
        var configured = string.IsNullOrWhiteSpace(configuredUrl)
            ? ChatGptCodexResponsesUrl
            : configuredUrl.Trim();
        if (Uri.TryCreate(configured, UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Host, "chatgpt.com", StringComparison.OrdinalIgnoreCase)
            && uri.IsDefaultPort
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
            && string.Equals(uri.AbsolutePath, "/backend-api/codex/responses", StringComparison.Ordinal))
        {
            endpoint = uri;
            return true;
        }

        endpoint = null!;
        return false;
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
