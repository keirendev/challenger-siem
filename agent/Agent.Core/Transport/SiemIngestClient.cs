using System.Net.Http.Headers;
using System.Net.Http.Json;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.Agent.Core.Serialization;

namespace Challenger.Siem.Agent.Core.Transport;

public interface IAgentTransportConfiguration
{
    string AgentId { get; }
    string ApiToken { get; }
}

public sealed class SiemIngestClient(HttpClient httpClient, IAgentTransportConfiguration options)
{

    public async Task<AgentRegistrationResponse> RegisterAsync(
        AgentRegistrationRequest registration,
        string enrollmentToken,
        CancellationToken cancellationToken)
    {
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register")
        {
            Content = JsonContent.Create(registration, options: JsonDefaults.Options)
        };
        httpRequest.Headers.Add("X-Enrollment-Token", enrollmentToken);

        using var response = await httpClient.SendAsync(httpRequest, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Server returned {(int)response.StatusCode} {response.ReasonPhrase} for agent registration. Body: {Truncate(responseBody, 500)}");
        }

        var registrationResponse = await response.Content.ReadFromJsonAsync<AgentRegistrationResponse>(JsonDefaults.Options, cancellationToken);
        return registrationResponse ?? throw new InvalidOperationException("Server returned an empty registration response.");
    }

    public async Task<IngestBatchResponse> SendBatchAsync(
        IReadOnlyList<EventEnvelope> events,
        CancellationToken cancellationToken)
    {
        var request = new IngestBatchRequest
        {
            AgentId = options.AgentId,
            BatchId = Guid.NewGuid(),
            SentAt = DateTimeOffset.UtcNow,
            Events = events
        };

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/ingest/events")
        {
            Content = JsonContent.Create(request, options: JsonDefaults.Options)
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiToken);

        using var response = await httpClient.SendAsync(httpRequest, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Server returned {(int)response.StatusCode} {response.ReasonPhrase} for event batch. Body: {Truncate(responseBody, 500)}");
        }

        var acknowledgement = await response.Content.ReadFromJsonAsync<IngestBatchResponse>(JsonDefaults.Options, cancellationToken);
        return acknowledgement ?? throw new InvalidOperationException("Server returned an empty ingest acknowledgement.");
    }

    public async Task SendHeartbeatAsync(HeartbeatRequest heartbeat, CancellationToken cancellationToken)
    {
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/heartbeat")
        {
            Content = JsonContent.Create(heartbeat, options: JsonDefaults.Options)
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiToken);

        using var response = await httpClient.SendAsync(httpRequest, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Server returned {(int)response.StatusCode} {response.ReasonPhrase} for heartbeat. Body: {Truncate(responseBody, 500)}");
        }
    }

    public async Task SendInventoryAsync(IReadOnlyList<AssetInventorySnapshot> snapshots, CancellationToken cancellationToken)
    {
        var request = new AssetInventoryBatchRequest
        {
            AgentId = options.AgentId,
            SentAt = DateTimeOffset.UtcNow,
            Snapshots = snapshots
        };

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/inventory")
        {
            Content = JsonContent.Create(request, options: JsonDefaults.Options)
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiToken);

        using var response = await httpClient.SendAsync(httpRequest, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Server returned {(int)response.StatusCode} {response.ReasonPhrase} for inventory. Body: {Truncate(responseBody, 500)}");
        }
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }
}
