using System.Text.Json;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Services;

public sealed class LinuxEnrollmentService(
    IOptions<LinuxAgentOptions> configured,
    SiemIngestClient client,
    LinuxStateStore state,
    ILogger<LinuxEnrollmentService> logger)
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly SemaphoreSlim enrollmentLock = new(1, 1);

    public async Task EnsureAsync(string version, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(options.ApiToken)) return;
        await enrollmentLock.WaitAsync(cancellationToken);
        try
        {
            if (!string.IsNullOrWhiteSpace(options.ApiToken)) return;
            if (string.IsNullOrWhiteSpace(options.EnrollmentToken)) throw new InvalidOperationException("An API token or enrollment token is required.");
            var response = await client.RegisterAsync(new AgentRegistrationRequest
            {
                AgentId = options.AgentId,
                Hostname = Environment.MachineName,
                OsVersion = Environment.OSVersion.VersionString,
                AgentVersion = version,
                Platform = "linux"
            }, options.EnrollmentToken, cancellationToken);
            if (response.AgentId != options.AgentId) throw new InvalidOperationException("Registration response agent ID mismatch.");
            options.ApiToken = response.ApiToken;
            await PersistTokenAsync(cancellationToken);
            await state.WriteEnrollmentAsync(options.AgentId, cancellationToken);
            logger.LogInformation("Agent {AgentId} enrollment completed and credentials were persisted.", options.AgentId);
        }
        finally { enrollmentLock.Release(); }
    }

    private async Task PersistTokenAsync(CancellationToken cancellationToken)
    {
        var path = Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json";
        var json = JsonSerializer.Serialize(new
        {
            Agent = new
            {
                options.AgentId,
                ServerBaseUrl = options.ServerBaseUrl?.ToString(),
                options.ApiToken,
                EnrollmentToken = "",
                options.HeartbeatIntervalSeconds,
                options.InventoryIntervalSeconds,
                options.DrainBatchSize,
                options.Inventory,
                options.Queue,
                options.State
            }
        }, new JsonSerializerOptions { WriteIndented = true });
        var temporary = path + ".tmp";
        await File.WriteAllTextAsync(temporary, json, cancellationToken);
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(temporary, path, overwrite: true);
    }
}
