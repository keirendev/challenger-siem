using System.Text.Json;
using System.Text.Json.Nodes;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Security;
using Challenger.Siem.WindowsAgent.Time;
using Challenger.Siem.Agent.Core.Transport;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.WindowsAgent.Services;

public sealed class AgentEnrollmentService(
    IOptions<AgentOptions> options,
    AgentConfigFile configFile,
    SiemIngestClient client,
    ISecretProtector secretProtector,
    ILogger<AgentEnrollmentService> logger)
{
    private readonly AgentOptions options = options.Value;

    public async Task EnsureEnrolledAsync(string agentVersion, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(options.ApiToken))
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(options.ProtectedApiToken))
        {
            options.ApiToken = secretProtector.Unprotect(options.ProtectedApiToken);
            return;
        }

        var enrollmentToken = options.Enrollment.EnrollmentToken;
        if (string.IsNullOrWhiteSpace(enrollmentToken))
        {
            throw new InvalidOperationException("Agent API token is not configured and enrollment token is missing.");
        }

        var registration = new AgentRegistrationRequest
        {
            AgentId = options.AgentId,
            Hostname = Environment.MachineName,
            MachineGuid = string.IsNullOrWhiteSpace(options.Enrollment.MachineGuid) ? null : options.Enrollment.MachineGuid,
            OsVersion = Environment.OSVersion.VersionString,
            AgentVersion = agentVersion,
            HostTimezone = HostTimezoneProvider.Current()
        };

        logger.LogInformation("Registering Challenger SIEM agent {AgentId} with the configured enrollment token.", options.AgentId);
        var response = await client.RegisterAsync(registration, enrollmentToken, cancellationToken);
        if (!string.Equals(response.AgentId, options.AgentId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Registration response agent ID did not match the configured agent ID.");
        }

        options.ApiToken = response.ApiToken;
        options.Enrollment.Enabled = false;
        options.Enrollment.EnrollmentToken = string.Empty;
        await PersistApiTokenAsync(cancellationToken);
        logger.LogInformation("Agent {AgentId} enrollment completed. The returned API token was persisted to the configured agent settings path.", options.AgentId);
    }

    private async Task PersistApiTokenAsync(CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(configFile.Path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        JsonObject root;
        if (File.Exists(configFile.Path))
        {
            await using var readStream = File.OpenRead(configFile.Path);
            root = await JsonNode.ParseAsync(readStream, cancellationToken: cancellationToken) as JsonObject ?? new JsonObject();
        }
        else
        {
            root = new JsonObject();
        }

        if (root[AgentOptions.SectionName] is not JsonObject target)
        {
            target = new JsonObject();
            root[AgentOptions.SectionName] = target;
        }

        target["AgentId"] = options.AgentId;
        target["ServerBaseUrl"] = options.ServerBaseUrl?.ToString();
        target["ApiToken"] = string.Empty;
        target["ProtectedApiToken"] = secretProtector.Protect(options.ApiToken);

        if (target["Enrollment"] is JsonObject enrollment)
        {
            enrollment["Enabled"] = false;
            enrollment["EnrollmentToken"] = string.Empty;
        }

        var tempPath = configFile.Path + ".tmp";
        await using (var writeStream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(
                writeStream,
                root,
                new JsonSerializerOptions { WriteIndented = true },
                cancellationToken);
        }

        File.Move(tempPath, configFile.Path, overwrite: true);
    }
}
