using System.Reflection;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Reliability;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Services;

public sealed class LinuxAgentWorker(
    IOptions<LinuxAgentOptions> configured,
    IEventQueue queue,
    SiemIngestClient client,
    LinuxEnrollmentService enrollment,
    ILogger<LinuxAgentWorker> logger) : BackgroundService
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly string version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        await enrollment.EnsureAsync(version, cancellationToken);
        await queue.InitializeAsync(cancellationToken);
        var nextHeartbeat = DateTimeOffset.MinValue;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    await client.SendHeartbeatAsync(new HeartbeatRequest
                    {
                        AgentId = options.AgentId,
                        Hostname = Environment.MachineName,
                        AgentVersion = version,
                        Os = Environment.OSVersion.VersionString,
                        Platform = "linux",
                        QueueDepth = await queue.CountAsync(cancellationToken),
                        MemoryMb = (int)(GC.GetTotalMemory(false) / 1024 / 1024),
                        ConfigHash = AgentConfigurationHasher.ComputeConfigurationHash(Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json"),
                        QueueMetrics = await queue.GetMetricsAsync(null, cancellationToken),
                        SourceManifest = Array.Empty<SourceManifestEntry>(),
                        SourceHealth = Array.Empty<SourceHealthReport>()
                    }, cancellationToken);
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(options.HeartbeatIntervalSeconds);
                }
                await DrainAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning("Agent transport cycle failed ({ErrorType}); queued data remains durable.", ex.GetType().Name);
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
            }
        }
    }

    private async Task DrainAsync(CancellationToken cancellationToken)
    {
        var batch = await queue.DequeueBatchAsync(options.DrainBatchSize, cancellationToken);
        if (batch.Count == 0) return;
        var ids = batch.Select(item => item.QueueId).ToArray();
        await queue.MarkAttemptAsync(ids, cancellationToken);
        var acknowledgement = await client.SendBatchAsync(batch.Select(item => item.Envelope).ToArray(), cancellationToken);
        await queue.DeleteAsync(IngestAcknowledgement.AcknowledgedQueueIds(batch, acknowledgement), cancellationToken);
        var rejected = IngestAcknowledgement.RejectedQueueIds(batch, acknowledgement);
        if (rejected.Length > 0) await queue.MarkPoisonAsync(rejected, "server_rejected", cancellationToken);
    }
}
