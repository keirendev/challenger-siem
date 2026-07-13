using System.Reflection;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Reliability;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Agent.Core.Util;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.SelfIntegrity;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Services;

public sealed class LinuxAgentWorker(
    IOptions<LinuxAgentOptions> configured,
    IEventQueue queue,
    SiemIngestClient client,
    LinuxQueueDrainer queueDrainer,
    LinuxTransportRuntimeState transportState,
    LinuxEnrollmentService enrollment,
    LinuxJournalRuntime journalRuntime,
    LinuxSelfIntegrityRuntime selfIntegrityRuntime,
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
                    var journal = journalRuntime.Snapshot();
                    var selfIntegrityManifest = selfIntegrityRuntime.Manifest;
                    var selfIntegrityHealth = selfIntegrityRuntime.Health();
                    await client.SendHeartbeatAsync(new HeartbeatRequest
                    {
                        AgentId = options.AgentId,
                        Hostname = Environment.MachineName,
                        AgentVersion = version,
                        Os = Environment.OSVersion.VersionString,
                        Platform = "linux",
                        HostId = options.AgentId,
                        LastEventTime = journal.Health.Max(source => source.Enabled ? source.LastEventTime : null),
                        QueueDepth = await queue.CountAsync(cancellationToken),
                        MemoryMb = (int)(GC.GetTotalMemory(false) / 1024 / 1024),
                        ResourceMetrics = ResourceMetricsSampler.Sample(),
                        ConfigHash = AgentConfigurationHasher.ComputeConfigurationHash(Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json"),
                        QueueMetrics = transportState.Enrich(await queue.GetMetricsAsync(transportState.LastSuccessfulSendTime, cancellationToken)),
                        SourceManifest = journal.Manifest.Concat([selfIntegrityManifest]).ToArray(),
                        SourceHealth = journal.Health.Concat([selfIntegrityHealth]).ToArray()
                    }, cancellationToken);
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(options.HeartbeatIntervalSeconds);
                }
                await queueDrainer.DrainAsync(cancellationToken);
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
}

public sealed class LinuxTransportRuntimeState
{
    private readonly object sync = new();
    private DateTimeOffset? lastSuccessfulSendTime;
    private DateTimeOffset? lastAttemptTime;
    private DateTimeOffset? lastFailedSendTime;
    private DateTimeOffset? lastRecoveryTime;
    private string sendState = QueueSendStates.Unknown;
    private long? backoffSeconds;

    public DateTimeOffset? LastSuccessfulSendTime { get { lock (sync) return lastSuccessfulSendTime; } }

    public void ObserveAttempt()
    {
        lock (sync)
        {
            lastAttemptTime = DateTimeOffset.UtcNow;
            sendState = QueueSendStates.Sending;
            backoffSeconds = null;
        }
    }

    public void ObserveFailure(TimeSpan backoff)
    {
        lock (sync)
        {
            lastFailedSendTime = DateTimeOffset.UtcNow;
            sendState = QueueSendStates.BackingOff;
            backoffSeconds = Math.Max(0, (long)Math.Ceiling(backoff.TotalSeconds));
        }
    }

    public void ObserveSuccess()
    {
        lock (sync)
        {
            var now = DateTimeOffset.UtcNow;
            if (lastFailedSendTime.HasValue && (!lastSuccessfulSendTime.HasValue || lastFailedSendTime > lastSuccessfulSendTime))
            {
                lastRecoveryTime = now;
                sendState = QueueSendStates.Recovering;
            }
            else
            {
                sendState = QueueSendStates.Succeeded;
            }
            lastSuccessfulSendTime = now;
            backoffSeconds = null;
        }
    }

    public QueueSloMetrics Enrich(QueueSloMetrics metrics)
    {
        lock (sync)
        {
            return metrics with
            {
                SendState = sendState,
                BackoffSeconds = backoffSeconds,
                LastAttemptTime = lastAttemptTime,
                LastFailedSendTime = lastFailedSendTime,
                LastRecoveryTime = lastRecoveryTime
            };
        }
    }
}

public sealed class LinuxQueueDrainer(IOptions<LinuxAgentOptions> configured, IEventQueue queue, SiemIngestClient client, LinuxJournalRuntime journalRuntime, LinuxTransportRuntimeState? transportState = null, LinuxSelfIntegrityRuntime? selfIntegrityRuntime = null)
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly LinuxTransportRuntimeState runtimeState = transportState ?? new LinuxTransportRuntimeState();

    public async Task DrainAsync(CancellationToken cancellationToken)
    {
        var batch = await queue.DequeueBatchAsync(options.DrainBatchSize, cancellationToken);
        if (batch.Count == 0) return;
        var ids = batch.Select(item => item.QueueId).ToArray();
        await queue.MarkAttemptAsync(ids, cancellationToken);
        runtimeState.ObserveAttempt();
        IngestBatchResponse acknowledgement;
        try
        {
            acknowledgement = await client.SendBatchAsync(batch.Select(item => item.Envelope).ToArray(), cancellationToken);
        }
        catch
        {
            runtimeState.ObserveFailure(TimeSpan.FromSeconds(Math.Min(300, options.Queue.MaxBackoffSeconds)));
            throw;
        }
        var acknowledgedIds = IngestAcknowledgement.AcknowledgedQueueIds(batch, acknowledgement);
        var acknowledgedSet = acknowledgedIds.ToHashSet();
        var acknowledgedEvents = batch.Where(item => acknowledgedSet.Contains(item.QueueId)).Select(item => item.Envelope).ToArray();
        await journalRuntime.RecordAcknowledgedAsync(acknowledgedEvents, cancellationToken);
        if (selfIntegrityRuntime is not null)
        {
            await selfIntegrityRuntime.RecordAcknowledgedAsync(acknowledgedEvents, cancellationToken);
        }
        await queue.DeleteAsync(acknowledgedIds, cancellationToken);
        if (acknowledgedIds.Length > 0) runtimeState.ObserveSuccess();
        var rejected = IngestAcknowledgement.RejectedQueueIds(batch, acknowledgement);
        if (rejected.Length > 0) await queue.MarkPoisonAsync(rejected, "server_rejected", cancellationToken);
    }
}
