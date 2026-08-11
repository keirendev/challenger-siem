using System.Reflection;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Reliability;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Agent.Core.Util;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.KernelNetwork;
using Challenger.Siem.LinuxAgent.L4;
using Challenger.Siem.LinuxAgent.Package;
using Challenger.Siem.LinuxAgent.Passive;
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
    LinuxPackageInventoryDiffRuntime packageInventoryRuntime,
    LinuxSelfIntegrityRuntime selfIntegrityRuntime,
    LinuxPassiveTelemetryRuntime passiveTelemetryRuntime,
    LinuxKernelNetworkRuntime kernelNetworkRuntime,
    LinuxL4TelemetryRuntime l4TelemetryRuntime,
    TimeProvider timeProvider,
    ILogger<LinuxAgentWorker> logger) : BackgroundService
{
    private static readonly TimeSpan FailureLogInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan BacklogDrainDelay = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan IdleDrainDelay = TimeSpan.FromSeconds(5);
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly RuntimeWarningThrottle failureLog = new(timeProvider, FailureLogInterval);
    private readonly string version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        await enrollment.EnsureAsync(version, cancellationToken);
        await queue.InitializeAsync(cancellationToken);
        await packageInventoryRuntime.InitializeAsync(cancellationToken);
        var nextHeartbeat = DateTimeOffset.MinValue;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    var journal = journalRuntime.Snapshot();
                    var packageManifest = packageInventoryRuntime.Manifest;
                    var packageHealth = packageInventoryRuntime.Health();
                    var selfIntegrityManifest = selfIntegrityRuntime.Manifest;
                    var selfIntegrityHealth = selfIntegrityRuntime.Health();
                    var passiveManifest = passiveTelemetryRuntime.Manifest;
                    var passiveHealth = passiveTelemetryRuntime.Health();
                    var kernelNetworkManifest = kernelNetworkRuntime.Manifest;
                    var kernelNetworkHealth = kernelNetworkRuntime.Health();
                    var l4Manifest = l4TelemetryRuntime.Manifest;
                    var l4Health = l4TelemetryRuntime.Health();
                    var allHealth = journal.Health.Concat([packageHealth, selfIntegrityHealth]).Concat(passiveHealth).Concat([kernelNetworkHealth]).Concat(l4Health).ToArray();
                    await client.SendHeartbeatAsync(new HeartbeatRequest
                    {
                        AgentId = options.AgentId,
                        Hostname = Environment.MachineName,
                        AgentVersion = version,
                        Os = Environment.OSVersion.VersionString,
                        Platform = "linux",
                        HostId = options.AgentId,
                        LastEventTime = allHealth.Where(source => source.Enabled).Select(source => source.LastEventTime).DefaultIfEmpty().Max(),
                        QueueDepth = await queue.CountAsync(cancellationToken),
                        MemoryMb = (int)(GC.GetTotalMemory(false) / 1024 / 1024),
                        ResourceMetrics = ResourceMetricsSampler.Sample(),
                        ConfigHash = AgentConfigurationHasher.ComputeConfigurationHash(Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json"),
                        QueueMetrics = transportState.Enrich(await queue.GetMetricsAsync(transportState.LastSuccessfulSendTime, cancellationToken)),
                        SourceManifest = journal.Manifest.Concat([packageManifest, selfIntegrityManifest]).Concat(passiveManifest).Concat([kernelNetworkManifest]).Concat(l4Manifest).ToArray(),
                        SourceHealth = allHealth
                    }, cancellationToken);
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(options.HeartbeatIntervalSeconds);
                }
                var likelyBacklog = await queueDrainer.DrainAsync(cancellationToken);
                await Task.Delay(DrainDelay(likelyBacklog), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                if (failureLog.TryAcquire())
                {
                    logger.LogWarning("Agent transport cycle failed ({ErrorType}); queued data remains durable.", ex.GetType().Name);
                }
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
            }
        }
    }

    internal static TimeSpan DrainDelay(bool likelyBacklog) => likelyBacklog ? BacklogDrainDelay : IdleDrainDelay;
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

public sealed class LinuxQueueDrainer(
    IOptions<LinuxAgentOptions> configured,
    IEventQueue queue,
    SiemIngestClient client,
    LinuxJournalRuntime journalRuntime,
    LinuxTransportRuntimeState? transportState = null,
    LinuxSelfIntegrityRuntime? selfIntegrityRuntime = null,
    IEnumerable<ILinuxAcknowledgementObserver>? acknowledgementObservers = null)
{
    internal const int MaximumAuditRowsPerBatch = 100;
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly LinuxTransportRuntimeState runtimeState = transportState ?? new LinuxTransportRuntimeState();
    private readonly IReadOnlyList<ILinuxAcknowledgementObserver> observers = BuildObservers(
        journalRuntime,
        selfIntegrityRuntime,
        acknowledgementObservers);

    public async Task<bool> DrainAsync(CancellationToken cancellationToken)
    {
        var dequeued = await queue.DequeueBatchAsync(options.DrainBatchSize, cancellationToken);
        if (dequeued.Count == 0) return false;
        var auditRows = 0;
        var batch = dequeued.TakeWhile(item => item.Envelope.Source != EventSources.LinuxAudit
            || ++auditRows <= MaximumAuditRowsPerBatch).ToArray();
        var ids = batch.Select(item => item.QueueId).ToArray();
        var outboundEvents = batch.Select(item => PrepareForTransport(item.Envelope)).ToArray();
        runtimeState.ObserveAttempt();
        IngestBatchResponse acknowledgement;
        try
        {
            acknowledgement = await client.SendBatchAsync(outboundEvents, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            runtimeState.ObserveFailure(TimeSpan.FromSeconds(Math.Min(300, options.Queue.MaxBackoffSeconds)));
            await queue.MarkAttemptAsync(ids, cancellationToken);
            throw;
        }
        var acknowledgedIds = IngestAcknowledgement.AcknowledgedQueueIds(batch, acknowledgement);
        var acknowledgedSet = acknowledgedIds.ToHashSet();
        var acknowledgedItems = batch.Where(item => acknowledgedSet.Contains(item.QueueId)).ToArray();
        var rejectedIds = IngestAcknowledgement.RejectedQueueIds(batch, acknowledgement);
        var rejectedSet = rejectedIds.ToHashSet();
        var rejectedItems = batch.Where(item => rejectedSet.Contains(item.QueueId)).ToArray();
        var poisonableIds = rejectedIds.ToHashSet();
        var deletableIds = acknowledgedIds.ToHashSet();
        foreach (var observer in observers)
        {
            var relevant = acknowledgedItems.Where(item => observer.HandlesSource(item.Envelope.SourceId)).ToArray();
            if (relevant.Length == 0) continue;
            var relevantEvents = relevant.Select(item => item.Envelope).ToArray();
            try
            {
                await observer.RecordAcknowledgedAsync(relevantEvents, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                foreach (var item in relevant) deletableIds.Remove(item.QueueId);
                try
                {
                    observer.RecordAcknowledgementFailure(relevantEvents);
                }
                catch
                {
                    // Observer health reporting is best effort; accepted rows remain queued for a safe retry.
                }
            }
        }
        // Persist contiguous acceptances first. Rejection observers can then abandon only the
        // immediately following durable sequence without jumping over an unseen/backed-off row.
        foreach (var observer in observers)
        {
            var relevant = rejectedItems.Where(item => observer.HandlesSource(item.Envelope.SourceId)).ToArray();
            if (relevant.Length == 0) continue;
            var relevantEvents = relevant.Select(item => item.Envelope).ToArray();
            try
            {
                await observer.RecordRejectedAsync(relevantEvents, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                foreach (var item in relevant) poisonableIds.Remove(item.QueueId);
                try { observer.RecordAcknowledgementFailure(relevantEvents); }
                catch { }
            }
        }
        var retainedOrRejectedIds = ids.Where(id => !deletableIds.Contains(id)).ToArray();
        if (retainedOrRejectedIds.Length > 0)
        {
            await queue.MarkAttemptAsync(retainedOrRejectedIds, cancellationToken);
        }
        try
        {
            await queue.DeleteAsync(deletableIds, cancellationToken);
            queue.RecordAcknowledgedWork(batch.Where(item => deletableIds.Contains(item.QueueId)).ToArray());
        }
        catch
        {
            // A failed atomic delete leaves the acknowledged rows durable. Mark only
            // that exceptional replay path so restart/retry still observes backoff.
            await queue.MarkAttemptAsync(deletableIds, cancellationToken);
            throw;
        }
        if (deletableIds.Count > 0) runtimeState.ObserveSuccess();
        if (poisonableIds.Count > 0) await queue.MarkPoisonAsync(poisonableIds, "server_rejected", cancellationToken);
        return dequeued.Count >= options.DrainBatchSize;
    }

    internal static EventEnvelope PrepareForTransport(EventEnvelope envelope)
    {
        var handling = envelope.DataHandling;
        if (!string.Equals(envelope.Source, EventSources.LinuxAudit, StringComparison.Ordinal)
            || !string.Equals(envelope.SourceId, LinuxTelemetrySourceIds.AuditFramework, StringComparison.Ordinal)
            || handling is not { TruncationApplied: true, OriginalSizeBytes: null }
            || handling.TruncatedFields is not { Count: > 0 }
            || handling.RawSizeBytes is < 0 or > ContractLimits.RawPayloadMaxUtf8Bytes)
        {
            return envelope;
        }

        return envelope with
        {
            DataHandling = handling with { OriginalSizeBytes = handling.RawSizeBytes + 1 }
        };
    }

    private static IReadOnlyList<ILinuxAcknowledgementObserver> BuildObservers(
        LinuxJournalRuntime journalRuntime,
        LinuxSelfIntegrityRuntime? selfIntegrityRuntime,
        IEnumerable<ILinuxAcknowledgementObserver>? additional)
    {
        var result = new HashSet<ILinuxAcknowledgementObserver>(ReferenceEqualityComparer.Instance) { journalRuntime };
        if (selfIntegrityRuntime is not null) result.Add(selfIntegrityRuntime);
        if (additional is not null)
        {
            foreach (var observer in additional) result.Add(observer);
        }
        return result.ToArray();
    }
}
