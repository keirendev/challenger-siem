using System.Reflection;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Collectors;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Coverage;
using Challenger.Siem.WindowsAgent.Inventory;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Reliability;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.WindowsAgent.State;
using Challenger.Siem.WindowsAgent.Time;
using Challenger.Siem.Agent.Core.Transport;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.WindowsAgent.Services;

public sealed class AgentWorker(
    IOptions<AgentOptions> options,
    IWindowsEventCollector collector,
    IChannelStateStore stateStore,
    IEventQueue queue,
    SiemIngestClient client,
    AgentRuntimeState runtimeState,
    AgentEnrollmentService enrollmentService,
    AgentConfigFile configFile,
    ILogger<AgentWorker> logger) : BackgroundService
{
    private readonly AgentOptions options = options.Value;
    private readonly string hostname = Environment.MachineName;
    private readonly string agentVersion = Assembly.GetExecutingAssembly()
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
        ?? "0.0.0";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Challenger SIEM agent starting for agent {AgentId}.", options.AgentId);
        await enrollmentService.EnsureEnrolledAsync(agentVersion, stoppingToken);
        await queue.InitializeAsync(stoppingToken);

        var nextHeartbeat = DateTimeOffset.MinValue;
        var nextInventory = DateTimeOffset.MinValue;
        var consecutiveFailures = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    await TrySendHeartbeatAsync(stoppingToken);
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(options.HeartbeatIntervalSeconds);
                }

                if (DateTimeOffset.UtcNow >= nextInventory)
                {
                    await TrySendInventoryAsync(stoppingToken);
                    nextInventory = DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, options.InventoryIntervalSeconds));
                }

                var collected = await CollectConfiguredChannelsAsync(stoppingToken);
                var sent = await DrainQueueAsync(stoppingToken);

                if (collected > 0 || sent > 0)
                {
                    logger.LogInformation("Agent cycle completed. Collected={Collected}, SentOrDeduplicated={Sent}.", collected, sent);
                }

                consecutiveFailures = 0;
                await Task.Delay(TimeSpan.FromSeconds(options.PollIntervalSeconds), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                consecutiveFailures++;
                var delay = BackoffDelay(consecutiveFailures);
                logger.LogWarning(ex, "Agent cycle failed. Retrying in {DelaySeconds} seconds.", delay.TotalSeconds);
                await Task.Delay(delay, stoppingToken);
            }
        }

        logger.LogInformation("Challenger SIEM agent stopped.");
    }

    private async Task<int> CollectConfiguredChannelsAsync(CancellationToken cancellationToken)
    {
        var collected = 0;
        var channels = options.Channels
            .Concat(options.OptionalChannels)
            .Where(channel => !string.IsNullOrWhiteSpace(channel))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var channel in channels)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var lastRecordId = await stateStore.GetLastRecordIdAsync(channel, cancellationToken);
            if (!lastRecordId.HasValue && options.StartAtEndWhenNoState)
            {
                var latestRecordId = await collector.GetLatestRecordIdAsync(channel, cancellationToken);
                if (latestRecordId.HasValue)
                {
                    await stateStore.SetLastRecordIdAsync(channel, latestRecordId.Value, cancellationToken);
                    logger.LogInformation("Initialized channel {Channel} at record ID {RecordId}.", channel, latestRecordId.Value);
                }

                continue;
            }

            var events = await collector.ReadEventsAsync(channel, lastRecordId, options.Batching.MaxEvents, cancellationToken);
            foreach (var collectedEvent in events)
            {
                await queue.EnqueueAsync(collectedEvent.Envelope, cancellationToken);
                await stateStore.SetLastRecordIdAsync(channel, collectedEvent.RecordId, cancellationToken);
                runtimeState.ObserveEventTime(collectedEvent.Envelope.EventTime);
                collected++;
            }
        }

        return collected;
    }

    private async Task<int> DrainQueueAsync(CancellationToken cancellationToken)
    {
        var sentOrDeduplicated = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            var batch = await queue.DequeueBatchAsync(options.Batching.MaxEvents, cancellationToken);
            if (batch.Count == 0)
            {
                break;
            }

            var queueIds = batch.Select(item => item.QueueId).ToArray();
            await queue.MarkAttemptAsync(queueIds, cancellationToken);

            IngestBatchResponse acknowledgement;
            try
            {
                acknowledgement = await client.SendBatchAsync(batch.Select(item => item.Envelope).ToArray(), cancellationToken);
            }
            catch (HttpRequestException ex) when (IsPayloadTooLarge(ex))
            {
                sentOrDeduplicated += await RecoverPayloadTooLargeBatchAsync(batch, cancellationToken);
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await QuarantineExhaustedEventsAsync(batch, "send_failed", cancellationToken);
                throw;
            }

            var deleted = await DeleteAcknowledgedEventsAsync(batch, acknowledgement, cancellationToken);
            if (deleted > 0)
            {
                runtimeState.ObserveSuccessfulSend();
            }

            sentOrDeduplicated += deleted;

            var rejected = await QuarantineRejectedEventsAsync(batch, acknowledgement, cancellationToken);
            var exhausted = await QuarantineExhaustedEventsAsync(batch, "max_send_attempts_exceeded", cancellationToken);

            var acknowledged = acknowledgement.Accepted + acknowledgement.Duplicates;
            if (acknowledgement.Rejected == 0 && acknowledged >= batch.Count)
            {
                continue;
            }

            logger.LogWarning(
                "Server did not acknowledge the full batch. Accepted={Accepted}, Duplicates={Duplicates}, Rejected={Rejected}, BatchSize={BatchSize}, Deleted={Deleted}, Quarantined={Quarantined}.",
                acknowledgement.Accepted,
                acknowledgement.Duplicates,
                acknowledgement.Rejected,
                batch.Count,
                deleted,
                rejected + exhausted);
            break;
        }

        return sentOrDeduplicated;
    }

    private async Task<int> RecoverPayloadTooLargeBatchAsync(
        IReadOnlyList<QueuedEvent> batch,
        CancellationToken cancellationToken)
    {
        var recovered = 0;
        foreach (var item in batch)
        {
            try
            {
                var acknowledgement = await client.SendBatchAsync(new[] { item.Envelope }, cancellationToken);
                recovered += await DeleteAcknowledgedEventsAsync(new[] { item }, acknowledgement, cancellationToken);
            }
            catch (HttpRequestException ex) when (IsPayloadTooLarge(ex))
            {
                logger.LogWarning(
                    "Quarantining queued event {EventId} because the single-event payload exceeded the server request limit.",
                    item.Envelope.EventId);
                await queue.MarkPoisonAsync(new[] { item.QueueId }, "payload_too_large", cancellationToken);
            }
        }

        if (recovered > 0)
        {
            runtimeState.ObserveSuccessfulSend();
        }

        return recovered;
    }

    private async Task<int> DeleteAcknowledgedEventsAsync(
        IReadOnlyList<QueuedEvent> batch,
        IngestBatchResponse acknowledgement,
        CancellationToken cancellationToken)
    {
        var queueIds = IngestAcknowledgement.AcknowledgedQueueIds(batch, acknowledgement);
        await queue.DeleteAsync(queueIds, cancellationToken);
        return queueIds.Length;
    }

    private async Task<int> QuarantineRejectedEventsAsync(
        IReadOnlyList<QueuedEvent> batch,
        IngestBatchResponse acknowledgement,
        CancellationToken cancellationToken)
    {
        var rejectedQueueIds = IngestAcknowledgement.RejectedQueueIds(batch, acknowledgement);
        if (rejectedQueueIds.Length == 0) return 0;
        await queue.MarkPoisonAsync(rejectedQueueIds, "server_rejected", cancellationToken);
        return rejectedQueueIds.Length;
    }

    private async Task<int> QuarantineExhaustedEventsAsync(
        IReadOnlyList<QueuedEvent> batch,
        string reason,
        CancellationToken cancellationToken)
    {
        var exhaustedQueueIds = batch
            .Where(item => item.SendAttempts + 1 >= options.Queue.MaxSendAttempts)
            .Select(item => item.QueueId)
            .ToArray();

        if (exhaustedQueueIds.Length == 0)
        {
            return 0;
        }

        logger.LogWarning(
            "Quarantining {Count} queued events after reaching MaxSendAttempts={MaxSendAttempts}. Reason={Reason}.",
            exhaustedQueueIds.Length,
            options.Queue.MaxSendAttempts,
            reason);
        await queue.MarkPoisonAsync(exhaustedQueueIds, reason, cancellationToken);
        return exhaustedQueueIds.Length;
    }

    private async Task TrySendHeartbeatAsync(CancellationToken cancellationToken)
    {
        try
        {
            var heartbeat = new HeartbeatRequest
            {
                AgentId = options.AgentId,
                Hostname = hostname,
                AgentVersion = agentVersion,
                Os = Environment.OSVersion.VersionString,
                LastEventTime = runtimeState.LastEventTime,
                HostTimezone = HostTimezoneProvider.Current(),
                QueueDepth = await queue.CountAsync(cancellationToken),
                CpuPercent = null,
                MemoryMb = Convert.ToInt32(GC.GetTotalMemory(forceFullCollection: false) / 1024L / 1024L),
                ConfigHash = AgentConfigurationHasher.ComputeConfigurationHash(configFile.Path),
                QueueMetrics = await queue.GetMetricsAsync(runtimeState.LastSuccessfulSendTime, cancellationToken),
                SourceManifest = WindowsSourceManifest.Build(options.Channels, options.OptionalChannels),
                SourceHealth = await ProbeSourceHealthAsync(cancellationToken),
                TamperChecks = new TamperCheckSummary
                {
                    BinaryHash = AgentConfigurationHasher.ComputeFileHash(Environment.ProcessPath ?? string.Empty),
                    ConfigHash = AgentConfigurationHasher.ComputeConfigurationHash(configFile.Path),
                    AclStatus = "not_evaluated",
                    SignatureStatus = "not_evaluated"
                }
            };

            await client.SendHeartbeatAsync(heartbeat, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Heartbeat failed.");
        }
    }

    private async Task TrySendInventoryAsync(CancellationToken cancellationToken)
    {
        try
        {
            var snapshots = WindowsInventoryCollectors.CollectAllSnapshots(options.AgentId, hostname);
            await client.SendInventoryAsync(snapshots, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Inventory snapshot upload failed.");
        }
    }

    private async Task<IReadOnlyList<SourceHealthReport>> ProbeSourceHealthAsync(CancellationToken cancellationToken)
    {
        var manifest = WindowsSourceManifest.Build(options.Channels, options.OptionalChannels);
        var results = new List<SourceHealthReport>(manifest.Count);
        foreach (var source in manifest)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var report = await collector.ProbeChannelAsync(source, cancellationToken);
            var lastRecordId = await stateStore.GetLastRecordIdAsync(source.Channel!, cancellationToken);
            if (lastRecordId.HasValue)
            {
                var clearedDetected = report.NewestRecordId.HasValue && report.NewestRecordId.Value < lastRecordId.Value;
                var bookmarkGapDetected = report.OldestRecordId.HasValue && report.OldestRecordId.Value > lastRecordId.Value + 1;
                report = report with
                {
                    ClearedDetected = clearedDetected,
                    BookmarkGapDetected = bookmarkGapDetected,
                    GapDetected = clearedDetected || bookmarkGapDetected
                };
            }

            results.Add(report);
        }

        return results;
    }

    private static bool IsPayloadTooLarge(HttpRequestException exception) =>
        exception.Message.Contains("413", StringComparison.OrdinalIgnoreCase)
        || exception.Message.Contains("Payload Too Large", StringComparison.OrdinalIgnoreCase);

    private static TimeSpan BackoffDelay(int consecutiveFailures)
    {
        var seconds = Math.Min(60, Math.Pow(2, Math.Min(consecutiveFailures, 6)));
        return TimeSpan.FromSeconds(seconds);
    }
}
