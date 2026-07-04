using System.Reflection;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Collectors;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Queue;
using Challenger.Siem.WindowsAgent.State;
using Challenger.Siem.WindowsAgent.Transport;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.WindowsAgent.Services;

public sealed class AgentWorker(
    IOptions<AgentOptions> options,
    IWindowsEventCollector collector,
    IChannelStateStore stateStore,
    IEventQueue queue,
    SiemIngestClient client,
    AgentRuntimeState runtimeState,
    ILogger<AgentWorker> logger) : BackgroundService
{
    private readonly AgentOptions options = options.Value;
    private readonly string hostname = Environment.MachineName;
    private readonly string agentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.1.0";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Challenger SIEM agent starting for agent {AgentId}.", options.AgentId);
        await queue.InitializeAsync(stoppingToken);

        var nextHeartbeat = DateTimeOffset.MinValue;
        var consecutiveFailures = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var collected = await CollectConfiguredChannelsAsync(stoppingToken);
                var sent = await DrainQueueAsync(stoppingToken);

                if (collected > 0 || sent > 0)
                {
                    logger.LogInformation("Agent cycle completed. Collected={Collected}, SentOrDeduplicated={Sent}.", collected, sent);
                }

                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    await TrySendHeartbeatAsync(stoppingToken);
                    nextHeartbeat = DateTimeOffset.UtcNow.AddSeconds(options.HeartbeatIntervalSeconds);
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

            var acknowledgement = await client.SendBatchAsync(batch.Select(item => item.Envelope).ToArray(), cancellationToken);
            var acknowledged = acknowledgement.Accepted + acknowledgement.Duplicates;
            if (acknowledgement.Rejected == 0 && acknowledged >= batch.Count)
            {
                await queue.DeleteAsync(batch.Select(item => item.QueueId).ToArray(), cancellationToken);
                sentOrDeduplicated += acknowledged;
                continue;
            }

            logger.LogWarning(
                "Server did not acknowledge the full batch. Accepted={Accepted}, Duplicates={Duplicates}, Rejected={Rejected}, BatchSize={BatchSize}.",
                acknowledgement.Accepted,
                acknowledgement.Duplicates,
                acknowledgement.Rejected,
                batch.Count);
            break;
        }

        return sentOrDeduplicated;
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
                QueueDepth = await queue.CountAsync(cancellationToken),
                CpuPercent = null,
                MemoryMb = Convert.ToInt32(GC.GetTotalMemory(forceFullCollection: false) / 1024L / 1024L)
            };

            await client.SendHeartbeatAsync(heartbeat, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Heartbeat failed.");
        }
    }

    private static TimeSpan BackoffDelay(int consecutiveFailures)
    {
        var seconds = Math.Min(60, Math.Pow(2, Math.Min(consecutiveFailures, 6)));
        return TimeSpan.FromSeconds(seconds);
    }
}
