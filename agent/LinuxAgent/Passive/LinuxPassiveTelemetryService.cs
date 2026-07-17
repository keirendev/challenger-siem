using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxPassiveTelemetryService(
    IOptions<LinuxAgentOptions> configured,
    LinuxPassiveTelemetryCollector collector,
    LinuxPassiveTelemetryRuntime runtime,
    IEventQueue queue,
    TimeProvider timeProvider,
    ILogger<LinuxPassiveTelemetryService> logger) : BackgroundService
{
    private readonly LinuxAgentOptions options = configured.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!runtime.IsEnabledAndApproved)
        {
            if (runtime.CleanupRequested)
            {
                try
                {
                    await runtime.CleanupIfDisabledAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    logger.LogWarning("Linux passive telemetry cleanup failed ({ErrorType}); no collection or queue access was attempted.", ex.GetType().Name);
                }
            }
            return;
        }

        try
        {
            await queue.InitializeAsync(stoppingToken);
            await runtime.InitializeAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            logger.LogWarning("Linux passive telemetry initialization failed ({ErrorType}); other agent services remain independent.", ex.GetType().Name);
            return;
        }
        if (!runtime.IsReady) return;
        var startup = TimeSpan.FromSeconds(options.PassiveTelemetry.StartupDelaySeconds);
        var processSchedule = new PassiveSchedule(timeProvider, TimeSpan.FromSeconds(options.PassiveTelemetry.ProcessPollIntervalSeconds), startup);
        var networkSchedule = new PassiveSchedule(timeProvider, TimeSpan.FromSeconds(options.PassiveTelemetry.NetworkPollIntervalSeconds), startup);
        var metricsSchedule = new PassiveSchedule(timeProvider, TimeSpan.FromSeconds(options.PassiveTelemetry.HostMetricsIntervalSeconds), startup);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await processSchedule.TryRunDueAsync(
                    token => CollectAsync(
                        LinuxTelemetrySourceIds.ProcessSnapshotDiff,
                        (state, cancellation) => collector.CollectProcessesAsync(state, options.AgentId, Environment.MachineName, cancellation),
                        token),
                    stoppingToken);
                await networkSchedule.TryRunDueAsync(
                    token => CollectAsync(
                        LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff,
                        (state, cancellation) => collector.CollectNetworkAsync(state, options.AgentId, Environment.MachineName, cancellation),
                        token),
                    stoppingToken);
                await metricsSchedule.TryRunDueAsync(
                    token => CollectAsync(
                        LinuxTelemetrySourceIds.HostBehaviourMetrics,
                        (state, cancellation) => collector.CollectMetricsAsync(state, options.AgentId, Environment.MachineName, cancellation),
                        token),
                    stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(
                    "Linux passive telemetry cycle failed ({ErrorType}); journal collection, heartbeat, and queue delivery remain independent.",
                    ex.GetType().Name);
            }

            var delay = runtime.IsEnabledAndApproved
                ? MinDelay(processSchedule.DelayUntilDue(), networkSchedule.DelayUntilDue(), metricsSchedule.DelayUntilDue())
                : TimeSpan.FromSeconds(30);
            await Task.Delay(delay, timeProvider, stoppingToken);
        }
    }

    private async Task CollectAsync(
        string sourceId,
        Func<LinuxPassiveTelemetryState, CancellationToken, Task<PassiveCollectionResult>> collect,
        CancellationToken cancellationToken)
    {
        var queueMetrics = await queue.GetMetricsAsync(null, cancellationToken);
        var rowPressure = (long)queueMetrics.QueueDepth + options.PassiveTelemetry.MaxEventsPerScan
            > options.PassiveTelemetry.QueuePauseDepth;
        var byteHeadroom = HasPassiveByteHeadroom(queueMetrics, options);
        if (rowPressure || !byteHeadroom)
        {
            await runtime.RecordPressureAsync(
                sourceId,
                queueMetrics.QueueDepth,
                queueMetrics.QueueSizeBytes,
                rowPressure ? "row_headroom" : "byte_headroom",
                cancellationToken);
            return;
        }

        var result = await collect(runtime.CurrentState, cancellationToken);
        await runtime.CommitCollectionAsync(
            result,
            async (events, token) =>
            {
                foreach (var envelope in events) await queue.EnqueueAsync(envelope, token);
            },
            cancellationToken);
    }

    internal static bool HasPassiveByteHeadroom(QueueSloMetrics metrics, LinuxAgentOptions options)
    {
        if (metrics.QueueSizeBytes is not { } currentBytes
            || metrics.MaxSizeBytes is not { } maximumBytes
            || currentBytes < 0
            || maximumBytes <= 0)
        {
            return false;
        }

        var passiveLimit = Math.Min(maximumBytes, options.PassiveQueueByteLimit());
        var passiveBatch = options.PassiveMaximumEstimatedBatchBytes();
        return currentBytes <= passiveLimit && passiveBatch <= passiveLimit - currentBytes;
    }

    private static TimeSpan MinDelay(params TimeSpan[] values)
    {
        var minimum = values.Min();
        if (minimum <= TimeSpan.Zero) return TimeSpan.FromSeconds(1);
        return minimum > TimeSpan.FromSeconds(5) ? TimeSpan.FromSeconds(5) : minimum;
    }
}

public sealed class PassiveSchedule(TimeProvider timeProvider, TimeSpan interval, TimeSpan startupDelay)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private DateTimeOffset nextDue = timeProvider.GetUtcNow().Add(startupDelay);

    public async Task TryRunDueAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        if (timeProvider.GetUtcNow() < nextDue) return;
        if (!await gate.WaitAsync(0, cancellationToken)) return;
        try
        {
            if (timeProvider.GetUtcNow() < nextDue) return;
            await action(cancellationToken);
        }
        finally
        {
            nextDue = timeProvider.GetUtcNow().Add(interval);
            gate.Release();
        }
    }

    public TimeSpan DelayUntilDue()
    {
        var remaining = nextDue - timeProvider.GetUtcNow();
        return remaining <= TimeSpan.Zero ? TimeSpan.Zero : remaining;
    }
}
