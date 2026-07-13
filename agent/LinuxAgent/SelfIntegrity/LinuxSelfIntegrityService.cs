using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.SelfIntegrity;

public sealed class LinuxSelfIntegrityService(
    IOptions<LinuxAgentOptions> configured,
    LinuxSelfIntegrityCollector collector,
    LinuxSelfIntegrityRuntime runtime,
    IEventQueue queue,
    TimeProvider timeProvider,
    ILogger<LinuxSelfIntegrityService> logger) : BackgroundService
{
    private readonly LinuxAgentOptions options = configured.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await runtime.InitializeAsync(stoppingToken);
        var schedule = new SelfIntegritySchedule(
            timeProvider,
            TimeSpan.FromSeconds(options.SelfIntegrity.IntervalSeconds),
            TimeSpan.FromSeconds(options.SelfIntegrity.StartupDelaySeconds));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!runtime.IsEnabledAndApproved)
                {
                    await runtime.CleanupIfDisabledAsync(stoppingToken);
                }
                else
                {
                    await schedule.TryRunDueAsync(async cancellationToken =>
                    {
                        var previous = runtime.CurrentState;
                        var depth = await queue.CountAsync(cancellationToken);
                        var result = depth >= options.SelfIntegrity.QueuePauseDepth
                            ? collector.BuildPressureGap(previous, options.AgentId, Environment.MachineName, depth)
                            : await collector.CollectAsync(previous, options.AgentId, Environment.MachineName, cancellationToken);

                        foreach (var collected in result.Events)
                        {
                            await queue.EnqueueAsync(collected.Envelope, cancellationToken);
                        }
                        await runtime.RecordCollectedAsync(result, cancellationToken);
                    }, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning("Linux self-integrity snapshot cycle failed ({ErrorType}); L1/L2 journal collection and queue delivery remain independent.", ex.GetType().Name);
            }

            var delay = runtime.IsEnabledAndApproved
                ? schedule.DelayUntilDue()
                : TimeSpan.FromSeconds(30);
            await Task.Delay(delay, timeProvider, stoppingToken);
        }
    }
}

public sealed class SelfIntegritySchedule(TimeProvider timeProvider, TimeSpan interval, TimeSpan startupDelay)
{
    private readonly SemaphoreSlim singleFlight = new(1, 1);
    private DateTimeOffset nextDue = timeProvider.GetUtcNow().Add(startupDelay);

    public async Task TryRunDueAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        if (timeProvider.GetUtcNow() < nextDue) return;
        if (!await singleFlight.WaitAsync(0, cancellationToken)) return;
        try
        {
            if (timeProvider.GetUtcNow() < nextDue) return;
            nextDue = timeProvider.GetUtcNow().Add(interval);
            await action(cancellationToken);
        }
        finally { singleFlight.Release(); }
    }

    public TimeSpan DelayUntilDue()
    {
        var untilDue = nextDue - timeProvider.GetUtcNow();
        return untilDue <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : TimeSpan.FromSeconds(Math.Min(5, untilDue.TotalSeconds));
    }
}
