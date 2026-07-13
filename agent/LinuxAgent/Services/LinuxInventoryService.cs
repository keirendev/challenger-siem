using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Services;

public enum InventoryRunDecision { Started, NotDue, AlreadyRunning }

public sealed class InventorySchedule(TimeProvider timeProvider, TimeSpan interval, TimeSpan startupDelay)
{
    private readonly SemaphoreSlim singleFlight = new(1, 1);
    private DateTimeOffset nextDue = timeProvider.GetUtcNow().Add(startupDelay);

    public DateTimeOffset NextDue => nextDue;

    public async Task<InventoryRunDecision> TryRunDueAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        if (!await singleFlight.WaitAsync(0, cancellationToken)) return InventoryRunDecision.AlreadyRunning;
        try
        {
            if (timeProvider.GetUtcNow() < nextDue) return InventoryRunDecision.NotDue;
            nextDue = timeProvider.GetUtcNow().Add(interval);
            await action(cancellationToken);
            return InventoryRunDecision.Started;
        }
        finally { singleFlight.Release(); }
    }
}

public sealed class LinuxInventoryService(
    IOptions<LinuxAgentOptions> configured,
    ILinuxInventoryCollector collector,
    SiemIngestClient client,
    LinuxEnrollmentService enrollment,
    TimeProvider timeProvider,
    ILogger<LinuxInventoryService> logger) : BackgroundService
{
    private readonly LinuxAgentOptions options = configured.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await enrollment.EnsureAsync(GetVersion(), stoppingToken);
        var schedule = new InventorySchedule(
            timeProvider,
            TimeSpan.FromSeconds(options.InventoryIntervalSeconds),
            TimeSpan.FromSeconds(options.Inventory.StartupDelaySeconds));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await schedule.TryRunDueAsync(async cancellationToken =>
                {
                    var snapshots = await collector.CollectAsync(options.AgentId, Environment.MachineName, cancellationToken);
                    await client.SendInventoryAsync(snapshots, cancellationToken);
                }, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning("Linux inventory cycle failed ({ErrorType}); heartbeat and queue delivery remain independent.", ex.GetType().Name);
            }

            var untilDue = schedule.NextDue - timeProvider.GetUtcNow();
            var delay = untilDue <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : TimeSpan.FromSeconds(Math.Min(5, untilDue.TotalSeconds));
            await Task.Delay(delay, timeProvider, stoppingToken);
        }
    }

    private static string GetVersion() =>
        typeof(LinuxInventoryService).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion ?? "0.0.0";
}
