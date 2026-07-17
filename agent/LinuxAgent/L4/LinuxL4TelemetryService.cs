using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.L4;

public sealed class LinuxL4TelemetryService(
    IOptions<LinuxAgentOptions> configured,
    LinuxL4TelemetryRuntime runtime,
    TimeProvider timeProvider,
    ILogger<LinuxL4TelemetryService> logger) : BackgroundService
{
    private readonly LinuxAgentOptions options = configured.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await runtime.InitializeAsync(stoppingToken);
            if (!runtime.IsEnabledAndApproved)
            {
                await runtime.CleanupIfDisabledAsync(stoppingToken);
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(options.L4Telemetry.StartupDelaySeconds), timeProvider, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        catch (Exception ex)
        {
            logger.LogWarning("Linux L4 telemetry initialization failed ({ErrorType}); lower-level collection remains independent.", ex.GetType().Name);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await runtime.CollectPendingPolicyAsync(stoppingToken);
                await runtime.CollectSloAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning("Linux L4 SLO cycle failed ({ErrorType}); journal, inventory, heartbeat, and queue delivery remain independent.", ex.GetType().Name);
            }
            await Task.Delay(TimeSpan.FromSeconds(options.L4Telemetry.SloSampleIntervalSeconds), timeProvider, stoppingToken);
        }
    }
}
