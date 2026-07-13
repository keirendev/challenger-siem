using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Storage;

public sealed class ManagedRetentionHostedService(IServiceScopeFactory scopeFactory, IOptions<ManagedRetentionOptions> options, ILogger<ManagedRetentionHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var configured = options.Value;
        if (!configured.Enabled || !configured.HostedServiceEnabled)
        {
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(Math.Clamp(configured.HostedServiceIntervalMinutes, 5, 1440)));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var repository = scope.ServiceProvider.GetRequiredService<RetentionRepository>();
                var latestOptions = scope.ServiceProvider.GetRequiredService<IOptions<ManagedRetentionOptions>>().Value;
                var admin = scope.ServiceProvider.GetRequiredService<AdminRepository>();
                var effectiveOptions = await admin.GetEffectiveRetentionOptionsAsync(latestOptions, stoppingToken);
                await repository.RunAsync(effectiveOptions, new RetentionRunRequest(DryRun: false), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Managed telemetry retention pass failed; the next scheduled pass can resume idempotently.");
            }
        }
    }
}
