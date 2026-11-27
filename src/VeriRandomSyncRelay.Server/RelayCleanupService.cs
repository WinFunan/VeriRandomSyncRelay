using Microsoft.Extensions.Options;

namespace VeriRandomSyncRelay.Server;

public sealed class RelayCleanupService(
    RelayStore store,
    IOptions<RelayOptions> options,
    ILogger<RelayCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, options.Value.CleanupIntervalSeconds));
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                var removed = store.RemoveExpired();
                if (removed > 0)
                    logger.LogInformation("Removed {Count} expired transfers", removed);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }
}
