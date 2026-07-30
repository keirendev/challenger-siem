namespace Challenger.Siem.LinuxAgent.Services;

internal sealed class RuntimeWarningThrottle(TimeProvider timeProvider, TimeSpan interval)
{
    private readonly object sync = new();
    private DateTimeOffset nextWarningAt = DateTimeOffset.MinValue;

    public bool TryAcquire()
    {
        var now = timeProvider.GetUtcNow();
        lock (sync)
        {
            if (now < nextWarningAt)
            {
                return false;
            }

            nextWarningAt = now + interval;
            return true;
        }
    }
}
