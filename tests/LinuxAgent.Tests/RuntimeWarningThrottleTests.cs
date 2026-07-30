using Challenger.Siem.LinuxAgent.Services;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class RuntimeWarningThrottleTests
{
    [Fact]
    public void RepeatedFailuresProduceAtMostOneWarningPerInterval()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 7, 30, 0, 0, 0, TimeSpan.Zero));
        var throttle = new RuntimeWarningThrottle(time, TimeSpan.FromMinutes(1));

        Assert.True(throttle.TryAcquire());
        Assert.False(throttle.TryAcquire());
        time.Advance(TimeSpan.FromSeconds(59));
        Assert.False(throttle.TryAcquire());
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(throttle.TryAcquire());
    }

    private sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset current = value;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan duration) => current += duration;
    }
}
