namespace Challenger.Siem.WindowsAgent.Services;

public sealed class AgentRuntimeState
{
    private readonly object gate = new();
    private DateTimeOffset? lastEventTime;

    public DateTimeOffset? LastEventTime
    {
        get
        {
            lock (gate)
            {
                return lastEventTime;
            }
        }
    }

    public void ObserveEventTime(DateTimeOffset eventTime)
    {
        lock (gate)
        {
            if (lastEventTime is null || eventTime > lastEventTime)
            {
                lastEventTime = eventTime;
            }
        }
    }
}
