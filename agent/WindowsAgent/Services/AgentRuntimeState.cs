namespace Challenger.Siem.WindowsAgent.Services;

public sealed class AgentRuntimeState
{
    private readonly object gate = new();
    private DateTimeOffset? lastEventTime;
    private DateTimeOffset? lastSuccessfulSendTime;

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

    public DateTimeOffset? LastSuccessfulSendTime
    {
        get
        {
            lock (gate)
            {
                return lastSuccessfulSendTime;
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

    public void ObserveSuccessfulSend()
    {
        lock (gate)
        {
            lastSuccessfulSendTime = DateTimeOffset.UtcNow;
        }
    }
}
