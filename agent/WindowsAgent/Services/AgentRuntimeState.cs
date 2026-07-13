namespace Challenger.Siem.WindowsAgent.Services;

public sealed class AgentRuntimeState
{
    private readonly object gate = new();
    private DateTimeOffset? lastEventTime;
    private DateTimeOffset? lastSuccessfulSendTime;
    private DateTimeOffset? lastAttemptTime;
    private DateTimeOffset? lastFailedSendTime;
    private DateTimeOffset? lastRecoveryTime;
    private string sendState = Challenger.Siem.Contracts.V1.QueueSendStates.Unknown;
    private long? backoffSeconds;

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

    public QueueRuntimeSnapshot QueueSnapshot
    {
        get
        {
            lock (gate)
            {
                return new QueueRuntimeSnapshot(sendState, backoffSeconds, lastAttemptTime, lastFailedSendTime, lastSuccessfulSendTime, lastRecoveryTime);
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

    public void ObserveSendAttempt()
    {
        lock (gate)
        {
            lastAttemptTime = DateTimeOffset.UtcNow;
            sendState = Challenger.Siem.Contracts.V1.QueueSendStates.Sending;
            backoffSeconds = null;
        }
    }

    public void ObserveSendFailure(TimeSpan backoff)
    {
        lock (gate)
        {
            lastFailedSendTime = DateTimeOffset.UtcNow;
            sendState = Challenger.Siem.Contracts.V1.QueueSendStates.BackingOff;
            backoffSeconds = Math.Max(0, (long)Math.Ceiling(backoff.TotalSeconds));
        }
    }

    public void ObserveSuccessfulSend()
    {
        lock (gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (lastFailedSendTime.HasValue && (!lastSuccessfulSendTime.HasValue || lastFailedSendTime > lastSuccessfulSendTime))
            {
                lastRecoveryTime = now;
            }
            lastSuccessfulSendTime = now;
            sendState = lastFailedSendTime.HasValue && lastRecoveryTime == now
                ? Challenger.Siem.Contracts.V1.QueueSendStates.Recovering
                : Challenger.Siem.Contracts.V1.QueueSendStates.Succeeded;
            backoffSeconds = null;
        }
    }
}

public sealed record QueueRuntimeSnapshot(
    string SendState,
    long? BackoffSeconds,
    DateTimeOffset? LastAttemptTime,
    DateTimeOffset? LastFailedSendTime,
    DateTimeOffset? LastSuccessfulSendTime,
    DateTimeOffset? LastRecoveryTime);
