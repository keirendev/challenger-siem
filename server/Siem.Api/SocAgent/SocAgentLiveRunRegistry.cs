using System.Collections.Concurrent;
using System.Threading.Channels;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.SocAgent;

public sealed record SocAgentLiveEvent(
    long Sequence,
    string Type,
    Guid RunId,
    Guid? SessionId,
    DateTimeOffset CreatedAt,
    IReadOnlyDictionary<string, object?> Data);

public sealed class SocAgentLiveRunRegistry
{
    private const int MaxRetainedCompletedRuns = 128;
    private static readonly TimeSpan CompletedRunRetention = TimeSpan.FromMinutes(30);

    private readonly ConcurrentDictionary<Guid, SocAgentLiveRunState> runs = new();
    private readonly ConcurrentDictionary<Guid, Guid> activeRunsBySession = new();

    public SocAgentLiveRunState CreateRun(SocAgentChatTurn turn)
    {
        if (activeRunsBySession.ContainsKey(turn.Session.SessionId))
        {
            throw new InvalidOperationException("A soc-agent run is already active for this session.");
        }

        var state = new SocAgentLiveRunState(Guid.NewGuid(), turn);
        if (!activeRunsBySession.TryAdd(turn.Session.SessionId, state.RunId))
        {
            throw new InvalidOperationException("A soc-agent run is already active for this session.");
        }

        if (!runs.TryAdd(state.RunId, state))
        {
            activeRunsBySession.TryRemove(turn.Session.SessionId, out _);
            throw new InvalidOperationException("The soc-agent run could not be registered.");
        }

        return state;
    }

    public bool TryGetRun(Guid runId, out SocAgentLiveRunState state) => runs.TryGetValue(runId, out state!);

    public bool TryGetActiveRunForSession(Guid sessionId, out SocAgentLiveRunState state)
    {
        state = null!;
        return activeRunsBySession.TryGetValue(sessionId, out var runId)
            && runs.TryGetValue(runId, out state!)
            && !state.IsCompleted;
    }

    public void CompleteRun(SocAgentLiveRunState state, string status)
    {
        state.Complete(status);
        activeRunsBySession.TryRemove(state.SessionId, out _);
        PruneCompletedRuns();
    }

    private void PruneCompletedRuns()
    {
        var cutoff = DateTimeOffset.UtcNow.Subtract(CompletedRunRetention);
        var completed = runs.Values
            .Where(run => run.IsCompleted)
            .OrderByDescending(run => run.CompletedAt ?? DateTimeOffset.MinValue)
            .ToArray();

        foreach (var run in completed.Where((run, index) => index >= MaxRetainedCompletedRuns || run.CompletedAt < cutoff))
        {
            runs.TryRemove(run.RunId, out _);
        }
    }
}

public sealed class SocAgentLiveRunState
{
    private readonly object gate = new();
    private readonly List<SocAgentLiveEvent> events = new();
    private readonly List<Channel<SocAgentLiveEvent>> subscribers = new();
    private long nextSequence;
    private string status = "running";

    public SocAgentLiveRunState(Guid runId, SocAgentChatTurn turn)
    {
        RunId = runId;
        Turn = turn;
        CancelSource = new CancellationTokenSource();
    }

    public Guid RunId { get; }

    public SocAgentChatTurn Turn { get; }

    public Guid SessionId => Turn.Session.SessionId;

    public CancellationTokenSource CancelSource { get; }

    public bool IsCompleted { get; private set; }

    public DateTimeOffset? CompletedAt { get; private set; }

    public string Status
    {
        get
        {
            lock (gate)
            {
                return status;
            }
        }
    }

    public long LastSequence
    {
        get
        {
            lock (gate)
            {
                return nextSequence;
            }
        }
    }

    public SocAgentLiveEvent Append(string type, IReadOnlyDictionary<string, object?> data)
    {
        SocAgentLiveEvent liveEvent;
        Channel<SocAgentLiveEvent>[] currentSubscribers;
        lock (gate)
        {
            liveEvent = new SocAgentLiveEvent(
                ++nextSequence,
                type,
                RunId,
                SessionId,
                DateTimeOffset.UtcNow,
                data);
            events.Add(liveEvent);
            if (events.Count > 256)
            {
                events.RemoveRange(0, events.Count - 256);
            }

            currentSubscribers = subscribers.ToArray();
        }

        foreach (var subscriber in currentSubscribers)
        {
            subscriber.Writer.TryWrite(liveEvent);
        }

        return liveEvent;
    }

    public bool RequestCancel()
    {
        bool shouldCancel;
        lock (gate)
        {
            shouldCancel = !IsCompleted && !CancelSource.IsCancellationRequested;
            if (shouldCancel)
            {
                status = "cancel_requested";
            }
        }

        if (!shouldCancel)
        {
            return false;
        }

        Append("run_cancel_requested", new Dictionary<string, object?>
        {
            ["status"] = "cancel_requested",
            ["message"] = "Cancellation requested by the operator."
        });
        CancelSource.Cancel();
        return true;
    }

    public IAsyncEnumerable<SocAgentLiveEvent> ReadEventsAsync(long afterSequence, CancellationToken cancellationToken)
    {
        var channel = Channel.CreateUnbounded<SocAgentLiveEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        lock (gate)
        {
            foreach (var liveEvent in events.Where(item => item.Sequence > afterSequence))
            {
                channel.Writer.TryWrite(liveEvent);
            }

            if (IsCompleted)
            {
                channel.Writer.TryComplete();
            }
            else
            {
                subscribers.Add(channel);
            }
        }

        var registration = cancellationToken.Register(() =>
        {
            lock (gate)
            {
                subscribers.Remove(channel);
            }

            channel.Writer.TryComplete();
        });

        return ReadChannelAsync(channel.Reader, registration, cancellationToken);
    }

    public void Complete(string completionStatus)
    {
        Channel<SocAgentLiveEvent>[] currentSubscribers;
        lock (gate)
        {
            if (IsCompleted)
            {
                return;
            }

            status = completionStatus;
            IsCompleted = true;
            CompletedAt = DateTimeOffset.UtcNow;
            currentSubscribers = subscribers.ToArray();
            subscribers.Clear();
        }

        foreach (var subscriber in currentSubscribers)
        {
            subscriber.Writer.TryComplete();
        }
    }

    private static async IAsyncEnumerable<SocAgentLiveEvent> ReadChannelAsync(
        ChannelReader<SocAgentLiveEvent> reader,
        CancellationTokenRegistration registration,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        try
        {
            while (await reader.WaitToReadAsync(cancellationToken))
            {
                while (reader.TryRead(out var liveEvent))
                {
                    yield return liveEvent;
                }
            }
        }
        finally
        {
            registration.Dispose();
        }
    }
}
