namespace Challenger.Siem.WindowsAgent.Config;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public string AgentId { get; init; } = string.Empty;
    public Uri? ServerBaseUrl { get; init; }
    public string ApiToken { get; init; } = string.Empty;
    public IReadOnlyList<string> Channels { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> OptionalChannels { get; init; } = Array.Empty<string>();
    public bool StartAtEndWhenNoState { get; init; } = true;
    public int PollIntervalSeconds { get; init; } = 10;
    public int HeartbeatIntervalSeconds { get; init; } = 60;
    public BatchingOptions Batching { get; init; } = new();
    public QueueOptions Queue { get; init; } = new();
    public StateOptions State { get; init; } = new();
}

public sealed class BatchingOptions
{
    public int MaxEvents { get; init; } = 100;
    public int MaxIntervalSeconds { get; init; } = 10;
}

public sealed class QueueOptions
{
    public string Path { get; init; } = @"C:\ProgramData\ChallengerSIEM\Agent\queue.sqlite";
    public int MaxSizeMb { get; init; } = 512;
}

public sealed class StateOptions
{
    public string Path { get; init; } = @"C:\ProgramData\ChallengerSIEM\Agent\state.json";
}
