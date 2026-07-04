namespace Challenger.Siem.WindowsAgent.Config;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public string AgentId { get; set; } = string.Empty;
    public Uri? ServerBaseUrl { get; set; }
    public string ApiToken { get; set; } = string.Empty;
    public EnrollmentOptions Enrollment { get; set; } = new();
    public IReadOnlyList<string> Channels { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> OptionalChannels { get; set; } = Array.Empty<string>();
    public bool StartAtEndWhenNoState { get; set; } = true;
    public int PollIntervalSeconds { get; set; } = 10;
    public int HeartbeatIntervalSeconds { get; set; } = 60;
    public BatchingOptions Batching { get; set; } = new();
    public QueueOptions Queue { get; set; } = new();
    public StateOptions State { get; set; } = new();
}

public sealed class EnrollmentOptions
{
    public bool Enabled { get; set; }
    public string EnrollmentToken { get; set; } = string.Empty;
    public string? MachineGuid { get; set; }
}

public sealed class BatchingOptions
{
    public int MaxEvents { get; set; } = 100;
    public int MaxIntervalSeconds { get; set; } = 10;
}

public sealed class QueueOptions
{
    public string Path { get; set; } = @"C:\ProgramData\ChallengerSIEM\Agent\queue.sqlite";
    public int MaxSizeMb { get; set; } = 512;
    public int MaxSendAttempts { get; set; } = 10;
    public int MaxBackoffSeconds { get; set; } = 300;
    public int WarningSizePercent { get; set; } = 80;
}

public sealed class StateOptions
{
    public string Path { get; set; } = @"C:\ProgramData\ChallengerSIEM\Agent\state.json";
}
