namespace Challenger.Siem.Agent.Core.Queue;

public sealed class AgentQueueOptions
{
    public string Path { get; init; } = string.Empty;
    public int MaxSizeMb { get; init; } = 512;
    public int MaxSendAttempts { get; init; } = 10;
    public int MaxBackoffSeconds { get; init; } = 300;
    public int WarningSizePercent { get; init; } = 80;
}
