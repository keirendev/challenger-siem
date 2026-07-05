namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentOptions
{
    public const string SectionName = "SocAgent";

    public bool Enabled { get; set; } = true;
    public string Provider { get; set; } = "Local";
    public string Model { get; set; } = "soc-agent-local-v1";
    public int MaxEvents { get; set; } = 5;
    public int MaxAgents { get; set; } = 10;
    public int MaxAlerts { get; set; } = 10;
    public bool RequireApprovalForMutations { get; set; } = true;
}
