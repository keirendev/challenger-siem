using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Review;

public sealed record DashboardSummary(
    long TotalAgents,
    long RecentAgents,
    long StaleAgents,
    long AgentsWithQueuedEvents,
    long RecentEventCount,
    DateTimeOffset? LatestIngestTime)
{
    public static DashboardSummary Empty { get; } = new(0, 0, 0, 0, 0, null);
}

public sealed record AgentInventoryQuery(
    string? Hostname,
    string? AgentId,
    string? Health);

public sealed record AgentInventoryItem(
    string AgentId,
    string Hostname,
    string? MachineGuid,
    string OsVersion,
    string AgentVersion,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    string Status,
    DateTimeOffset? LatestHeartbeatTime,
    int? LatestQueueDepth,
    DateTimeOffset? LastEventTime,
    bool IsStale,
    WindowsCoverageLevel CurrentCoverageLevel,
    string CoverageStatus,
    int MissingMandatorySources,
    int StaleSources,
    int ErrorSources);

public sealed record DatabaseStatus(bool IsConnected, string Message)
{
    public static DatabaseStatus Connected { get; } = new(true, "connected");
}
