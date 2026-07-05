using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Review;

public sealed record DashboardSummary(
    long ActiveAgents,
    long RecentActiveAgents,
    long StaleActiveAgents,
    long RetiredAgents,
    long HistoricalAgents,
    long AgentsWithQueuedEvents,
    long RecentEventCount,
    DateTimeOffset? LatestIngestTime)
{
    public static DashboardSummary Empty { get; } = new(0, 0, 0, 0, 0, 0, 0, null);
}

public sealed record AgentInventoryQuery(
    string? Hostname,
    string? AgentId,
    string? Health,
    string? Status);

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

public sealed record StaleAgentCleanupPreview(
    DateTimeOffset Cutoff,
    long CandidateCount,
    IReadOnlyList<string> SampleAgentIds)
{
    public static StaleAgentCleanupPreview Empty { get; } = new(DateTimeOffset.MinValue, 0, Array.Empty<string>());
}

public sealed record StaleAgentCleanupSummary(
    DateTimeOffset Cutoff,
    long CandidateCount,
    long DisabledCount,
    long SkippedRecentCount,
    IReadOnlyList<string> SampleAgentIds);

public sealed record DatabaseStatus(bool IsConnected, string Message)
{
    public static DatabaseStatus Connected { get; } = new(true, "connected");
}
