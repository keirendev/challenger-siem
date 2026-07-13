using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Config;

public sealed class LinuxAgentOptions : IAgentTransportConfiguration
{
    public const string SectionName = "Agent";
    public const int MinimumInventoryIntervalSeconds = 300;

    public string AgentId { get; set; } = "";
    public Uri? ServerBaseUrl { get; set; }
    public string ApiToken { get; set; } = "";
    public string EnrollmentToken { get; set; } = "";
    public int HeartbeatIntervalSeconds { get; set; } = 60;
    public int InventoryIntervalSeconds { get; set; } = 3600;
    public int DrainBatchSize { get; set; } = 100;
    public InventoryOptions Inventory { get; set; } = new();
    public JournalOptions Journal { get; set; } = new();
    public SelfIntegrityOptions SelfIntegrity { get; set; } = new();
    public QueueOptions Queue { get; set; } = new();
    public StateOptions State { get; set; } = new();

    public bool HasValidInventoryBounds() =>
        InventoryIntervalSeconds >= MinimumInventoryIntervalSeconds
        && Inventory.StartupDelaySeconds is >= 0 and <= 300
        && Inventory.CollectionTimeoutSeconds is >= 10 and <= 300
        && Inventory.MaxSerializedBytes is >= 64 * 1024 and <= 512 * 1024;

    public bool HasValidJournalBounds() =>
        Journal.PollIntervalSeconds is >= 1 and <= 300
        && Journal.MaxRecordsPerPoll is >= 1 and <= 5000
        && Journal.MaxInputRecordBytes is >= 4096 and <= 262144
        && Journal.QueuePauseDepth is >= 100 and <= 1_000_000
        && Journal.TargetCoverageLevel is WindowsCoverageLevel.L1 or WindowsCoverageLevel.L2
        && Journal.DeclaredRoles is { Length: <= 16 }
        && Journal.DeclaredRoles.Distinct(StringComparer.Ordinal).Count() == Journal.DeclaredRoles.Length
        && Journal.DeclaredRoles.All(role => role.Length is >= 1 and <= 64
            && role.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-'));

    public bool HasValidSelfIntegrityBounds() =>
        SelfIntegrity.IntervalSeconds >= MinimumInventoryIntervalSeconds
        && SelfIntegrity.StartupDelaySeconds is >= 0 and <= 300
        && SelfIntegrity.ScanTimeoutSeconds is >= 5 and <= 30
        && SelfIntegrity.QueuePauseDepth is >= 100 and <= 1_000_000
        && SelfIntegrity.MaxEventsPerScan is >= 1 and <= 20
        && (string.IsNullOrWhiteSpace(SelfIntegrity.ApprovedPlanHash) || SelfIntegrity.ApprovedPlanHash.StartsWith("sha256:", StringComparison.Ordinal));
}

public sealed class InventoryOptions
{
    public int StartupDelaySeconds { get; set; } = 30;
    public int CollectionTimeoutSeconds { get; set; } = 120;
    public int MaxSerializedBytes { get; set; } = 256 * 1024;
}

public sealed class JournalOptions
{
    public bool Enabled { get; set; } = true;
    public WindowsCoverageLevel TargetCoverageLevel { get; set; } = WindowsCoverageLevel.L1;
    public string[] DeclaredRoles { get; set; } = Array.Empty<string>();
    public int PollIntervalSeconds { get; set; } = 5;
    public int MaxRecordsPerPoll { get; set; } = 500;
    public int MaxInputRecordBytes { get; set; } = 131072;
    public int QueuePauseDepth { get; set; } = 100000;
}

public sealed class SelfIntegrityOptions
{
    public bool Enabled { get; set; }
    public string ApprovedPlanHash { get; set; } = string.Empty;
    public int StartupDelaySeconds { get; set; } = 60;
    public int IntervalSeconds { get; set; } = 3600;
    public int ScanTimeoutSeconds { get; set; } = 30;
    public int QueuePauseDepth { get; set; } = 100000;
    public int MaxEventsPerScan { get; set; } = 20;
    public bool CleanupStateOnDisable { get; set; }
    public string StatePath { get; set; } = "/var/lib/challenger-siem-agent/self-integrity-state.json";
}

public sealed class QueueOptions
{
    public string Path { get; set; } = "/var/lib/challenger-siem-agent/queue.sqlite";
    public int MaxSizeMb { get; set; } = 512;
    public int MaxSendAttempts { get; set; } = 10;
    public int MaxBackoffSeconds { get; set; } = 300;
    public int WarningSizePercent { get; set; } = 80;
}

public sealed class StateOptions
{
    public string Path { get; set; } = "/var/lib/challenger-siem-agent/state.json";
}
