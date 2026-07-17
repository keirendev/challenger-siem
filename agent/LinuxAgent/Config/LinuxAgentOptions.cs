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
    public PassiveTelemetryOptions PassiveTelemetry { get; set; } = new();
    public L4TelemetryOptions L4Telemetry { get; set; } = new();
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
        && Journal.TargetCoverageLevel is >= WindowsCoverageLevel.L1 and <= WindowsCoverageLevel.L4
        && Journal.DeclaredRoles is { Length: <= 16 }
        && Journal.DeclaredRoles.Distinct(StringComparer.Ordinal).Count() == Journal.DeclaredRoles.Length
        && Journal.DeclaredRoles.All(role => role.Length is >= 1 and <= 64
            && role.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-'))
        && (Journal.TargetCoverageLevel < WindowsCoverageLevel.L4
            || Journal.DeclaredRoles.Length > 0
                && Journal.DeclaredRoles.All(LinuxDeclaredRoles.IsKnown));

    public bool HasValidSelfIntegrityBounds() =>
        SelfIntegrity.IntervalSeconds >= MinimumInventoryIntervalSeconds
        && SelfIntegrity.StartupDelaySeconds is >= 0 and <= 300
        && SelfIntegrity.ScanTimeoutSeconds is >= 5 and <= 30
        && SelfIntegrity.QueuePauseDepth is >= 100 and <= 1_000_000
        && SelfIntegrity.MaxEventsPerScan is >= 1 and <= 20
        && (string.IsNullOrWhiteSpace(SelfIntegrity.ApprovedPlanHash) || SelfIntegrity.ApprovedPlanHash.StartsWith("sha256:", StringComparison.Ordinal));

    public bool HasValidQueueBounds() =>
        Queue.MaxSizeMb is >= 1 and <= 1_048_576
        && Queue.MaxSendAttempts is >= 1 and <= 1_000
        && Queue.MaxBackoffSeconds is >= 1 and <= 86_400
        && Queue.WarningSizePercent is >= 1 and <= 95;

    public bool HasValidPassiveTelemetryBounds() =>
        PassiveTelemetry.StartupDelaySeconds is >= 0 and <= 300
        && PassiveTelemetry.ProcessPollIntervalSeconds is >= 5 and <= 300
        && PassiveTelemetry.NetworkPollIntervalSeconds is >= 5 and <= 300
        && PassiveTelemetry.HostMetricsIntervalSeconds is >= 10 and <= 3600
        && PassiveTelemetry.ScanTimeoutSeconds is >= 1 and <= 30
        && 2 * PassiveTelemetry.ScanTimeoutSeconds <= PassiveTelemetry.ProcessPollIntervalSeconds
        && 2 * PassiveTelemetry.ScanTimeoutSeconds <= PassiveTelemetry.NetworkPollIntervalSeconds
        && PassiveTelemetry.ScanTimeoutSeconds < PassiveTelemetry.HostMetricsIntervalSeconds
        && HasValidQueueBounds()
        && PassiveTelemetry.QueuePauseDepth is >= 100 and <= 1_000_000
        && PassiveTelemetry.QueuePauseDepth <= Journal.QueuePauseDepth
        && PassiveTelemetry.MaxProcessesPerScan is >= 1 and <= 4096
        && PassiveTelemetry.MaxSocketsPerScan is >= 1 and <= 8192
        && PassiveTelemetry.MaxEventsPerScan is >= 1 and <= 5_000
        && PassiveTelemetry.MaxEventsPerScan <= PassiveTelemetry.QueuePauseDepth
        && PassiveTelemetry.MaxProcessReadBytesPerScan is >= 1024 * 1024 and <= 64 * 1024 * 1024
        && PassiveTelemetry.MaxNetworkReadBytesPerScan is >= 256 * 1024 and <= 16 * 1024 * 1024
        && PassiveTelemetry.MaxCommandLineBytes is >= 256 and <= 4096
        && PassiveTelemetry.MaxRawEventBytes is >= 4096 and <= 32 * 1024
        && PassiveMaximumEstimatedBatchBytes() <= PassiveQueueByteLimit()
        && IsSafePassiveTelemetryStatePath(PassiveTelemetry.StatePath)
        && (string.IsNullOrWhiteSpace(PassiveTelemetry.ApprovedPlanHash)
            || PassiveTelemetry.ApprovedPlanHash.StartsWith("sha256:", StringComparison.Ordinal));

    public bool HasValidL4TelemetryBounds() =>
        L4Telemetry.StartupDelaySeconds is >= 0 and <= 300
        && L4Telemetry.PostureIntervalSeconds is >= 300 and <= 3600
        && L4Telemetry.PostureIntervalSeconds >= InventoryIntervalSeconds
        && L4Telemetry.SloSampleIntervalSeconds is >= 30 and <= 240
        && L4Telemetry.SloWindowMinutes is >= 10 and <= 60
        && L4Telemetry.ScanTimeoutSeconds is >= 1 and <= 30
        && L4Telemetry.SloSampleIntervalSeconds + L4Telemetry.ScanTimeoutSeconds <= 270
        && L4Telemetry.ScanTimeoutSeconds < L4Telemetry.PostureIntervalSeconds
        && L4Telemetry.ScanTimeoutSeconds < L4Telemetry.SloSampleIntervalSeconds
        && L4Telemetry.QueuePauseDepth is >= 100 and <= 1_000_000
        && L4Telemetry.QueuePauseDepth <= PassiveTelemetry.QueuePauseDepth
        && L4Telemetry.MaxEventsPerScan is >= 7 and <= 500
        && L4Telemetry.MaxEventsPerScan <= L4Telemetry.QueuePauseDepth
        && IsSafeL4TelemetryStatePath(L4Telemetry.StatePath)
        && IsOptionalSha256(L4Telemetry.ApprovedPlanHash)
        && IsOptionalSha256(L4Telemetry.ApprovedBaselineHash)
        && (!L4Telemetry.Enabled || HasValidL4ActivationBounds());

    public bool HasValidL4ActivationBounds() =>
        HeartbeatIntervalSeconds > 0
        && HasValidJournalBounds()
        && (long)L4Telemetry.SloSampleIntervalSeconds + L4Telemetry.ScanTimeoutSeconds + HeartbeatIntervalSeconds <= 270
        && (long)L4Telemetry.PostureIntervalSeconds + Inventory.CollectionTimeoutSeconds + HeartbeatIntervalSeconds <= 6_900
        && Journal.TargetCoverageLevel == WindowsCoverageLevel.L4
        && Journal.Enabled
        && Journal.DeclaredRoles is { Length: > 0 }
        && Journal.DeclaredRoles.All(LinuxDeclaredRoles.IsKnown);

    public long PassiveQueueByteLimit()
    {
        if (!HasValidQueueBounds()) return 0;
        var maximumBytes = SaturatingMultiply(Queue.MaxSizeMb, 1024L * 1024);
        var softLimit = SaturatingMultiply(maximumBytes, Queue.WarningSizePercent) / 100;
        var journalPerRecord = SaturatingMultiply(
            SaturatingAdd(Journal.MaxInputRecordBytes, 32L * 1024),
            2);
        var journalReserve = SaturatingMultiply(Journal.MaxRecordsPerPoll, journalPerRecord);
        var journalHeadroomLimit = Math.Max(0, maximumBytes - Math.Min(maximumBytes, journalReserve));
        return Math.Min(softLimit, journalHeadroomLimit);
    }

    public long PassiveMaximumEstimatedBatchBytes()
    {
        var perEvent = SaturatingMultiply(
            SaturatingAdd(
                SaturatingAdd(PassiveTelemetry.MaxRawEventBytes,
                    SaturatingMultiply(PassiveTelemetry.MaxCommandLineBytes, 3)),
                32L * 1024),
            2);
        return SaturatingMultiply(PassiveTelemetry.MaxEventsPerScan, perEvent);
    }

    private static long SaturatingAdd(long left, long right) =>
        left <= 0 ? Math.Max(0, right) : right <= 0 ? left : left > long.MaxValue - right ? long.MaxValue : left + right;

    private static long SaturatingMultiply(long left, long right) =>
        left <= 0 || right <= 0 ? 0 : left > long.MaxValue / right ? long.MaxValue : left * right;

    private static bool IsSafePassiveTelemetryStatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        try
        {
            return string.Equals(
                Path.GetFullPath(path),
                "/var/lib/challenger-siem-agent/passive-telemetry-state.json",
                StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsSafeL4TelemetryStatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        try
        {
            return string.Equals(
                Path.GetFullPath(path),
                "/var/lib/challenger-siem-agent/l4-telemetry-state.json",
                StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsOptionalSha256(string? value) =>
        string.IsNullOrWhiteSpace(value)
        || value.Length == 71
            && value.StartsWith("sha256:", StringComparison.Ordinal)
            && value.AsSpan(7).ToString().All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public static class LinuxDeclaredRoles
{
    public static readonly IReadOnlySet<string> Known = new HashSet<string>(StringComparer.Ordinal)
    {
        "general_server",
        "workstation",
        "ssh_server",
        "bastion",
        "web_server",
        "database_server",
        "dns_server",
        "file_server",
        "container_host",
        "identity_server"
    };

    public static bool IsKnown(string role) => Known.Contains(role);
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
    public bool IncludeAccessibleUserJournals { get; set; }
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

public sealed class PassiveTelemetryOptions
{
    public bool Enabled { get; set; }
    public string ApprovedPlanHash { get; set; } = string.Empty;
    public int StartupDelaySeconds { get; set; } = 30;
    public int ProcessPollIntervalSeconds { get; set; } = 15;
    public int NetworkPollIntervalSeconds { get; set; } = 15;
    public int HostMetricsIntervalSeconds { get; set; } = 60;
    public int ScanTimeoutSeconds { get; set; } = 5;
    public int QueuePauseDepth { get; set; } = 50_000;
    public int MaxProcessesPerScan { get; set; } = 4096;
    public int MaxSocketsPerScan { get; set; } = 8192;
    public int MaxEventsPerScan { get; set; } = 500;
    public int MaxProcessReadBytesPerScan { get; set; } = 16 * 1024 * 1024;
    public int MaxNetworkReadBytesPerScan { get; set; } = 4 * 1024 * 1024;
    public int MaxCommandLineBytes { get; set; } = 4096;
    public int MaxRawEventBytes { get; set; } = 16 * 1024;
    public bool CleanupStateOnDisable { get; set; }
    public string StatePath { get; set; } = "/var/lib/challenger-siem-agent/passive-telemetry-state.json";
}

public sealed class L4TelemetryOptions
{
    public bool Enabled { get; set; }
    public string ApprovedPlanHash { get; set; } = string.Empty;
    public string ApprovedBaselineHash { get; set; } = string.Empty;
    public int StartupDelaySeconds { get; set; } = 60;
    public int PostureIntervalSeconds { get; set; } = 3600;
    public int SloSampleIntervalSeconds { get; set; } = 60;
    public int SloWindowMinutes { get; set; } = 15;
    public int ScanTimeoutSeconds { get; set; } = 10;
    public int QueuePauseDepth { get; set; } = 25_000;
    public int MaxEventsPerScan { get; set; } = 100;
    public bool CleanupStateOnDisable { get; set; }
    public string StatePath { get; set; } = "/var/lib/challenger-siem-agent/l4-telemetry-state.json";
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
