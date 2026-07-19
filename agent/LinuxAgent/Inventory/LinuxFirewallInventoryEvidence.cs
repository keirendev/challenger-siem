using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Inventory;

public static class LinuxFirewallInventoryStates
{
    public const string Unknown = "unknown";
    public const string Absent = "absent";
    public const string LoggingDisabled = "logging_disabled";
    public const string LoggingEnabled = "logging_enabled";
    public const string Unsupported = "unsupported";
    public const string PermissionDenied = "permission_denied";
    public const string Timeout = "timeout";
    public const string Malformed = "malformed";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Unknown,
        Absent,
        LoggingDisabled,
        LoggingEnabled,
        Unsupported,
        PermissionDenied,
        Timeout,
        Malformed
    };
}

public sealed record LinuxFirewallInventoryProbe(
    string Producer,
    bool Supported,
    InventorySourceState State,
    bool Present,
    bool Active,
    bool? LoggingEnabled,
    string ErrorCode);

public sealed record LinuxFirewallInventoryEvidence(
    string State,
    string Producer,
    string Reason)
{
    public const string SnapshotType = "linux_firewall";
    public const string StateKey = "firewall_evidence";
    public const string ProducerKey = "firewall_producer";
    public const string ReasonKey = "firewall_reason";
    public const string LoggingKey = "firewall_logging";

    private static readonly IReadOnlySet<string> Producers = new HashSet<string>(StringComparer.Ordinal)
    {
        "none",
        "unknown",
        "nftables",
        "firewalld",
        "ufw",
        "iptables"
    };

    private static readonly IReadOnlySet<string> Reasons = new HashSet<string>(StringComparer.Ordinal)
    {
        "firewall_inventory_not_observed",
        "firewall_inventory_snapshot_missing",
        "firewall_inventory_evidence_malformed",
        "supported_firewall_not_present",
        "firewall_logging_disabled",
        "firewall_logging_enabled",
        "firewall_producer_out_of_scope",
        "firewall_inventory_permission_denied",
        "firewall_inventory_timeout",
        "firewall_inventory_malformed",
        "firewall_logging_state_unverified"
    };

    public static LinuxFirewallInventoryEvidence Evaluate(IReadOnlyList<LinuxFirewallInventoryProbe> probes)
    {
        if (probes.Count == 0)
        {
            return new(
                LinuxFirewallInventoryStates.Unknown,
                "unknown",
                "firewall_inventory_not_observed");
        }

        var producers = probes
            .GroupBy(probe => probe.Producer, StringComparer.Ordinal)
            .Select(group => Combine(group.Key, group.ToArray()))
            .ToArray();

        var loggingEnabled = producers.FirstOrDefault(producer =>
            producer.Supported && producer.Active && producer.LoggingEnabled == true);
        if (loggingEnabled is not null)
        {
            return new(
                LinuxFirewallInventoryStates.LoggingEnabled,
                loggingEnabled.Producer,
                "firewall_logging_enabled");
        }

        var loggingDisabled = producers.FirstOrDefault(producer =>
            producer.Supported && producer.Active && producer.LoggingEnabled == false);
        if (loggingDisabled is not null)
        {
            return new(
                LinuxFirewallInventoryStates.LoggingDisabled,
                loggingDisabled.Producer,
                "firewall_logging_disabled");
        }

        var unresolvedActive = producers.FirstOrDefault(producer =>
            producer.Supported && producer.Active && producer.LoggingEnabled is null);
        if (unresolvedActive is not null)
        {
            return Failure(unresolvedActive);
        }

        var failure = producers
            .Where(producer => producer.HasUnresolvedFailure
                && !(producer.Present && !producer.Active))
            .OrderByDescending(producer => StatePriority(producer.FailureState))
            .FirstOrDefault();
        if (failure is not null)
        {
            return Failure(failure);
        }

        var unsupported = producers.FirstOrDefault(producer => !producer.Supported && producer.Active);
        if (unsupported is not null)
        {
            return new(
                LinuxFirewallInventoryStates.Unsupported,
                unsupported.Producer,
                "firewall_producer_out_of_scope");
        }

        var inactive = producers.FirstOrDefault(producer => producer.Supported && producer.Present && !producer.Active);
        if (inactive is not null)
        {
            return new(
                LinuxFirewallInventoryStates.LoggingDisabled,
                inactive.Producer,
                "firewall_logging_disabled");
        }

        return new(
            LinuxFirewallInventoryStates.Absent,
            "none",
            "supported_firewall_not_present");
    }

    public static LinuxFirewallInventoryEvidence FromSnapshots(IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var snapshot = snapshots.FirstOrDefault(item =>
            string.Equals(item.SnapshotType, SnapshotType, StringComparison.Ordinal));
        if (snapshot is null)
        {
            return new(
                LinuxFirewallInventoryStates.Unknown,
                "unknown",
                "firewall_inventory_snapshot_missing");
        }

        var state = snapshot.Summary.GetValueOrDefault(StateKey);
        var producer = snapshot.Summary.GetValueOrDefault(ProducerKey);
        var reason = snapshot.Summary.GetValueOrDefault(ReasonKey);
        var logging = snapshot.Summary.GetValueOrDefault(LoggingKey);
        if (state is null || !LinuxFirewallInventoryStates.All.Contains(state)
            || producer is null || !Producers.Contains(producer)
            || reason is null || !Reasons.Contains(reason)
            || !string.Equals(logging, LoggingState(state), StringComparison.Ordinal))
        {
            return new(
                LinuxFirewallInventoryStates.Malformed,
                "unknown",
                "firewall_inventory_evidence_malformed");
        }

        return new(state, producer, reason);
    }

    public IReadOnlyDictionary<string, string> AddTo(IReadOnlyDictionary<string, string> summary)
    {
        var augmented = new Dictionary<string, string>(summary, StringComparer.Ordinal)
        {
            ["state"] = CollectionState,
            ["error_code"] = CollectionState == "success" ? "none" : Reason,
            [StateKey] = State,
            [ProducerKey] = Producer,
            [ReasonKey] = Reason,
            [LoggingKey] = LoggingState(State)
        };
        return augmented;
    }

    public string Applicability => State switch
    {
        LinuxFirewallInventoryStates.LoggingDisabled or LinuxFirewallInventoryStates.LoggingEnabled => SourceApplicabilityStatuses.Applicable,
        LinuxFirewallInventoryStates.Absent => SourceApplicabilityStatuses.NotApplicable,
        LinuxFirewallInventoryStates.Unsupported => SourceApplicabilityStatuses.Unsupported,
        _ => SourceApplicabilityStatuses.Unknown
    };

    public string PrerequisiteStatus => State switch
    {
        LinuxFirewallInventoryStates.LoggingEnabled => SourceEvidenceStatuses.Satisfied,
        LinuxFirewallInventoryStates.LoggingDisabled => SourceEvidenceStatuses.Disabled,
        LinuxFirewallInventoryStates.Absent => SourceEvidenceStatuses.NotApplicable,
        LinuxFirewallInventoryStates.Unsupported => SourceEvidenceStatuses.Unsupported,
        LinuxFirewallInventoryStates.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
        LinuxFirewallInventoryStates.Timeout => SourceEvidenceStatuses.Stale,
        LinuxFirewallInventoryStates.Malformed => SourceEvidenceStatuses.Degraded,
        _ => SourceEvidenceStatuses.Unknown
    };

    private string CollectionState => State switch
    {
        LinuxFirewallInventoryStates.Absent => "not_applicable",
        LinuxFirewallInventoryStates.LoggingDisabled or LinuxFirewallInventoryStates.LoggingEnabled or LinuxFirewallInventoryStates.Unsupported => "success",
        LinuxFirewallInventoryStates.PermissionDenied => "permission_denied",
        LinuxFirewallInventoryStates.Timeout => "timeout",
        LinuxFirewallInventoryStates.Malformed => "malformed",
        _ => "unavailable"
    };

    private static string LoggingState(string state) => state switch
    {
        LinuxFirewallInventoryStates.LoggingEnabled => "enabled",
        LinuxFirewallInventoryStates.LoggingDisabled => "disabled",
        LinuxFirewallInventoryStates.Absent => "not_applicable",
        LinuxFirewallInventoryStates.Unsupported => "unsupported",
        _ => "unknown"
    };

    private static CombinedProducer Combine(string producer, IReadOnlyList<LinuxFirewallInventoryProbe> probes)
    {
        var successful = probes.Where(probe => probe.State == InventorySourceState.Success).ToArray();
        var supported = probes.Any(probe => probe.Supported);
        var present = successful.Any(probe => probe.Present);
        var active = successful.Any(probe => probe.Active);
        var loggingEnabled = successful
            .Where(probe => probe.LoggingEnabled.HasValue)
            .Select(probe => probe.LoggingEnabled)
            .FirstOrDefault();
        var failure = probes
            .Where(probe => probe.State != InventorySourceState.Success
                && probe.State != InventorySourceState.NotApplicable
                && (probe.State != InventorySourceState.Unavailable
                    || !string.Equals(probe.ErrorCode, "command_missing", StringComparison.Ordinal)))
            .OrderByDescending(probe => StatePriority(probe.State))
            .FirstOrDefault();
        return new(
            producer,
            supported,
            present,
            active,
            loggingEnabled,
            failure?.State ?? InventorySourceState.Unavailable,
            failure is not null);
    }

    private static LinuxFirewallInventoryEvidence Failure(CombinedProducer producer) => producer.FailureState switch
    {
        InventorySourceState.PermissionDenied => new(
            LinuxFirewallInventoryStates.PermissionDenied,
            producer.Producer,
            "firewall_inventory_permission_denied"),
        InventorySourceState.Timeout => new(
            LinuxFirewallInventoryStates.Timeout,
            producer.Producer,
            "firewall_inventory_timeout"),
        InventorySourceState.Malformed => new(
            LinuxFirewallInventoryStates.Malformed,
            producer.Producer,
            "firewall_inventory_malformed"),
        _ => new(
            LinuxFirewallInventoryStates.Malformed,
            producer.Producer,
            "firewall_logging_state_unverified")
    };

    private static int StatePriority(InventorySourceState state) => state switch
    {
        InventorySourceState.PermissionDenied => 4,
        InventorySourceState.Timeout => 3,
        InventorySourceState.Malformed => 2,
        _ => 1
    };

    private sealed record CombinedProducer(
        string Producer,
        bool Supported,
        bool Present,
        bool Active,
        bool? LoggingEnabled,
        InventorySourceState FailureState,
        bool HasUnresolvedFailure);
}
