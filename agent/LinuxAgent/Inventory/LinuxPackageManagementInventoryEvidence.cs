using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Inventory;

public static class LinuxPackageManagementInventoryStates
{
    public const string Unknown = "unknown";
    public const string Supported = "supported";
    public const string Unsupported = "unsupported";
    public const string Missing = "missing";
    public const string PermissionDenied = "permission_denied";
    public const string Timeout = "timeout";
    public const string Malformed = "malformed";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Unknown,
        Supported,
        Unsupported,
        Missing,
        PermissionDenied,
        Timeout,
        Malformed
    };
}

public sealed record LinuxPackageManagerInventoryProbe(
    string Producer,
    InventorySourceState State,
    string ErrorCode);

public sealed record LinuxPackageManagementInventoryEvidence(
    string State,
    string Producer,
    string Reason)
{
    public const string SnapshotType = "linux_packages";
    public const string StateKey = "package_manager_evidence";
    public const string ProducerKey = "package_manager_producer";
    public const string ReasonKey = "package_manager_reason";

    private static readonly IReadOnlyDictionary<string, string> UnsupportedDistributionProducers =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["alpine"] = "apk",
            ["gentoo"] = "portage",
            ["nixos"] = "nix",
            ["solus"] = "eopkg",
            ["void"] = "xbps",
            ["wolfi"] = "apk"
        };

    public static LinuxPackageManagementInventoryEvidence Evaluate(
        string? distributionId,
        IReadOnlyList<LinuxPackageManagerInventoryProbe> probes)
    {
        var supported = probes.FirstOrDefault(probe => probe.State == InventorySourceState.Success);
        if (supported is not null)
        {
            return new(
                LinuxPackageManagementInventoryStates.Supported,
                supported.Producer,
                "supported_package_manager_inventory");
        }

        var permissionDenied = probes.FirstOrDefault(probe => probe.State == InventorySourceState.PermissionDenied);
        if (permissionDenied is not null)
        {
            return new(
                LinuxPackageManagementInventoryStates.PermissionDenied,
                permissionDenied.Producer,
                "package_manager_inventory_permission_denied");
        }

        var timeout = probes.FirstOrDefault(probe => probe.State == InventorySourceState.Timeout);
        if (timeout is not null)
        {
            return new(
                LinuxPackageManagementInventoryStates.Timeout,
                timeout.Producer,
                "package_manager_inventory_timeout");
        }

        var malformed = probes.FirstOrDefault(probe => probe.State == InventorySourceState.Malformed);
        if (malformed is not null)
        {
            return new(
                LinuxPackageManagementInventoryStates.Malformed,
                malformed.Producer,
                "package_manager_inventory_malformed");
        }

        var normalizedDistribution = distributionId?.Trim().ToLowerInvariant();
        if (normalizedDistribution is not null
            && UnsupportedDistributionProducers.TryGetValue(normalizedDistribution, out var unsupportedProducer))
        {
            return new(
                LinuxPackageManagementInventoryStates.Unsupported,
                unsupportedProducer,
                "package_manager_producer_out_of_scope");
        }

        return new(
            LinuxPackageManagementInventoryStates.Missing,
            "unknown",
            "supported_package_manager_inventory_missing");
    }

    public static LinuxPackageManagementInventoryEvidence FromSnapshots(
        IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var snapshot = snapshots.FirstOrDefault(item =>
            string.Equals(item.SnapshotType, SnapshotType, StringComparison.Ordinal));
        if (snapshot is null)
        {
            return new(
                LinuxPackageManagementInventoryStates.Missing,
                "unknown",
                "package_manager_inventory_snapshot_missing");
        }

        var state = snapshot.Summary.GetValueOrDefault(StateKey);
        var producer = snapshot.Summary.GetValueOrDefault(ProducerKey);
        var reason = snapshot.Summary.GetValueOrDefault(ReasonKey);
        if (state is null || !LinuxPackageManagementInventoryStates.All.Contains(state)
            || string.IsNullOrWhiteSpace(producer) || producer.Length > 32
            || string.IsNullOrWhiteSpace(reason) || reason.Length > 128)
        {
            return new(
                LinuxPackageManagementInventoryStates.Malformed,
                "unknown",
                "package_manager_inventory_evidence_malformed");
        }

        return new(state, producer, reason);
    }

    public IReadOnlyDictionary<string, string> AddTo(IReadOnlyDictionary<string, string> summary)
    {
        var augmented = new Dictionary<string, string>(summary, StringComparer.Ordinal)
        {
            [StateKey] = State,
            [ProducerKey] = Producer,
            [ReasonKey] = Reason
        };
        return augmented;
    }

    public string Applicability => State switch
    {
        LinuxPackageManagementInventoryStates.Supported => SourceApplicabilityStatuses.Applicable,
        LinuxPackageManagementInventoryStates.Unsupported => SourceApplicabilityStatuses.Unsupported,
        _ => SourceApplicabilityStatuses.Unknown
    };

    public string PrerequisiteStatus => State switch
    {
        LinuxPackageManagementInventoryStates.Unsupported => SourceEvidenceStatuses.Unsupported,
        LinuxPackageManagementInventoryStates.Missing => SourceEvidenceStatuses.Missing,
        LinuxPackageManagementInventoryStates.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
        LinuxPackageManagementInventoryStates.Timeout => SourceEvidenceStatuses.Stale,
        LinuxPackageManagementInventoryStates.Malformed => SourceEvidenceStatuses.Degraded,
        _ => SourceEvidenceStatuses.Unknown
    };
}
