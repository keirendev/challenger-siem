using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Inventory;

public static class LinuxSshInventoryStates
{
    public const string Unknown = "unknown";
    public const string SupportedActive = "supported_active";
    public const string SupportedInactive = "supported_inactive";
    public const string Unsupported = "unsupported";
    public const string PermissionDenied = "permission_denied";
    public const string Timeout = "timeout";
    public const string Malformed = "malformed";
}

/// <summary>
/// Bounded SSH producer evidence derived only from the existing systemd-service and approved
/// sshd-config inventory snapshots. It does not read another path, scan for daemons, or change
/// service/authentication configuration.
/// </summary>
public sealed record LinuxSshInventoryEvidence(
    string State,
    string Producer,
    string Reason)
{
    public const string SshSnapshotType = "linux_ssh";
    public const string ServiceSnapshotType = "linux_services";

    private static readonly IReadOnlySet<string> SshServiceNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "ssh.service",
        "sshd.service"
    };

    public static LinuxSshInventoryEvidence Unknown { get; } = new(
        LinuxSshInventoryStates.Unknown,
        "unknown",
        "ssh_inventory_not_observed");

    public static LinuxSshInventoryEvidence FromSnapshots(IReadOnlyList<AssetInventorySnapshot> snapshots)
    {
        var services = snapshots.FirstOrDefault(snapshot =>
            string.Equals(snapshot.SnapshotType, ServiceSnapshotType, StringComparison.Ordinal));
        var ssh = snapshots.FirstOrDefault(snapshot =>
            string.Equals(snapshot.SnapshotType, SshSnapshotType, StringComparison.Ordinal));

        if (services is null || ssh is null)
        {
            return Unknown;
        }

        var serviceState = SummaryState(services);
        var sshState = SummaryState(ssh);
        if (serviceState is null || sshState is null)
        {
            return new(
                LinuxSshInventoryStates.Malformed,
                "unknown",
                "ssh_inventory_evidence_malformed");
        }

        var sshServices = serviceState == "success"
            ? services.Items
                .Where(item => string.Equals(item.Kind, "service", StringComparison.Ordinal)
                    && SshServiceNames.Contains(item.Name))
                .OrderBy(item => item.Name, StringComparer.Ordinal)
                .ToArray()
            : Array.Empty<InventoryItem>();
        var activeService = sshServices.FirstOrDefault(item =>
            string.Equals(item.Status, "active", StringComparison.Ordinal));
        if (activeService is not null)
        {
            return new(
                LinuxSshInventoryStates.SupportedActive,
                activeService.Name,
                "active_ssh_service_observed");
        }

        var inactiveService = sshServices.FirstOrDefault();
        if (inactiveService is not null)
        {
            return new(
                LinuxSshInventoryStates.SupportedInactive,
                inactiveService.Name,
                "ssh_service_not_active");
        }

        if (serviceState == "permission_denied" || sshState == "permission_denied")
        {
            return new(
                LinuxSshInventoryStates.PermissionDenied,
                "unknown",
                "ssh_inventory_permission_denied");
        }

        if (serviceState == "timeout" || sshState == "timeout")
        {
            return new(
                LinuxSshInventoryStates.Timeout,
                "unknown",
                "ssh_inventory_timeout");
        }

        if (serviceState == "malformed" || sshState == "malformed")
        {
            return new(
                LinuxSshInventoryStates.Malformed,
                "unknown",
                "ssh_inventory_malformed");
        }

        // The service inventory is bounded. Absence from a truncated snapshot cannot prove
        // that neither supported unit exists, so fail closed instead of reporting inactive or
        // unsupported producer state from incomplete evidence.
        if (serviceState == "success"
            && string.Equals(services.Summary.GetValueOrDefault("truncated"), "true", StringComparison.Ordinal))
        {
            return new(
                LinuxSshInventoryStates.Unknown,
                "unknown",
                "ssh_service_inventory_truncated");
        }

        if (serviceState == "success" && sshState == "success")
        {
            return new(
                LinuxSshInventoryStates.SupportedInactive,
                "openssh",
                "ssh_configuration_present_service_not_active");
        }

        if ((serviceState is "success" or "not_applicable")
            && sshState == "unavailable"
            && string.Equals(ssh.Summary.GetValueOrDefault("error_code"), "file_missing", StringComparison.Ordinal))
        {
            return new(
                LinuxSshInventoryStates.Unsupported,
                "openssh",
                "ssh_producer_not_present");
        }

        return new(
            LinuxSshInventoryStates.Unknown,
            "unknown",
            "ssh_service_state_unresolved");
    }

    public string ApplicabilityWithoutDeclaredRole => State switch
    {
        LinuxSshInventoryStates.SupportedActive => SourceApplicabilityStatuses.Applicable,
        LinuxSshInventoryStates.Unsupported => SourceApplicabilityStatuses.Unsupported,
        _ => SourceApplicabilityStatuses.Unknown
    };

    public string PrerequisiteStatus => State switch
    {
        LinuxSshInventoryStates.SupportedActive => SourceEvidenceStatuses.Satisfied,
        LinuxSshInventoryStates.SupportedInactive => SourceEvidenceStatuses.Disabled,
        LinuxSshInventoryStates.Unsupported => SourceEvidenceStatuses.Unsupported,
        LinuxSshInventoryStates.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
        LinuxSshInventoryStates.Timeout => SourceEvidenceStatuses.Stale,
        LinuxSshInventoryStates.Malformed => SourceEvidenceStatuses.Degraded,
        _ => SourceEvidenceStatuses.Unknown
    };

    public bool SupportsQuietJournalObservation => State == LinuxSshInventoryStates.SupportedActive;

    private static string? SummaryState(AssetInventorySnapshot snapshot)
    {
        var state = snapshot.Summary.GetValueOrDefault("state");
        return state is "success" or "unavailable" or "not_applicable" or "permission_denied" or "timeout" or "malformed"
            ? state
            : null;
    }
}
