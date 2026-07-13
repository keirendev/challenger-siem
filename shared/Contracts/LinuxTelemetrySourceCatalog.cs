namespace Challenger.Siem.Contracts.V1;

/// <summary>Stable source identifiers emitted by the Linux journal security pack.</summary>
public static class LinuxTelemetrySourceIds
{
    public const string JournalL1 = "linux-journal-l1";
    public const string LoginSession = "linux-login-session";
    public const string Ssh = "linux-ssh";
    public const string Privilege = "linux-sudo-su";
    public const string Scheduler = "linux-cron-timers";
    public const string PackageManagement = "linux-package-management";
    public const string Firewall = "linux-firewall";
    public const string KernelSecurity = "linux-kernel-security";
    public const string ServiceChange = "linux-service-change";
    public const string AgentLogTamper = "linux-agent-log-tamper";
    public const string AuditFramework = "linux-audit-framework";
    public const string AgentSelfIntegrity = "linux-agent-self-integrity-snapshot";
}

/// <summary>
/// Canonical Linux source matrix shared by the agent and server. L2 entries describe logical
/// security families carried by the one durable system-journal cursor; they do not create
/// additional readers or authorize producer configuration changes.
/// </summary>
public static class LinuxTelemetrySourceCatalog
{
    public const string L1PackId = "linux-l1-journal";
    public const string L2PackId = "linux-l2-security";
    public const string L3SelfIntegrityPackId = "linux-l3-self-integrity-snapshot";

    public static readonly IReadOnlyList<SourceManifestEntry> L1 =
    [
        Entry(
            LinuxTelemetrySourceIds.JournalL1,
            "Linux L1 system journal",
            WindowsCoverageLevel.L1,
            SourceRequirementKinds.Mandatory,
            "journal-l1",
            prerequisites: "systemd_journal_available,systemd_journal_readable",
            eventFamilies: "boot,system,application_service",
            validationScenarios: "cursor_restart,rotation_vacuum,outage_replay,pressure",
            enabledByDefault: true)
    ];

    public static readonly IReadOnlyList<SourceManifestEntry> L2Security =
    [
        Entry(
            LinuxTelemetrySourceIds.LoginSession,
            "Linux login and session activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-login-session-v1",
            prerequisites: "systemd_journal_readable,pam_or_logind_journal_visibility",
            eventFamilies: "login,session",
            validationScenarios: "login_success_failure,session_open_close"),
        Entry(
            LinuxTelemetrySourceIds.Ssh,
            "Linux SSH activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.RoleSpecific,
            "linux-ssh-v1",
            prerequisites: "systemd_journal_readable,sshd_journal_visibility",
            eventFamilies: "ssh_authentication,ssh_session",
            validationScenarios: "ssh_success_failure,ssh_session_lifecycle",
            applicableRoles: "ssh_server,bastion"),
        Entry(
            LinuxTelemetrySourceIds.Privilege,
            "Linux sudo and su activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-privilege-v1",
            prerequisites: "systemd_journal_readable,sudo_or_su_journal_visibility",
            eventFamilies: "sudo,su",
            validationScenarios: "sudo_command,su_session"),
        Entry(
            LinuxTelemetrySourceIds.Scheduler,
            "Linux cron and systemd timer activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-scheduler-v1",
            prerequisites: "systemd_journal_readable,cron_or_systemd_timer_visibility",
            eventFamilies: "cron,systemd_timer",
            validationScenarios: "cron_execution,timer_trigger"),
        Entry(
            LinuxTelemetrySourceIds.PackageManagement,
            "Linux package-management activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-package-v1",
            prerequisites: "systemd_journal_readable,package_manager_journal_visibility",
            eventFamilies: "package_install,package_update,package_remove",
            validationScenarios: "package_install_update_remove"),
        Entry(
            LinuxTelemetrySourceIds.Firewall,
            "Linux firewall activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Optional,
            "linux-firewall-v1",
            prerequisites: "systemd_journal_readable,firewall_logging_already_enabled",
            eventFamilies: "firewall_allow,firewall_deny,firewall_change",
            validationScenarios: "firewall_allow_deny,firewall_policy_change"),
        Entry(
            LinuxTelemetrySourceIds.KernelSecurity,
            "Linux kernel and security-module activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-kernel-security-v1",
            prerequisites: "systemd_journal_readable,kernel_journal_visibility",
            eventFamilies: "kernel_security,security_module,kernel_module",
            validationScenarios: "security_module_denial,kernel_module_change"),
        Entry(
            LinuxTelemetrySourceIds.ServiceChange,
            "Linux service-change activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-service-change-v1",
            prerequisites: "systemd_journal_readable,systemd_unit_journal_visibility",
            eventFamilies: "service_start,service_stop,service_reload,service_failure",
            validationScenarios: "service_start_stop_failure"),
        Entry(
            LinuxTelemetrySourceIds.AgentLogTamper,
            "Linux agent and log-tamper activity",
            WindowsCoverageLevel.L2,
            SourceRequirementKinds.Mandatory,
            "linux-tamper-v1",
            prerequisites: "systemd_journal_readable,journald_and_agent_unit_visibility",
            eventFamilies: "agent_tamper,log_tamper",
            validationScenarios: "agent_unit_change,journal_gap_or_corruption")
    ];

    /// <summary>
    /// Audit is declared honestly but is not collected by this pack. The entry prevents an absent
    /// collector from being mistaken for healthy coverage and does not enable or alter audit policy.
    /// </summary>
    public static readonly SourceManifestEntry SelfIntegritySnapshot = new()
    {
        SourceId = LinuxTelemetrySourceIds.AgentSelfIntegrity,
        Platform = TelemetryPlatforms.Linux,
        SourceKind = TelemetrySourceKinds.AgentHealth,
        SourceNamespace = "challenger.siem.agent",
        Applicability = SourceApplicabilityStatuses.Unknown,
        ApplicabilityReason = "explicit_opt_in_required",
        CheckpointKind = SourceCheckpointKinds.Sequence,
        DisplayName = "Linux agent self-integrity snapshot",
        CoverageLevel = WindowsCoverageLevel.L3,
        Required = false,
        Requirement = SourceRequirementKinds.Optional,
        EnabledByDefault = false,
        SourcePack = L3SelfIntegrityPackId,
        ParserId = "linux-agent-self-integrity-snapshot-v1",
        Prerequisites = ["explicit_self_integrity_opt_in", "approval_hash_matches", "allowlist_paths_readable"],
        EventFamilies = ["self_integrity_snapshot"],
        ValidationScenarios = ["preflight_plan", "allowlist_escape", "snapshot_change_loss_pressure_restart", "disable_cleanup"],
        Privacy = "agent_metadata_only",
        InstallerManaged = false
    };

    public static readonly SourceManifestEntry UnsupportedAuditFramework = new()
    {
        SourceId = LinuxTelemetrySourceIds.AuditFramework,
        Platform = TelemetryPlatforms.Linux,
        SourceKind = TelemetrySourceKinds.LinuxAudit,
        SourceNamespace = "linux.audit",
        Applicability = SourceApplicabilityStatuses.Unsupported,
        ApplicabilityReason = "collector_not_included",
        CheckpointKind = SourceCheckpointKinds.Sequence,
        DisplayName = "Linux Audit Framework",
        CoverageLevel = WindowsCoverageLevel.L2,
        Required = false,
        Requirement = SourceRequirementKinds.Optional,
        EnabledByDefault = false,
        SourcePack = L2PackId,
        ParserId = "unsupported",
        Prerequisites = ["linux_audit_collector"],
        EventFamilies = ["audit"],
        ValidationScenarios = ["unsupported_source_reporting"],
        Privacy = "high_sensitivity",
        InstallerManaged = false
    };

    public static readonly IReadOnlyList<SourceManifestEntry> All = L1
        .Concat(L2Security)
        .Append(UnsupportedAuditFramework)
        .Append(SelfIntegritySnapshot)
        .OrderBy(entry => entry.CoverageLevel)
        .ThenBy(entry => entry.DisplayName, StringComparer.Ordinal)
        .ToArray();

    public static IReadOnlyList<SourceManifestEntry> ExpectedFor(WindowsCoverageLevel targetLevel, bool includeOptional = true) => All
        .Where(entry => entry.CoverageLevel <= targetLevel
            && (includeOptional || entry.Requirement == SourceRequirementKinds.Mandatory))
        .OrderBy(entry => entry.CoverageLevel)
        .ThenBy(entry => entry.DisplayName, StringComparer.Ordinal)
        .ToArray();

    public static IReadOnlyList<SourceManifestEntry> BuildHeartbeatManifest(
        WindowsCoverageLevel targetLevel,
        IReadOnlyCollection<string> declaredRoles,
        IReadOnlySet<string> observedSourceIds)
    {
        var roles = declaredRoles.ToHashSet(StringComparer.Ordinal);
        return All.Select(entry => ResolveApplicability(entry, targetLevel, roles, observedSourceIds)).ToArray();
    }

    public static SourceManifestEntry? Find(string sourceId) => All.FirstOrDefault(entry =>
        string.Equals(entry.SourceId, sourceId, StringComparison.Ordinal));

    public static bool IsKnownSource(string? sourceId) => sourceId is not null && Find(sourceId) is not null;

    private static SourceManifestEntry ResolveApplicability(
        SourceManifestEntry entry,
        WindowsCoverageLevel targetLevel,
        IReadOnlySet<string> declaredRoles,
        IReadOnlySet<string> observedSourceIds)
    {
        if (entry.Applicability == SourceApplicabilityStatuses.Unsupported)
        {
            return entry;
        }

        if (entry.CoverageLevel > targetLevel)
        {
            return entry;
        }

        if (observedSourceIds.Contains(entry.SourceId))
        {
            return entry with
            {
                Applicability = SourceApplicabilityStatuses.Applicable,
                ApplicabilityReason = null
            };
        }

        if (entry.Requirement == SourceRequirementKinds.RoleSpecific)
        {
            var applicableRoles = entry.ApplicableRoles ?? Array.Empty<string>();
            if (declaredRoles.Count == 0)
            {
                return entry with
                {
                    Applicability = SourceApplicabilityStatuses.Unknown,
                    ApplicabilityReason = "host_role_not_declared"
                };
            }

            return applicableRoles.Any(declaredRoles.Contains)
                ? entry with { Applicability = SourceApplicabilityStatuses.Applicable, ApplicabilityReason = null }
                : entry with
                {
                    Applicability = SourceApplicabilityStatuses.NotApplicable,
                    ApplicabilityReason = "declared_roles_do_not_require_source"
                };
        }

        if (entry.Requirement == SourceRequirementKinds.Optional)
        {
            return entry with
            {
                Applicability = SourceApplicabilityStatuses.Unknown,
                ApplicabilityReason = "source_prerequisite_not_observed"
            };
        }

        return entry;
    }

    private static SourceManifestEntry Entry(
        string sourceId,
        string displayName,
        WindowsCoverageLevel coverageLevel,
        string requirement,
        string parserId,
        string prerequisites,
        string eventFamilies,
        string validationScenarios,
        string applicableRoles = "",
        bool enabledByDefault = false) => new()
        {
            SourceId = sourceId,
            Platform = TelemetryPlatforms.Linux,
            SourceKind = TelemetrySourceKinds.LinuxJournal,
            SourceNamespace = "systemd.journal",
            Applicability = requirement is SourceRequirementKinds.RoleSpecific or SourceRequirementKinds.Optional
                ? SourceApplicabilityStatuses.Unknown
                : SourceApplicabilityStatuses.Applicable,
            ApplicabilityReason = requirement switch
            {
                SourceRequirementKinds.RoleSpecific => "host_role_not_declared",
                SourceRequirementKinds.Optional => "source_prerequisite_not_observed",
                _ => null
            },
            CheckpointKind = SourceCheckpointKinds.Cursor,
            DisplayName = displayName,
            CoverageLevel = coverageLevel,
            Required = requirement == SourceRequirementKinds.Mandatory,
            Requirement = requirement,
            ApplicableRoles = Split(applicableRoles),
            EnabledByDefault = enabledByDefault,
            SourcePack = coverageLevel == WindowsCoverageLevel.L1 ? L1PackId : L2PackId,
            ParserId = parserId,
            Prerequisites = Split(prerequisites),
            EventFamilies = Split(eventFamilies),
            ValidationScenarios = Split(validationScenarios),
            Privacy = "high_sensitivity",
            InstallerManaged = false
        };

    private static IReadOnlyList<string> Split(string value) => string.IsNullOrWhiteSpace(value)
        ? Array.Empty<string>()
        : value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
}
