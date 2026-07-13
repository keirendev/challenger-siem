namespace Challenger.Siem.Contracts.V1;

/// <summary>
/// Canonical Windows source matrix used by agents, server-side coverage checks, and operator validation surfaces.
/// Source IDs are stable API identifiers; parser IDs provide broader aliases for detection prerequisites.
/// </summary>
public static class WindowsTelemetrySourceCatalog
{
    public static readonly IReadOnlyList<SourceManifestEntry> L2Default = new[]
    {
        Entry(
            "security",
            "Security",
            "Windows Security",
            WindowsCoverageLevel.L1,
            required: true,
            "security-log",
            prerequisites: "security_log_read_access,audit_policy_baseline,process_command_line_auditing,event_log_size_baseline",
            eventFamilies: "authentication,account,privilege,process,object_access,policy,tamper,firewall",
            validationScenarios: "synthetic_logon,synthetic_process_creation,audit_policy_snapshot",
            privacy: "sensitive"),
        Entry(
            "system",
            "System",
            "Windows System",
            WindowsCoverageLevel.L1,
            required: true,
            "system-log",
            prerequisites: "event_log_size_baseline,service_control_manager_visibility",
            eventFamilies: "service,driver,boot_shutdown,time_change,system_error,tamper",
            validationScenarios: "system_event_presence,service_state_presence"),
        Entry(
            "application",
            "Application",
            "Windows Application",
            WindowsCoverageLevel.L1,
            required: true,
            "application-log",
            prerequisites: "event_log_size_baseline",
            eventFamilies: "application,software,error_reporting,installer",
            validationScenarios: "application_event_presence,msi_event_presence"),
        Entry(
            "powershell-classic",
            "Windows PowerShell",
            "Windows PowerShell",
            WindowsCoverageLevel.L2,
            required: true,
            "powershell-classic",
            prerequisites: "powershell_engine_logging,event_log_enabled,event_log_size_baseline",
            eventFamilies: "powershell,script,engine_lifecycle",
            validationScenarios: "powershell_engine_event_presence",
            privacy: "sensitive"),
        Entry(
            "powershell-operational",
            "Microsoft-Windows-PowerShell/Operational",
            "PowerShell Operational",
            WindowsCoverageLevel.L2,
            required: true,
            "powershell-operational",
            prerequisites: "powershell_script_block_logging,powershell_module_logging,event_log_enabled,event_log_size_baseline",
            eventFamilies: "powershell,script,module_logging,script_block_logging,remote_session",
            validationScenarios: "powershell_script_block_event,powershell_module_event",
            privacy: "high_sensitivity"),
        Entry(
            "defender-operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft Defender Operational",
            WindowsCoverageLevel.L2,
            required: true,
            "defender-operational",
            prerequisites: "defender_operational_channel,security_control_inventory",
            eventFamilies: "malware,asr,remediation,security_control,tamper",
            validationScenarios: "defender_status_snapshot,defender_event_presence"),
        Entry(
            "task-scheduler",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Task Scheduler Operational",
            WindowsCoverageLevel.L2,
            required: true,
            "task-scheduler",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "persistence,scheduled_task,task_action",
            validationScenarios: "scheduled_task_inventory,task_event_presence"),
        Entry(
            "wmi-activity",
            "Microsoft-Windows-WMI-Activity/Operational",
            "WMI Activity Operational",
            WindowsCoverageLevel.L2,
            required: true,
            "wmi-activity",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "wmi,remote_management,persistence,error",
            validationScenarios: "wmi_activity_event_presence"),
        Entry(
            "terminalservices-local-sessionmanager",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "RDP Local Session Manager",
            WindowsCoverageLevel.L2,
            required: true,
            "rdp-terminalservices",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "rdp,remote_access,session_lifecycle",
            validationScenarios: "rdp_source_health"),
        Entry(
            "terminalservices-remoteconnectionmanager",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "RDP Remote Connection Manager",
            WindowsCoverageLevel.L2,
            required: true,
            "rdp-terminalservices",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "rdp,remote_access,authentication",
            validationScenarios: "rdp_source_health"),
        Entry(
            "rdp-corets",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "RDP CoreTS Operational",
            WindowsCoverageLevel.L2,
            required: true,
            "rdp-corets",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "rdp,remote_access,transport",
            validationScenarios: "rdp_source_health"),
        Entry(
            "winrm-operational",
            "Microsoft-Windows-WinRM/Operational",
            "WinRM Operational",
            WindowsCoverageLevel.L2,
            required: true,
            "winrm-operational",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "winrm,remote_management,powershell_remoting",
            validationScenarios: "winrm_source_health"),
        Entry(
            "firewall-advanced",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "Windows Firewall",
            WindowsCoverageLevel.L2,
            required: true,
            "windows-firewall",
            prerequisites: "windows_firewall_enabled,firewall_audit_policy,event_log_enabled,event_log_size_baseline",
            eventFamilies: "network,firewall,policy,tamper",
            validationScenarios: "firewall_profile_snapshot,firewall_event_presence"),
        Entry(
            "group-policy",
            "Microsoft-Windows-GroupPolicy/Operational",
            "Group Policy Operational",
            WindowsCoverageLevel.L2,
            required: false,
            "group-policy",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "policy,configuration_drift",
            validationScenarios: "group_policy_source_health"),
        Entry(
            "code-integrity",
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Code Integrity Operational",
            WindowsCoverageLevel.L2,
            required: false,
            "code-integrity",
            prerequisites: "event_log_enabled,event_log_size_baseline",
            eventFamilies: "code_integrity,image_load,security_control",
            validationScenarios: "code_integrity_source_health"),
        Entry(
            "applocker-exe-dll",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "AppLocker EXE and DLL",
            WindowsCoverageLevel.L2,
            required: false,
            "applocker-wdac",
            prerequisites: "applocker_or_wdac_policy,event_log_enabled,event_log_size_baseline",
            eventFamilies: "code_integrity,execution_control",
            validationScenarios: "applocker_source_health"),
        Entry(
            "applocker-msi-script",
            "Microsoft-Windows-AppLocker/MSI and Script",
            "AppLocker MSI and Script",
            WindowsCoverageLevel.L2,
            required: false,
            "applocker-wdac",
            prerequisites: "applocker_or_wdac_policy,event_log_enabled,event_log_size_baseline",
            eventFamilies: "code_integrity,script,installer_control",
            validationScenarios: "applocker_source_health"),
        Entry(
            "applocker-packaged-app",
            "Microsoft-Windows-AppLocker/Packaged app-Execution",
            "AppLocker Packaged App Execution",
            WindowsCoverageLevel.L2,
            required: false,
            "applocker-wdac",
            prerequisites: "applocker_or_wdac_policy,event_log_enabled,event_log_size_baseline",
            eventFamilies: "code_integrity,packaged_app_control",
            validationScenarios: "applocker_source_health")
    };

    public static readonly IReadOnlyList<SourceManifestEntry> SysmonL3 = new[]
    {
        Entry(
            "sysmon-operational",
            "Microsoft-Windows-Sysmon/Operational",
            "Sysmon Operational",
            WindowsCoverageLevel.L3,
            required: true,
            "sysmon",
            prerequisites: "sysmon_installed,sysmon_eula_accepted,sysmon_signed_binary_verified,sysmon_approved_config,sysmon_config_hash_reported,event_log_enabled,event_log_size_baseline",
            eventFamilies: "process,network,dns,file,registry,image,driver,process_access,raw_disk,wmi,named_pipe,tamper,error",
            validationScenarios: "sysmon_process_event,sysmon_network_dns_event,sysmon_file_registry_event,sysmon_wmi_pipe_tamper_event",
            privacy: "high_sensitivity")
    };

    public static readonly IReadOnlyList<RoleSourcePackDesign> L4RolePacks = new[]
    {
        new RoleSourcePackDesign
        {
            Role = "domain_controller",
            Sources = new[] { "Directory Service", "DNS Server", "DFS Replication", "Kerberos Key Distribution Center", "Security" },
            Parsers = new[] { "active-directory", "dns-server", "kerberos", "security-log" },
            Detections = new[] { "dc.account_logon", "dc.directory_replication", "dc.kerberos_abuse", "dc.sysvol_integrity" },
            Validation = new[] { "role_detected", "source_health", "audit_policy", "sanitized_event_counts" },
            PrivacyNotes = "Domain-controller validation must publish only aggregate status/counts."
        },
        new RoleSourcePackDesign
        {
            Role = "file_server",
            Sources = new[] { "Microsoft-Windows-SMBServer/Security", "Microsoft-Windows-SMBServer/Operational", "Security", "FSRM" },
            Parsers = new[] { "smb-server", "security-object-access", "file-server" },
            Detections = new[] { "file_server.sensitive_share_access", "file_server.shadow_copy_tamper" },
            Validation = new[] { "role_detected", "source_health", "share_inventory_counts" },
            PrivacyNotes = "Do not publish share names or file paths from real hosts."
        },
        new RoleSourcePackDesign
        {
            Role = "iis_web_server",
            Sources = new[] { "IIS W3C logs", "HTTPERR", "System", "Application" },
            Parsers = new[] { "iis-w3c", "httperr", "application-log" },
            Detections = new[] { "iis.webshell_indicator", "iis.suspicious_status_spike" },
            Validation = new[] { "role_detected", "log_path_access", "sanitized_request_counts" },
            PrivacyNotes = "Tracked examples must not contain real URLs, client IPs, usernames, or user agents."
        },
        new RoleSourcePackDesign
        {
            Role = "hyper_v",
            Sources = new[] { "Microsoft-Windows-Hyper-V-VMMS/Admin", "Microsoft-Windows-Hyper-V-Worker/Admin", "Microsoft-Windows-Hyper-V-Hypervisor/Admin" },
            Parsers = new[] { "hyper-v" },
            Detections = new[] { "hyperv.vm_state_change", "hyperv.virtual_switch_change" },
            Validation = new[] { "role_detected", "source_health", "vm_inventory_counts" },
            PrivacyNotes = "Publish only VM/source counts unless an operator approves local-only review."
        },
        new RoleSourcePackDesign
        {
            Role = "certificate_authority",
            Sources = new[] { "Active Directory Certificate Services", "CAPI2", "CertificateServicesClient" },
            Parsers = new[] { "adcs", "capi2", "certificate-services-client" },
            Detections = new[] { "adcs.template_change", "adcs.suspicious_enrollment" },
            Validation = new[] { "role_detected", "source_health", "certificate_event_counts" },
            PrivacyNotes = "Do not publish certificate subjects, account names, or requester identities from real hosts."
        }
    };

    public static readonly IReadOnlyList<SourceManifestEntry> All = L2Default
        .Concat(SysmonL3)
        .OrderBy(entry => entry.CoverageLevel)
        .ThenBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    public static IReadOnlyList<SourceManifestEntry> ExpectedFor(WindowsCoverageLevel targetLevel, bool includeOptional = true)
    {
        return All
            .Where(entry => entry.CoverageLevel <= targetLevel && (includeOptional || entry.Required))
            .OrderBy(entry => entry.CoverageLevel)
            .ThenBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<SourceManifestEntry> BuildManifest(IEnumerable<string> requiredChannels, IEnumerable<string> optionalChannels)
    {
        var required = requiredChannels
            .Where(channel => !string.IsNullOrWhiteSpace(channel))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var enabled = required
            .Concat(optionalChannels.Where(channel => !string.IsNullOrWhiteSpace(channel)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var known = All.ToDictionary(entry => entry.Channel!, StringComparer.OrdinalIgnoreCase);
        var results = new List<SourceManifestEntry>();
        foreach (var channel in enabled)
        {
            if (known.TryGetValue(channel, out var entry))
            {
                var configuredAsRequired = required.Contains(channel);
                results.Add(entry with
                {
                    Required = configuredAsRequired,
                    EnabledByDefault = entry.EnabledByDefault || configuredAsRequired
                });
            }
            else
            {
                results.Add(Entry(Slug(channel), channel, channel, WindowsCoverageLevel.L2, required.Contains(channel), "custom", installerManaged: false));
            }
        }

        return results
            .OrderBy(entry => entry.CoverageLevel)
            .ThenBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> DefaultRequiredChannels() => L2Default
        .Where(entry => entry.Required && entry.CoverageLevel <= WindowsCoverageLevel.L1)
        .Select(entry => entry.Channel!)
        .ToArray();

    public static IReadOnlyList<string> DefaultOptionalChannels() => L2Default
        .Where(entry => entry.CoverageLevel >= WindowsCoverageLevel.L2)
        .Concat(SysmonL3)
        .Select(entry => entry.Channel!)
        .ToArray();

    public static SourceManifestEntry? FindByChannel(string channel)
    {
        return All.FirstOrDefault(entry => string.Equals(entry.Channel, channel, StringComparison.OrdinalIgnoreCase));
    }

    public static bool SourceMatches(string expectedOrAlias, string sourceId)
    {
        if (string.Equals(expectedOrAlias, sourceId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return AliasesFor(expectedOrAlias).Any(alias => string.Equals(alias, sourceId, StringComparison.OrdinalIgnoreCase));
    }

    public static IReadOnlyList<string> AliasesFor(string sourceId)
    {
        return sourceId.ToLowerInvariant() switch
        {
            "powershell" => new[] { "powershell", "powershell-classic", "powershell-operational" },
            "rdp" => new[] { "rdp", "terminalservices-local-sessionmanager", "terminalservices-remoteconnectionmanager", "rdp-corets" },
            "sysmon" => new[] { "sysmon", "sysmon-operational" },
            "applocker-wdac" => new[] { "applocker-wdac", "applocker-exe-dll", "applocker-msi-script", "applocker-packaged-app" },
            _ => new[] { sourceId }
        };
    }

    private static SourceManifestEntry Entry(
        string sourceId,
        string channel,
        string displayName,
        WindowsCoverageLevel level,
        bool required,
        string parserId,
        string prerequisites = "",
        string eventFamilies = "",
        string validationScenarios = "",
        string privacy = "standard",
        bool installerManaged = true) => new()
        {
            SourceId = sourceId,
            Channel = channel,
            DisplayName = displayName,
            CoverageLevel = level,
            Required = required,
            EnabledByDefault = required || level <= WindowsCoverageLevel.L2,
            SourcePack = level >= WindowsCoverageLevel.L3 ? "windows-l3-sysmon" : "windows-l2",
            ParserId = parserId,
            Prerequisites = Split(prerequisites),
            EventFamilies = Split(eventFamilies),
            ValidationScenarios = Split(validationScenarios),
            Privacy = privacy,
            InstallerManaged = installerManaged
        };

    private static IReadOnlyList<string> Split(string value) => string.IsNullOrWhiteSpace(value)
        ? Array.Empty<string>()
        : value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    private static string Slug(string value)
    {
        var chars = value.ToLowerInvariant().Select(ch => char.IsLetterOrDigit(ch) ? ch : '-').ToArray();
        return new string(chars).Trim('-');
    }
}
