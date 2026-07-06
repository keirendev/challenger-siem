using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Detections;

public sealed record DetectionPrerequisiteProfile(
    string RuleId,
    IReadOnlyList<int> RequiredEventIds,
    IReadOnlyList<string> RequiredEventCategories,
    IReadOnlyList<string> RequiredEventActions,
    IReadOnlyList<string> AuditPolicyRequirements,
    IReadOnlyList<string> InventoryRequirements,
    IReadOnlyList<string> OptionalSources);

public static class DetectionPrerequisiteCatalog
{
    public static DetectionPrerequisiteProfile ForRule(string ruleId) => Profiles.TryGetValue(ruleId, out var profile)
        ? profile
        : Empty(ruleId);

    private static readonly IReadOnlyDictionary<string, DetectionPrerequisiteProfile> Profiles = new Dictionary<string, DetectionPrerequisiteProfile>(StringComparer.OrdinalIgnoreCase)
    {
        ["auth.bruteforce.windows"] = Profile(
            "auth.bruteforce.windows",
            eventIds: new[] { 4625 },
            categories: new[] { "authentication" },
            actions: new[] { "logon" },
            audit: new[] { "Logon failure", "Account Lockout success/failure" },
            inventory: new[] { "host_identity" },
            optional: new[] { "rdp", "winrm-operational" }),
        ["auth.admin-special-logon"] = Profile(
            "auth.admin-special-logon",
            eventIds: new[] { 4672 },
            categories: new[] { "authentication" },
            actions: new[] { "special_logon" },
            audit: new[] { "Special Logon success" },
            inventory: new[] { "host_identity", "windows_role_detection" },
            optional: new[] { "rdp", "winrm-operational" }),
        ["account.user-created"] = Profile(
            "account.user-created",
            eventIds: new[] { 4720 },
            categories: new[] { "account" },
            actions: new[] { "user_created" },
            audit: new[] { "User Account Management success/failure" },
            inventory: new[] { "local_users_groups" },
            optional: Array.Empty<string>()),
        ["account.group-member-added"] = Profile(
            "account.group-member-added",
            eventIds: new[] { 4732, 4728, 4756 },
            categories: new[] { "account" },
            actions: new[] { "group_member_added" },
            audit: new[] { "Security Group Management success/failure" },
            inventory: new[] { "local_users_groups", "windows_role_detection" },
            optional: Array.Empty<string>()),
        ["powershell.suspicious-script-block"] = Profile(
            "powershell.suspicious-script-block",
            eventIds: new[] { 4104 },
            categories: new[] { "powershell" },
            actions: new[] { "script_block" },
            audit: new[] { "PowerShell script block logging", "PowerShell module logging" },
            inventory: new[] { "defender_firewall_bitlocker_policy" },
            optional: new[] { "powershell-classic", "sysmon" }),
        ["lolbin.suspicious-child-process"] = Profile(
            "lolbin.suspicious-child-process",
            eventIds: new[] { 4688, 1 },
            categories: new[] { "process" },
            actions: new[] { "process_created" },
            audit: new[] { "Process Creation success", "Include command line in process creation events" },
            inventory: new[] { "host_identity" },
            optional: new[] { "sysmon", "code-integrity", "applocker-wdac" }),
        ["credential.lsass-access"] = Profile(
            "credential.lsass-access",
            eventIds: new[] { 10, 4656, 4663 },
            categories: new[] { "credential_access" },
            actions: new[] { "process_access", "object_access" },
            audit: new[] { "Object Access for protected credential targets", "Sensitive Privilege Use success/failure" },
            inventory: new[] { "defender_firewall_bitlocker_policy" },
            optional: new[] { "security" }),
        ["persistence.scheduled-task"] = Profile(
            "persistence.scheduled-task",
            eventIds: new[] { 4698, 4699, 4700, 4701, 4702, 106, 140 },
            categories: new[] { "persistence" },
            actions: new[] { "scheduled_task_created", "scheduled_task_updated" },
            audit: new[] { "Other Object Access Events success/failure", "Process Creation success" },
            inventory: new[] { "scheduled_tasks_autoruns" },
            optional: new[] { "sysmon" }),
        ["persistence.wmi-subscription"] = Profile(
            "persistence.wmi-subscription",
            eventIds: new[] { 5857, 5858, 5861, 19, 20, 21 },
            categories: new[] { "persistence" },
            actions: new[] { "wmi_filter", "wmi_consumer", "wmi_binding" },
            audit: new[] { "Process Creation success" },
            inventory: new[] { "services_drivers", "scheduled_tasks_autoruns" },
            optional: new[] { "sysmon" }),
        ["tamper.event-log-cleared"] = Profile(
            "tamper.event-log-cleared",
            eventIds: new[] { 1102, 104 },
            categories: new[] { "tamper" },
            actions: new[] { "event_log_cleared" },
            audit: new[] { "Audit Policy Change success/failure", "System Integrity success/failure" },
            inventory: new[] { "audit_policy" },
            optional: new[] { "system" }),
        ["tamper.defender-disabled"] = Profile(
            "tamper.defender-disabled",
            eventIds: new[] { 5007 },
            categories: new[] { "tamper" },
            actions: new[] { "defender_configuration_changed" },
            audit: new[] { "Policy Change success/failure" },
            inventory: new[] { "defender_firewall_bitlocker_policy" },
            optional: new[] { "security", "sysmon" }),
        ["malware.defender-detection"] = Profile(
            "malware.defender-detection",
            eventIds: new[] { 1116, 1117 },
            categories: new[] { "malware" },
            actions: new[] { "malware_detected", "malware_remediated" },
            audit: new[] { "Defender real-time protection enabled" },
            inventory: new[] { "defender_firewall_bitlocker_policy" },
            optional: new[] { "sysmon" }),
        ["network.bits-suspicious"] = Profile(
            "network.bits-suspicious",
            eventIds: new[] { 3, 59, 60 },
            categories: new[] { "network" },
            actions: new[] { "network_connection", "bits_transfer" },
            audit: new[] { "Filtering Platform Connection success/failure" },
            inventory: new[] { "network", "defender_firewall_bitlocker_policy" },
            optional: new[] { "firewall-advanced", "powershell-operational" }),
        ["impact.ransomware-burst"] = Profile(
            "impact.ransomware-burst",
            eventIds: new[] { 11, 23, 4663 },
            categories: new[] { "impact", "file" },
            actions: new[] { "file_created", "file_deleted", "object_access" },
            audit: new[] { "Object Access for high-value paths", "Process Creation success" },
            inventory: new[] { "services_drivers", "scheduled_tasks_autoruns" },
            optional: new[] { "security" }),
        ["coverage.source-missing"] = Profile(
            "coverage.source-missing",
            eventIds: Array.Empty<int>(),
            categories: new[] { "coverage" },
            actions: new[] { "source_health_gap" },
            audit: new[] { "Source-health heartbeat present" },
            inventory: new[] { "audit_policy", "host_identity" },
            optional: Array.Empty<string>())
    };

    private static DetectionPrerequisiteProfile Profile(
        string ruleId,
        IReadOnlyList<int> eventIds,
        IReadOnlyList<string> categories,
        IReadOnlyList<string> actions,
        IReadOnlyList<string> audit,
        IReadOnlyList<string> inventory,
        IReadOnlyList<string> optional) => new(ruleId, eventIds, categories, actions, audit, inventory, optional);

    private static DetectionPrerequisiteProfile Empty(string ruleId) =>
        new(ruleId, Array.Empty<int>(), Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());
}
