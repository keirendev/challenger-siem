using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Normalization;

public sealed record WindowsEventNormalizationRule(
    string RuleId,
    string Channel,
    string Provider,
    int EventId,
    string Category,
    string Action,
    string? Outcome = null,
    IReadOnlyList<string>? EntityTypes = null,
    IReadOnlyList<string>? RequiredFields = null);

public static class WindowsEventNormalizationCatalog
{
    public static IReadOnlyList<WindowsEventNormalizationRule> Rules { get; } = new[]
    {
        // Security logon/session.
        Rule("security-logon-success", "Security", "Microsoft-Windows-Security-Auditing", 4624, "authentication", "logon", "success", "user,host,ip", "user_name,source_ip,logon_type"),
        Rule("security-logon-failure", "Security", "Microsoft-Windows-Security-Auditing", 4625, "authentication", "logon", "failure", "user,host,ip", "target_user_name,source_ip,logon_type"),
        Rule("security-logoff", "Security", "Microsoft-Windows-Security-Auditing", 4634, "authentication", "logoff", "success", "user,host", "user_name,logon_type"),
        Rule("security-special-logon", "Security", "Microsoft-Windows-Security-Auditing", 4672, "privilege", "special_logon", "success", "user,host", "user_name"),
        Rule("security-credential-validation", "Security", "Microsoft-Windows-Security-Auditing", 4776, "authentication", "credential_validation", null, "user,host", "target_user_name"),
        Rule("security-kerberos-tgt", "Security", "Microsoft-Windows-Security-Auditing", 4768, "authentication", "kerberos_tgt", null, "user,host,ip", "target_user_name,source_ip"),
        Rule("security-kerberos-service-ticket", "Security", "Microsoft-Windows-Security-Auditing", 4769, "authentication", "kerberos_service_ticket", null, "user,host,service", "target_user_name,service_name"),
        Rule("security-kerberos-preauth-failure", "Security", "Microsoft-Windows-Security-Auditing", 4771, "authentication", "kerberos_preauth", "failure", "user,host,ip", "target_user_name,source_ip"),

        // Security account, group, privilege, process, object, policy, tamper.
        Rule("security-user-created", "Security", "Microsoft-Windows-Security-Auditing", 4720, "account", "user_created", "success", "user", "target_user_name"),
        Rule("security-user-enabled", "Security", "Microsoft-Windows-Security-Auditing", 4722, "account", "user_enabled", "success", "user", "target_user_name"),
        Rule("security-password-reset", "Security", "Microsoft-Windows-Security-Auditing", 4724, "account", "password_reset", "success", "user", "target_user_name"),
        Rule("security-user-disabled", "Security", "Microsoft-Windows-Security-Auditing", 4725, "account", "user_disabled", "success", "user", "target_user_name"),
        Rule("security-user-deleted", "Security", "Microsoft-Windows-Security-Auditing", 4726, "account", "user_deleted", "success", "user", "target_user_name"),
        Rule("security-group-member-added", "Security", "Microsoft-Windows-Security-Auditing", 4732, "account", "group_member_added", "success", "user,group", "target_user_name"),
        Rule("security-group-member-removed", "Security", "Microsoft-Windows-Security-Auditing", 4733, "account", "group_member_removed", "success", "user,group", "target_user_name"),
        Rule("security-process-created", "Security", "Microsoft-Windows-Security-Auditing", 4688, "process", "process_created", "success", "process,user", "process_image,process_command_line,user_name"),
        Rule("security-process-exited", "Security", "Microsoft-Windows-Security-Auditing", 4689, "process", "process_exited", "success", "process,user", "process_image,user_name"),
        Rule("security-object-access", "Security", "Microsoft-Windows-Security-Auditing", 4663, "object", "object_access", null, "file,registry,user", "object_name,user_name"),
        Rule("security-audit-policy-change", "Security", "Microsoft-Windows-Security-Auditing", 4719, "policy", "audit_policy_changed", "success", "host,user", "user_name"),
        Rule("security-event-log-cleared", "Security", "Microsoft-Windows-Eventlog", 1102, "tamper", "event_log_cleared", "success", "host,user", "user_name"),

        // System.
        Rule("system-service-installed", "System", "Service Control Manager", 7045, "service", "service_installed", "success", "service,host", "service_name"),
        Rule("system-service-started", "System", "Service Control Manager", 7036, "service", "service_state_changed", null, "service,host", "service_name"),
        Rule("system-driver-loaded", "System", "Microsoft-Windows-Kernel-PnP", 219, "driver", "driver_loaded", null, "driver,host", "driver_name"),
        Rule("system-startup", "System", "EventLog", 6005, "system", "event_log_started", "success", "host", ""),
        Rule("system-shutdown", "System", "EventLog", 6006, "system", "event_log_stopped", "success", "host", ""),
        Rule("system-unexpected-shutdown", "System", "EventLog", 6008, "system", "unexpected_shutdown", "failure", "host", ""),
        Rule("system-time-changed", "System", "Microsoft-Windows-Kernel-General", 1, "system", "system_time_changed", null, "host", ""),

        // Application/MSI/crash.
        Rule("application-error", "Application", "Application Error", 1000, "application", "application_crash", "failure", "process,host", "process_image"),
        Rule("windows-error-reporting", "Application", "Windows Error Reporting", 1001, "application", "error_report", "failure", "process,host", "process_image"),
        Rule("msi-install", "Application", "MsiInstaller", 11707, "software", "msi_installed", "success", "package,host", "package_name"),
        Rule("msi-remove", "Application", "MsiInstaller", 11724, "software", "msi_removed", "success", "package,host", "package_name"),

        // PowerShell.
        Rule("powershell-classic-start", "Windows PowerShell", "PowerShell", 400, "powershell", "engine_started", "success", "host,user", "user_name"),
        Rule("powershell-classic-command", "Windows PowerShell", "PowerShell", 600, "powershell", "provider_lifecycle", null, "host,user", "user_name"),
        Rule("powershell-script-block", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, "powershell", "script_block", "success", "script,user,host", "process_command_line,user_name"),
        Rule("powershell-module", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4103, "powershell", "module_logging", "success", "script,user,host", "process_command_line,user_name"),

        // Defender.
        Rule("defender-malware-detected", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116, "malware", "malware_detected", "success", "file,host", "file_path,threat_name"),
        Rule("defender-action-taken", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1117, "malware", "remediation_action", "success", "file,host", "file_path,threat_name"),
        Rule("defender-disabled", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 5007, "tamper", "defender_configuration_changed", null, "host", ""),

        // Task Scheduler, WMI, RDP, WinRM, firewall, policy/code integrity.
        Rule("task-created", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", 106, "persistence", "scheduled_task_created", "success", "task,host,user", "task_name,user_name"),
        Rule("task-run", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", 200, "persistence", "scheduled_task_started", "success", "task,host", "task_name"),
        Rule("wmi-consumer", "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity", 5861, "persistence", "wmi_consumer_activity", null, "process,host,user", "process_image,user_name"),
        Rule("rdp-logon", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager", 21, "remote_access", "rdp_session_logon", "success", "user,host,ip", "user_name,source_ip"),
        Rule("rdp-disconnect", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager", 24, "remote_access", "rdp_session_disconnected", "success", "user,host", "user_name"),
        Rule("winrm-shell", "Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-WinRM", 6, "remote_access", "winrm_shell", null, "user,host,ip", "user_name,source_ip"),
        Rule("firewall-filter", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-Windows Firewall", 2004, "network", "firewall_rule_changed", "success", "host,user", "user_name"),
        Rule("group-policy-change", "Microsoft-Windows-GroupPolicy/Operational", "Microsoft-Windows-GroupPolicy", 5312, "policy", "group_policy_applied", "success", "host", ""),
        Rule("code-integrity-block", "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity", 3077, "code_integrity", "image_blocked", "failure", "file,host", "file_path"),
        Rule("applocker-block", "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker", 8004, "code_integrity", "applocker_blocked", "failure", "file,host,user", "file_path,user_name"),

        // Sysmon L3.
        Rule("sysmon-process-create", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, "process", "process_created", "success", "process,user,hash", "process_image,process_command_line,user_name,hash"),
        Rule("sysmon-process-terminate", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 5, "process", "process_terminated", "success", "process,user", "process_image,user_name"),
        Rule("sysmon-network", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "network", "network_connection", "success", "process,ip,host", "process_image,destination_ip,destination_port"),
        Rule("sysmon-dns", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 22, "network", "dns_query", "success", "process,dns,host", "process_image,query_name"),
        Rule("sysmon-file-create", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 11, "file", "file_created", "success", "file,process,host", "file_path,process_image"),
        Rule("sysmon-file-delete", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 23, "file", "file_deleted", "success", "file,process,host", "file_path,process_image"),
        Rule("sysmon-ads", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 15, "file", "alternate_data_stream_created", "success", "file,process,host", "file_path,process_image"),
        Rule("sysmon-registry-create", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 12, "registry", "registry_object_created", "success", "registry,process,host", "registry_key,process_image"),
        Rule("sysmon-registry-value", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 13, "registry", "registry_value_set", "success", "registry,process,host", "registry_key,process_image"),
        Rule("sysmon-registry-rename", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 14, "registry", "registry_renamed", "success", "registry,process,host", "registry_key,process_image"),
        Rule("sysmon-process-access", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 10, "credential_access", "process_access", "success", "process,user,host", "process_image"),
        Rule("sysmon-image-load", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 7, "image", "image_loaded", "success", "file,process,host", "file_path,process_image"),
        Rule("sysmon-driver-load", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 6, "driver", "driver_loaded", "success", "driver,host", "driver_name,hash"),
        Rule("sysmon-raw-disk", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 9, "impact", "raw_disk_access", "success", "process,host", "process_image"),
        Rule("sysmon-wmi-filter", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 19, "persistence", "wmi_filter", "success", "wmi,host", ""),
        Rule("sysmon-wmi-consumer", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 20, "persistence", "wmi_consumer", "success", "wmi,host", ""),
        Rule("sysmon-wmi-binding", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 21, "persistence", "wmi_binding", "success", "wmi,host", ""),
        Rule("sysmon-pipe-created", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 17, "named_pipe", "pipe_created", "success", "pipe,process,host", "process_image"),
        Rule("sysmon-pipe-connected", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 18, "named_pipe", "pipe_connected", "success", "pipe,process,host", "process_image"),
        Rule("sysmon-config-change", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 16, "tamper", "sysmon_config_changed", "success", "host", ""),
        Rule("sysmon-error", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 255, "tamper", "sysmon_error", "failure", "host", "")
    };

    public static WindowsEventNormalizationRule? Find(string channel, string provider, int eventId)
    {
        return Rules.FirstOrDefault(rule =>
            rule.EventId == eventId &&
            string.Equals(rule.Channel, channel, StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrWhiteSpace(rule.Provider) || provider.Contains(rule.Provider, StringComparison.OrdinalIgnoreCase) || rule.Provider.Contains(provider, StringComparison.OrdinalIgnoreCase)));
    }

    private static WindowsEventNormalizationRule Rule(
        string ruleId,
        string channel,
        string provider,
        int eventId,
        string category,
        string action,
        string? outcome,
        string entityTypes,
        string requiredFields) => new(
            ruleId,
            channel,
            provider,
            eventId,
            category,
            action,
            outcome,
            Split(entityTypes),
            Split(requiredFields));

    private static IReadOnlyList<string> Split(string value) => string.IsNullOrWhiteSpace(value)
        ? Array.Empty<string>()
        : value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
}

public static class WindowsEventNormalizer
{
    public static NormalizedEventFields Normalize(string channel, string provider, int eventId, string message)
    {
        var rule = WindowsEventNormalizationCatalog.Find(channel, provider, eventId);
        if (rule is null)
        {
            return new NormalizedEventFields
            {
                Category = NormalizeChannel(channel),
                Action = "observed",
                Outcome = null,
                Labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["parser"] = "generic_windows_event"
                }
            };
        }

        return new NormalizedEventFields
        {
            Category = rule.Category,
            Action = rule.Action,
            Outcome = rule.Outcome,
            Entities = rule.EntityTypes?.Select(type => new EventEntity
            {
                Type = type,
                Value = ExtractEntityValue(type, message),
                Role = "observed"
            }).Where(entity => !string.IsNullOrWhiteSpace(entity.Value)).ToArray() ?? Array.Empty<EventEntity>(),
            Labels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["normalization_rule"] = rule.RuleId,
                ["required_fields"] = string.Join(',', rule.RequiredFields ?? Array.Empty<string>())
            }
        };
    }

    private static string NormalizeChannel(string channel)
    {
        if (channel.Contains("PowerShell", StringComparison.OrdinalIgnoreCase)) return "powershell";
        if (channel.Contains("Sysmon", StringComparison.OrdinalIgnoreCase)) return "sysmon";
        if (channel.Contains("Defender", StringComparison.OrdinalIgnoreCase)) return "malware";
        if (channel.Contains("Security", StringComparison.OrdinalIgnoreCase)) return "security";
        if (channel.Contains("System", StringComparison.OrdinalIgnoreCase)) return "system";
        return "windows_event";
    }

    private static string ExtractEntityValue(string type, string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return string.Empty;
        }

        return type switch
        {
            "host" => Environment.MachineName,
            "process" => FirstTokenContaining(message, ".exe"),
            "file" => FirstTokenContaining(message, "\\"),
            "ip" => FirstTokenWithDigitAndDot(message),
            "user" => FirstTokenContaining(message, "\\"),
            _ => string.Empty
        };
    }

    private static string FirstTokenContaining(string value, string needle) => value
        .Split(new[] { ' ', '\t', '\r', '\n', '"', '\'' }, StringSplitOptions.RemoveEmptyEntries)
        .FirstOrDefault(token => token.Contains(needle, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

    private static string FirstTokenWithDigitAndDot(string value) => value
        .Split(new[] { ' ', '\t', '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
        .FirstOrDefault(token => token.Any(char.IsDigit) && token.Contains('.', StringComparison.Ordinal)) ?? string.Empty;
}
