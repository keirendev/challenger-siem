using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Detections;

public static class DetectionRuleCatalog
{
    public static IReadOnlyList<DetectionRuleMetadata> BuiltInRules { get; } = new[]
    {
        Rule("auth.bruteforce.windows", "Repeated Windows logon failures", "Detects repeated Security 4625 failures against a host or account.", DetectionSeverities.High, "authentication", "security", "target_user_name,source_ip", "T1110"),
        Rule("auth.admin-special-logon", "Administrative special logon", "Flags Security 4672 special privilege logons for review.", DetectionSeverities.Medium, "authentication", "security", "user_name", "T1078"),
        Rule("account.user-created", "Local or domain user created", "Detects Security 4720 user creation events.", DetectionSeverities.Medium, "account", "security", "target_user_name", "T1136"),
        Rule("account.group-member-added", "Privileged group membership changed", "Detects group membership additions such as Security 4732.", DetectionSeverities.High, "account", "security", "target_user_name", "T1098"),
        Rule("powershell.suspicious-script-block", "Suspicious PowerShell script block", "Detects suspicious encoded, download, reflection, or bypass script content from 4104 telemetry.", DetectionSeverities.High, "powershell", "powershell-operational", "process_command_line", "T1059.001"),
        Rule("lolbin.suspicious-child-process", "Suspicious LOLBin execution", "Detects high-risk Windows binaries used for proxy execution or download behavior.", DetectionSeverities.Medium, "process", "security,sysmon", "process_image,process_command_line", "T1218"),
        Rule("credential.lsass-access", "Possible credential theft through LSASS access", "Detects Sysmon process access to LSASS or raw Security credential-access signals.", DetectionSeverities.Critical, "credential_access", "sysmon", "process_image", "T1003.001"),
        Rule("persistence.scheduled-task", "Scheduled task persistence", "Detects task creation or modification through Task Scheduler/Security/Sysmon telemetry.", DetectionSeverities.High, "persistence", "task-scheduler,security,sysmon", "task_name,user_name", "T1053.005"),
        Rule("persistence.wmi-subscription", "WMI event subscription persistence", "Detects WMI consumer/filter/binding activity from WMI Activity or Sysmon.", DetectionSeverities.High, "persistence", "wmi-activity,sysmon", "process_image,user_name", "T1546.003"),
        Rule("tamper.event-log-cleared", "Windows event log cleared", "Detects Security 1102 and source-health clear/truncation indicators.", DetectionSeverities.Critical, "tamper", "security", "user_name", "T1070.001"),
        Rule("tamper.defender-disabled", "Defender configuration changed", "Detects Defender 5007 or equivalent policy changes.", DetectionSeverities.High, "tamper", "defender-operational", "threat_name", "T1562.001"),
        Rule("malware.defender-detection", "Microsoft Defender malware detection", "Creates an alert from Defender 1116/1117 malware detections.", DetectionSeverities.High, "malware", "defender-operational", "file_path,threat_name", "T1204"),
        Rule("network.bits-suspicious", "Suspicious BITS transfer", "Detects BITS/network/C2-like transfer telemetry when available.", DetectionSeverities.Medium, "network", "sysmon", "destination_ip,destination_port", "T1197"),
        Rule("impact.ransomware-burst", "Ransomware-like file activity burst", "Detects high-volume file create/delete/rename impact patterns from Sysmon.", DetectionSeverities.Critical, "impact", "sysmon", "file_path,process_image", "T1486"),
        Rule("coverage.source-missing", "Detection prerequisite source missing", "Creates prerequisite warnings when mandatory sources for enabled rules are missing, stale, or excepted.", DetectionSeverities.Informational, "coverage", "source-health", "source_id,status", "")
    };

    private static DetectionRuleMetadata Rule(
        string id,
        string name,
        string description,
        string severity,
        string category,
        string requiredSources,
        string requiredFields,
        string mitre) => new()
        {
            RuleId = id,
            Name = name,
            Description = description,
            Severity = severity,
            Confidence = "medium",
            Category = category,
            RequiredSources = Split(requiredSources),
            RequiredFields = Split(requiredFields),
            MitreAttack = Split(mitre),
            Enabled = true
        };

    private static IReadOnlyList<string> Split(string value) => string.IsNullOrWhiteSpace(value)
        ? Array.Empty<string>()
        : value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
}
