using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Tests;

public static class SyntheticWindowsEventFixtures
{
    public static IReadOnlyList<(string Channel, string Provider, int EventId, string Name)> MandatoryL2Events { get; } = new[]
    {
        ("Security", "Microsoft-Windows-Security-Auditing", 4624, "logon_success"),
        ("Security", "Microsoft-Windows-Security-Auditing", 4625, "logon_failure"),
        ("Security", "Microsoft-Windows-Security-Auditing", 4688, "process_created"),
        ("System", "Service Control Manager", 7045, "service_installed"),
        ("Application", "Application Error", 1000, "application_crash"),
        ("Windows PowerShell", "PowerShell", 400, "powershell_engine"),
        ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, "script_block"),
        ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116, "defender_malware"),
        ("Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler", 106, "task_created"),
        ("Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity", 5861, "wmi_activity"),
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager", 21, "rdp_logon"),
        ("Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-WinRM", 6, "winrm_shell"),
        ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Microsoft-Windows-Windows Firewall", 2004, "firewall_rule_changed"),
        ("Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity", 3077, "code_integrity_block")
    };

    public static EventEnvelope CreateEnvelope(string agentId, string hostname, string channel, string provider, int eventId, NormalizedEventFields normalized)
    {
        return new EventEnvelope
        {
            EventId = Guid.NewGuid(),
            AgentId = agentId,
            Hostname = hostname,
            Source = EventSources.WindowsEventLog,
            Channel = channel,
            Provider = provider,
            WindowsEventId = eventId,
            RecordId = eventId,
            EventTime = DateTimeOffset.UtcNow,
            Severity = "information",
            Message = $"Synthetic fixture {channel} {eventId}",
            Normalized = normalized,
            Raw = System.Text.Json.JsonSerializer.SerializeToElement(new { synthetic = true, channel, eventId })
        };
    }
}
