using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Coverage;

public static class WindowsSourceManifest
{
    public static readonly IReadOnlyList<SourceManifestEntry> L2Default = new[]
    {
        Entry("security", "Security", "Windows Security", WindowsCoverageLevel.L1, required: true, "security-log"),
        Entry("system", "System", "Windows System", WindowsCoverageLevel.L1, required: true, "system-log"),
        Entry("application", "Application", "Windows Application", WindowsCoverageLevel.L1, required: true, "application-log"),
        Entry("powershell-classic", "Windows PowerShell", "Windows PowerShell", WindowsCoverageLevel.L2, required: true, "powershell-classic"),
        Entry("powershell-operational", "Microsoft-Windows-PowerShell/Operational", "PowerShell Operational", WindowsCoverageLevel.L2, required: true, "powershell-operational"),
        Entry("defender-operational", "Microsoft-Windows-Windows Defender/Operational", "Microsoft Defender Operational", WindowsCoverageLevel.L2, required: true, "defender-operational"),
        Entry("task-scheduler", "Microsoft-Windows-TaskScheduler/Operational", "Task Scheduler Operational", WindowsCoverageLevel.L2, required: true, "task-scheduler"),
        Entry("wmi-activity", "Microsoft-Windows-WMI-Activity/Operational", "WMI Activity Operational", WindowsCoverageLevel.L2, required: true, "wmi-activity"),
        Entry("terminalservices-local-sessionmanager", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "RDP Local Session Manager", WindowsCoverageLevel.L2, required: true, "rdp-terminalservices"),
        Entry("terminalservices-remoteconnectionmanager", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "RDP Remote Connection Manager", WindowsCoverageLevel.L2, required: true, "rdp-terminalservices"),
        Entry("winrm-operational", "Microsoft-Windows-WinRM/Operational", "WinRM Operational", WindowsCoverageLevel.L2, required: true, "winrm-operational"),
        Entry("firewall-advanced", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Windows Firewall", WindowsCoverageLevel.L2, required: true, "windows-firewall"),
        Entry("group-policy", "Microsoft-Windows-GroupPolicy/Operational", "Group Policy Operational", WindowsCoverageLevel.L2, required: false, "group-policy"),
        Entry("code-integrity", "Microsoft-Windows-CodeIntegrity/Operational", "Code Integrity Operational", WindowsCoverageLevel.L2, required: false, "code-integrity"),
        Entry("applocker-exe-dll", "Microsoft-Windows-AppLocker/EXE and DLL", "AppLocker EXE and DLL", WindowsCoverageLevel.L2, required: false, "applocker-wdac")
    };

    public static readonly IReadOnlyList<SourceManifestEntry> SysmonL3 = new[]
    {
        Entry("sysmon-operational", "Microsoft-Windows-Sysmon/Operational", "Sysmon Operational", WindowsCoverageLevel.L3, required: true, "sysmon")
    };

    public static IReadOnlyList<SourceManifestEntry> Build(IEnumerable<string> requiredChannels, IEnumerable<string> optionalChannels)
    {
        var enabled = requiredChannels
            .Concat(optionalChannels)
            .Where(channel => !string.IsNullOrWhiteSpace(channel))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var known = L2Default.Concat(SysmonL3).ToDictionary(entry => entry.Channel, StringComparer.OrdinalIgnoreCase);
        var results = new List<SourceManifestEntry>();
        foreach (var channel in enabled)
        {
            if (known.TryGetValue(channel, out var entry))
            {
                results.Add(entry);
            }
            else
            {
                results.Add(Entry(Slug(channel), channel, channel, WindowsCoverageLevel.L2, required: false, "custom"));
            }
        }

        return results
            .OrderBy(entry => entry.CoverageLevel)
            .ThenBy(entry => entry.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> DefaultRequiredChannels() => L2Default
        .Where(entry => entry.Required && entry.CoverageLevel <= WindowsCoverageLevel.L1)
        .Select(entry => entry.Channel)
        .ToArray();

    public static IReadOnlyList<string> DefaultOptionalChannels() => L2Default
        .Where(entry => entry.CoverageLevel >= WindowsCoverageLevel.L2)
        .Concat(SysmonL3)
        .Select(entry => entry.Channel)
        .ToArray();

    private static SourceManifestEntry Entry(
        string sourceId,
        string channel,
        string displayName,
        WindowsCoverageLevel level,
        bool required,
        string parserId) => new()
        {
            SourceId = sourceId,
            Channel = channel,
            DisplayName = displayName,
            CoverageLevel = level,
            Required = required,
            EnabledByDefault = required || level <= WindowsCoverageLevel.L2,
            SourcePack = level >= WindowsCoverageLevel.L3 ? "windows-l3-sysmon" : "windows-l2",
            ParserId = parserId
        };

    private static string Slug(string value)
    {
        var chars = value.ToLowerInvariant().Select(ch => char.IsLetterOrDigit(ch) ? ch : '-').ToArray();
        return new string(chars).Trim('-');
    }
}
