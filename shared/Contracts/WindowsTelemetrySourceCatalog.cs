namespace Challenger.Siem.Contracts.V1;

/// <summary>
/// Canonical Windows source matrix used by agents, server-side coverage checks, and operator validation surfaces.
/// Source IDs are stable API identifiers; parser IDs provide broader aliases for detection prerequisites.
/// </summary>
public static class WindowsTelemetrySourceCatalog
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
        Entry("rdp-corets", "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "RDP CoreTS Operational", WindowsCoverageLevel.L2, required: true, "rdp-corets"),
        Entry("winrm-operational", "Microsoft-Windows-WinRM/Operational", "WinRM Operational", WindowsCoverageLevel.L2, required: true, "winrm-operational"),
        Entry("firewall-advanced", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "Windows Firewall", WindowsCoverageLevel.L2, required: true, "windows-firewall"),
        Entry("group-policy", "Microsoft-Windows-GroupPolicy/Operational", "Group Policy Operational", WindowsCoverageLevel.L2, required: false, "group-policy"),
        Entry("code-integrity", "Microsoft-Windows-CodeIntegrity/Operational", "Code Integrity Operational", WindowsCoverageLevel.L2, required: false, "code-integrity"),
        Entry("applocker-exe-dll", "Microsoft-Windows-AppLocker/EXE and DLL", "AppLocker EXE and DLL", WindowsCoverageLevel.L2, required: false, "applocker-wdac"),
        Entry("applocker-msi-script", "Microsoft-Windows-AppLocker/MSI and Script", "AppLocker MSI and Script", WindowsCoverageLevel.L2, required: false, "applocker-wdac"),
        Entry("applocker-packaged-app", "Microsoft-Windows-AppLocker/Packaged app-Execution", "AppLocker Packaged App Execution", WindowsCoverageLevel.L2, required: false, "applocker-wdac")
    };

    public static readonly IReadOnlyList<SourceManifestEntry> SysmonL3 = new[]
    {
        Entry("sysmon-operational", "Microsoft-Windows-Sysmon/Operational", "Sysmon Operational", WindowsCoverageLevel.L3, required: true, "sysmon")
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

        var known = All.ToDictionary(entry => entry.Channel, StringComparer.OrdinalIgnoreCase);
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
                results.Add(Entry(Slug(channel), channel, channel, WindowsCoverageLevel.L2, required.Contains(channel), "custom"));
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
