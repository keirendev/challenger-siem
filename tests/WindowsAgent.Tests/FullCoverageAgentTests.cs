using System.Text.Json;
using System.Xml.Linq;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Coverage;
using Challenger.Siem.WindowsAgent.Inventory;
using Challenger.Siem.WindowsAgent.Normalization;
using Challenger.Siem.WindowsAgent.Security;
using Xunit;

namespace Challenger.Siem.WindowsAgent.Tests;

public sealed class FullCoverageAgentTests
{
    [Fact]
    public void CoverageLevelsAndSourceStatusesSerializeAsStableStrings()
    {
        var json = JsonSerializer.Serialize(new SourceHealthReport
        {
            SourceId = "security",
            DisplayName = "Windows Security",
            Channel = "Security",
            CoverageLevel = WindowsCoverageLevel.L2,
            Status = SourceHealthStatuses.Healthy,
            Required = true,
            Enabled = true
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.Contains("\"coverage_level\":\"L2\"", json, StringComparison.Ordinal);
        Assert.Contains("\"status\":\"healthy\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void L2ManifestContainsMandatoryWindowsSources()
    {
        var manifest = WindowsSourceManifest.L2Default;
        Assert.Contains(manifest, source => source.Channel == "Security" && source.Required);
        Assert.Contains(manifest, source => source.Channel == "Microsoft-Windows-PowerShell/Operational" && source.CoverageLevel == WindowsCoverageLevel.L2);
        Assert.Contains(manifest, source => source.Channel == "Microsoft-Windows-WinRM/Operational");
        Assert.Contains(WindowsSourceManifest.SysmonL3, source => source.Channel == "Microsoft-Windows-Sysmon/Operational");
    }

    [Fact]
    public void BuildManifestTreatsOptionalChannelsAsConfiguredButNotLocallyRequired()
    {
        var manifest = WindowsSourceManifest.Build(
            new[] { "Security" },
            new[] { "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-Sysmon/Operational" });

        Assert.Contains(manifest, source => source.Channel == "Security" && source.Required);
        Assert.Contains(manifest, source => source.Channel == "Microsoft-Windows-TaskScheduler/Operational" && !source.Required);
        Assert.Contains(manifest, source => source.Channel == "Microsoft-Windows-Sysmon/Operational" && !source.Required);
    }

    [Theory]
    [InlineData("Security", "Microsoft-Windows-Security-Auditing", 4624, "authentication", "logon")]
    [InlineData("Security", "Microsoft-Windows-Security-Auditing", 4720, "account", "user_created")]
    [InlineData("System", "Service Control Manager", 7045, "service", "service_installed")]
    [InlineData("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, "powershell", "script_block")]
    [InlineData("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116, "malware", "malware_detected")]
    [InlineData("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 1, "process", "process_created")]
    [InlineData("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 3, "network", "network_connection")]
    [InlineData("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 13, "registry", "registry_value_set")]
    [InlineData("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", 22, "network", "dns_query")]
    public void NormalizationCatalogCoversMandatoryParserGroups(string channel, string provider, int eventId, string category, string action)
    {
        var normalized = WindowsEventNormalizer.Normalize(channel, provider, eventId, "unit test message");
        Assert.Equal(category, normalized.Category);
        Assert.Equal(action, normalized.Action);
    }

    [Fact]
    public void SyntheticMandatoryL2FixturesMapToNormalizationRules()
    {
        foreach (var fixture in SyntheticWindowsEventFixtures.MandatoryL2Events)
        {
            var normalized = WindowsEventNormalizer.Normalize(fixture.Channel, fixture.Provider, fixture.EventId, fixture.Name);
            Assert.NotEqual("windows_event", normalized.Category);
            Assert.NotEqual("observed", normalized.Action);
        }
    }

    [Fact]
    public void EventLogBaselineRulesFlagSmallLogs()
    {
        var result = EventLogBaselineRules.Evaluate(new SourceHealthReport
        {
            SourceId = "security",
            DisplayName = "Windows Security",
            Channel = "Security",
            LogSizeBytes = 1024
        });

        Assert.False(result.MeetsBaseline);
        Assert.Contains("log size", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AuditPolicyAndRoleHelpersEvaluateBaselineState()
    {
        var policy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Logon"] = "Success and Failure",
            ["Process Creation"] = "Success"
        };

        var snapshot = WindowsInventoryCollectors.CreateAuditPolicySnapshot("agent-1", "HOST1", policy);
        Assert.Equal("audit_policy", snapshot.SnapshotType);
        Assert.NotNull(snapshot.HostTimezone);
        Assert.True(RequiredAuditPolicy.CountDrift(policy) > 0);

        var roles = WindowsRoleDetector.DetectRoles(new[] { "Web-Server" }, new[] { "W3SVC" });
        Assert.Contains("iis_web_server", roles);
    }

    [Fact]
    public void ConfigurationHasherRedactsSecretsBeforeHashing()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"challenger-config-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tempPath, "{\"Agent\":{\"ApiToken\":\"one\",\"ServerBaseUrl\":\"https://siem.example\"}}");
            var first = AgentConfigurationHasher.ComputeHash(new Challenger.Siem.WindowsAgent.Config.AgentConfigFile(tempPath));
            File.WriteAllText(tempPath, "{\"Agent\":{\"ApiToken\":\"two\",\"ServerBaseUrl\":\"https://siem.example\"}}");
            var second = AgentConfigurationHasher.ComputeHash(new Challenger.Siem.WindowsAgent.Config.AgentConfigFile(tempPath));
            Assert.Equal(first, second);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    [Fact]
    public void SourceManifestCarriesMachineReadableInstallerAndValidationMatrix()
    {
        var security = Assert.Single(WindowsTelemetrySourceCatalog.All, source => source.SourceId == "security");
        Assert.Contains("audit_policy_baseline", security.Prerequisites);
        Assert.Contains("authentication", security.EventFamilies);
        Assert.Contains("synthetic_process_creation", security.ValidationScenarios);
        Assert.True(security.InstallerManaged);

        var sysmon = Assert.Single(WindowsTelemetrySourceCatalog.SysmonL3, source => source.SourceId == "sysmon-operational");
        Assert.Contains("sysmon_signed_binary_verified", sysmon.Prerequisites);
        Assert.Contains("dns", sysmon.EventFamilies);
        Assert.Contains("sysmon_wmi_pipe_tamper_event", sysmon.ValidationScenarios);
        Assert.Equal("high_sensitivity", sysmon.Privacy);

        Assert.Contains(WindowsTelemetrySourceCatalog.L4RolePacks, pack => pack.Role == "domain_controller" && pack.Sources.Contains("Directory Service"));
    }

    [Fact]
    public void SysmonProfileHasVersionedSafeFamilyCoverage()
    {
        var path = RepositoryPath("agent", "WindowsAgent", "Sysmon", "challenger-siem-sysmon-l3.xml");
        var text = File.ReadAllText(path);
        var document = XDocument.Parse(text);

        Assert.Contains("Profile version: challenger-siem-l3-2026.07.06", text, StringComparison.Ordinal);
        foreach (var elementName in new[]
        {
            "ProcessCreate",
            "NetworkConnect",
            "DnsQuery",
            "FileCreate",
            "FileDelete",
            "RegistryEvent",
            "DriverLoad",
            "ImageLoad",
            "ProcessAccess",
            "RawAccessRead",
            "WmiEvent",
            "PipeEvent"
        })
        {
            Assert.NotEmpty(document.Descendants(elementName));
        }

        Assert.DoesNotContain("ClipboardChange", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InstallerWorkflowScriptExposesGuardedFullCapabilityModes()
    {
        var script = File.ReadAllText(RepositoryPath("scripts", "install-windows-agent.ps1"));
        Assert.Contains("ValidateSet(\"plan\", \"install\", \"upgrade\", \"repair\", \"validate\", \"uninstall\")", script, StringComparison.Ordinal);
        Assert.Contains("ConfigurePrerequisites", script, StringComparison.Ordinal);
        Assert.Contains("ConfigurePrivacySensitiveAuditPolicy", script, StringComparison.Ordinal);
        Assert.Contains("ManageSysmon", script, StringComparison.Ordinal);
        Assert.Contains("AcceptSysmonEula", script, StringComparison.Ordinal);
        Assert.Contains("Get-AuthenticodeSignature", script, StringComparison.Ordinal);
        Assert.Contains("RestartService", script, StringComparison.Ordinal);
        Assert.Contains("Plan complete. No changes were made.", script, StringComparison.Ordinal);
    }

    private static string RepositoryPath(params string[] segments)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Challenger.Siem.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new InvalidOperationException("Could not locate repository root from test output path.");
        }

        return Path.Combine(new[] { directory.FullName }.Concat(segments).ToArray());
    }
}
