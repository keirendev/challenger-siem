using System.Text.Json;
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
}
