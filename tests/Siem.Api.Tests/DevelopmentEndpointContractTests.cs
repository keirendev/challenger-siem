using System.Text.Json;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class DevelopmentEndpointContractTests
{
    [Fact]
    public void StableEndpointDefaultsAreCentralizedAndUsedByLifecycleScripts()
    {
        var endpoints = File.ReadAllText(FindRepositoryFile("scripts/dev-endpoints.sh"));
        Assert.Contains("SIEM_DEV_PERSISTENT_PLATFORM_URL=\"https://127.0.0.1:5443\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("SIEM_DEV_PLATFORM_FALLBACK_URL=\"http://127.0.0.1:5081\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("SIEM_DEV_API_SMOKE_URL=\"http://127.0.0.1:5080\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("SIEM_DEV_WEB_SMOKE_URL=\"http://127.0.0.1:5081\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("SIEM_DEV_WINDOWS_LAB_BIND_URL=\"http://0.0.0.0:4444\"", endpoints, StringComparison.Ordinal);
        Assert.Contains("SIEM_DEV_WINDOWS_LAB_LOCAL_URL=\"http://127.0.0.1:4444\"", endpoints, StringComparison.Ordinal);

        AssertScriptUsesEndpoint("scripts/platform.sh", "SIEM_DEV_PLATFORM_FALLBACK_URL");
        AssertScriptUsesEndpoint("scripts/platform.sh", "SIEM_DEV_PERSISTENT_PLATFORM_URL");
        AssertScriptUsesEndpoint("scripts/smoke-test-server.sh", "SIEM_DEV_API_SMOKE_URL");
        AssertScriptUsesEndpoint("scripts/smoke-test-web.sh", "SIEM_DEV_WEB_SMOKE_URL");
        AssertScriptUsesEndpoint("scripts/run-server-4444.sh", "SIEM_DEV_WINDOWS_LAB_BIND_URL");
        AssertScriptUsesEndpoint("scripts/register-agent.sh", "SIEM_DEV_WINDOWS_LAB_LOCAL_URL");
        AssertScriptUsesEndpoint("scripts/prepare-windows-agent-files.sh", "SIEM_DEV_WINDOWS_LAB_LOCAL_URL");
    }

    [Fact]
    public void PlatformHelperPreventsCompetingPersistentOwnershipAndImplicitHttpsCertificates()
    {
        var script = File.ReadAllText(FindRepositoryFile("scripts/platform.sh"));
        Assert.Contains("CHALLENGER_SIEM_PLATFORM_SYSTEMD_UNIT", script, StringComparison.Ordinal);
        Assert.Contains("systemctl --user", script, StringComparison.Ordinal);
        Assert.Contains("Configured user-systemd unit name is invalid", script, StringComparison.Ordinal);
        Assert.Contains("Refusing to start $SYSTEMD_UNIT while the background helper owns", script, StringComparison.Ordinal);
        Assert.Contains("Refusing HTTPS background start without an explicit stable Kestrel certificate path", script, StringComparison.Ordinal);
        Assert.Contains("CHALLENGER_SIEM_PLATFORM_CA_CERT", script, StringComparison.Ordinal);
    }

    [Fact]
    public void DirectLaunchProfileUsesTheDocumentedInteractivePort()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(
            FindRepositoryFile("server/Siem.Api/Properties/launchSettings.json")));
        var applicationUrl = document.RootElement
            .GetProperty("profiles")
            .GetProperty("http")
            .GetProperty("applicationUrl")
            .GetString();

        Assert.Equal("http://127.0.0.1:5081", applicationUrl);
    }

    private static void AssertScriptUsesEndpoint(string relativePath, string endpointName)
    {
        var script = File.ReadAllText(FindRepositoryFile(relativePath));
        Assert.Contains("source scripts/dev-endpoints.sh", script, StringComparison.Ordinal);
        Assert.Contains(endpointName, script, StringComparison.Ordinal);
    }

    private static string FindRepositoryFile(string relativePath)
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            current = current.Parent;
        }

        throw new FileNotFoundException($"Could not locate repository file: {relativePath}");
    }
}
