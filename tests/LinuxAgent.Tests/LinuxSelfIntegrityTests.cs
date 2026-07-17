using System.Diagnostics;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.SelfIntegrity;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxSelfIntegrityTests
{
    [Fact]
    public async Task SelfIntegrityIsDisabledByDefaultAndRequiresMatchingPlanHash()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = await CreateAllowlistedRootAsync();
        try
        {
            var options = Options(root);
            var collector = Collector(options, root);
            var runtime = new LinuxSelfIntegrityRuntime(Microsoft.Extensions.Options.Options.Create(options), new LinuxSelfIntegrityStateStore(Path.Combine(root, "state.json")), collector, TimeProvider.System);
            await runtime.InitializeAsync(default);

            Assert.False(options.SelfIntegrity.Enabled);
            Assert.False(runtime.IsEnabledAndApproved);
            var disabled = runtime.Health();
            Assert.Equal(SourceHealthStatuses.Disabled, disabled.Status);
            Assert.Equal("collector_disabled", disabled.ErrorCode);

            options.SelfIntegrity.Enabled = true;
            Assert.False(collector.IsEnabledAndApproved);
            options.SelfIntegrity.ApprovedPlanHash = collector.PlanHash;
            Assert.True(collector.IsEnabledAndApproved);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task PreflightReportsExactAllowlistAndRejectsSymlinkEscape()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = await CreateAllowlistedRootAsync();
        try
        {
            File.Delete(Path.Combine(root, "etc/systemd/system/challenger-siem-agent.service"));
            File.CreateSymbolicLink(Path.Combine(root, "etc/systemd/system/challenger-siem-agent.service"), "/etc/passwd");
            var options = Options(root, enabled: true);
            var collector = Collector(options, root);
            var plan = await collector.PreflightAsync(default);

            Assert.Equal(5, plan.Entries.Count);
            Assert.Contains(plan.Entries, item => item.Path == "/etc/systemd/system/challenger-siem-agent.service" && item.State == "unreadable" && item.Reason == "symlink_rejected");
            Assert.Contains("no audit, eBPF, fanotify, inotify, IMA", plan.FilesystemSupport);
            Assert.DoesNotContain("/etc/passwd", string.Join('\n', plan.Entries.Select(item => item.Path)));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task PlanScriptPrintsCanonicalApprovalHashWithoutMutatingState()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = await CreateAllowlistedRootAsync();
        try
        {
            var options = Options(root, enabled: true);
            options.SelfIntegrity.IntervalSeconds = 600;
            options.SelfIntegrity.ScanTimeoutSeconds = 10;
            options.SelfIntegrity.QueuePauseDepth = 1234;
            options.SelfIntegrity.MaxEventsPerScan = 7;
            var expectedHash = LinuxSelfIntegrityCollector.ComputePlanHash(options.SelfIntegrity);
            var configPath = Path.Combine(root, "agentsettings.json");
            await File.WriteAllTextAsync(configPath, """
                {
                  "Agent": {
                    "AgentId": "agent-1",
                    "ServerBaseUrl": "https://siem.synthetic",
                    "ApiToken": "synthetic-token",
                    "SelfIntegrity": {
                      "Enabled": true,
                      "IntervalSeconds": 600,
                      "ScanTimeoutSeconds": 10,
                      "QueuePauseDepth": 1234,
                      "MaxEventsPerScan": 7
                    }
                  }
                }
                """);

            var script = FindRepositoryFile("scripts", "linux-agent.sh");
            var result = await RunProcessAsync("bash", $"\"{script}\" plan --root \"{root}\" --config \"{configPath}\"");

            Assert.Equal(0, result.ExitCode);
            Assert.Contains($"self-integrity approval plan hash: {expectedHash}", result.Stdout, StringComparison.Ordinal);
            Assert.False(File.Exists(options.SelfIntegrity.StatePath));
            Assert.Contains("host policy changes: none", result.Stdout, StringComparison.Ordinal);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task SnapshotEmitsSyntheticAddChangeDeleteUnreadableSampleAndStableIds()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = await CreateAllowlistedRootAsync();
        try
        {
            var options = Options(root, enabled: true);
            options.SelfIntegrity.ApprovedPlanHash = LinuxSelfIntegrityCollector.ComputePlanHash(options.SelfIntegrity);
            var collector = Collector(options, root);
            var state = new LinuxSelfIntegrityState();

            var first = await collector.CollectAsync(state, "agent-1", "SYNTHETIC-LINUX-01", default);
            Assert.Contains(first.Events, item => item.State == LinuxSelfIntegrityStates.Added);
            Assert.Contains(first.Events, item => item.State == LinuxSelfIntegrityStates.Sample);
            Assert.All(first.Events, item => Assert.Equal(DeterministicEventIdentity.ComputeSha256Uuid(item.Envelope), item.Envelope.EventId));

            state = state with { Signatures = first.NewSignatures, NextSequence = first.NextSequence };
            await File.AppendAllTextAsync(Path.Combine(root, "opt/challenger-siem-agent/Challenger.Siem.LinuxAgent"), "SYNTHETIC-CONTENT-CANARY");
            File.Delete(Path.Combine(root, "etc/systemd/system/challenger-siem-agent.service"));
            File.WriteAllBytes(Path.Combine(root, "etc/challenger-siem-agent/agentsettings.json"), new byte[300 * 1024]);

            var second = await collector.CollectAsync(state, "agent-1", "SYNTHETIC-LINUX-01", default);
            Assert.Contains(second.Events, item => item.State == LinuxSelfIntegrityStates.Changed);
            Assert.Contains(second.Events, item => item.State == LinuxSelfIntegrityStates.Deleted);
            Assert.Contains(second.Events, item => item.State == LinuxSelfIntegrityStates.Unreadable);
            Assert.Contains(second.Events, item => item.State == LinuxSelfIntegrityStates.Sample);
            Assert.DoesNotContain(second.Events, item => item.Envelope.Raw.GetRawText().Contains("SYNTHETIC-CONTENT-CANARY", StringComparison.Ordinal));
            Assert.DoesNotContain(second.Events, item => item.Envelope.Raw.GetRawText().Contains("ApiToken", StringComparison.OrdinalIgnoreCase));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void DependenciesDocumentationNamesImplementedSnapshotCollectors()
    {
        var text = File.ReadAllText(FindRepositoryFile("docs", "dependencies.md"));

        Assert.Contains("implements disabled-by-default explicit-opt-in snapshot collectors for agent self-integrity and passive process/socket/host-behaviour evidence", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("documentation-only spike", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Adopted as design only", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PressureDropRestartAndCleanupAreBoundedToCollectorState()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = await CreateAllowlistedRootAsync();
        try
        {
            var options = Options(root, enabled: true);
            options.SelfIntegrity.MaxEventsPerScan = 1;
            options.SelfIntegrity.ApprovedPlanHash = LinuxSelfIntegrityCollector.ComputePlanHash(options.SelfIntegrity);
            var collector = Collector(options, root);
            var stateStorePath = Path.Combine(root, "var/lib/challenger-siem-agent/self-integrity-state.json");
            var stateStore = new LinuxSelfIntegrityStateStore(stateStorePath);
            var runtime = new LinuxSelfIntegrityRuntime(Microsoft.Extensions.Options.Options.Create(options), stateStore, collector, TimeProvider.System);
            await runtime.InitializeAsync(default);

            var dropped = await collector.CollectAsync(new LinuxSelfIntegrityState(), "agent-1", "SYNTHETIC-LINUX-01", default);
            Assert.True(dropped.DroppedCount > 0);
            await runtime.RecordCollectedAsync(dropped, default);
            Assert.True(File.Exists(stateStorePath));
            var loaded = await stateStore.ReadAsync(default);
            Assert.True(loaded.CollectedSequence > 0);

            var pressure = collector.BuildPressureGap(loaded, "agent-1", "SYNTHETIC-LINUX-01", 100000);
            Assert.Single(pressure.Events);
            Assert.Equal(LinuxSelfIntegrityStates.Gap, pressure.Events[0].State);

            options.SelfIntegrity.Enabled = false;
            options.SelfIntegrity.CleanupStateOnDisable = true;
            await runtime.CleanupIfDisabledAsync(default);
            Assert.False(File.Exists(stateStorePath));
            Assert.True(File.Exists(Path.Combine(root, "opt/challenger-siem-agent/Challenger.Siem.LinuxAgent")));
            Assert.True(File.Exists(Path.Combine(root, "etc/challenger-siem-agent/agentsettings.json")));
        }
        finally { Directory.Delete(root, true); }
    }

    private static LinuxAgentOptions Options(string root, bool enabled = false) => new()
    {
        AgentId = "agent-1",
        ServerBaseUrl = new Uri("https://siem.synthetic"),
        ApiToken = "synthetic-token",
        SelfIntegrity = new SelfIntegrityOptions
        {
            Enabled = enabled,
            StatePath = Path.Combine(root, "var/lib/challenger-siem-agent/self-integrity-state.json"),
            IntervalSeconds = 300,
            StartupDelaySeconds = 0,
            ScanTimeoutSeconds = 5,
            QueuePauseDepth = 100,
            MaxEventsPerScan = 20
        }
    };

    private static LinuxSelfIntegrityCollector Collector(LinuxAgentOptions options, string root) =>
        new(Microsoft.Extensions.Options.Options.Create(options), new LinuxSelfIntegritySource(root), TimeProvider.System);

    private static string FindRepositoryFile(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }

        throw new FileNotFoundException("Repository file was not found.", Path.Combine(parts));
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunProcessAsync(string fileName, string arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        process.Start();
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, stdout, stderr);
    }

    private static async Task<string> CreateAllowlistedRootAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-self-integrity-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "opt/challenger-siem-agent"));
        Directory.CreateDirectory(Path.Combine(root, "etc/systemd/system"));
        Directory.CreateDirectory(Path.Combine(root, "etc/challenger-siem-agent"));
        Directory.CreateDirectory(Path.Combine(root, "var/lib/challenger-siem-agent"));
        await File.WriteAllTextAsync(Path.Combine(root, "opt/challenger-siem-agent/Challenger.Siem.LinuxAgent"), "synthetic-binary");
        await File.WriteAllTextAsync(Path.Combine(root, "etc/systemd/system/challenger-siem-agent.service"), "[Service]\nUser=challenger-siem\n");
        await File.WriteAllTextAsync(Path.Combine(root, "etc/challenger-siem-agent/agentsettings.json"), "{\"ApiToken\":\"synthetic-secret\"}");
        return root;
    }
}
