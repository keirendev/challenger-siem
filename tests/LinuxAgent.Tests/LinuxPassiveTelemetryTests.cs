using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.Passive;
using Challenger.Siem.LinuxAgent.Services;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxPassiveTelemetryTests
{
    private static readonly DateTimeOffset SyntheticNow = DateTimeOffset.Parse("2026-07-16T00:00:00Z");
    private const string SyntheticBootId = "11111111-2222-4333-8444-555555555555";
    private static readonly string SyntheticBootHash = Sha256(SyntheticBootId);

    [Fact]
    public void PackIsDisabledByDefaultMandatoryAtL3AndRequiresExactPlanHash()
    {
        var options = CreateAgentOptions();
        var sources = new SyntheticSources();
        var collector = Collector(options, sources);

        Assert.False(options.PassiveTelemetry.Enabled);
        Assert.True(options.HasValidPassiveTelemetryBounds());
        Assert.False(collector.IsEnabledAndApproved);
        var originalHash = collector.PlanHash;
        Assert.StartsWith("sha256:", originalHash, StringComparison.Ordinal);
        options.PassiveTelemetry.StartupDelaySeconds++;
        Assert.NotEqual(originalHash, collector.PlanHash);
        options.PassiveTelemetry.StartupDelaySeconds--;
        Assert.Equal(originalHash, collector.PlanHash);
        options.Queue.WarningSizePercent++;
        Assert.NotEqual(originalHash, collector.PlanHash);
        options.Queue.WarningSizePercent--;
        options.Journal.MaxRecordsPerPoll++;
        Assert.NotEqual(originalHash, collector.PlanHash);
        options.Journal.MaxRecordsPerPoll--;
        Assert.Equal(originalHash, collector.PlanHash);
        options.Journal.IncludeAccessibleUserJournals = true;
        Assert.NotEqual(originalHash, collector.PlanHash);
        options.Journal.IncludeAccessibleUserJournals = false;
        Assert.Equal(originalHash, collector.PlanHash);
        options.PassiveTelemetry.StatePath = "/tmp/not-pack-owned.json";
        Assert.False(options.HasValidPassiveTelemetryBounds());
        options.PassiveTelemetry.StatePath = "/var/lib/challenger-siem-agent/passive-telemetry-state.json";
        options.PassiveTelemetry.MaxEventsPerScan = options.PassiveTelemetry.QueuePauseDepth + 1;
        Assert.False(options.HasValidPassiveTelemetryBounds());
        options.PassiveTelemetry.MaxEventsPerScan = 500;
        options.Journal.QueuePauseDepth = options.PassiveTelemetry.QueuePauseDepth - 1;
        Assert.False(options.HasValidPassiveTelemetryBounds());
        options.Journal.QueuePauseDepth = 100_000;
        Assert.True(options.HasValidPassiveTelemetryBounds());
        options.Queue.MaxSizeMb = 1;
        Assert.True(options.HasValidQueueBounds());
        Assert.False(options.HasValidPassiveTelemetryBounds());
        options.Queue.MaxSizeMb = 512;
        options.Queue.WarningSizePercent = 96;
        Assert.False(options.HasValidQueueBounds());
        Assert.False(options.HasValidPassiveTelemetryBounds());
        options.Queue.WarningSizePercent = 80;
        Assert.True(options.HasValidQueueBounds());
        Assert.True(options.HasValidPassiveTelemetryBounds());
        Assert.Equal(3, LinuxTelemetrySourceCatalog.L3Passive.Count);
        Assert.All(LinuxTelemetrySourceCatalog.L3Passive, source =>
        {
            Assert.Equal(WindowsCoverageLevel.L3, source.CoverageLevel);
            Assert.True(source.Required);
            Assert.Equal(SourceRequirementKinds.Mandatory, source.Requirement);
            Assert.False(source.EnabledByDefault);
            Assert.Equal(SourceCheckpointKinds.Sequence, source.CheckpointKind);
        });

        options.PassiveTelemetry.Enabled = true;
        options.PassiveTelemetry.ApprovedPlanHash = "sha256:mismatch";
        Assert.False(collector.IsEnabledAndApproved);
        options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
        Assert.True(collector.IsEnabledAndApproved);

        var plan = collector.Preflight();
        Assert.True(plan.ApprovalHashMatches);
        Assert.Equal(3, plan.Sources.Count);
        var serialized = JsonSerializer.Serialize(plan);
        Assert.DoesNotContain("/proc/<numeric-pid>/environ", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("/proc/<numeric-pid>/fd", serialized, StringComparison.Ordinal);
        Assert.Contains("No environment values", plan.Exclusions, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PlanScriptMatchesCanonicalHashAndDoesNotCreatePassiveState()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-plan-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.StartupDelaySeconds = 8;
            options.PassiveTelemetry.ProcessPollIntervalSeconds = 18;
            options.PassiveTelemetry.NetworkPollIntervalSeconds = 20;
            options.PassiveTelemetry.HostMetricsIntervalSeconds = 61;
            options.PassiveTelemetry.ScanTimeoutSeconds = 6;
            options.PassiveTelemetry.QueuePauseDepth = 5432;
            options.PassiveTelemetry.MaxProcessesPerScan = 1234;
            options.PassiveTelemetry.MaxSocketsPerScan = 2345;
            options.PassiveTelemetry.MaxEventsPerScan = 345;
            options.PassiveTelemetry.MaxProcessReadBytesPerScan = 2 * 1024 * 1024;
            options.PassiveTelemetry.MaxNetworkReadBytesPerScan = 512 * 1024;
            options.PassiveTelemetry.MaxCommandLineBytes = 2048;
            options.PassiveTelemetry.MaxRawEventBytes = 8192;
            options.PassiveTelemetry.CleanupStateOnDisable = true;
            options.Queue.MaxSizeMb = 640;
            options.Queue.WarningSizePercent = 75;
            options.Journal.MaxRecordsPerPoll = 321;
            options.Journal.MaxInputRecordBytes = 65_536;
            options.Journal.IncludeAccessibleUserJournals = true;
            Assert.True(options.HasValidPassiveTelemetryBounds());
            var expected = LinuxPassiveTelemetryCollector.ComputePlanHash(options);
            var configPath = Path.Combine(root, "agentsettings.json");
            var passive = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["sTaRtUpDeLaYsEcOnDs"] = options.PassiveTelemetry.StartupDelaySeconds,
                ["ProcessPollIntervalSeconds"] = options.PassiveTelemetry.ProcessPollIntervalSeconds,
                ["NetworkPollIntervalSeconds"] = options.PassiveTelemetry.NetworkPollIntervalSeconds,
                ["HostMetricsIntervalSeconds"] = options.PassiveTelemetry.HostMetricsIntervalSeconds,
                ["ScanTimeoutSeconds"] = options.PassiveTelemetry.ScanTimeoutSeconds,
                ["QueuePauseDepth"] = options.PassiveTelemetry.QueuePauseDepth,
                ["MaxProcessesPerScan"] = options.PassiveTelemetry.MaxProcessesPerScan,
                ["MaxSocketsPerScan"] = options.PassiveTelemetry.MaxSocketsPerScan,
                ["MaxEventsPerScan"] = options.PassiveTelemetry.MaxEventsPerScan,
                ["MaxProcessReadBytesPerScan"] = options.PassiveTelemetry.MaxProcessReadBytesPerScan,
                ["MaxNetworkReadBytesPerScan"] = options.PassiveTelemetry.MaxNetworkReadBytesPerScan,
                ["MaxCommandLineBytes"] = options.PassiveTelemetry.MaxCommandLineBytes,
                ["MaxRawEventBytes"] = options.PassiveTelemetry.MaxRawEventBytes,
                ["CleanupStateOnDisable"] = options.PassiveTelemetry.CleanupStateOnDisable,
                ["StatePath"] = options.PassiveTelemetry.StatePath
            };
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["aGeNt"] = new Dictionary<string, object?>
                {
                    ["pAsSiVeTeLeMeTrY"] = passive,
                    ["jOuRnAl"] = new Dictionary<string, object?>
                    {
                        ["qUeUePaUsEdEpTh"] = options.Journal.QueuePauseDepth,
                        ["mAxReCoRdSpErPoLl"] = options.Journal.MaxRecordsPerPoll,
                        ["mAxInPuTrEcOrDbYtEs"] = options.Journal.MaxInputRecordBytes,
                        ["iNcLuDeAcCeSsIbLeUsErJoUrNaLs"] = options.Journal.IncludeAccessibleUserJournals
                    },
                    ["qUeUe"] = new Dictionary<string, object?>
                    {
                        ["mAxSiZeMb"] = options.Queue.MaxSizeMb,
                        ["wArNiNgSiZePeRcEnT"] = options.Queue.WarningSizePercent
                    }
                }
            }));
            var script = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../scripts/linux-agent.sh"));

            var result = await RunProcessAsync("bash", $"\"{script}\" plan --root \"{root}\" --config \"{configPath}\"");

            Assert.Equal(0, result.ExitCode);
            Assert.Contains($"passive telemetry approval plan hash: {expected}", result.Output, StringComparison.Ordinal);
            Assert.Contains("journal scope: all_accessible_local", result.Output, StringComparison.Ordinal);
            Assert.Contains("durable sequence reservation before queue insertion", result.Output, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(root, "var/lib/challenger-siem-agent/passive-telemetry-state.json")));

            var overrideRejected = await RunProcessAsync(
                "bash",
                $"\"{script}\" plan --root \"{root}\" --config \"{configPath}\"",
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["CHALLENGER_SIEM_AGENT_Agent__PassiveTelemetry__MaxEventsPerScan"] = "1",
                    ["CHALLENGER_SIEM_AGENT_Agent__Queue__MaxSizeMb"] = "1024"
                });
            Assert.NotEqual(0, overrideRejected.ExitCode);
            Assert.Contains("configuration environment overrides are present", overrideRejected.Output, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("/usr/bin/tool --token synthetic-secret", "/usr/bin/tool --token <redacted>")]
    [InlineData("curl -H Authorization:BearerValue https://example.invalid", "curl -H Authorization:<redacted> https://example.invalid")]
    [InlineData("client dsn=postgres://synthetic-user:synthetic-password@example.invalid/db", "client dsn=<redacted>")]
    [InlineData("fetch https://synthetic-user:synthetic-password@example.invalid/path", "fetch https://<redacted>@example.invalid/path")]
    public void SharedSanitizerRedactsCredentialForms(string input, string expected)
    {
        var result = TelemetryTextSanitizer.SanitizeAndRedact(input, 4096);
        Assert.False(result.Dropped);
        Assert.True(result.Redacted);
        Assert.Equal(expected, result.Value);
        Assert.DoesNotContain("synthetic-secret", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-password", result.Value, StringComparison.Ordinal);
    }

    [Fact]
    public void ProcessStatParserHandlesSpacesParenthesesAndPidReuseIdentityFields()
    {
        var stat = "42 (synthetic worker (one)) S 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98765 0 0";
        Assert.True(LinuxProcfsProcessSource.TryParseStat(stat, out var parsed));
        Assert.Equal(42, parsed.ProcessId);
        Assert.Equal(7, parsed.ParentProcessId);
        Assert.Equal(98765, parsed.StartTicks);
        Assert.Equal("synthetic worker (one)", parsed.Command);
        Assert.True(LinuxProcfsProcessSource.TryParseStat(
            "42 (synthetic worker (one)) R 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98766 0 0",
            out var reused));
        Assert.False(LinuxProcfsProcessSource.SameIdentity(parsed, reused));
        Assert.Equal("restricted", LinuxProcfsProcessSource.DetermineProcVisibility(
            "24 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=2\n"));

        var status = LinuxProcfsProcessSource.ParseStatus("""
            Name:	synthetic
            Uid:	1001	1001	1001	1001
            Gid:	1002	1002	1002	1002
            CapEff:	0000000000000000
            NoNewPrivs:	1
            Seccomp:	2
            TracerPid:	0
            VmRSS:	9999 kB
            """);
        Assert.Equal(6, status.Count);
        Assert.DoesNotContain("VmRSS", status.Keys);
    }

    [Fact]
    public async Task ProcessSourceExcludesSchedulerStateChurnAndFailsClosedOnInvalidSensitiveText()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-proc-identity-{Guid.NewGuid():N}");
        var process = Path.Combine(root, "100");
        Directory.CreateDirectory(process);
        Directory.CreateDirectory(Path.Combine(root, "self"));
        Directory.CreateDirectory(Path.Combine(root, "sys", "kernel", "random"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "self", "mountinfo"),
                "24 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n");
            await File.WriteAllTextAsync(Path.Combine(root, "sys", "kernel", "random", "boot_id"), SyntheticBootId + "\n");
            await File.WriteAllTextAsync(Path.Combine(process, "stat"), ProcessStat(100, 1, 5000, "S"));
            var options = CreateAgentOptions(enabled: true);
            var source = new LinuxProcfsProcessSource(root);

            var sleeping = await source.ReadAsync(options.PassiveTelemetry, default);
            await File.WriteAllTextAsync(Path.Combine(process, "stat"), ProcessStat(100, 1, 5000, "R"));
            var running = await source.ReadAsync(options.PassiveTelemetry, default);

            Assert.Equal(PassiveReadStatuses.Success, sleeping.Status);
            Assert.Equal(PassiveReadStatuses.Success, running.Status);
            Assert.Equal("S", Assert.Single(sleeping.Items).State);
            Assert.Equal("R", Assert.Single(running.Items).State);
            Assert.Equal(sleeping.Items[0].Signature, running.Items[0].Signature);

            await File.WriteAllBytesAsync(Path.Combine(process, "cmdline"), [0xff, 0xfe, 0x00]);
            var invalid = await source.ReadAsync(options.PassiveTelemetry, default);
            var observation = Assert.Single(invalid.Items);
            Assert.Equal(PassiveReadStatuses.Partial, invalid.Status);
            Assert.Null(observation.CommandLine);
            Assert.True(observation.CommandLineRedacted);
            Assert.True(observation.InvalidText);
            Assert.True(observation.EnrichmentPartial);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void NetworkParserDecodesIpv4Ipv6AndKeepsPollingHonestState()
    {
        Assert.True(LinuxProcfsNetworkSource.TryParseEndpoint("0100007F:0016", false, out var ipv4, out var port));
        Assert.Equal(IPAddress.Loopback.ToString(), ipv4);
        Assert.Equal(22, port);
        Assert.True(LinuxProcfsNetworkSource.TryParseEndpoint("00000000000000000000000001000000:01BB", true, out var ipv6, out port));
        Assert.Equal(IPAddress.IPv6Loopback.ToString(), ipv6);
        Assert.Equal(443, port);

        const string line = "0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1001 0 12345 1";
        Assert.True(LinuxProcfsNetworkSource.TryParseSocketLine(line, "tcp", false, out var socket));
        Assert.Equal("listen", socket.State);
        Assert.Null(socket.RemoteAddress);
        Assert.Null(socket.RemotePort);
        Assert.Equal("1001", socket.UserId);
        Assert.Equal(12345, socket.Inode);
        const string establishedLine = "0: 0100007F:0016 00000000:0000 01 00000000:00000000 00:00000000 00000000 1001 0 12345 1";
        Assert.True(LinuxProcfsNetworkSource.TryParseSocketLine(establishedLine, "tcp", false, out var established));
        Assert.Equal(socket.Key, established.Key);
        Assert.NotEqual(socket.Signature, established.Signature);
    }

    [Fact]
    public void HostMetricsParserCoalescesOnlyAggregateCounters()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["stat"] = "cpu  100 20 30 400 10 0 0 0 999 888\nprocs_running 3\nprocs_blocked 1\n",
            ["meminfo"] = "MemTotal: 1000 kB\nMemAvailable: 600 kB\nSwapFree: 200 kB\n",
            ["loadavg"] = "1.25 0.50 0.10 2/100 1\n",
            ["uptime"] = "1234.50 0.00\n",
            ["diskstats"] = "8 0 sda 1 0 11 0 2 0 22 0 0 0 0 0 0 0 0\n",
            ["netdev"] = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n",
            ["pressure_cpu"] = "some avg10=1.50 avg60=1.00 avg300=0.50 total=10\n",
            ["pressure_memory"] = "some avg10=0.25 avg60=0.10 avg300=0.05 total=5\n",
            ["pressure_io"] = "some avg10=2.75 avg60=1.00 avg300=0.50 total=20\n"
        };

        var metrics = LinuxHostMetricsSource.Parse(values, SyntheticNow);
        Assert.Equal(1250, metrics.Load1Milli);
        Assert.Equal(1_024_000, metrics.MemoryTotalBytes);
        Assert.Equal(1234, metrics.UptimeSeconds);
        Assert.Equal(560, metrics.CpuTotalTicks);
        Assert.Equal(410, metrics.CpuIdleTicks);
        Assert.Equal(11, metrics.DiskReadSectors);
        Assert.Equal(22, metrics.DiskWrittenSectors);
        Assert.Equal(100, metrics.NetworkReceiveBytes);
        Assert.Equal(200, metrics.NetworkTransmitBytes);
        Assert.Equal(1500, metrics.CpuPressureSomeAvg10Milli);
    }

    [Fact]
    public async Task OptionalIpv6AndPressureFilesDoNotDegradeRequiredProcfsEvidence()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-optional-synthetic-{Guid.NewGuid():N}");
        var net = Path.Combine(root, "net");
        Directory.CreateDirectory(net);
        Directory.CreateDirectory(Path.Combine(root, "sys", "kernel", "random"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "sys", "kernel", "random", "boot_id"), SyntheticBootId + "\n");
            const string header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
            const string socket = "0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1001 0 12345 1\n";
            await File.WriteAllTextAsync(Path.Combine(net, "tcp"), header + socket + socket);
            await File.WriteAllTextAsync(Path.Combine(net, "udp"), header);
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.MaxSocketsPerScan = 1;
            var network = await new LinuxProcfsNetworkSource(net).ReadAsync(options.PassiveTelemetry, default);

            Assert.Equal(PassiveReadStatuses.Success, network.Status);
            Assert.Equal(0, network.VisibilityGapCount);
            Assert.Equal(2, Assert.Single(network.Items).Count);
            Assert.Equal("not_available", network.Details!["table_tcp6"]);
            Assert.Equal("not_available", network.Details["table_udp6"]);

            await File.WriteAllTextAsync(Path.Combine(root, "stat"), "cpu  100 20 30 400 10 0 0 0 0 0\nprocs_running 3\nprocs_blocked 1\n");
            await File.WriteAllTextAsync(Path.Combine(root, "meminfo"), "MemTotal: 1000 kB\nMemAvailable: 600 kB\nSwapFree: 200 kB\n");
            await File.WriteAllTextAsync(Path.Combine(root, "loadavg"), "1.25 0.50 0.10 2/100 1\n");
            await File.WriteAllTextAsync(Path.Combine(root, "uptime"), "1234.50 0.00\n");
            await File.WriteAllTextAsync(Path.Combine(root, "diskstats"), "8 0 sda 1 0 11 0 2 0 22 0 0 0 0 0 0 0 0\n");
            await File.WriteAllTextAsync(Path.Combine(net, "dev"),
                "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\nlo: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n");
            var metrics = await new LinuxHostMetricsSource(root, new FixedTimeProvider(SyntheticNow))
                .ReadAsync(options.PassiveTelemetry, default);

            Assert.Equal(PassiveReadStatuses.Success, metrics.Status);
            Assert.Equal(0, metrics.VisibilityGapCount);
            Assert.Equal("not_available", metrics.Details!["input_pressure_cpu"]);
            Assert.Equal("complete", metrics.Details["core_parse"]);

            await File.WriteAllTextAsync(Path.Combine(root, "loadavg"), "1.25 malformed 0.10 2/100 1\n");
            var malformed = await new LinuxHostMetricsSource(root, new FixedTimeProvider(SyntheticNow))
                .ReadAsync(options.PassiveTelemetry, default);
            Assert.Equal(PassiveReadStatuses.Partial, malformed.Status);
            Assert.Equal("incomplete", malformed.Details!["core_parse"]);
            Assert.Null(Assert.Single(malformed.Items).Load5Milli);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task NormalProcRaceAndMissingOptionalEnrichmentDoNotCreateDropsOrDegradedHealth()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-proc-synthetic-{Guid.NewGuid():N}");
        var stable = Path.Combine(root, "100");
        var vanished = Path.Combine(root, "101");
        var bootDirectory = Path.Combine(root, "sys", "kernel", "random");
        Directory.CreateDirectory(stable);
        Directory.CreateDirectory(vanished);
        Directory.CreateDirectory(bootDirectory);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(bootDirectory, "boot_id"), SyntheticBootId + "\n");
            Directory.CreateDirectory(Path.Combine(root, "self"));
            await File.WriteAllTextAsync(
                Path.Combine(root, "self", "mountinfo"),
                "24 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n");
            await File.WriteAllTextAsync(
                Path.Combine(stable, "stat"),
                "100 (synthetic worker) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5000 0 0");

            var options = CreateAgentOptions(enabled: true);
            var read = await new LinuxProcfsProcessSource(root).ReadAsync(options.PassiveTelemetry, default);

            Assert.Equal(PassiveReadStatuses.Success, read.Status);
            Assert.Equal(1, read.SkippedCount);
            Assert.Equal(0, read.VisibilityGapCount);
            Assert.False(Assert.Single(read.Items).EnrichmentPartial);

            var sources = new SyntheticSources { Processes = read };
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var result = await collector.CollectProcessesAsync(new(), options.AgentId, "synthetic-host", default);

            Assert.Equal(SourceHealthStatuses.Healthy, result.HealthStatus);
            Assert.Equal(1, result.ReadSkipCount);
            Assert.Equal(0, result.GapCount);
            Assert.Equal(0, result.DroppedCount);
            Assert.False(result.Partial);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ProcessDiffIsDeterministicBoundedRedactedAndDoesNotInventExitsFromPartialReads()
    {
        var options = CreateAgentOptions(enabled: true);
        options.PassiveTelemetry.MaxEventsPerScan = 2;
        var sources = new SyntheticSources
        {
            Processes = Successful(
                Process(10, 1, 100, "/usr/bin/synthetic-a", "--token synthetic-secret"),
                Process(11, 1, 101, "/usr/bin/synthetic-b", null),
                Process(12, 1, 102, "/usr/bin/synthetic-c", null))
        };
        var collector = Collector(options, sources);
        options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;

        var first = await collector.CollectProcessesAsync(new(), "synthetic-agent", "synthetic-host", default);
        var replay = await collector.CollectProcessesAsync(new(), "synthetic-agent", "synthetic-host", default);
        Assert.Equal(2, first.Events.Count);
        Assert.Equal(first.Events.Select(item => item.EventId), replay.Events.Select(item => item.EventId));
        Assert.Equal(0, first.DroppedCount);
        Assert.Equal(1, first.DeferredCount);
        Assert.Equal(SourceHealthStatuses.Degraded, first.HealthStatus);
        Assert.All(first.Events, item =>
        {
            Assert.Equal(EventSources.InventoryDiff, item.Source);
            Assert.Equal(LinuxTelemetrySourceIds.ProcessSnapshotDiff, item.SourceId);
            Assert.Equal(item.EventId, DeterministicEventIdentity.ComputeSha256Uuid(item));
            Assert.Equal("process_baseline", item.EventCode);
        });
        var serialized = JsonSerializer.Serialize(first.Events);
        Assert.DoesNotContain("synthetic-secret", serialized, StringComparison.Ordinal);
        Assert.Contains(first.Events, item => item.Normalized?.ProcessCommandLine?.Contains("<redacted>", StringComparison.Ordinal) == true);

        sources.Processes = Successful(
            Process(10, 1, 100, "/usr/bin/synthetic-a", "--token synthetic-secret"),
            Process(11, 1, 101, "/usr/bin/synthetic-b", null),
            Process(12, 1, 102, "/usr/bin/synthetic-c", null));
        var completedBaseline = await collector.CollectProcessesAsync(first.NewState, "synthetic-agent", "synthetic-host", default);
        Assert.Single(completedBaseline.Events);
        Assert.Equal("process_baseline", completedBaseline.Events[0].EventCode);
        Assert.Equal(0, completedBaseline.DeferredCount);
        Assert.Equal(SourceHealthStatuses.Healthy, completedBaseline.HealthStatus);
        Assert.Equal(3, completedBaseline.NewState.Process.Baseline.Count);
        Assert.True(completedBaseline.NewState.Process.BaselineEstablished);

        var visibilityDegraded = Process(10, 1, 100, "/usr/bin/synthetic-a", "--token synthetic-secret") with
        {
            Signature = Sha256("synthetic-incomplete-enrichment"),
            EnrichmentPartial = true
        };
        var priorCompleteSignature = completedBaseline.NewState.Process.Baseline[visibilityDegraded.Key].Signature;
        sources.Processes = new(
            [visibilityDegraded],
            PassiveReadStatuses.Partial,
            "process_enrichment_partial",
            true,
            100,
            2,
            Details: BootDetails());
        var partial = await collector.CollectProcessesAsync(completedBaseline.NewState, "synthetic-agent", "synthetic-host", default);
        Assert.DoesNotContain(partial.Events, item => item.EventCode == "process_disappeared");
        Assert.DoesNotContain(partial.Events, item => item.EventCode == "process_changed");
        Assert.Equal(priorCompleteSignature, partial.NewState.Process.Baseline[visibilityDegraded.Key].Signature);
        Assert.Equal(3, partial.NewState.Process.Baseline.Count);

        sources.Processes = Successful(Process(10, 1, 100, "/usr/bin/synthetic-a", "--token synthetic-secret"));
        var complete = await collector.CollectProcessesAsync(partial.NewState, "synthetic-agent", "synthetic-host", default);
        Assert.Contains(complete.Events, item => item.EventCode == "process_disappeared");
    }

    [Fact]
    public async Task PartialBaselinesAgeAndCapDeterministicallyWithoutUnboundedStateGrowth()
    {
        var options = CreateAgentOptions(enabled: true);
        options.PassiveTelemetry.MaxProcessesPerScan = 2;
        var staleKey = Sha256("stale");
        var previous = new LinuxPassiveTelemetryState
        {
            BootIdentitySha256 = SyntheticBootHash,
            Process = new LinuxPassiveProcessState
            {
                BaselineEstablished = true,
                Baseline = new Dictionary<string, LinuxProcessBaseline>(StringComparer.Ordinal)
                {
                    [staleKey] = new()
                    {
                        Signature = Sha256("stale-signature"),
                        ProcessId = 9,
                        ParentProcessId = 1,
                        MissedPartialScans = LinuxPassiveTelemetryLimits.PartialBaselineMissLimit - 1
                    }
                }
            }
        };
        var sources = new SyntheticSources
        {
            Processes = new(
                [Process(20, 1, 200, "/usr/bin/current-a", null), Process(21, 1, 201, "/usr/bin/current-b", null)],
                PassiveReadStatuses.Partial,
                "process_visibility_partial",
                false,
                100,
                0,
                1,
                BootDetails())
        };
        var collector = Collector(options, sources);
        options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;

        var result = await collector.CollectProcessesAsync(previous, options.AgentId, "synthetic-host", default);

        Assert.Equal(2, result.NewState.Process.Baseline.Count);
        Assert.DoesNotContain(staleKey, result.NewState.Process.Baseline.Keys);
        Assert.True(result.GapCount >= 1);
        Assert.Equal(SourceHealthStatuses.Degraded, result.HealthStatus);
    }

    [Fact]
    public async Task BootstrapDisappearanceIsNonAlertableAndSensitiveMetadataListsEveryNormalizedCopy()
    {
        var options = CreateAgentOptions(enabled: true);
        var flagged = Process(30, 1, 300, "/usr/bin/synthetic", "--token synthetic-secret") with
        {
            CommandRedacted = true,
            ExecutableRedacted = true,
            ExecutableTruncated = true
        };
        var sources = new SyntheticSources
        {
            Processes = new([flagged], PassiveReadStatuses.Partial, "process_visibility_partial", false, 100, 0, 1, BootDetails())
        };
        var collector = Collector(options, sources);
        options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;

        var partial = await collector.CollectProcessesAsync(new(), options.AgentId, "synthetic-host", default);
        var baseline = Assert.Single(partial.Events);
        Assert.Equal("process_baseline", baseline.EventCode);
        Assert.Equal("false", baseline.Normalized!.Labels["baseline.alertable"]);
        Assert.Contains("normalized.labels.process.command", baseline.DataHandling!.RedactedFields);
        Assert.Contains("normalized.process_image", baseline.DataHandling.RedactedFields);
        Assert.Contains("normalized.process.executable", baseline.DataHandling.RedactedFields);
        Assert.Contains("normalized.process_command_line", baseline.DataHandling.RedactedFields);
        Assert.Contains("normalized.process.executable", baseline.DataHandling.TruncatedFields);

        sources.Processes = Successful<LinuxProcessObservation>();
        var complete = await collector.CollectProcessesAsync(partial.NewState, options.AgentId, "synthetic-host", default);
        var disappeared = Assert.Single(complete.Events);
        Assert.Equal("process_baseline_disappeared", disappeared.EventCode);
        Assert.Equal("false", disappeared.Normalized!.Labels["baseline.alertable"]);
        Assert.Equal("unavailable", disappeared.Normalized.Labels["process.enrichment"]);
        Assert.True(disappeared.Raw.GetProperty("enrichment_partial").GetBoolean());
        Assert.DoesNotContain(complete.Events, item => item.EventCode == "process_disappeared");
    }

    [Fact]
    public async Task NetworkDiffAndMetricsUseIndependentSequencesAndPortableConcepts()
    {
        var options = CreateAgentOptions(enabled: true);
        var sources = new SyntheticSources
        {
            Sockets = Successful(Socket("socket-one", "established", "192.0.2.10", 50000, "198.51.100.20", 443)),
            Metrics = Successful(Metrics(1000, 600))
        };
        var collector = Collector(options, sources);
        options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;

        var network = await collector.CollectNetworkAsync(new(), "synthetic-agent", "synthetic-host", default);
        var metrics = await collector.CollectMetricsAsync(network.NewState, "synthetic-agent", "synthetic-host", default);
        var socketEvent = Assert.Single(network.Events);
        var metricsEvent = Assert.Single(metrics.Events);
        Assert.Equal(1, socketEvent.Checkpoint!.Sequence);
        Assert.Equal(1, metricsEvent.Checkpoint!.Sequence);
        Assert.Equal("192.0.2.10", socketEvent.Normalized!.Network!.SourceIp);
        Assert.Equal("198.51.100.20", socketEvent.Normalized.Network.DestinationIp);
        Assert.Equal("not_collected", socketEvent.Normalized.Labels["network.process_attribution"]);
        Assert.Equal(EventSources.AgentHealth, metricsEvent.Source);
        Assert.Equal("host_metrics_sample", metricsEvent.EventCode);
        Assert.True(metricsEvent.DataHandling!.RawSizeBytes <= options.PassiveTelemetry.MaxRawEventBytes);
    }

    [Fact]
    public async Task BootEpochResetIsNonAlertableCrossSourceAndPreservesSequences()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-boot-epoch-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        try
        {
            var oldProcess = Process(10, 1, 100, "/usr/bin/old", null);
            var oldSocket = Socket("old-socket", "established", "192.0.2.10", 50000, "198.51.100.20", 443);
            var oldBootHash = Sha256("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
            var newBootHash = Sha256("11111111-aaaa-4bbb-8ccc-222222222222");
            var previous = new LinuxPassiveTelemetryState
            {
                BootIdentitySha256 = oldBootHash,
                Process = new LinuxPassiveProcessState
                {
                    BaselineEstablished = true,
                    Progress = new PassiveSourceProgress { NextSequence = 5, CollectedSequence = 4, AcknowledgedSequence = 3 },
                    Baseline = new Dictionary<string, LinuxProcessBaseline>(StringComparer.Ordinal)
                    {
                        [oldProcess.Key] = new()
                        {
                            Signature = oldProcess.Signature,
                            ProcessId = oldProcess.ProcessId,
                            ParentProcessId = oldProcess.ParentProcessId
                        }
                    }
                },
                Network = new LinuxPassiveNetworkState
                {
                    BaselineEstablished = true,
                    Progress = new PassiveSourceProgress { NextSequence = 8, CollectedSequence = 7, AcknowledgedSequence = 6 },
                    Baseline = new Dictionary<string, LinuxSocketBaseline>(StringComparer.Ordinal)
                    {
                        [oldSocket.Key] = SocketBaseline(oldSocket)
                    }
                },
                Metrics = new LinuxPassiveMetricsState
                {
                    Progress = new PassiveSourceProgress { NextSequence = 3, CollectedSequence = 2, AcknowledgedSequence = 2 },
                    Previous = Metrics(10_000, 5_000)
                }
            };
            var currentProcess = Process(20, 1, 200, "/usr/bin/current", null) with
            {
                Key = Sha256($"{newBootHash}:20:200")
            };
            var currentSocket = Socket("current-socket", "listen", "192.0.2.11", 22, null, null);
            var sources = new SyntheticSources
            {
                Processes = new([currentProcess], PassiveReadStatuses.Success, "none", false, 1024,
                    Details: BootDetails(newBootHash)),
                Sockets = new([currentSocket], PassiveReadStatuses.Success, "none", false, 1024,
                    Details: BootDetails(newBootHash))
            };
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.StatePath = statePath;
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            await store.WriteAsync(previous, default);
            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await runtime.InitializeAsync(default);

            var processResult = await collector.CollectProcessesAsync(runtime.CurrentState, options.AgentId, "synthetic-host", default);
            var processEvent = Assert.Single(processResult.Events);
            Assert.Equal("process_baseline", processEvent.EventCode);
            Assert.Equal(5, processEvent.Checkpoint!.Sequence);
            Assert.Equal("false", processEvent.Normalized!.Labels["baseline.alertable"]);
            await runtime.CommitCollectionAsync(processResult, (_, _) => Task.CompletedTask, default);

            Assert.Equal(newBootHash, runtime.CurrentState.BootIdentitySha256);
            Assert.Empty(runtime.CurrentState.Network.Baseline);
            Assert.False(runtime.CurrentState.Network.BaselineEstablished);
            Assert.Equal(8, runtime.CurrentState.Network.Progress.NextSequence);
            Assert.Null(runtime.CurrentState.Metrics.Previous);
            Assert.Equal(3, runtime.CurrentState.Metrics.Progress.NextSequence);

            var networkResult = await collector.CollectNetworkAsync(runtime.CurrentState, options.AgentId, "synthetic-host", default);
            var networkEvent = Assert.Single(networkResult.Events);
            Assert.Equal("socket_baseline", networkEvent.EventCode);
            Assert.Equal(8, networkEvent.Checkpoint!.Sequence);
            Assert.Equal("false", networkEvent.Normalized!.Labels["baseline.alertable"]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RuntimePersistsCollectedAndAcknowledgedSequenceAndCleansOnlyItsState()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-synthetic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        var unrelated = Path.Combine(root, "unrelated.txt");
        await File.WriteAllTextAsync(unrelated, "synthetic-unrelated");
        try
        {
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.StatePath = statePath;
            var sources = new SyntheticSources { Processes = Successful(Process(10, 1, 100, "/usr/bin/synthetic", null)) };
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await runtime.InitializeAsync(default);

            var result = await collector.CollectProcessesAsync(runtime.CurrentState, options.AgentId, "synthetic-host", default);
            await runtime.CommitCollectionAsync(result, (_, _) => Task.CompletedTask, default);
            Assert.True(File.Exists(statePath));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(statePath));
            runtime.RecordAcknowledgementFailure(result.Events);
            var failedAck = Assert.Single(runtime.Health(), item => item.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
            Assert.Equal(SourceHealthStatuses.Error, failedAck.Status);
            Assert.False(failedAck.GapDetected);
            await runtime.RecordAcknowledgedAsync(result.Events, default);
            var health = Assert.Single(runtime.Health(), item => item.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
            Assert.Equal(SourceHealthStatuses.Healthy, health.Status);
            Assert.Equal("persisted", health.Details["acknowledgement_state"]);
            Assert.False(health.GapDetected);
            Assert.Equal(1, health.CollectedCheckpoint!.Sequence);
            Assert.Equal(1, health.AcknowledgedCheckpoint!.Sequence);

            options.PassiveTelemetry.Enabled = false;
            options.PassiveTelemetry.CleanupStateOnDisable = true;
            await runtime.CleanupIfDisabledAsync(default);
            Assert.False(File.Exists(statePath));
            Assert.True(File.Exists(unrelated));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task DisabledServiceAndAcknowledgementObserverPerformNoQueueOrStateIo()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-disabled-synthetic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        await File.WriteAllTextAsync(statePath, "synthetic-unchanged-state");
        try
        {
            var options = CreateAgentOptions();
            options.PassiveTelemetry.StatePath = statePath;
            var sources = new SyntheticSources();
            var collector = Collector(options, sources);
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            var queue = new CountingQueue();
            var service = new LinuxPassiveTelemetryService(
                Options.Create(options),
                collector,
                runtime,
                queue,
                new FixedTimeProvider(SyntheticNow),
                NullLogger<LinuxPassiveTelemetryService>.Instance);

            await service.StartAsync(default);
            await service.StopAsync(default);
            await runtime.InitializeAsync(default);
            await runtime.RecordAcknowledgedAsync([PassiveEnvelope(1)], default);

            Assert.Equal(0, queue.InitializeCalls);
            Assert.Equal("synthetic-unchanged-state", await File.ReadAllTextAsync(statePath));

            options.PassiveTelemetry.CleanupStateOnDisable = true;
            await runtime.CleanupIfDisabledAsync(default);
            await runtime.RecordAcknowledgedAsync([PassiveEnvelope(1)], default);
            Assert.False(File.Exists(statePath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ByteHeadroomGateAndPressureHealthAreDurableRecoverableAndDoNotInventDrops()
    {
        if (!OperatingSystem.IsLinux()) return;
        var options = CreateAgentOptions(enabled: true);
        var maximumBytes = options.Queue.MaxSizeMb * 1024L * 1024L;
        Assert.True(LinuxPassiveTelemetryService.HasPassiveByteHeadroom(
            new QueueSloMetrics { QueueSizeBytes = 0, MaxSizeBytes = maximumBytes }, options));
        Assert.False(LinuxPassiveTelemetryService.HasPassiveByteHeadroom(
            new QueueSloMetrics { QueueSizeBytes = 400L * 1024 * 1024, MaxSizeBytes = maximumBytes }, options));
        Assert.False(LinuxPassiveTelemetryService.HasPassiveByteHeadroom(new QueueSloMetrics(), options));

        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-pressure-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        try
        {
            options.PassiveTelemetry.StatePath = statePath;
            var sources = new SyntheticSources
            {
                Processes = Successful(Process(10, 1, 100, "/usr/bin/synthetic", null))
            };
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await runtime.InitializeAsync(default);
            await runtime.RecordPressureAsync(
                LinuxTelemetrySourceIds.ProcessSnapshotDiff,
                49_900,
                400L * 1024 * 1024,
                "byte_headroom",
                default);

            var pressure = Assert.Single(runtime.Health(), item => item.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
            Assert.Equal(SourceHealthStatuses.Degraded, pressure.Status);
            Assert.True(pressure.GapDetected);
            Assert.Equal(1, pressure.GapCount);
            Assert.Equal(0, pressure.DroppedEvents);
            Assert.Equal("1", pressure.Details["pressure_skipped_scans"]);

            var restarted = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await restarted.InitializeAsync(default);
            var durable = Assert.Single(restarted.Health(), item => item.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
            Assert.Equal(SourceHealthStatuses.Degraded, durable.Status);
            Assert.True(durable.GapDetected);
            Assert.Equal("byte_headroom", durable.Details["pressure_reason"]);

            var collection = await collector.CollectProcessesAsync(restarted.CurrentState, options.AgentId, "synthetic-host", default);
            await restarted.CommitCollectionAsync(collection, (_, _) => Task.CompletedTask, default);
            var recovered = Assert.Single(restarted.Health(), item => item.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
            Assert.Equal(SourceHealthStatuses.Healthy, recovered.Status);
            Assert.False(recovered.GapDetected);
            Assert.False(recovered.BookmarkGapDetected);
            Assert.Equal(1, recovered.GapCount);
            Assert.Equal(0, recovered.DroppedEvents);
            Assert.Equal(HealthTransitionStates.Healthy, recovered.TransitionState);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SequenceReservationSurvivesInterruptedEnqueueAndAcknowledgesOnlyCommittedMaximum()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-reservation-synthetic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        try
        {
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.StatePath = statePath;
            var sources = new SyntheticSources
            {
                Processes = Successful(
                    Process(10, 1, 100, "/usr/bin/synthetic-a", null),
                    Process(11, 1, 101, "/usr/bin/synthetic-b", null))
            };
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await runtime.InitializeAsync(default);
            var interrupted = await collector.CollectProcessesAsync(runtime.CurrentState, options.AgentId, "synthetic-host", default);
            var attempted = 0;

            await Assert.ThrowsAsync<IOException>(() => runtime.CommitCollectionAsync(
                interrupted,
                (_, _) =>
                {
                    attempted++;
                    throw new IOException("synthetic enqueue interruption");
                },
                default));
            Assert.Equal(1, attempted);
            var pending = (await store.ReadAsync(default)).State.Process.Progress;
            Assert.Equal(1, pending.PendingReservationStart);
            Assert.Equal(2, pending.PendingReservationEnd);
            Assert.Equal(3, pending.NextSequence);
            Assert.Equal(0, pending.CollectedSequence);

            var recoveredRuntime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await recoveredRuntime.InitializeAsync(default);
            var recovered = recoveredRuntime.CurrentState.Process.Progress;
            Assert.Null(recovered.PendingReservationStart);
            Assert.Null(recovered.PendingReservationEnd);
            Assert.Equal(2, recovered.AbandonedSequenceCount);
            var retry = await collector.CollectProcessesAsync(recoveredRuntime.CurrentState, options.AgentId, "synthetic-host", default);
            Assert.Equal([3L, 4L], retry.Events.Select(item => item.Checkpoint!.Sequence!.Value));

            await recoveredRuntime.CommitCollectionAsync(retry, (_, _) => Task.CompletedTask, default);
            await recoveredRuntime.RecordAcknowledgedAsync(retry.Events.Reverse().ToArray(), default);
            Assert.Equal(4, recoveredRuntime.CurrentState.Process.Progress.AcknowledgedSequence);
            await recoveredRuntime.RecordAcknowledgedAsync(
                [retry.Events[0] with { Checkpoint = retry.Events[0].Checkpoint! with { Sequence = 99 } }],
                default);
            Assert.Equal(4, recoveredRuntime.CurrentState.Process.Progress.AcknowledgedSequence);
            var health = Assert.Single(recoveredRuntime.Health(), item => item.SourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff);
            Assert.Equal(2, health.GapCount);
            Assert.Equal(0, health.DroppedEvents);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StructurallyInvalidStateIsRejectedWithoutBreakingHealth()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-invalid-state-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        await File.WriteAllTextAsync(statePath,
            "{\"schema_version\":1,\"process\":null,\"network\":null,\"metrics\":null}");
        File.SetUnixFileMode(statePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        try
        {
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.StatePath = statePath;
            var sources = new SyntheticSources();
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);
            Assert.Equal("state_invalid", (await store.ReadAsync(default)).ErrorCode);

            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await runtime.InitializeAsync(default);
            Assert.False(runtime.IsReady);
            var health = runtime.Health();
            Assert.Equal(3, health.Count);
            Assert.All(health, item =>
            {
                Assert.Equal(SourceHealthStatuses.Error, item.Status);
                Assert.Equal("state_invalid", item.ErrorCode);
                Assert.Null(item.ObservedAt);
            });
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PermissiveStateModeIsRejectedAndReportedFailClosed()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-permissions-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        try
        {
            await File.WriteAllTextAsync(statePath, JsonSerializer.Serialize(new LinuxPassiveTelemetryState(), JsonDefaults.Options));
            File.SetUnixFileMode(statePath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            var options = CreateAgentOptions(enabled: true);
            options.PassiveTelemetry.StatePath = statePath;
            var sources = new SyntheticSources();
            var collector = Collector(options, sources);
            options.PassiveTelemetry.ApprovedPlanHash = collector.PlanHash;
            var store = new LinuxPassiveTelemetryStateStore(statePath, root);

            Assert.Equal("state_permissions_not_private", (await store.ReadAsync(default)).ErrorCode);
            var runtime = new LinuxPassiveTelemetryRuntime(Options.Create(options), store, collector, new FixedTimeProvider(SyntheticNow));
            await runtime.InitializeAsync(default);
            Assert.False(runtime.IsReady);
            Assert.All(runtime.Health(), item =>
            {
                Assert.Equal(SourceHealthStatuses.Error, item.Status);
                Assert.Equal("state_permissions_not_private", item.ErrorCode);
            });
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FailingPassiveAcknowledgementRetainsOnlyPassiveRowsAndDoesNotBlockJournalDelete()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-ack-isolation-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var options = CreateAgentOptions();
            options.DrainBatchSize = 10;
            var journalState = new LinuxStateStore(Path.Combine(root, "journal-state.json"));
            var journalRuntime = new LinuxJournalRuntime(Options.Create(options), journalState, new FixedTimeProvider(SyntheticNow));
            await journalRuntime.InitializeAsync("synthetic", "synthetic", default);
            var journal = PassiveEnvelope(1) with
            {
                EventId = Guid.Parse("10000000-0000-5000-8000-000000000010"),
                Source = EventSources.LinuxJournal,
                SourceId = LinuxTelemetrySourceIds.JournalL1,
                EventCode = "journal_synthetic",
                Checkpoint = new SourceCheckpoint
                {
                    Cursor = "s=synthetic;i=10;b=fake",
                    EventTime = SyntheticNow,
                    RecordedAt = SyntheticNow
                }
            };
            var passive = PassiveEnvelope(2) with
            {
                EventId = Guid.Parse("10000000-0000-5000-8000-000000000011")
            };
            var queue = new BatchQueue(
                new QueuedEvent(10, journal, 0, null),
                new QueuedEvent(11, passive, 0, null));
            using var http = new HttpClient(new AcceptAllHandler()) { BaseAddress = options.ServerBaseUrl };
            var throwing = new ThrowingPassiveObserver();
            var drainer = new LinuxQueueDrainer(
                Options.Create(options),
                queue,
                new SiemIngestClient(http, options),
                journalRuntime,
                acknowledgementObservers: [throwing]);

            await drainer.DrainAsync(default);

            Assert.Equal([10L], queue.DeletedQueueIds);
            Assert.Equal(1, throwing.FailureCalls);
            Assert.Equal("s=synthetic;i=10;b=fake", (await journalState.ReadJournalAsync(default)).AcknowledgedCursor);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void MaximumAcceptedBaselineStateRemainsWithinDurableByteLimit()
    {
        var processes = Enumerable.Range(1, LinuxPassiveTelemetryLimits.MaximumProcesses)
            .ToDictionary(
                index => Sha256($"process-{index}"),
                index => new LinuxProcessBaseline
                {
                    Signature = Sha256($"process-signature-{index}"),
                    ProcessId = index,
                    ParentProcessId = Math.Max(0, index - 1)
                },
                StringComparer.Ordinal);
        var sockets = Enumerable.Range(1, LinuxPassiveTelemetryLimits.MaximumSockets)
            .ToDictionary(
                index => Sha256($"socket-{index}"),
                index => new LinuxSocketBaseline
                {
                    Signature = Sha256($"socket-signature-{index}"),
                    Protocol = "tcp",
                    State = "established",
                    LocalAddress = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                    LocalPort = 65_535,
                    RemoteAddress = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                    RemotePort = 65_535,
                    Inode = long.MaxValue,
                    UserId = uint.MaxValue.ToString(),
                    Count = int.MaxValue
                },
                StringComparer.Ordinal);
        var state = new LinuxPassiveTelemetryState
        {
            BootIdentitySha256 = SyntheticBootHash,
            Process = new LinuxPassiveProcessState { BaselineEstablished = true, Baseline = processes },
            Network = new LinuxPassiveNetworkState { BaselineEstablished = true, Baseline = sockets }
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, JsonDefaults.Options);
        Assert.True(bytes.Length < LinuxPassiveTelemetryStateStore.MaximumStateBytes, $"Synthetic maximum state was {bytes.Length} bytes.");
    }

    [Fact]
    public async Task StateStoreRejectsSymlinkTargetsAndDoesNotClobberPredictableTemporaryFiles()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-passive-state-synthetic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var statePath = Path.Combine(root, "passive-state.json");
        var targetPath = Path.Combine(root, "synthetic-target.txt");
        var predictableTemporary = $"{statePath}.tmp";
        await File.WriteAllTextAsync(targetPath, "synthetic-target");
        File.CreateSymbolicLink(statePath, targetPath);
        var store = new LinuxPassiveTelemetryStateStore(statePath, root);
        try
        {
            var read = await store.ReadAsync(default);
            Assert.Equal("state_path_not_regular", read.ErrorCode);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.WriteAsync(new(), default));
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.CleanupAsync(default));
            Assert.Equal("synthetic-target", await File.ReadAllTextAsync(targetPath));

            File.Delete(statePath);
            await File.WriteAllTextAsync(predictableTemporary, "synthetic-temporary");
            await store.WriteAsync(new(), default);
            Assert.True(File.Exists(statePath));
            Assert.Equal("synthetic-temporary", await File.ReadAllTextAsync(predictableTemporary));
            Assert.DoesNotContain(
                Directory.EnumerateFiles(root),
                candidate => candidate.StartsWith($"{statePath}.tmp.", StringComparison.Ordinal));
        }
        finally
        {
            if (new FileInfo(statePath).LinkTarget is not null || File.Exists(statePath)) File.Delete(statePath);
            Directory.Delete(root, recursive: true);
        }
    }

    private static LinuxAgentOptions CreateAgentOptions(bool enabled = false) => new()
    {
        AgentId = "synthetic-agent",
        ServerBaseUrl = new Uri("https://siem.example.invalid"),
        ApiToken = "synthetic-token",
        PassiveTelemetry = new PassiveTelemetryOptions
        {
            Enabled = enabled,
            StatePath = "/var/lib/challenger-siem-agent/passive-telemetry-state.json"
        }
    };

    private static LinuxPassiveTelemetryCollector Collector(LinuxAgentOptions options, SyntheticSources sources) =>
        new(Options.Create(options), sources, sources, sources, new FixedTimeProvider(SyntheticNow));

    private static PassiveReadResult<T> Successful<T>(params T[] items) =>
        new(items, PassiveReadStatuses.Success, "none", false, 1024, Details: BootDetails());

    private static IReadOnlyDictionary<string, string> BootDetails(string? hash = null) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["boot_identity_sha256"] = hash ?? SyntheticBootHash
        };

    private static LinuxProcessObservation Process(int pid, int parent, long start, string executable, string? commandLine)
    {
        var handled = TelemetryTextSanitizer.SanitizeAndRedact(commandLine, 4096);
        var signature = Sha256($"{pid}:{parent}:{start}:{executable}:{handled.Value}");
        return new(
            Sha256($"synthetic-boot:{pid}:{start}"),
            signature,
            pid,
            parent,
            start,
            "S",
            Path.GetFileName(executable),
            executable,
            handled.Value.Length == 0 ? null : handled.Value,
            "1001",
            "1001",
            "0000000000000000",
            true,
            2,
            0,
            "1001",
            new string('a', 64),
            handled.Redacted,
            handled.Truncated,
            handled.InvalidText,
            false);
    }

    private static LinuxSocketObservation Socket(
        string key,
        string state,
        string localAddress,
        int localPort,
        string? remoteAddress,
        int? remotePort) =>
        new(Sha256(key), Sha256($"{key}:signature"), "tcp", state, localAddress, localPort, remoteAddress, remotePort, 12345, "1001", 1);

    private static LinuxSocketBaseline SocketBaseline(LinuxSocketObservation value) => new()
    {
        Signature = value.Signature,
        Protocol = value.Protocol,
        State = value.State,
        LocalAddress = value.LocalAddress,
        LocalPort = value.LocalPort,
        RemoteAddress = value.RemoteAddress,
        RemotePort = value.RemotePort,
        Inode = value.Inode,
        UserId = value.UserId,
        Count = value.Count
    };

    private static LinuxHostMetricsObservation Metrics(long totalTicks, long idleTicks) => new()
    {
        ObservedAt = SyntheticNow,
        UptimeSeconds = 100,
        Load1Milli = 100,
        MemoryTotalBytes = 1_000_000,
        MemoryAvailableBytes = 500_000,
        CpuTotalTicks = totalTicks,
        CpuIdleTicks = idleTicks,
        DiskReadSectors = 10,
        DiskWrittenSectors = 20,
        NetworkReceiveBytes = 30,
        NetworkTransmitBytes = 40
    };

    private static EventEnvelope PassiveEnvelope(long sequence) => new()
    {
        EventId = Guid.Parse("10000000-0000-5000-8000-000000000001"),
        AgentId = "synthetic-agent",
        Hostname = "synthetic-host",
        Platform = TelemetryPlatforms.Linux,
        Source = EventSources.InventoryDiff,
        SourceId = LinuxTelemetrySourceIds.ProcessSnapshotDiff,
        EventCode = "process_baseline",
        EventTime = SyntheticNow,
        Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = SyntheticNow, RecordedAt = SyntheticNow },
        Raw = JsonDefaults.ToJsonElement(new { synthetic = true })
    };

    private sealed class SyntheticSources : ILinuxProcessSnapshotSource, ILinuxNetworkSnapshotSource, ILinuxHostMetricsSource
    {
        public PassiveReadResult<LinuxProcessObservation> Processes { get; set; } =
            Successful<LinuxProcessObservation>();
        public PassiveReadResult<LinuxSocketObservation> Sockets { get; set; } =
            Successful<LinuxSocketObservation>();
        public PassiveReadResult<LinuxHostMetricsObservation> Metrics { get; set; } =
            Successful<LinuxHostMetricsObservation>(LinuxPassiveTelemetryTests.Metrics(100, 50));

        Task<PassiveReadResult<LinuxProcessObservation>> ILinuxProcessSnapshotSource.ReadAsync(PassiveTelemetryOptions options, CancellationToken cancellationToken) =>
            Task.FromResult(Processes);

        Task<PassiveReadResult<LinuxSocketObservation>> ILinuxNetworkSnapshotSource.ReadAsync(PassiveTelemetryOptions options, CancellationToken cancellationToken) =>
            Task.FromResult(Sockets);

        Task<PassiveReadResult<LinuxHostMetricsObservation>> ILinuxHostMetricsSource.ReadAsync(PassiveTelemetryOptions options, CancellationToken cancellationToken) =>
            Task.FromResult(Metrics);
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class CountingQueue : IEventQueue
    {
        public int InitializeCalls { get; private set; }
        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            InitializeCalls++;
            return Task.CompletedTask;
        }
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<QueuedEvent>>(Array.Empty<QueuedEvent>());
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(0);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) =>
            Task.FromResult(new QueueSloMetrics());
    }

    private sealed class BatchQueue(params QueuedEvent[] events) : IEventQueue
    {
        private bool returned;
        public IReadOnlyList<long> DeletedQueueIds { get; private set; } = Array.Empty<long>();
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken)
        {
            IReadOnlyList<QueuedEvent> result = returned ? Array.Empty<QueuedEvent>() : events.Take(maxEvents).ToArray();
            returned = true;
            return Task.FromResult(result);
        }
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken)
        {
            DeletedQueueIds = queueIds.Order().ToArray();
            return Task.CompletedTask;
        }
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(events.Length - DeletedQueueIds.Count);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) =>
            Task.FromResult(new QueueSloMetrics());
    }

    private sealed class ThrowingPassiveObserver : ILinuxAcknowledgementObserver
    {
        public int FailureCalls { get; private set; }
        public bool HandlesSource(string? sourceId) => sourceId == LinuxTelemetrySourceIds.ProcessSnapshotDiff;
        public Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken) =>
            throw new IOException("synthetic passive acknowledgement failure");
        public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events) => FailureCalls++;
    }

    private sealed class AcceptAllHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            var batchId = document.RootElement.GetProperty("batch_id").GetGuid();
            var accepted = document.RootElement.GetProperty("events")
                .EnumerateArray()
                .Select(item => item.GetProperty("event_id").GetGuid())
                .ToArray();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new IngestBatchResponse
                {
                    BatchId = batchId,
                    Accepted = accepted.Length,
                    AcceptedEventIds = accepted
                })
            };
        }
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string ProcessStat(int pid, int parentPid, long startTicks, string state) =>
        $"{pid} (synthetic worker) {state} {parentPid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {startTicks} 0 0";

    private static async Task<(int ExitCode, string Output)> RunProcessAsync(
        string fileName,
        string arguments,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var startInfo = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        if (environment is not null)
        {
            foreach (var pair in environment) startInfo.Environment[pair.Key] = pair.Value;
        }
        using var process = System.Diagnostics.Process.Start(startInfo)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await stdout + await stderr);
    }
}
