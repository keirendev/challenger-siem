using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.Services;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxInventoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CatalogUsesOnlyFixedBoundedOperations()
    {
        Assert.Equal(Enum.GetValues<LinuxInventoryOperation>().Length, LinuxInventoryCatalog.All.Count);
        foreach (var policy in LinuxInventoryCatalog.All)
        {
            Assert.InRange(policy.Timeout, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(20));
            Assert.InRange(policy.MaxOutputBytes, 1, policy.Kind == InventorySourceKind.Command ? 64 * 1024 : 64 * 1024 * 1024);
            if (policy.Kind == InventorySourceKind.Command)
            {
                Assert.NotEmpty(policy.ExecutablePaths);
                Assert.All(policy.ExecutablePaths, path =>
                {
                    Assert.StartsWith("/", path, StringComparison.Ordinal);
                    Assert.Contains(Path.GetDirectoryName(path), new[] { "/usr/bin", "/bin", "/usr/sbin", "/sbin" });
                    Assert.DoesNotContain("sh", Path.GetFileName(path), StringComparison.Ordinal);
                });
            }
            else
            {
                Assert.StartsWith("/", policy.FilePath!, StringComparison.Ordinal);
                Assert.Empty(policy.ExecutablePaths);
            }
        }
    }

    [Fact]
    public async Task CollectsEveryRequestedCategoryFromSyntheticSources()
    {
        var source = CompleteSource();
        var snapshots = await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);

        var expected = new[]
        {
            "linux_host_identity", "linux_users", "linux_groups", "linux_services", "linux_units", "linux_timers", "linux_packages",
            "linux_available_updates", "linux_interfaces", "linux_listeners", "linux_mounts", "linux_firewall", "linux_ssh",
            "linux_mandatory_access_control", "linux_secure_boot", "linux_agent_integrity"
        };
        Assert.Equal(expected, snapshots.Select(snapshot => snapshot.SnapshotType));
        Assert.All(snapshots, snapshot => Assert.Equal("success", snapshot.Summary["state"]));
        Assert.Contains(snapshots.Single(x => x.SnapshotType == "linux_users").Items, item => item.Name == "synthetic-user" && item.Metadata["uid"] == "1001");
        Assert.Contains(snapshots.Single(x => x.SnapshotType == "linux_services").Items, item => item.Name == "synthetic-api.service" && item.Status == "active");
        Assert.Contains(snapshots.Single(x => x.SnapshotType == "linux_units").Items, item => item.Name == "synthetic-failed.service" && item.Status == "failed");
        Assert.Contains(snapshots.Single(x => x.SnapshotType == "linux_listeners").Items, item => item.Name == "tcp:8443");
        Assert.Contains(snapshots.Single(x => x.SnapshotType == "linux_ssh").Items.Single().Metadata, pair => pair.Key == "passwordauthentication" && pair.Value == "no");
        var integrity = snapshots.Single(x => x.SnapshotType == "linux_agent_integrity").Items;
        Assert.False(integrity.Single(item => item.Name == "configuration").Metadata.ContainsKey("sha256"));
        Assert.Matches("^[a-f0-9]{64}$", integrity.Single(item => item.Name == "executable").Metadata["sha256"]);
    }

    [Fact]
    public async Task MissingCommandsAndFilesAreExplicitlyUnavailable()
    {
        var snapshots = await Collector(new SyntheticSource()).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.All(snapshots, snapshot =>
        {
            Assert.Equal("unavailable", snapshot.Summary["state"]);
            Assert.Empty(snapshot.Items);
            Assert.NotEqual("none", snapshot.Summary["error_code"]);
        });
    }

    [Fact]
    public async Task NonSystemdHostSkipsUnitAndTimerCommands()
    {
        var source = CompleteSource();
        source.Set(LinuxInventoryOperation.InitSystem, InventorySourceResult.Success("offline\n"));
        var snapshots = await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);

        Assert.Equal("not_applicable", snapshots.Single(x => x.SnapshotType == "linux_services").Summary["state"]);
        Assert.Equal("not_applicable", snapshots.Single(x => x.SnapshotType == "linux_timers").Summary["state"]);
        Assert.DoesNotContain(LinuxInventoryOperation.Services, source.Calls);
        Assert.DoesNotContain(LinuxInventoryOperation.Units, source.Calls);
        Assert.DoesNotContain(LinuxInventoryOperation.Timers, source.Calls);
    }

    [Fact]
    public async Task NonEfiSecureBootIsExplicitlyNotApplicable()
    {
        var source = CompleteSource();
        source.Set(LinuxInventoryOperation.SecureBoot, InventorySourceResult.Success("EFI variables are not supported on this system\n", exitCode: 1));
        var snapshot = (await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default))
            .Single(x => x.SnapshotType == "linux_secure_boot");
        Assert.Equal("not_applicable", snapshot.Summary["state"]);
        Assert.Equal("non_efi_host", snapshot.Summary["error_code"]);
    }

    [Theory]
    [InlineData(InventorySourceState.PermissionDenied, "permission_denied")]
    [InlineData(InventorySourceState.Timeout, "timeout")]
    [InlineData(InventorySourceState.Unavailable, "unavailable")]
    public async Task PreservesSafeFailureStates(InventorySourceState sourceState, string expected)
    {
        var source = CompleteSource();
        source.Set(LinuxInventoryOperation.Users, new(sourceState, "synthetic_failure"));
        var snapshot = (await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default))
            .Single(x => x.SnapshotType == "linux_users");
        Assert.Equal(expected, snapshot.Summary["state"]);
        Assert.Equal("synthetic_failure", snapshot.Summary["error_code"]);
        Assert.Empty(snapshot.Items);
    }

    [Fact]
    public async Task MalformedOutputIsNotReportedAsHealthy()
    {
        var source = CompleteSource();
        source.Set(LinuxInventoryOperation.Services, InventorySourceResult.Success("not a unit listing\n"));
        var snapshot = (await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default))
            .Single(x => x.SnapshotType == "linux_services");
        Assert.Equal("malformed", snapshot.Summary["state"]);
        Assert.Equal("malformed_output", snapshot.Summary["error_code"]);
    }

    [Fact]
    public async Task CallerCancellationStopsCollection()
    {
        var source = CompleteSource();
        source.Handler = async (operation, cancellationToken) =>
        {
            if (operation != LinuxInventoryOperation.Users) return source.Get(operation);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return InventorySourceResult.Success();
        };
        using var cancellation = new CancellationTokenSource();
        var task = Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", cancellation.Token);
        await source.UsersStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    [Fact]
    public async Task CollectionDeadlineProducesTimeoutStatesWithoutLeakingCancellation()
    {
        var source = new SyntheticSource
        {
            Handler = async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return InventorySourceResult.Success();
            }
        };
        var collector = new LinuxInventory(source, new ManualTimeProvider(Now), TimeSpan.FromMilliseconds(20), LinuxInventory.DefaultMaxSerializedBytes);
        var snapshots = await collector.CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.All(snapshots, snapshot => Assert.Equal("timeout", snapshot.Summary["state"]));
    }

    [Fact]
    public async Task LargePackageAndServiceInventoriesAreDeterministicallyBounded()
    {
        var source = CompleteSource();
        source.Set(LinuxInventoryOperation.Services, InventorySourceResult.Success(string.Join('\n', Enumerable.Range(0, 1_000)
            .Select(index => $"synthetic-{index:D4}.service loaded active running Synthetic service"))));
        source.Set(LinuxInventoryOperation.DpkgPackages, InventorySourceResult.Success(string.Join('\n', Enumerable.Range(0, 2_000)
            .Select(index => $"synthetic-package-{index:D4}\t1.2.{index}"))));

        var first = await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        var second = await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        foreach (var type in new[] { "linux_services", "linux_packages" })
        {
            var left = first.Single(x => x.SnapshotType == type);
            var right = second.Single(x => x.SnapshotType == type);
            Assert.Equal(200, left.Items.Count);
            Assert.Equal("true", left.Summary["truncated"]);
            Assert.Equal(left.Items.Select(ItemIdentity), right.Items.Select(ItemIdentity));
        }
        Assert.All(first, snapshot => Assert.InRange(snapshot.Items.Count, 0, 200));
        Assert.InRange(first.Count, 1, 20);
    }

    [Fact]
    public async Task SerializedBudgetIsDeterministicAndExplicitlyTruncated()
    {
        var source = CompleteSource();
        var longVersion = new string('v', 90);
        source.Set(LinuxInventoryOperation.DpkgPackages, InventorySourceResult.Success(string.Join('\n', Enumerable.Range(0, 500)
            .Select(index => $"synthetic-package-{index:D4}\t{longVersion}"))));
        source.Set(LinuxInventoryOperation.Services, InventorySourceResult.Success(string.Join('\n', Enumerable.Range(0, 500)
            .Select(index => $"synthetic-{index:D4}.service loaded active running"))));
        var collector = new LinuxInventory(source, new ManualTimeProvider(Now), TimeSpan.FromSeconds(10), LinuxInventory.MinimumSerializedBytes);

        var first = await collector.CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        var second = await collector.CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.InRange(collector.SerializedSize("synthetic-agent", Now, first), 1, LinuxInventory.MinimumSerializedBytes);
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Contains(first, snapshot => snapshot.Summary.GetValueOrDefault("payload_budget_truncated") == "true");
    }

    [Fact]
    public async Task ParsersNeverSerializeSecretBearingOrUnapprovedFields()
    {
        const string canary = "SYNTHETIC_SECRET_CANARY";
        var source = CompleteSource();
        source.Set(LinuxInventoryOperation.Users, InventorySourceResult.Success($"synthetic-user:x:1001:1001:{canary}:/home/{canary}:/bin/bash\n"));
        source.Set(LinuxInventoryOperation.Groups, InventorySourceResult.Success($"synthetic-group:x:1001:synthetic-user,{canary}\n"));
        source.Set(LinuxInventoryOperation.SshConfig, InventorySourceResult.Success($"PasswordAuthentication no\nProxyCommand {canary}\nMatch User {canary}\nPasswordAuthentication yes\n"));
        source.Set(LinuxInventoryOperation.Nftables, InventorySourceResult.Success($"table inet synthetic\nchain input {{ comment {canary}; }}\n"));

        var snapshots = await Collector(source).CollectAsync("synthetic-agent", "SYNTHETIC-LINUX-01", default);
        var json = JsonSerializer.Serialize(snapshots);
        Assert.DoesNotContain(canary, json, StringComparison.Ordinal);
        Assert.DoesNotContain("/home/", json, StringComparison.Ordinal);
        Assert.DoesNotContain("proxycommand", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("chain", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OptionsEnforceSafeInventoryFrequencyAndResourceBounds()
    {
        var options = new LinuxAgentOptions();
        Assert.True(options.HasValidInventoryBounds());
        options.InventoryIntervalSeconds = LinuxAgentOptions.MinimumInventoryIntervalSeconds - 1;
        Assert.False(options.HasValidInventoryBounds());
        options.InventoryIntervalSeconds = LinuxAgentOptions.MinimumInventoryIntervalSeconds;
        options.Inventory.MaxSerializedBytes = 64 * 1024 - 1;
        Assert.False(options.HasValidInventoryBounds());
        options.Inventory.MaxSerializedBytes = 64 * 1024;
        options.Inventory.CollectionTimeoutSeconds = 301;
        Assert.False(options.HasValidInventoryBounds());
    }

    [Fact]
    public async Task ScheduleEnforcesFrequencyAndSingleFlight()
    {
        var clock = new ManualTimeProvider(Now);
        var schedule = new InventorySchedule(clock, TimeSpan.FromHours(1), TimeSpan.FromMinutes(1));
        var calls = 0;
        Assert.Equal(InventoryRunDecision.NotDue, await schedule.TryRunDueAsync(_ => { calls++; return Task.CompletedTask; }, default));
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(InventoryRunDecision.Started, await schedule.TryRunDueAsync(_ => { calls++; return Task.CompletedTask; }, default));
        Assert.Equal(InventoryRunDecision.NotDue, await schedule.TryRunDueAsync(_ => { calls++; return Task.CompletedTask; }, default));
        clock.Advance(TimeSpan.FromHours(1));

        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = schedule.TryRunDueAsync(async _ => { calls++; started.SetResult(); await release.Task; }, default);
        await started.Task;
        Assert.Equal(InventoryRunDecision.AlreadyRunning, await schedule.TryRunDueAsync(_ => Task.CompletedTask, default));
        release.SetResult();
        Assert.Equal(InventoryRunDecision.Started, await running);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task BlockedInventoryDoesNotBlockPassiveOrQueueWork()
    {
        var clock = new ManualTimeProvider(Now);
        var schedule = new InventorySchedule(clock, TimeSpan.FromHours(1), TimeSpan.Zero);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var inventory = schedule.TryRunDueAsync(async _ => { started.SetResult(); await release.Task; }, default);
        await started.Task;

        var queueDrains = 0;
        var passiveEvents = 0;
        await Task.WhenAll(Task.Run(() => Interlocked.Increment(ref queueDrains)), Task.Run(() => Interlocked.Increment(ref passiveEvents)));
        Assert.Equal(1, queueDrains);
        Assert.Equal(1, passiveEvents);
        Assert.False(inventory.IsCompleted);
        release.SetResult();
        await inventory;
    }

    private static LinuxInventory Collector(SyntheticSource source) =>
        new(source, new ManualTimeProvider(Now), TimeSpan.FromSeconds(30), LinuxInventory.DefaultMaxSerializedBytes);

    private static string ItemIdentity(InventoryItem item) => $"{item.Kind}|{item.Name}|{item.Status}|{string.Join(',', item.Metadata.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"))}";

    private static SyntheticSource CompleteSource()
    {
        var source = new SyntheticSource();
        source.Set(LinuxInventoryOperation.OsReleaseEtc, InventorySourceResult.Success("ID=synthetic\nVERSION_ID=1.0\nPRETTY_NAME=\"Synthetic Linux 1.0\"\n"));
        source.Set(LinuxInventoryOperation.Kernel, InventorySourceResult.Success("Linux 6.8.0 x86_64 GNU/Linux\n"));
        source.Set(LinuxInventoryOperation.Users, InventorySourceResult.Success("synthetic-user:x:1001:1001:Synthetic User:/home/synthetic-user:/bin/bash\n"));
        source.Set(LinuxInventoryOperation.Groups, InventorySourceResult.Success("synthetic-group:x:1001:synthetic-user\n"));
        source.Set(LinuxInventoryOperation.InitSystem, InventorySourceResult.Success("running\n"));
        source.Set(LinuxInventoryOperation.Services, InventorySourceResult.Success("synthetic-api.service loaded active running Synthetic API\nsynthetic-idle.service loaded inactive dead Synthetic idle\n"));
        source.Set(LinuxInventoryOperation.Units, InventorySourceResult.Success("synthetic-api.service loaded active running Synthetic API\n● synthetic-failed.service loaded failed failed Synthetic failed\nsynthetic-data.mount loaded active mounted Synthetic mount\n"));
        source.Set(LinuxInventoryOperation.Timers, InventorySourceResult.Success("synthetic.timer enabled enabled\n"));
        source.Set(LinuxInventoryOperation.DpkgPackages, InventorySourceResult.Success("synthetic-package\t1.2.3-1\n"));
        source.Set(LinuxInventoryOperation.AptUpdates, InventorySourceResult.Success("Listing...\nsynthetic-package/stable 1.2.4 amd64 [upgradable from: 1.2.3]\n"));
        source.Set(LinuxInventoryOperation.Interfaces, InventorySourceResult.Success("1: lo: <LOOPBACK,UP> mtu 65536 state UNKNOWN mode DEFAULT\n2: synthetic0: <BROADCAST,UP> mtu 1500 state UP mode DEFAULT\n"));
        source.Set(LinuxInventoryOperation.Listeners, InventorySourceResult.Success("tcp LISTEN 0 128 192.0.2.10:8443 0.0.0.0:*\nudp UNCONN 0 0 192.0.2.10:5353 0.0.0.0:*\n"));
        source.Set(LinuxInventoryOperation.Mounts, InventorySourceResult.Success("ext4\next4\ntmpfs\n"));
        source.Set(LinuxInventoryOperation.Nftables, InventorySourceResult.Success("table inet synthetic\n"));
        source.Set(LinuxInventoryOperation.SshConfig, InventorySourceResult.Success("PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n"));
        source.Set(LinuxInventoryOperation.AppArmor, InventorySourceResult.Success());
        source.Set(LinuxInventoryOperation.Selinux, InventorySourceResult.Success("Disabled\n"));
        source.Set(LinuxInventoryOperation.SecureBoot, InventorySourceResult.Success("SecureBoot enabled\n"));
        var syntheticHash = new string('a', 64);
        source.Set(LinuxInventoryOperation.AgentConfig, InventorySourceResult.Success(mode: UnixFileMode.UserRead | UnixFileMode.UserWrite, size: 512, ownerId: 1001));
        source.Set(LinuxInventoryOperation.AgentExecutable, InventorySourceResult.Success(mode: UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute, size: 4096, ownerId: 0, sha256: syntheticHash));
        return source;
    }

    private sealed class SyntheticSource : ILinuxInventorySource
    {
        private readonly Dictionary<LinuxInventoryOperation, InventorySourceResult> results = new();
        private readonly List<LinuxInventoryOperation> calls = new();
        public Func<LinuxInventoryOperation, CancellationToken, Task<InventorySourceResult>>? Handler { get; set; }
        public TaskCompletionSource UsersStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IReadOnlyList<LinuxInventoryOperation> Calls { get { lock (calls) return calls.ToArray(); } }

        public void Set(LinuxInventoryOperation operation, InventorySourceResult result) => results[operation] = result;
        public InventorySourceResult Get(LinuxInventoryOperation operation) => results.GetValueOrDefault(operation, new(InventorySourceState.Unavailable, "command_missing"));

        public async Task<InventorySourceResult> ReadAsync(LinuxInventoryOperation operation, CancellationToken cancellationToken)
        {
            lock (calls) calls.Add(operation);
            if (operation == LinuxInventoryOperation.Users) UsersStarted.TrySetResult();
            cancellationToken.ThrowIfCancellationRequested();
            return Handler is null ? Get(operation) : await Handler(operation, cancellationToken);
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset current = value;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan amount) => current = current.Add(amount);
    }
}
