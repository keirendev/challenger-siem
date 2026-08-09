using System.Net.Sockets;
using System.Text;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.KernelNetwork;
using Challenger.Siem.Contracts.V2;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxKernelNetworkTests
{
    [Fact]
    public void PlanIsStableBoundedAndApprovalGated()
    {
        var options = CreateOptions();
        var first = LinuxKernelNetworkPlanBuilder.Build(options);
        var second = LinuxKernelNetworkPlanBuilder.Build(options);
        Assert.Equal(first.PlanHash, second.PlanHash);
        Assert.StartsWith("sha256:", first.PlanHash, StringComparison.Ordinal);
        Assert.False(first.ApprovalHashMatches);
        Assert.Contains("CAP_BPF,CAP_PERFMON,CAP_NET_ADMIN", first.RequiredCapabilities, StringComparison.Ordinal);
        Assert.Contains("no payload", first.PrivacyBoundary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CAP_SYS_ADMIN", first.RequiredCapabilities, StringComparison.Ordinal);
        Assert.DoesNotContain("CAP_NET_RAW", first.RequiredCapabilities, StringComparison.Ordinal);
        Assert.Equal(options.KernelNetworkTelemetry.ApprovedHelperSha256, first.HelperSha256);
        Assert.Equal(options.KernelNetworkTelemetry.ApprovedSignerPublicKeySha256, first.SignerPublicKeySha256);
        Assert.Contains("libbpf.so.1", first.Dependencies, StringComparison.Ordinal);
        Assert.Contains("SO_PEERCRED", first.IpcBoundary, StringComparison.Ordinal);
        Assert.Contains("Ed25519", first.SignedBundle, StringComparison.Ordinal);
        Assert.Contains("detach", first.Rollback, StringComparison.Ordinal);
        Assert.Contains("100 events", first.Bounds, StringComparison.Ordinal);
        Assert.Contains("1048576 bytes", first.Bounds, StringComparison.Ordinal);
        Assert.Equal("linux-network-flow-summary-v3", first.CollectorVersion);
        Assert.Equal("challenger-siem-ebpf-helper-v2", first.HelperVersion);
        Assert.Contains("kernel pre-drain every 1 second", first.Bounds, StringComparison.Ordinal);
        Assert.Contains("5000 per 10-second health interval", first.Bounds, StringComparison.Ordinal);

        options.KernelNetworkTelemetry.ApprovedPlanHash = first.PlanHash;
        Assert.True(LinuxKernelNetworkPlanBuilder.Build(options).ApprovalHashMatches);
        options.KernelNetworkTelemetry.ApprovedHelperSha256 = "sha256:" + new string('1', 64);
        Assert.NotEqual(first.PlanHash, LinuxKernelNetworkPlanBuilder.Build(options).PlanHash);
    }

    [Fact]
    public async Task PrivilegedUnitAndNativeProgramKeepTheFixedNoPayloadBoundary()
    {
        var repository = FindRepositoryRoot();
        var unit = await File.ReadAllTextAsync(Path.Combine(repository, "packaging/linux/challenger-siem-ebpf-helper.service"));
        var socket = await File.ReadAllTextAsync(Path.Combine(repository, "packaging/linux/challenger-siem-ebpf-helper.socket"));
        var bpf = await File.ReadAllTextAsync(Path.Combine(repository, "agent/KernelNetwork/Native/challenger_network.bpf.c"));
        var helper = await File.ReadAllTextAsync(Path.Combine(repository, "agent/KernelNetwork/Native/challenger-siem-ebpf-helper.c"));

        Assert.Contains("CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN", unit, StringComparison.Ordinal);
        Assert.Contains("AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN", unit, StringComparison.Ordinal);
        Assert.DoesNotContain("CAP_SYS_ADMIN", unit, StringComparison.Ordinal);
        Assert.DoesNotContain("CAP_NET_RAW", unit, StringComparison.Ordinal);
        Assert.Contains("ListenSequentialPacket=", socket, StringComparison.Ordinal);
        Assert.Contains("SocketMode=0660", socket, StringComparison.Ordinal);
        Assert.Contains("DirectoryMode=0755", socket, StringComparison.Ordinal);
        Assert.Contains("BPF_MAP_TYPE_HASH", bpf, StringComparison.Ordinal);
        Assert.Contains("SEC(\"cgroup/sock_create\")", bpf, StringComparison.Ordinal);
        Assert.Contains("SEC(\"cgroup/bind4\")", bpf, StringComparison.Ordinal);
        Assert.Contains("SEC(\"sockops\")", bpf, StringComparison.Ordinal);
        Assert.Contains("SEC(\"raw_tracepoint/inet_sock_set_state\")", bpf, StringComparison.Ordinal);
        var rawTracepoint = bpf[bpf.IndexOf("SEC(\"raw_tracepoint/inet_sock_set_state\")", StringComparison.Ordinal)..bpf.IndexOf("static __always_inline int capture_packet", StringComparison.Ordinal)];
        Assert.Contains("if (value.process_id != 0", rawTracepoint, StringComparison.Ordinal);
        Assert.Contains("if (owner && owner->process_id != 0", bpf, StringComparison.Ordinal);
        Assert.Contains("bpf_skb_load_bytes", bpf, StringComparison.Ordinal);
        Assert.Contains("bpf_skb_load_bytes_relative", bpf, StringComparison.Ordinal);
        Assert.Contains("BPF_HDR_START_NET", bpf, StringComparison.Ordinal);
        Assert.Contains("bpf_get_current_comm", bpf, StringComparison.Ordinal);
        Assert.Contains("CHALLENGER_OWNER_WINDOW_NS", bpf, StringComparison.Ordinal);
        Assert.Contains("__sync_fetch_and_add", bpf, StringComparison.Ordinal);
        Assert.Contains("bpf_ringbuf_reserve", bpf, StringComparison.Ordinal);
        Assert.DoesNotContain("skb->data", bpf, StringComparison.Ordinal);
        Assert.DoesNotContain("bpf_skb_pull_data", bpf, StringComparison.Ordinal);
        Assert.DoesNotContain("BPF_MAP_TYPE_PERF_EVENT_ARRAY", bpf, StringComparison.Ordinal);
        Assert.Contains("\\\"payload_capture\\\":false", helper, StringComparison.Ordinal);
        Assert.Contains("network_flow_started", helper, StringComparison.Ordinal);
        Assert.Contains("network_flow_sample", helper, StringComparison.Ordinal);
        Assert.Contains("network_flow_closed", helper, StringComparison.Ordinal);
        Assert.Contains("ACTIVE_SUMMARY_NS", helper, StringComparison.Ordinal);
        Assert.Contains("bpf_link_create(", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("bpf_prog_attach(", helper, StringComparison.Ordinal);
        Assert.Contains("O_NONBLOCK", helper, StringComparison.Ordinal);
        Assert.Contains("\\\"process_name\\\":\\\"%s\\\"", helper, StringComparison.Ordinal);
        Assert.Contains("bpf_map_lookup_and_delete_elem", helper, StringComparison.Ordinal);
        Assert.Contains("collect_flows(flow_fd, health_fd, &collected)", helper, StringComparison.Ordinal);
        Assert.Contains("CHALLENGER_KERNEL_DRAIN_INTERVAL_SECONDS * 1000", helper, StringComparison.Ordinal);
        Assert.Contains("CHALLENGER_COUNTER_TRACKED_FLOW_TABLE_FULL", helper, StringComparison.Ordinal);
        Assert.Contains("kernel_drain_backlog", helper, StringComparison.Ordinal);
        Assert.Contains("send_health", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("SOCK_RAW", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("AF_PACKET", helper, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IdleHealthFramesKeepTheSourceFreshAndSequenceLossDegradesIt()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var clock = new FixedTimeProvider(DateTimeOffset.Parse("2026-08-03T12:00:00Z"));
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json")),
                clock);
            var epoch = new string('a', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);

            Assert.Equal(SourceHealthStatuses.Healthy, runtime.Health().Status);
            Assert.Equal((ulong)1, runtime.Snapshot().LastHelperSequence);

            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 3 }, default);
            Assert.Equal(SourceHealthStatuses.Degraded, runtime.Health().Status);
            Assert.True(runtime.Health().GapDetected);
            Assert.Equal("helper_sequence_gap", runtime.Health().ErrorCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task HistoricalHelperLossRecoversAfterThreeCleanHealthFramesButRemainsCounted()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json")),
                new FixedTimeProvider(DateTimeOffset.Parse("2026-08-03T12:00:00Z")));
            var epoch = new string('b', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1, ParseFailures = 1 }, default);
            Assert.True(runtime.Snapshot().ActiveLoss);

            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 2, ParseFailures = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 3, ParseFailures = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 4, ParseFailures = 1 }, default);

            Assert.False(runtime.Snapshot().ActiveLoss);
            Assert.Equal((ulong)1, runtime.Snapshot().ParseFailures);
            Assert.Equal(SourceHealthStatuses.Healthy, runtime.Health().Status);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task HelperCountersRemainMonotonicAcrossLegacyMigrationAndHelperEpochs()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var store = new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json"));
            var firstEpoch = new string('1', 32);
            await store.WriteAsync(new LinuxKernelNetworkState
            {
                LastHelperEpoch = firstEpoch,
                LastHelperSequence = 10,
                ParseFailures = 1,
                FlowMapFull = 3,
                OwnerMisses = 4,
                RingLosses = 2,
                IpcSendFailures = 1
            }, default);

            var runtime = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = firstEpoch, Sequence = 11 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
            {
                Epoch = firstEpoch,
                Sequence = 11,
                ParseFailures = 1,
                FlowMapFull = 3,
                OwnerMisses = 4,
                RingLosses = 2,
                IpcSendFailures = 1
            }, default);
            Assert.Equal((ulong)3, runtime.Snapshot().FlowMapFull);

            var secondEpoch = new string('2', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = secondEpoch, Sequence = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = secondEpoch, Sequence = 1 }, default);
            Assert.Equal((ulong)3, runtime.Snapshot().FlowMapFull);
            Assert.Equal((ulong)1, runtime.Snapshot().ParseFailures);
            Assert.Equal((ulong)4, runtime.Snapshot().OwnerMisses);
            Assert.Equal((ulong)2, runtime.Snapshot().RingLosses);
            Assert.Equal((ulong)1, runtime.Snapshot().IpcSendFailures);

            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
            {
                Epoch = secondEpoch,
                Sequence = 2,
                ParseFailures = 2,
                FlowMapFull = 1,
                KernelFlowMapUpdateFailures = 1,
                OwnerMisses = 3,
                RingLosses = 1,
                KernelDrainCappedTicks = 2,
                KernelDrainBacklogTicks = 1
            }, default);
            Assert.Equal((ulong)4, runtime.Snapshot().FlowMapFull);
            Assert.Equal((ulong)1, runtime.Snapshot().KernelFlowMapUpdateFailures);
            Assert.Equal((ulong)3, runtime.Snapshot().ParseFailures);
            Assert.Equal((ulong)7, runtime.Snapshot().OwnerMisses);
            Assert.Equal((ulong)3, runtime.Snapshot().RingLosses);
            Assert.Equal((ulong)2, runtime.Snapshot().KernelDrainCappedTicks);
            Assert.Equal((ulong)1, runtime.Snapshot().KernelDrainBacklogTicks);

            var thirdEpoch = new string('3', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = thirdEpoch, Sequence = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
            {
                Epoch = thirdEpoch,
                Sequence = 1,
                FlowMapFull = 1,
                TrackedFlowTableFull = 1,
                OwnerMisses = 1,
                IpcSendFailures = 1,
                KernelDrainCappedTicks = 1
            }, default);
            var snapshot = runtime.Snapshot();
            Assert.Equal((ulong)5, snapshot.FlowMapFull);
            Assert.Equal((ulong)1, snapshot.KernelFlowMapUpdateFailures);
            Assert.Equal((ulong)1, snapshot.TrackedFlowTableFull);
            Assert.Equal((ulong)8, snapshot.OwnerMisses);
            Assert.Equal((ulong)2, snapshot.IpcSendFailures);
            Assert.Equal((ulong)3, snapshot.KernelDrainCappedTicks);
            Assert.Equal((ulong)1, snapshot.KernelDrainBacklogTicks);
            Assert.Equal(thirdEpoch, snapshot.CounterHelperEpoch);

            var persisted = await store.ReadAsync(default);
            Assert.Equal((ulong)5, persisted.FlowMapFull);
            Assert.Equal((ulong)1, persisted.RawFlowMapFull);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task KernelDrainBacklogDegradesAndDelaysLossRecoveryWithoutInventingLoss()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json")),
                new FixedTimeProvider(DateTimeOffset.Parse("2026-08-09T08:00:00Z")));
            var epoch = new string('7', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
            {
                Epoch = epoch,
                Sequence = 1,
                FlowMapFull = 1,
                KernelFlowMapUpdateFailures = 1,
                KernelDrainRecords = 5_000,
                KernelDrainHighWater = 5_000,
                KernelDrainCappedTicks = 10
            }, default);

            Assert.True(runtime.Snapshot().ActiveLoss);
            Assert.Equal("kernel_flow_map_update_failed", runtime.Health().ErrorCode);
            Assert.Equal("1", runtime.Health().Details!["kernel_flow_map_update_failures"]);

            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
            {
                Epoch = epoch,
                Sequence = 2,
                FlowMapFull = 1,
                KernelFlowMapUpdateFailures = 1,
                KernelDrainRecords = 500,
                KernelDrainHighWater = 5_000,
                KernelDrainCappedTicks = 11,
                KernelDrainBacklogTicks = 1,
                KernelDrainBacklog = true
            }, default);
            Assert.True(runtime.Snapshot().ActiveLoss);
            Assert.Equal(0, runtime.Snapshot().CleanHealthFrames);
            Assert.Equal("kernel_flow_map_update_failed", runtime.Health().ErrorCode);
            Assert.Equal("true", runtime.Health().Details!["kernel_drain_backlog"]);

            for (ulong sequence = 3; sequence <= 5; sequence++)
                await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
                {
                    Epoch = epoch,
                    Sequence = sequence,
                    FlowMapFull = 1,
                    KernelFlowMapUpdateFailures = 1,
                    KernelDrainHighWater = 5_000,
                    KernelDrainCappedTicks = 11,
                    KernelDrainBacklogTicks = 1
                }, default);

            Assert.False(runtime.Snapshot().ActiveLoss);
            Assert.Equal(SourceHealthStatuses.Healthy, runtime.Health().Status);

            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame
            {
                Epoch = epoch,
                Sequence = 6,
                FlowMapFull = 1,
                KernelFlowMapUpdateFailures = 1,
                KernelDrainRecords = 500,
                KernelDrainHighWater = 5_000,
                KernelDrainCappedTicks = 12,
                KernelDrainBacklogTicks = 2,
                KernelDrainBacklog = true
            }, default);
            Assert.False(runtime.Snapshot().ActiveLoss);
            Assert.False(runtime.Health().GapDetected);
            Assert.Equal(SourceHealthStatuses.Degraded, runtime.Health().Status);
            Assert.Equal("kernel_flow_map_drain_backlog", runtime.Health().ErrorCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ConnectionFailureReasonRemainsBoundedAndVisibleAfterHealthRecovery()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json")),
                TimeProvider.System);

            await runtime.ObserveConnectionFailureAsync("helper_flow_port_rejected", default);
            var epoch = new string('9', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            await runtime.ObserveHealthAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);

            Assert.Equal("helper_flow_port_rejected", runtime.Snapshot().LastConnectionError);
            Assert.Equal("helper_flow_port_rejected", runtime.Health().Details!["last_connection_error"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task QueueBeforeCheckpointAndRestartReplayKeepDurableOrderingAndFamilies()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var store = new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json"));
            var runtime = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            var epoch = new string('c', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            var callbackObservedOldCheckpoint = false;
            await runtime.CollectDrainAsync(
                [new(Flow(epoch, 1, "network_flow_started"), DateTimeOffset.UtcNow)],
                Health(epoch, 2),
                async (assignments, finalizeChunk) =>
                {
                    var beforeCheckpoint = await store.ReadAsync(default);
                    callbackObservedOldCheckpoint = beforeCheckpoint.CollectedSequence == 0;
                    Assert.Equal(1, assignments[0].AgentSequence);
                    Assert.False(assignments[0].HelperGap);
                    await finalizeChunk(1, Diagnostics(1));
                },
                default);
            Assert.True(callbackObservedOldCheckpoint);

            var restarted = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            await restarted.InitializeAsync(default);
            Assert.Equal(2, restarted.Snapshot().NextSequence);
            Assert.Equal(1, restarted.Snapshot().EventFamilyCounts["network_flow_started"]);

            await Assert.ThrowsAsync<IOException>(() => restarted.CollectDrainAsync(
                [new(Flow(epoch, 3, "network_flow_sample"), DateTimeOffset.UtcNow)],
                Health(epoch, 4),
                (_, _) => throw new IOException("synthetic queue failure"),
                default));
            Assert.Equal(1, (await store.ReadAsync(default)).CollectedSequence);
            Assert.Equal(3, restarted.Snapshot().NextSequence);
            Assert.Equal(2, restarted.Snapshot().AbandonedThroughSequence);
            Assert.True(restarted.Snapshot().ActiveLoss);

            await restarted.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = new string('d', 32), Sequence = 1 }, default);
            Assert.Equal(1, restarted.Snapshot().HelperRestartCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task DrainBatchUsesOneDurableCheckpointAfterTheQueueBatch()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var store = new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json"));
            var runtime = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            var epoch = new string('7', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            var observedCheckpoint = -1L;
            IReadOnlyList<LinuxKernelNetworkSequenceAssignment>? observedAssignments = null;

            var result = await runtime.CollectDrainAsync(
                [
                    new(Flow(epoch, 1, "network_flow_started"), DateTimeOffset.UtcNow),
                    new(Flow(epoch, 2, "network_flow_sample"), DateTimeOffset.UtcNow),
                    new(Flow(epoch, 3, "network_flow_closed"), DateTimeOffset.UtcNow)
                ],
                Health(epoch, 4),
                async (assignments, finalizeChunk) =>
                {
                    observedAssignments = assignments;
                    observedCheckpoint = (await store.ReadAsync(default)).CollectedSequence;
                    await finalizeChunk(3, Diagnostics(3));
                },
                default);

            Assert.Equal(0, observedCheckpoint);
            var assignments = Assert.IsAssignableFrom<IReadOnlyList<LinuxKernelNetworkSequenceAssignment>>(observedAssignments);
            Assert.Equal([1L, 2L, 3L], assignments.Select(item => item.AgentSequence));
            Assert.All(assignments, item => Assert.False(item.HelperGap));
            Assert.Equal(3, result.State.CollectedSequence);
            Assert.Equal((ulong)4, result.State.LastHelperSequence);
            Assert.Equal(3, (await store.ReadAsync(default)).CollectedSequence);
            Assert.Equal(1, result.State.EventFamilyCounts["network_flow_started"]);
            Assert.Equal(1, result.State.EventFamilyCounts["network_flow_sample"]);
            Assert.Equal(1, result.State.EventFamilyCounts["network_flow_closed"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FailedDrainBatchAbandonsItsReservationOnceAndNeverReusesASequence()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var store = new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json"));
            var runtime = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            var epoch = new string('8', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);

            await Assert.ThrowsAsync<IOException>(() => runtime.CollectDrainAsync(
                [
                    new(Flow(epoch, 1, "network_flow_started"), DateTimeOffset.UtcNow),
                    new(Flow(epoch, 2, "network_flow_sample"), DateTimeOffset.UtcNow)
                ],
                Health(epoch, 3),
                (_, _) => throw new IOException("synthetic durable queue failure"),
                default));

            Assert.Equal(0, runtime.Snapshot().CollectedSequence);
            Assert.Equal(0, (await store.ReadAsync(default)).CollectedSequence);
            Assert.Equal(3, runtime.Snapshot().NextSequence);
            Assert.Equal(2, runtime.Snapshot().AbandonedThroughSequence);
            Assert.Equal(1, runtime.Snapshot().GapCount);
            Assert.True(runtime.Snapshot().ActiveLoss);

            var restarted = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            await restarted.InitializeAsync(default);
            Assert.Equal(1, restarted.Snapshot().GapCount);
            var retry = await restarted.CollectDrainAsync(
                [new(Flow(epoch, 4, "network_flow_sample"), DateTimeOffset.UtcNow)],
                Health(epoch, 5),
                async (assignments, finalizeChunk) =>
                {
                    Assert.Equal(3, assignments[0].AgentSequence);
                    await finalizeChunk(1, Diagnostics(1));
                },
                default);
            Assert.Equal(3, retry.State.CollectedSequence);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RestartAbandonsAPersistedReservationExactlyOnce()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var store = new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json"));
            await store.WriteAsync(new LinuxKernelNetworkState
            {
                NextSequence = 13,
                CollectedSequence = 7,
                PendingReservationStart = 8,
                PendingReservationEnd = 12,
                PendingReservationHelperEpoch = new string('5', 32),
                PendingReservationHelperSequence = 19
            }, default);
            var options = CreateOptions();
            var first = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            await first.InitializeAsync(default);

            Assert.Equal(12, first.Snapshot().AbandonedThroughSequence);
            Assert.Equal(1, first.Snapshot().GapCount);
            Assert.True(first.Snapshot().ActiveLoss);
            Assert.Null(first.Snapshot().PendingReservationStart);
            Assert.Equal((ulong)19, first.Snapshot().LastHelperSequence);

            var second = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            await second.InitializeAsync(default);
            Assert.Equal(1, second.Snapshot().GapCount);
            Assert.Equal(13, second.Snapshot().NextSequence);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task SameEpochReconnectMakesAnUncommittedDrainSequenceGapExplicit()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json")),
                TimeProvider.System);
            var epoch = new string('6', 32);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 1 }, default);
            await runtime.ObserveHelloAsync(new LinuxKernelNetworkFrame { Epoch = epoch, Sequence = 9 }, default);

            Assert.True(runtime.Snapshot().ActiveLoss);
            Assert.Equal(1, runtime.Snapshot().GapCount);
            Assert.Equal("helper_sequence_gap", runtime.Snapshot().LastError);
            Assert.Equal((ulong)8, runtime.Snapshot().LastHelperSequence);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ApplicableHealthAlwaysCarriesSequenceCheckpointsIncludingZero()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var options = CreateOptions();
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json")),
                TimeProvider.System);

            var health = runtime.Health();

            Assert.Equal(SourceApplicabilityStatuses.Applicable, health.Applicability);
            Assert.Equal(0, Assert.IsType<long>(health.CollectedCheckpoint?.Sequence));
            Assert.Equal(0, Assert.IsType<long>(health.AcknowledgedCheckpoint?.Sequence));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task FiveHundredFrameDrainCompletesBeforeSlowEnrichmentAndPersistsInOrderWithCaching()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"challenger-kernel-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var socketPath = Path.Combine("/tmp", $"csi-{Guid.NewGuid():N}.sock");
        try
        {
            var options = CreateOptions();
            options.AgentId = "synthetic-kernel-agent";
            options.KernelNetworkTelemetry.Enabled = true;
            options.KernelNetworkTelemetry.ApprovedPlanHash = LinuxKernelNetworkPlanBuilder.Build(options).PlanHash;
            var store = new LinuxKernelNetworkStateStore(Path.Combine(directory, "state.json"));
            var runtime = new LinuxKernelNetworkRuntime(
                Options.Create(options),
                store,
                new FixedTimeProvider(DateTimeOffset.Parse("2026-08-04T02:00:00Z")));
            var queue = new RecordingQueue(store);
            var enricher = new DelayedProcessEnricher(TimeSpan.FromMilliseconds(250));
            var service = new LinuxKernelNetworkService(
                Options.Create(options),
                queue,
                runtime,
                enricher,
                new FixedTimeProvider(DateTimeOffset.Parse("2026-08-04T02:00:00Z")),
                NullLogger<LinuxKernelNetworkService>.Instance);

            using var listener = new Socket(AddressFamily.Unix, SocketType.Seqpacket, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(socketPath));
            listener.Listen(1);
            using var sender = new Socket(AddressFamily.Unix, SocketType.Seqpacket, ProtocolType.Unspecified)
            {
                SendTimeout = 1_000
            };
            var accept = listener.AcceptAsync();
            await sender.ConnectAsync(new UnixDomainSocketEndPoint(socketPath));
            using var receiver = await accept;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var receive = service.ReceiveDrainAsync(receiver, timeout.Token);
            var send = Task.Run(async () =>
            {
                for (ulong sequence = 1; sequence <= 500; sequence++)
                    await sender.SendAsync(Encoding.UTF8.GetBytes(FlowJson("network_flow_sample", sequence: sequence)), SocketFlags.None, timeout.Token);
                await sender.SendAsync(Encoding.UTF8.GetBytes(HealthJson(501)), SocketFlags.None, timeout.Token);
            }, timeout.Token);

            var drain = await receive;
            await send.WaitAsync(TimeSpan.FromSeconds(1));

            Assert.Equal(500, drain.Flows.Count);
            Assert.Equal((ulong)501, drain.Health.Sequence);
            Assert.Equal(0, enricher.Calls);

            await service.PersistDrainAsync(drain, timeout.Token);

            Assert.Equal(1, enricher.Calls);
            Assert.Equal([100, 100, 100, 100, 100], queue.BatchCounts);
            Assert.Equal([0L, 100L, 200L, 300L, 400L], queue.CollectedBeforeBatch);
            Assert.Equal(
                Enumerable.Range(1, 500).Select(value => (ulong)value),
                queue.Events.Select(item => item.Raw.GetProperty("helper_sequence").GetUInt64()));
            var state = runtime.Snapshot();
            Assert.Equal(500, state.CollectedSequence);
            Assert.Equal((ulong)501, state.LastHelperSequence);
            Assert.Equal(500, state.LastDrainRecordCount);
            Assert.Equal(500, state.HighWaterDrainRecordCount);
            Assert.Equal(1, state.LastDrainUniqueEnrichmentIdentities);
            Assert.Equal(499, state.LastDrainEnrichmentCacheHits);
            Assert.True(state.LastDrainSerializedBytes > 0);
            Assert.True(state.LastDrainPersistDurationMilliseconds >= 250);
            Assert.Equal("500", runtime.Health().Details!["last_drain_record_count"]);
        }
        finally
        {
            if (File.Exists(socketPath)) File.Delete(socketPath);
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void IpcFramesRejectUnknownDuplicateMissingAndOversizedContent()
    {
        var json = FlowJson("network_flow_started");
        var frame = LinuxKernelNetworkService.ParseFrame(json);
        LinuxKernelNetworkService.ValidateFlow(frame);

        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ParseFrame(json.Replace("\"event_code\"", "\"unknown\":1,\"event_code\"", StringComparison.Ordinal)));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ParseFrame(json.Replace("\"event_code\":\"network_flow_started\"", "\"event_code\":\"network_flow_started\",\"event_code\":\"network_flow_sample\"", StringComparison.Ordinal)));
        var missing = LinuxKernelNetworkService.ParseFrame(json.Replace(",\"event_code\":\"network_flow_started\"", string.Empty, StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ValidateFlow(missing));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ParseFrame(new string('x', LinuxKernelNetworkConstants.MaximumFrameBytes + 1)));

        var closed = LinuxKernelNetworkService.ParseFrame(FlowJson("network_flow_closed", packetCount: 0));
        LinuxKernelNetworkService.ValidateFlow(closed);
    }

    [Fact]
    public void IpcHealthFramesEnforceSplitLossAndKernelDrainBounds()
    {
        var hello = LinuxKernelNetworkService.ParseFrame(HelloJson(1));
        LinuxKernelNetworkService.ValidateHello(hello);
        var legacyHello = LinuxKernelNetworkService.ParseFrame(
            HelloJson(1).Replace(",\"kernel_drain_interval_seconds\":1,\"max_kernel_records_per_drain\":500,\"max_kernel_records_per_health_interval\":5000", string.Empty, StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ValidateHello(legacyHello));

        var health = LinuxKernelNetworkService.ParseFrame(HealthJson(1));
        LinuxKernelNetworkService.ValidateHealth(health);

        var inconsistentLoss = LinuxKernelNetworkService.ParseFrame(
            HealthJson(1).Replace("\"flow_map_full\":0", "\"flow_map_full\":1", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ValidateHealth(inconsistentLoss));

        var oversizedDrain = LinuxKernelNetworkService.ParseFrame(
            HealthJson(1).Replace("\"kernel_drain_records\":0", "\"kernel_drain_records\":5001", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ValidateHealth(oversizedDrain));

        var uncountedBacklog = LinuxKernelNetworkService.ParseFrame(
            HealthJson(1).Replace("\"kernel_drain_backlog\":false", "\"kernel_drain_backlog\":true", StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(() => LinuxKernelNetworkService.ValidateHealth(uncountedBacklog));
    }

    [Fact]
    public void ProcessEnrichmentIsBoundedAndRedactsCredentialShapedArguments()
    {
        const string secret = "synthetic-private-value";
        var metadata = LinuxKernelNetworkService.SanitizeProcessMetadata(
            Flow(new string('e', 32), 1, "network_flow_sample") with { ProcessName = "probe", AttributionSource = "current_task" },
            "/usr/bin/probe",
            $"probe --token={secret}",
            "1000",
            truncated: false,
            maximumExecutableCharacters: 4096,
            maximumCommandLineCharacters: 1024);

        Assert.True(metadata.Redacted);
        Assert.DoesNotContain(secret, metadata.CommandLine, StringComparison.Ordinal);
        Assert.Contains("<redacted>", metadata.CommandLine, StringComparison.Ordinal);
        Assert.Equal("kernel_current_task_procfs_enriched", metadata.Confidence);
    }

    [Fact]
    public void OptionBoundsFixSocketStateAndPressurePriority()
    {
        var options = CreateOptions();
        Assert.True(options.HasValidKernelNetworkTelemetryBounds());
        options.KernelNetworkTelemetry.SocketPath = "/tmp/untrusted.sock";
        Assert.False(options.HasValidKernelNetworkTelemetryBounds());
        options = CreateOptions();
        options.KernelNetworkTelemetry.QueuePauseDepth = LinuxKernelNetworkConstants.MaximumRecordsPerDrain - 1;
        Assert.False(options.HasValidKernelNetworkTelemetryBounds());
        options = CreateOptions();
        options.KernelNetworkTelemetry.QueuePauseDepth = options.PassiveTelemetry.QueuePauseDepth + 1;
        Assert.False(options.HasValidKernelNetworkTelemetryBounds());
    }

    private static LinuxAgentOptions CreateOptions() => new()
    {
        PassiveTelemetry = new PassiveTelemetryOptions { QueuePauseDepth = 50_000 },
        KernelNetworkTelemetry = new KernelNetworkTelemetryOptions
        {
            ApprovedHelperSha256 = "sha256:" + new string('a', 64),
            ApprovedSignerPublicKeySha256 = "sha256:" + new string('b', 64)
        }
    };

    private static LinuxKernelNetworkFrame Flow(string epoch, ulong sequence, string eventCode) => new()
    {
        Epoch = epoch,
        Sequence = sequence,
        EventCode = eventCode
    };

    private static LinuxKernelNetworkFrame Health(string epoch, ulong sequence) => new()
    {
        Epoch = epoch,
        Sequence = sequence,
        Type = "health"
    };

    private static LinuxKernelNetworkDrainDiagnostics Diagnostics(int count) =>
        new(count, count * 1024L, count, 0, 1, 2);

    private static string FlowJson(string eventCode, ulong packetCount = 1, ulong sequence = 1) => $$"""
        {"schema_version":1,"helper_version":"challenger-siem-ebpf-helper-v2","epoch":"ffffffffffffffffffffffffffffffff","sequence":{{sequence}},"type":"flow","event_code":"{{eventCode}}","family":4,"protocol":"udp","direction":"outbound","local_ip":"192.0.2.10","local_port":41000,"remote_ip":"198.51.100.53","remote_port":53,"process_id":4242,"user_id":1000,"process_name":"probe","attribution_source":"current_task","first_seen_unix_ns":1785722400000000000,"last_seen_unix_ns":1785722401000000000,"packet_count_delta":{{packetCount}},"byte_count_delta":28,"tcp_flags_mask":0,"parse_failures":0,"unsupported_headers":0,"flow_map_full":0,"kernel_flow_map_update_failures":0,"tracked_flow_table_full":0,"owner_misses":0,"ring_losses":0,"ipc_send_failures":0}
        """;

    private static string HealthJson(ulong sequence) => $$"""
        {"schema_version":1,"helper_version":"challenger-siem-ebpf-helper-v2","epoch":"ffffffffffffffffffffffffffffffff","sequence":{{sequence}},"type":"health","payload_capture":false,"parse_failures":0,"unsupported_headers":0,"flow_map_full":0,"kernel_flow_map_update_failures":0,"tracked_flow_table_full":0,"owner_misses":0,"ring_losses":0,"ipc_send_failures":0,"kernel_drain_records":0,"kernel_drain_high_water":0,"kernel_drain_capped_ticks":0,"kernel_drain_backlog_ticks":0,"kernel_drain_backlog":false}
        """;

    private static string HelloJson(ulong sequence) => $$"""
        {"schema_version":1,"helper_version":"challenger-siem-ebpf-helper-v2","epoch":"ffffffffffffffffffffffffffffffff","sequence":{{sequence}},"type":"hello","payload_capture":false,"flow_capacity":16384,"owner_capacity":32768,"ring_bytes":1048576,"drain_seconds":10,"max_records_per_drain":500,"kernel_drain_interval_seconds":1,"max_kernel_records_per_drain":500,"max_kernel_records_per_health_interval":5000}
        """;

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Challenger.Siem.sln"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Could not locate repository root.");
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class DelayedProcessEnricher(TimeSpan delay) : ILinuxKernelProcessEnricher
    {
        public int Calls { get; private set; }

        public async Task<LinuxKernelProcessMetadata> EnrichAsync(
            LinuxKernelNetworkFrame frame,
            CancellationToken cancellationToken)
        {
            Calls++;
            await Task.Delay(delay, cancellationToken);
            return new("/usr/bin/synthetic-probe", null, "1000", false, false, "kernel_current_task_procfs_enriched");
        }
    }

    private sealed class RecordingQueue(LinuxKernelNetworkStateStore store) : IEventQueue
    {
        public List<EventEnvelope> Events { get; } = [];
        public List<int> BatchCounts { get; } = [];
        public List<long> CollectedBeforeBatch { get; } = [];

        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) =>
            EnqueueBatchAsync([envelope], cancellationToken);
        public async Task EnqueueBatchAsync(IReadOnlyCollection<EventEnvelope> envelopes, CancellationToken cancellationToken)
        {
            CollectedBeforeBatch.Add((await store.ReadAsync(cancellationToken)).CollectedSequence);
            BatchCounts.Add(envelopes.Count);
            Events.AddRange(envelopes);
        }
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<QueuedEvent>>([]);
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(Events.Count);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) =>
            Task.FromResult(new QueueSloMetrics());
    }
}
