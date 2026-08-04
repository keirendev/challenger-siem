using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.KernelNetwork;
using Challenger.Siem.Contracts.V2;
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
            await runtime.CollectAsync(
                Flow(epoch, 1, "network_flow_started"),
                DateTimeOffset.UtcNow,
                async (sequence, gap) =>
                {
                    var beforeCheckpoint = await store.ReadAsync(default);
                    callbackObservedOldCheckpoint = beforeCheckpoint.CollectedSequence == 0;
                    Assert.Equal(1, sequence);
                    Assert.False(gap);
                },
                default);
            Assert.True(callbackObservedOldCheckpoint);

            var restarted = new LinuxKernelNetworkRuntime(Options.Create(options), store, TimeProvider.System);
            await restarted.InitializeAsync(default);
            Assert.Equal(2, restarted.Snapshot().NextSequence);
            Assert.Equal(1, restarted.Snapshot().EventFamilyCounts["network_flow_started"]);

            await Assert.ThrowsAsync<IOException>(() => restarted.CollectAsync(
                Flow(epoch, 2, "network_flow_sample"),
                DateTimeOffset.UtcNow,
                (_, _) => throw new IOException("synthetic queue failure"),
                default));
            Assert.Equal(1, (await store.ReadAsync(default)).CollectedSequence);

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

            var result = await runtime.CollectBatchAsync(
                [
                    new(Flow(epoch, 1, "network_flow_started"), DateTimeOffset.UtcNow),
                    new(Flow(epoch, 2, "network_flow_sample"), DateTimeOffset.UtcNow),
                    new(Flow(epoch, 3, "network_flow_closed"), DateTimeOffset.UtcNow)
                ],
                async assignments =>
                {
                    observedAssignments = assignments;
                    observedCheckpoint = (await store.ReadAsync(default)).CollectedSequence;
                },
                default);

            Assert.Equal(0, observedCheckpoint);
            var assignments = Assert.IsAssignableFrom<IReadOnlyList<LinuxKernelNetworkSequenceAssignment>>(observedAssignments);
            Assert.Equal([1L, 2L, 3L], assignments.Select(item => item.AgentSequence));
            Assert.All(assignments, item => Assert.False(item.HelperGap));
            Assert.Equal(3, result.State.CollectedSequence);
            Assert.Equal((ulong)3, result.State.LastHelperSequence);
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
    public async Task FailedDrainBatchLeavesTheDurableCheckpointForDeterministicRetry()
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

            await Assert.ThrowsAsync<IOException>(() => runtime.CollectBatchAsync(
                [
                    new(Flow(epoch, 1, "network_flow_started"), DateTimeOffset.UtcNow),
                    new(Flow(epoch, 2, "network_flow_sample"), DateTimeOffset.UtcNow)
                ],
                _ => throw new IOException("synthetic durable queue failure"),
                default));

            Assert.Equal(0, runtime.Snapshot().CollectedSequence);
            Assert.Equal(0, (await store.ReadAsync(default)).CollectedSequence);
            Assert.Equal(1, runtime.Snapshot().NextSequence);
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

    private static string FlowJson(string eventCode, ulong packetCount = 1) => $$"""
        {"schema_version":1,"helper_version":"challenger-siem-ebpf-helper-v1","epoch":"ffffffffffffffffffffffffffffffff","sequence":1,"type":"flow","event_code":"{{eventCode}}","family":4,"protocol":"udp","direction":"outbound","local_ip":"192.0.2.10","local_port":41000,"remote_ip":"198.51.100.53","remote_port":53,"process_id":4242,"user_id":1000,"process_name":"probe","attribution_source":"current_task","first_seen_unix_ns":1785722400000000000,"last_seen_unix_ns":1785722401000000000,"packet_count_delta":{{packetCount}},"byte_count_delta":28,"tcp_flags_mask":0,"parse_failures":0,"unsupported_headers":0,"flow_map_full":0,"owner_misses":0,"ring_losses":0,"ipc_send_failures":0}
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
}
