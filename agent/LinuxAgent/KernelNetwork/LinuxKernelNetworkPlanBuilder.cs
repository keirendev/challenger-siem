using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public static class LinuxKernelNetworkPlanBuilder
{
    public static LinuxKernelNetworkPlan Build(LinuxAgentOptions options)
    {
        var kernel = options.KernelNetworkTelemetry;
        const string dependencies = "Linux x86_64, systemd, cgroup v2 root, readable kernel BTF, libbpf.so.1, libelf, and zlib; no endpoint compiler";
        const string ipcBoundary = "versioned SOCK_SEQPACKET, 16 KiB frame maximum, SO_PEERCRED both ways, fixed property/type allowlists, epochs, and monotonic sequences";
        const string signedBundle = "detached Ed25519 manifest; approved signer public-key and embedded fixed-helper SHA-256 values are plan-bound";
        const string rollback = "disable the kernel source, stop challenger-siem-ebpf-helper.socket and .service to detach links, preserve queue/state and the locked identity, and verify no Challenger SIEM pins or cgroup programs remain";
        var canonical = string.Join('\n',
            LinuxKernelNetworkConstants.HelperVersion,
            LinuxKernelNetworkConstants.CollectorVersion,
            "cgroup=/sys/fs/cgroup",
            $"socket={kernel.SocketPath}",
            $"state={kernel.StatePath}",
            $"queue_pause={kernel.QueuePauseDepth}",
            $"startup_delay={kernel.StartupDelaySeconds}",
            $"max_command_line={kernel.MaxCommandLineBytes}",
            $"helper_sha256={kernel.ApprovedHelperSha256}",
            $"signer_public_key_sha256={kernel.ApprovedSignerPublicKeySha256}",
            $"dependencies={dependencies}",
            $"ipc_boundary={ipcBoundary}",
            $"signed_bundle={signedBundle}",
            $"flow_entries={LinuxKernelNetworkConstants.FlowMapEntries}",
            $"tracked_flow_entries={LinuxKernelNetworkConstants.TrackedFlowEntries}",
            $"owner_entries={LinuxKernelNetworkConstants.OwnerMapEntries}",
            "owner_window_seconds=60",
            $"ring_bytes={LinuxKernelNetworkConstants.RingBytes}",
            $"health_interval_seconds={LinuxKernelNetworkConstants.HealthIntervalSeconds}",
            $"kernel_drain_interval_seconds={LinuxKernelNetworkConstants.KernelDrainIntervalSeconds}",
            $"kernel_drain_max={LinuxKernelNetworkConstants.MaximumKernelRecordsPerDrain}",
            $"kernel_drain_health_max={LinuxKernelNetworkConstants.MaximumKernelRecordsPerHealthInterval}",
            $"emit_max={LinuxKernelNetworkConstants.MaximumOutputRecordsPerHealthInterval}",
            $"process_enrichment_identities_max={LinuxKernelNetworkConstants.MaximumProcessEnrichmentIdentitiesPerDrain}",
            "closed_before_start=single_closed_record",
            $"durable_batch_events={LinuxKernelNetworkConstants.MaximumDurableBatchEvents}",
            $"durable_batch_bytes={LinuxKernelNetworkConstants.MaximumDurableBatchBytes}",
            "active_summary_seconds=60",
            "caps=CAP_BPF,CAP_PERFMON,CAP_NET_ADMIN",
            "attachments=cgroup/sock_create,cgroup/bind4,cgroup/bind6,cgroup/connect4,cgroup/connect6,cgroup/sendmsg4,cgroup/sendmsg6,cgroup/recvmsg4,cgroup/recvmsg6,sockops,raw_tracepoint/inet_sock_set_state,cgroup_skb/ingress,cgroup_skb/egress",
            "privacy=ipv4_ipv6_tcp_udp_headers_and_aggregate_counters_only_no_payload",
            $"rollback={rollback}");
        var hash = "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        return new(
            hash,
            kernel.Enabled,
            IsSha256(kernel.ApprovedHelperSha256)
                && IsSha256(kernel.ApprovedSignerPublicKeySha256)
                && string.Equals(hash, kernel.ApprovedPlanHash, StringComparison.Ordinal),
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" : "unsupported",
            RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            LinuxKernelNetworkConstants.HelperVersion,
            LinuxKernelNetworkConstants.CollectorVersion,
            kernel.ApprovedHelperSha256,
            kernel.ApprovedSignerPublicKeySha256,
            dependencies,
            ipcBoundary,
            signedBundle,
            "/sys/fs/cgroup",
            kernel.SocketPath,
            "dedicated helper only: CAP_BPF,CAP_PERFMON,CAP_NET_ADMIN; agent receives no new capability",
            "IPv4/IPv6 TCP/UDP bounded headers, tuple, direction, PID/UID, TCP flags, packet and SKB-byte interval counters only; no payload, DNS, TLS, process environment, memory, or file content",
            "fixed embedded cgroup v2 socket/bind/connect/sendmsg/recvmsg, sock-ops, accepted/closed socket-state raw tracepoint, and ingress/egress programs with multi-attach; no arbitrary program path and no bpffs pinning",
            $"{LinuxKernelNetworkConstants.FlowMapEntries} kernel flows; {LinuxKernelNetworkConstants.TrackedFlowEntries} helper-tracked flows; {LinuxKernelNetworkConstants.OwnerMapEntries} owners; {LinuxKernelNetworkConstants.RingBytes} ring bytes; kernel pre-drain every {LinuxKernelNetworkConstants.KernelDrainIntervalSeconds} second at most {LinuxKernelNetworkConstants.MaximumKernelRecordsPerDrain} records and {LinuxKernelNetworkConstants.MaximumKernelRecordsPerHealthInterval} per {LinuxKernelNetworkConstants.HealthIntervalSeconds}-second health interval; at most {LinuxKernelNetworkConstants.MaximumOutputRecordsPerHealthInterval} emitted records per health interval with close-before-start coalescing; at most {LinuxKernelNetworkConstants.MaximumProcessEnrichmentIdentitiesPerDrain} procfs enrichment identities per drain; 60-second active summaries; durable queue transactions at most {LinuxKernelNetworkConstants.MaximumDurableBatchEvents} events or {LinuxKernelNetworkConstants.MaximumDurableBatchBytes} bytes; queue pauses at {kernel.QueuePauseDepth}",
            rollback);
    }

    private static bool IsSha256(string value) => value.Length == 71
        && value.StartsWith("sha256:", StringComparison.Ordinal)
        && value.AsSpan(7).ToString().All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
