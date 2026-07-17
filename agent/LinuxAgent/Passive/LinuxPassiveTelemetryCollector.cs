using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxPassiveTelemetryCollector(
    IOptions<LinuxAgentOptions> configured,
    ILinuxProcessSnapshotSource processSource,
    ILinuxNetworkSnapshotSource networkSource,
    ILinuxHostMetricsSource metricsSource,
    TimeProvider timeProvider)
{
    public const string CollectorVersion = "linux-passive-snapshot-v1";
    private readonly LinuxAgentOptions options = configured.Value;

    public string PlanHash => ComputePlanHash(options);

    public bool IsEnabledAndApproved => options.PassiveTelemetry.Enabled
        && string.Equals(options.PassiveTelemetry.ApprovedPlanHash, PlanHash, StringComparison.Ordinal);

    public static string ComputePlanHash(LinuxAgentOptions configured)
    {
        var options = configured.PassiveTelemetry;
        var canonical = string.Join('\n',
            CollectorVersion,
            $"startup_delay={options.StartupDelaySeconds}",
            $"process_interval={options.ProcessPollIntervalSeconds}",
            $"network_interval={options.NetworkPollIntervalSeconds}",
            $"metrics_interval={options.HostMetricsIntervalSeconds}",
            $"scan_timeout={options.ScanTimeoutSeconds}",
            $"queue_pause={options.QueuePauseDepth}",
            $"queue_max_size_mb={configured.Queue.MaxSizeMb}",
            $"queue_warning_size_percent={configured.Queue.WarningSizePercent}",
            $"journal_queue_pause={configured.Journal.QueuePauseDepth}",
            $"journal_max_records_per_poll={configured.Journal.MaxRecordsPerPoll}",
            $"journal_max_input_record_bytes={configured.Journal.MaxInputRecordBytes}",
            $"journal_scope={LinuxJournalScopes.Configured(configured.Journal)}",
            $"max_processes={options.MaxProcessesPerScan}",
            $"max_sockets={options.MaxSocketsPerScan}",
            $"max_events={options.MaxEventsPerScan}",
            $"process_read_bytes={options.MaxProcessReadBytesPerScan}",
            $"network_read_bytes={options.MaxNetworkReadBytesPerScan}",
            $"command_line_bytes={options.MaxCommandLineBytes}",
            $"raw_event_bytes={options.MaxRawEventBytes}",
            $"partial_baseline_miss_limit={LinuxPassiveTelemetryLimits.PartialBaselineMissLimit}",
            $"cleanup_on_disable={options.CleanupStateOnDisable}",
            $"state_path={options.StatePath}",
            "process=/proc/self/mountinfo,/proc/sys/kernel/random/boot_id,/proc/<numeric-pid>/{stat,status,loginuid,cgroup,cmdline,exe}",
            "network=/proc/sys/kernel/random/boot_id,/proc/net/{tcp,tcp6,udp,udp6}",
            "metrics=/proc/sys/kernel/random/boot_id,/proc/{stat,meminfo,loadavg,uptime,diskstats,net/dev,pressure/cpu,pressure/memory,pressure/io}",
            "exclusions=environ,fd,cwd,root,maps,mem,stack,syscall,packet_payload,dns_payload,unix_socket_path");
        return "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public PassiveTelemetryPlan Preflight()
    {
        var settings = options.PassiveTelemetry;
        return new(
            PlanHash,
            OperatingSystem.IsLinux()
                ? $"linux/{System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}"
                : "unsupported_non_linux",
            settings.Enabled,
            IsEnabledAndApproved,
            "Existing unprivileged agent identity only. Missing or denied procfs fields remain explicit partial or permission-denied health; no privilege expansion is attempted.",
            "None. The pack reads fixed procfs metadata and writes only its protected agent queue/state files.",
            "No environment values, fd targets, cwd/root links, memory, maps, stack, syscall arguments, shell history, file contents, packet/DNS payloads, Unix-socket paths, audit, or eBPF.",
            $"Pause this L3 pack before journal L1/L2 at row depth {settings.QueuePauseDepth} or before estimated batch bytes {options.PassiveMaximumEstimatedBatchBytes()} would cross passive byte limit {options.PassiveQueueByteLimit()} after the queue warning threshold and one-journal-poll reserve; coalesce host metrics and persist bounded gap/drop/pressure counts.",
            settings.StatePath,
            [
                new(
                    LinuxTelemetrySourceIds.ProcessSnapshotDiff,
                    ["/proc/self/mountinfo", "/proc/sys/kernel/random/boot_id", "/proc/<numeric-pid>/stat", "/proc/<numeric-pid>/status", "/proc/<numeric-pid>/loginuid", "/proc/<numeric-pid>/cgroup", "/proc/<numeric-pid>/cmdline", "/proc/<numeric-pid>/exe"],
                    "Polling-honest baseline, observed, disappeared, and changed process snapshot differences; no exact exec/exit claim.",
                    "High-sensitivity process metadata. Command lines are bounded, common credential forms are redacted, and malformed/truncated sensitive text fails closed before queueing; this is not a guarantee that arbitrary unlabeled secrets can be identified. Raw procfs records are not retained.",
                    $"{settings.MaxProcessesPerScan} processes, {settings.MaxProcessReadBytesPerScan} read bytes, {settings.MaxEventsPerScan} events, {settings.ScanTimeoutSeconds}s deadline."),
                new(
                    LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff,
                    ["/proc/sys/kernel/random/boot_id", "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"],
                    "Polling-honest baseline, observed, disappeared, and changed socket tuple differences without process attribution.",
                    "High-sensitivity addresses, ports, state, UID, and socket inode only; no packet payload or fd scan.",
                    $"{settings.MaxSocketsPerScan} sockets, {settings.MaxNetworkReadBytesPerScan} read bytes, {settings.MaxEventsPerScan} events, {settings.ScanTimeoutSeconds}s deadline."),
                new(
                    LinuxTelemetrySourceIds.HostBehaviourMetrics,
                    ["/proc/sys/kernel/random/boot_id", "/proc/stat", "/proc/meminfo", "/proc/loadavg", "/proc/uptime", "/proc/diskstats", "/proc/net/dev", "/proc/pressure/cpu", "/proc/pressure/memory", "/proc/pressure/io"],
                    "At most one coalesced aggregate host metrics sample per completed scan on a nominal completion-plus-interval cadence; skipped intervals are not backfilled.",
                    "Aggregate counters and gauges only; no process, path, command, payload, or file-content data.",
                    $"At most one sample per completed scan; nominal completion-plus-{settings.HostMetricsIntervalSeconds}s cadence, skipped or failed intervals are not backfilled, at most 1 MiB input, {settings.ScanTimeoutSeconds}s deadline.")
            ]);
    }

    public async Task<PassiveCollectionResult> CollectProcessesAsync(
        LinuxPassiveTelemetryState previous,
        string agentId,
        string hostname,
        CancellationToken cancellationToken)
    {
        var read = await processSource.ReadAsync(options.PassiveTelemetry, cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (!TryGetBootIdentity(read, out var bootIdentitySha256))
            return BootIdentityUnavailableResult(LinuxTelemetrySourceIds.ProcessSnapshotDiff, previous, read, now);
        previous = LinuxBootIdentity.ApplyEpoch(previous, bootIdentitySha256);
        var current = read.Items.ToDictionary(
            item => item.Key,
            item => new LinuxProcessBaseline
            {
                Signature = item.Signature,
                ProcessId = item.ProcessId,
                ParentProcessId = item.ParentProcessId,
                EnrichmentPartial = item.EnrichmentPartial
            },
            StringComparer.Ordinal);
        var complete = read.Status == PassiveReadStatuses.Success && !read.Truncated;
        var changes = new List<(string Action, LinuxProcessObservation? Current, LinuxProcessBaseline? Prior, string Key)>();
        foreach (var item in read.Items.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            if (!previous.Process.Baseline.TryGetValue(item.Key, out var prior))
                changes.Add((previous.Process.BaselineEstablished ? "observed" : "baseline", item, null, item.Key));
            else if (!string.Equals(prior.Signature, item.Signature, StringComparison.Ordinal)
                && !prior.EnrichmentPartial
                && !item.EnrichmentPartial)
                changes.Add((previous.Process.BaselineEstablished ? "changed" : "baseline", item, prior, item.Key));
        }
        if (complete)
        {
            changes.AddRange(previous.Process.Baseline
                .Where(item => !current.ContainsKey(item.Key))
                .OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => (
                    previous.Process.BaselineEstablished ? "disappeared" : "baseline_disappeared",
                    (LinuxProcessObservation?)null,
                    (LinuxProcessBaseline?)item.Value,
                    item.Key)));
        }

        var retained = changes.Take(options.PassiveTelemetry.MaxEventsPerScan).ToArray();
        var dropped = Math.Max(0, changes.Count - retained.Length);
        var retainedKeys = retained.Select(item => item.Key).ToHashSet(StringComparer.Ordinal);
        var nextBaseline = new Dictionary<string, LinuxProcessBaseline>(previous.Process.Baseline, StringComparer.Ordinal);
        foreach (var item in current)
        {
            if (!previous.Process.Baseline.TryGetValue(item.Key, out var prior)
                || !string.Equals(prior.Signature, item.Value.Signature, StringComparison.Ordinal))
            {
                if (prior is not null && item.Value.EnrichmentPartial)
                    nextBaseline[item.Key] = prior with { MissedPartialScans = 0 };
                else if (prior?.EnrichmentPartial == true)
                    nextBaseline[item.Key] = item.Value;
                else if (retainedKeys.Contains(item.Key))
                    nextBaseline[item.Key] = item.Value;
                else if (prior is not null)
                    nextBaseline[item.Key] = prior with { MissedPartialScans = 0 };
            }
            else
            {
                nextBaseline[item.Key] = item.Value;
            }
        }

        long expiredPartialEntries = 0;
        foreach (var prior in previous.Process.Baseline.Where(item => !current.ContainsKey(item.Key)).ToArray())
        {
            if (complete)
            {
                if (retainedKeys.Contains(prior.Key)) nextBaseline.Remove(prior.Key);
                continue;
            }
            var missed = prior.Value.MissedPartialScans + 1;
            if (missed >= LinuxPassiveTelemetryLimits.PartialBaselineMissLimit)
            {
                nextBaseline.Remove(prior.Key);
                expiredPartialEntries++;
            }
            else
            {
                nextBaseline[prior.Key] = prior.Value with { MissedPartialScans = missed };
            }
        }
        expiredPartialEntries += BoundBaseline(nextBaseline, current.Keys, options.PassiveTelemetry.MaxProcessesPerScan);

        EnsureSequenceCapacity(previous.Process.Progress, retained.Length);
        var sequence = Math.Max(1, previous.Process.Progress.NextSequence);
        var events = new List<EventEnvelope>(retained.Length);
        foreach (var change in retained)
        {
            events.Add(BuildProcessEvent(agentId, hostname, change.Action, change.Key, change.Current, change.Prior, sequence++, now));
        }
        var progress = Advance(previous.Process.Progress, sequence, events, now);
        var established = previous.Process.BaselineEstablished || complete && dropped == 0;
        if (established) progress = ObserveFamily(progress, "process_baseline");
        var newState = previous with
        {
            Process = new()
            {
                BaselineEstablished = established,
                Progress = progress,
                Baseline = nextBaseline
            }
        };
        return Result(LinuxTelemetrySourceIds.ProcessSnapshotDiff, events, newState, read, dropped, read.Items.Count,
            expiredPartialEntries);
    }

    public async Task<PassiveCollectionResult> CollectNetworkAsync(
        LinuxPassiveTelemetryState previous,
        string agentId,
        string hostname,
        CancellationToken cancellationToken)
    {
        var read = await networkSource.ReadAsync(options.PassiveTelemetry, cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (!TryGetBootIdentity(read, out var bootIdentitySha256))
            return BootIdentityUnavailableResult(LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, previous, read, now);
        previous = LinuxBootIdentity.ApplyEpoch(previous, bootIdentitySha256);
        var current = read.Items.ToDictionary(
            item => item.Key,
            item => new LinuxSocketBaseline
            {
                Signature = item.Signature,
                Protocol = item.Protocol,
                State = item.State,
                LocalAddress = item.LocalAddress,
                LocalPort = item.LocalPort,
                RemoteAddress = item.RemoteAddress,
                RemotePort = item.RemotePort,
                Inode = item.Inode,
                UserId = item.UserId,
                Count = item.Count
            },
            StringComparer.Ordinal);
        var complete = read.Status == PassiveReadStatuses.Success && !read.Truncated;
        var changes = new List<(string Action, LinuxSocketObservation? Current, LinuxSocketBaseline? Prior, string Key)>();
        foreach (var item in read.Items.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            if (!previous.Network.Baseline.TryGetValue(item.Key, out var prior))
                changes.Add((previous.Network.BaselineEstablished ? "observed" : "baseline", item, null, item.Key));
            else if (!string.Equals(prior.Signature, item.Signature, StringComparison.Ordinal))
                changes.Add((previous.Network.BaselineEstablished ? "changed" : "baseline", item, prior, item.Key));
        }
        if (complete)
        {
            changes.AddRange(previous.Network.Baseline
                .Where(item => !current.ContainsKey(item.Key))
                .OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => (
                    previous.Network.BaselineEstablished ? "disappeared" : "baseline_disappeared",
                    (LinuxSocketObservation?)null,
                    (LinuxSocketBaseline?)item.Value,
                    item.Key)));
        }

        var retained = changes.Take(options.PassiveTelemetry.MaxEventsPerScan).ToArray();
        var dropped = Math.Max(0, changes.Count - retained.Length);
        var retainedKeys = retained.Select(item => item.Key).ToHashSet(StringComparer.Ordinal);
        var nextBaseline = new Dictionary<string, LinuxSocketBaseline>(previous.Network.Baseline, StringComparer.Ordinal);
        foreach (var item in current)
        {
            if (!previous.Network.Baseline.TryGetValue(item.Key, out var prior)
                || !string.Equals(prior.Signature, item.Value.Signature, StringComparison.Ordinal))
            {
                if (retainedKeys.Contains(item.Key)) nextBaseline[item.Key] = item.Value;
                else if (prior is not null) nextBaseline[item.Key] = prior with { MissedPartialScans = 0 };
            }
            else
            {
                nextBaseline[item.Key] = item.Value;
            }
        }

        long expiredPartialEntries = 0;
        foreach (var prior in previous.Network.Baseline.Where(item => !current.ContainsKey(item.Key)).ToArray())
        {
            if (complete)
            {
                if (retainedKeys.Contains(prior.Key)) nextBaseline.Remove(prior.Key);
                continue;
            }
            var missed = prior.Value.MissedPartialScans + 1;
            if (missed >= LinuxPassiveTelemetryLimits.PartialBaselineMissLimit)
            {
                nextBaseline.Remove(prior.Key);
                expiredPartialEntries++;
            }
            else
            {
                nextBaseline[prior.Key] = prior.Value with { MissedPartialScans = missed };
            }
        }
        expiredPartialEntries += BoundBaseline(nextBaseline, current.Keys, options.PassiveTelemetry.MaxSocketsPerScan);

        EnsureSequenceCapacity(previous.Network.Progress, retained.Length);
        var sequence = Math.Max(1, previous.Network.Progress.NextSequence);
        var events = new List<EventEnvelope>(retained.Length);
        foreach (var change in retained)
        {
            events.Add(BuildNetworkEvent(agentId, hostname, change.Action, change.Key, change.Current, change.Prior, sequence++, now));
        }
        var progress = Advance(previous.Network.Progress, sequence, events, now);
        var established = previous.Network.BaselineEstablished || complete && dropped == 0;
        if (established) progress = ObserveFamily(progress, "socket_baseline");
        var newState = previous with
        {
            Network = new()
            {
                BaselineEstablished = established,
                Progress = progress,
                Baseline = nextBaseline
            }
        };
        return Result(LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff, events, newState, read, dropped, read.Items.Count,
            expiredPartialEntries);
    }

    public async Task<PassiveCollectionResult> CollectMetricsAsync(
        LinuxPassiveTelemetryState previous,
        string agentId,
        string hostname,
        CancellationToken cancellationToken)
    {
        var read = await metricsSource.ReadAsync(options.PassiveTelemetry, cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (!TryGetBootIdentity(read, out var bootIdentitySha256))
            return BootIdentityUnavailableResult(LinuxTelemetrySourceIds.HostBehaviourMetrics, previous, read, now);
        previous = LinuxBootIdentity.ApplyEpoch(previous, bootIdentitySha256);
        if (read.Items.Count == 0)
        {
            return NoDataResult(LinuxTelemetrySourceIds.HostBehaviourMetrics, previous, read, now);
        }

        var current = read.Items[0];
        EnsureSequenceCapacity(previous.Metrics.Progress, 1);
        var sequence = Math.Max(1, previous.Metrics.Progress.NextSequence);
        var evt = BuildMetricsEvent(
            agentId,
            hostname,
            current,
            previous.Metrics.Previous,
            sequence++,
            now,
            read.Status == PassiveReadStatuses.Success && !read.Truncated);
        var events = new[] { evt };
        var progress = Advance(previous.Metrics.Progress, sequence, events, now);
        var newState = previous with
        {
            Metrics = new()
            {
                Progress = progress,
                Previous = current
            }
        };
        return Result(LinuxTelemetrySourceIds.HostBehaviourMetrics, events, newState, read, 0, 1, 0);
    }

    private EventEnvelope BuildProcessEvent(
        string agentId,
        string hostname,
        string action,
        string key,
        LinuxProcessObservation? current,
        LinuxProcessBaseline? prior,
        long sequence,
        DateTimeOffset now)
    {
        var processId = current?.ProcessId ?? prior!.ProcessId;
        var parentId = current?.ParentProcessId ?? prior!.ParentProcessId;
        var command = current?.Command ?? "unknown";
        var executable = current?.Executable;
        var userId = current?.UserId;
        var raw = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "linux-process-snapshot-v1",
            ["evidence_mode"] = "snapshot_diff",
            ["action"] = action,
            ["process_key"] = key,
            ["process_id"] = processId,
            ["parent_process_id"] = parentId,
            ["process_state"] = current?.State,
            ["command"] = command,
            ["executable"] = executable,
            ["command_line"] = current?.CommandLine,
            ["user_id"] = userId,
            ["group_id"] = current?.GroupId,
            ["effective_capabilities"] = current?.EffectiveCapabilities,
            ["no_new_privileges"] = current?.NoNewPrivileges,
            ["seccomp_mode"] = current?.SeccompMode,
            ["tracer_process_id"] = current?.TracerProcessId,
            ["login_user_id"] = current?.LoginUserId,
            ["cgroup_sha256"] = current?.CgroupSha256,
            ["enrichment_partial"] = current is null || current.EnrichmentPartial
        };
        var redactedFields = new List<string>();
        if (current?.CommandRedacted == true)
            redactedFields.AddRange(["raw.command", "normalized.labels.process.command"]);
        if (current?.ExecutableRedacted == true)
            redactedFields.AddRange(["raw.executable", "normalized.process_image", "normalized.process.executable"]);
        if (current?.CommandLineRedacted == true)
            redactedFields.AddRange(["raw.command_line", "normalized.process_command_line", "normalized.process.command_line"]);
        var truncatedFields = new List<string>();
        if (current?.ExecutableTruncated == true)
            truncatedFields.AddRange(["raw.executable", "normalized.process_image", "normalized.process.executable"]);
        if (current?.CommandLineTruncated == true)
            truncatedFields.AddRange(["raw.command_line", "normalized.process_command_line", "normalized.process.command_line"]);
        var redacted = redactedFields.Count > 0;
        var truncated = truncatedFields.Count > 0;
        return BuildEnvelope(
            agentId,
            hostname,
            EventSources.InventoryDiff,
            LinuxTelemetrySourceIds.ProcessSnapshotDiff,
            $"process_{action}",
            sequence,
            now,
            $"Linux process snapshot {action}.",
            new NormalizedEventFields
            {
                Category = "process",
                Action = action,
                Outcome = "unknown",
                ProcessId = processId.ToString(CultureInfo.InvariantCulture),
                ParentProcessId = parentId.ToString(CultureInfo.InvariantCulture),
                ProcessImage = executable,
                ProcessCommandLine = current?.CommandLine,
                Process = new ProcessTelemetryConcept
                {
                    Pid = processId.ToString(CultureInfo.InvariantCulture),
                    ParentPid = parentId.ToString(CultureInfo.InvariantCulture),
                    Executable = executable,
                    CommandLine = current?.CommandLine
                },
                User = userId is null ? null : new UserTelemetryConcept { Id = userId },
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["evidence_mode"] = "snapshot_diff",
                    ["telemetry.sensitivity"] = "high",
                    ["baseline.alertable"] = action.StartsWith("baseline", StringComparison.Ordinal) ? "false" : "not_baseline",
                    ["process.command"] = command,
                    ["process.state"] = current?.State ?? "unknown",
                    ["process.enrichment"] = current is null ? "unavailable" : current.EnrichmentPartial ? "partial" : "observed"
                }
            },
            raw,
            redacted,
            redactedFields,
            truncated,
            truncatedFields);
    }

    private EventEnvelope BuildNetworkEvent(
        string agentId,
        string hostname,
        string action,
        string key,
        LinuxSocketObservation? current,
        LinuxSocketBaseline? prior,
        long sequence,
        DateTimeOffset now)
    {
        var protocol = current?.Protocol ?? prior!.Protocol;
        var state = current?.State ?? prior!.State;
        var localAddress = current?.LocalAddress ?? prior!.LocalAddress;
        var localPort = current?.LocalPort ?? prior!.LocalPort;
        var remoteAddress = current?.RemoteAddress ?? prior?.RemoteAddress;
        var remotePort = current?.RemotePort ?? prior?.RemotePort;
        var inode = current?.Inode ?? prior?.Inode;
        var userId = current?.UserId ?? prior?.UserId;
        var count = current?.Count ?? prior?.Count ?? 1;
        var raw = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "linux-network-snapshot-v1",
            ["evidence_mode"] = "snapshot_diff",
            ["action"] = action,
            ["socket_key"] = key,
            ["protocol"] = protocol,
            ["state"] = state,
            ["local_address"] = localAddress,
            ["local_port"] = localPort,
            ["remote_address"] = remoteAddress,
            ["remote_port"] = remotePort,
            ["socket_inode"] = inode,
            ["user_id"] = userId,
            ["tuple_count"] = count,
            ["process_attribution"] = "not_collected"
        };
        return BuildEnvelope(
            agentId,
            hostname,
            EventSources.InventoryDiff,
            LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff,
            $"socket_{action}",
            sequence,
            now,
            $"Linux network socket snapshot {action}.",
            new NormalizedEventFields
            {
                Category = state == "listen" ? "network_listener" : "network",
                Action = action,
                Outcome = "unknown",
                SourceIp = localAddress,
                SourcePort = localPort.ToString(CultureInfo.InvariantCulture),
                DestinationIp = remoteAddress,
                DestinationPort = remotePort?.ToString(CultureInfo.InvariantCulture),
                Protocol = protocol,
                User = userId is null ? null : new UserTelemetryConcept { Id = userId },
                Network = new NetworkTelemetryConcept
                {
                    SourceIp = localAddress,
                    SourcePort = localPort,
                    DestinationIp = remoteAddress,
                    DestinationPort = remotePort,
                    Protocol = protocol
                },
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["evidence_mode"] = "snapshot_diff",
                    ["telemetry.sensitivity"] = "high",
                    ["baseline.alertable"] = action.StartsWith("baseline", StringComparison.Ordinal) ? "false" : "not_baseline",
                    ["network.state"] = state,
                    ["network.process_attribution"] = "not_collected",
                    ["network.tuple_count"] = count.ToString(CultureInfo.InvariantCulture)
                }
            },
            raw,
            false,
            [],
            false,
            []);
    }

    private EventEnvelope BuildMetricsEvent(
        string agentId,
        string hostname,
        LinuxHostMetricsObservation current,
        LinuxHostMetricsObservation? previous,
        long sequence,
        DateTimeOffset now,
        bool complete)
    {
        var cpuBusyPermille = DeltaRatioPermille(current.CpuTotalTicks, previous?.CpuTotalTicks, current.CpuIdleTicks, previous?.CpuIdleTicks);
        var raw = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "linux-host-behaviour-v1",
            ["evidence_mode"] = "coalesced_procfs_sample",
            ["uptime_seconds"] = current.UptimeSeconds,
            ["load_1_milli"] = current.Load1Milli,
            ["load_5_milli"] = current.Load5Milli,
            ["load_15_milli"] = current.Load15Milli,
            ["memory_total_bytes"] = current.MemoryTotalBytes,
            ["memory_available_bytes"] = current.MemoryAvailableBytes,
            ["swap_free_bytes"] = current.SwapFreeBytes,
            ["processes_running"] = current.ProcessesRunning,
            ["processes_blocked"] = current.ProcessesBlocked,
            ["cpu_busy_permille"] = cpuBusyPermille,
            ["disk_read_sectors_delta"] = Delta(current.DiskReadSectors, previous?.DiskReadSectors),
            ["disk_written_sectors_delta"] = Delta(current.DiskWrittenSectors, previous?.DiskWrittenSectors),
            ["network_receive_bytes_delta"] = Delta(current.NetworkReceiveBytes, previous?.NetworkReceiveBytes),
            ["network_transmit_bytes_delta"] = Delta(current.NetworkTransmitBytes, previous?.NetworkTransmitBytes),
            ["cpu_pressure_some_avg10_milli"] = current.CpuPressureSomeAvg10Milli,
            ["memory_pressure_some_avg10_milli"] = current.MemoryPressureSomeAvg10Milli,
            ["io_pressure_some_avg10_milli"] = current.IoPressureSomeAvg10Milli,
            ["disk_aggregate_scope"] = "sum_all_visible_diskstats_rows_including_stacked_devices_and_partitions",
            ["network_aggregate_scope"] = "sum_all_visible_netdev_interfaces_including_loopback_and_virtual"
        };
        return BuildEnvelope(
            agentId,
            hostname,
            EventSources.AgentHealth,
            LinuxTelemetrySourceIds.HostBehaviourMetrics,
            "host_metrics_sample",
            sequence,
            now,
            "Linux host behaviour metrics sampled.",
            new NormalizedEventFields
            {
                Category = "host_behavior",
                Action = "sampled",
                Outcome = complete ? "success" : "unknown",
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["evidence_mode"] = "coalesced_procfs_sample",
                    ["metrics.completeness"] = complete ? "complete" : "partial",
                    ["disk.aggregate_scope"] = "all_visible_rows_including_stacked_and_partitions",
                    ["network.aggregate_scope"] = "all_visible_interfaces_including_loopback_and_virtual",
                    ["metrics.interval_seconds"] = options.PassiveTelemetry.HostMetricsIntervalSeconds.ToString(CultureInfo.InvariantCulture)
                }
            },
            raw,
            false,
            [],
            false,
            []);
    }

    private EventEnvelope BuildEnvelope(
        string agentId,
        string hostname,
        string source,
        string sourceId,
        string eventCode,
        long sequence,
        DateTimeOffset now,
        string message,
        NormalizedEventFields normalized,
        SortedDictionary<string, object?> rawValues,
        bool redactionApplied,
        IReadOnlyList<string> redactedFields,
        bool truncationApplied,
        IReadOnlyList<string> truncatedFields)
    {
        var raw = ToJsonElement(rawValues);
        var rawBytes = JsonSerializer.SerializeToUtf8Bytes(raw, JsonDefaults.Options).Length;
        var originalRawBytes = rawBytes;
        if (rawBytes > options.PassiveTelemetry.MaxRawEventBytes)
        {
            rawValues["command_line"] = null;
            rawValues["executable"] = Bound(rawValues.GetValueOrDefault("executable") as string, 512);
            rawValues["raw_budget_truncated"] = true;
            raw = ToJsonElement(rawValues);
            rawBytes = JsonSerializer.SerializeToUtf8Bytes(raw, JsonDefaults.Options).Length;
            truncationApplied = true;
            truncatedFields = truncatedFields.Concat(["raw"]).Distinct(StringComparer.Ordinal).ToArray();
        }
        if (rawBytes > options.PassiveTelemetry.MaxRawEventBytes)
            throw new InvalidOperationException("Passive telemetry raw event exceeded its configured byte budget.");

        var rawHash = DeterministicEventIdentity.ComputeRawSha256(raw);
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = source,
            SourceId = sourceId,
            EventCode = eventCode,
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = now, RecordedAt = now },
            EventTime = now,
            Severity = "information",
            Message = message,
            Normalized = normalized,
            Raw = raw,
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs =
                [
                    DeduplicationInputs.AgentId,
                    DeduplicationInputs.SourceId,
                    DeduplicationInputs.CheckpointSequence,
                    DeduplicationInputs.EventCode,
                    DeduplicationInputs.RawSha256
                ],
                RawSha256 = rawHash
            },
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = rawBytes,
                RedactionApplied = redactionApplied,
                RedactedFields = redactedFields,
                TruncationApplied = truncationApplied,
                TruncatedFields = truncatedFields,
                OriginalSizeBytes = truncationApplied ? Math.Max(originalRawBytes, rawBytes + 1) : null
            }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private static PassiveSourceProgress Advance(
        PassiveSourceProgress previous,
        long nextSequence,
        IReadOnlyCollection<EventEnvelope> events,
        DateTimeOffset now)
    {
        var families = new Dictionary<string, long>(previous.FamilyCounts, StringComparer.Ordinal);
        foreach (var family in events.Select(item => item.EventCode).Where(item => !string.IsNullOrWhiteSpace(item)))
        {
            families[family!] = SaturatingAdd(families.GetValueOrDefault(family!), 1);
        }
        return previous with
        {
            NextSequence = nextSequence,
            CollectedSequence = events.Count == 0
                ? previous.CollectedSequence
                : events.Max(item => item.Checkpoint!.Sequence!.Value),
            LastScanAt = now,
            LastEventAt = events.Count == 0 ? previous.LastEventAt : now,
            FamilyCounts = families
        };
    }

    private static PassiveSourceProgress ObserveFamily(PassiveSourceProgress progress, string family)
    {
        if (progress.FamilyCounts.GetValueOrDefault(family) > 0) return progress;
        var families = new Dictionary<string, long>(progress.FamilyCounts, StringComparer.Ordinal) { [family] = 1 };
        return progress with { FamilyCounts = families };
    }

    private static PassiveCollectionResult Result<T>(
        string sourceId,
        IReadOnlyList<EventEnvelope> events,
        LinuxPassiveTelemetryState state,
        PassiveReadResult<T> read,
        long dropped,
        long sampled,
        long additionalGaps)
    {
        var health = MapHealth(read.Status);
        var error = read.ErrorCode;
        if (dropped > 0)
        {
            health = SourceHealthStatuses.Degraded;
            error = "event_cap_deferred";
        }
        if (additionalGaps > 0 && health == SourceHealthStatuses.Healthy)
        {
            health = SourceHealthStatuses.Degraded;
            error = "partial_baseline_evicted";
        }
        var visibilityGaps = SaturatingAdd(read.VisibilityGapCount, additionalGaps);
        var gaps = visibilityGaps == 0 ? 0 : Math.Max(1, visibilityGaps);
        var details = new Dictionary<string, string>(read.Details ?? new Dictionary<string, string>(), StringComparer.Ordinal)
        {
            ["deferred_events"] = dropped.ToString(CultureInfo.InvariantCulture),
            ["partial_baseline_evictions"] = additionalGaps.ToString(CultureInfo.InvariantCulture)
        };
        if (details.Remove(LinuxBootIdentity.DetailKey)) details["boot_epoch"] = "observed_hashed_locally";
        return new(sourceId, events, state, health, error, gaps,
            read.SkippedCount, 0, dropped, sampled, health != SourceHealthStatuses.Healthy, details);
    }

    private static PassiveCollectionResult NoDataResult<T>(
        string sourceId,
        LinuxPassiveTelemetryState state,
        PassiveReadResult<T> read,
        DateTimeOffset now)
    {
        var updated = sourceId switch
        {
            LinuxTelemetrySourceIds.ProcessSnapshotDiff => state with
            {
                Process = state.Process with { Progress = state.Process.Progress with { LastScanAt = now } }
            },
            LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff => state with
            {
                Network = state.Network with { Progress = state.Network.Progress with { LastScanAt = now } }
            },
            _ => state with
            {
                Metrics = state.Metrics with { Progress = state.Metrics.Progress with { LastScanAt = now } }
            }
        };
        var health = MapHealth(read.Status);
        return new(sourceId, Array.Empty<EventEnvelope>(), updated, health, read.ErrorCode,
            health == SourceHealthStatuses.Healthy ? 0 : Math.Max(1, read.VisibilityGapCount),
            read.SkippedCount, 0, 0, 0, health != SourceHealthStatuses.Healthy,
            read.Details ?? new Dictionary<string, string>(StringComparer.Ordinal));
    }

    private static bool TryGetBootIdentity<T>(PassiveReadResult<T> read, out string bootIdentitySha256)
    {
        bootIdentitySha256 = string.Empty;
        if (read.Details is null
            || !read.Details.TryGetValue(LinuxBootIdentity.DetailKey, out var value)
            || !LinuxBootIdentity.IsHash(value))
        {
            return false;
        }
        bootIdentitySha256 = value;
        return true;
    }

    private static PassiveCollectionResult BootIdentityUnavailableResult<T>(
        string sourceId,
        LinuxPassiveTelemetryState state,
        PassiveReadResult<T> read,
        DateTimeOffset now)
    {
        var details = new Dictionary<string, string>(read.Details ?? new Dictionary<string, string>(), StringComparer.Ordinal)
        {
            ["boot_identity"] = "unavailable_fail_closed"
        };
        var guarded = read with
        {
            Items = Array.Empty<T>(),
            Status = read.Status == PassiveReadStatuses.Success ? PassiveReadStatuses.Error : read.Status,
            ErrorCode = read.ErrorCode == "none" ? "boot_identity_unavailable" : read.ErrorCode,
            VisibilityGapCount = Math.Max(1, read.VisibilityGapCount),
            Details = details
        };
        return NoDataResult(sourceId, state, guarded, now);
    }

    private static string MapHealth(string status) => status switch
    {
        PassiveReadStatuses.Success => SourceHealthStatuses.Healthy,
        PassiveReadStatuses.Partial => SourceHealthStatuses.Degraded,
        PassiveReadStatuses.PermissionDenied => SourceHealthStatuses.PermissionDenied,
        PassiveReadStatuses.Missing => SourceHealthStatuses.Missing,
        _ => SourceHealthStatuses.Error
    };

    private static long? Delta(long? current, long? previous) =>
        current.HasValue && previous.HasValue && current.Value >= previous.Value ? current.Value - previous.Value : null;

    private static long? DeltaRatioPermille(long? total, long? priorTotal, long? idle, long? priorIdle)
    {
        var totalDelta = Delta(total, priorTotal);
        var idleDelta = Delta(idle, priorIdle);
        if (!totalDelta.HasValue || totalDelta <= 0 || !idleDelta.HasValue || idleDelta < 0) return null;
        return Math.Clamp((long)Math.Round((totalDelta.Value - Math.Min(totalDelta.Value, idleDelta.Value)) * 1000d / totalDelta.Value), 0, 1000);
    }

    private static string? Bound(string? value, int max) =>
        value is null ? null : value.Length <= max ? value : value[..max];

    private static int BoundBaseline<T>(Dictionary<string, T> baseline, IEnumerable<string> seenKeys, int maximum)
    {
        if (baseline.Count <= maximum) return 0;
        var seen = seenKeys.ToHashSet(StringComparer.Ordinal);
        var keep = seen
            .Where(baseline.ContainsKey)
            .OrderBy(item => item, StringComparer.Ordinal)
            .Concat(baseline.Keys.Where(key => !seen.Contains(key)).OrderBy(item => item, StringComparer.Ordinal))
            .Take(maximum)
            .ToHashSet(StringComparer.Ordinal);
        var remove = baseline.Keys.Where(key => !keep.Contains(key)).ToArray();
        foreach (var key in remove) baseline.Remove(key);
        return remove.Length;
    }

    private static void EnsureSequenceCapacity(PassiveSourceProgress progress, int eventCount)
    {
        if (eventCount < 0
            || progress.NextSequence < 1
            || progress.NextSequence > LinuxPassiveTelemetryLimits.MaximumSequence - eventCount)
        {
            throw new InvalidOperationException("Passive telemetry sequence space is exhausted or invalid.");
        }
    }

    private static long SaturatingAdd(long left, long right) => left > long.MaxValue - right ? long.MaxValue : left + right;

    private static JsonElement ToJsonElement<T>(T value) =>
        JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(value, JsonDefaults.Options), JsonDefaults.Options);
}
