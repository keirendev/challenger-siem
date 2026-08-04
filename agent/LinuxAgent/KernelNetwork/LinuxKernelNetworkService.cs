using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public sealed class LinuxKernelNetworkService(
    IOptions<LinuxAgentOptions> configured,
    IEventQueue queue,
    LinuxKernelNetworkRuntime runtime,
    ILinuxKernelProcessEnricher processEnricher,
    TimeProvider timeProvider,
    ILogger<LinuxKernelNetworkService> logger) : BackgroundService
{
    private static readonly HashSet<string> AllowedFrameProperties = new(StringComparer.Ordinal)
    {
        "schema_version", "helper_version", "epoch", "sequence", "type", "event_code", "payload_capture",
        "flow_capacity", "owner_capacity", "ring_bytes", "drain_seconds", "max_records_per_drain",
        "family", "protocol", "direction", "local_ip", "local_port", "remote_ip", "remote_port",
        "process_id", "user_id", "process_name", "attribution_source", "first_seen_unix_ns", "last_seen_unix_ns",
        "packet_count_delta", "byte_count_delta", "tcp_flags_mask", "parse_failures",
        "unsupported_headers", "flow_map_full", "owner_misses", "ring_losses", "ipc_send_failures"
    };
    private static readonly HashSet<string> HelloFrameProperties = new(StringComparer.Ordinal)
    {
        "schema_version", "helper_version", "epoch", "sequence", "type", "payload_capture",
        "flow_capacity", "owner_capacity", "ring_bytes", "drain_seconds", "max_records_per_drain"
    };
    private static readonly HashSet<string> HealthFrameProperties = new(StringComparer.Ordinal)
    {
        "schema_version", "helper_version", "epoch", "sequence", "type", "payload_capture",
        "parse_failures", "unsupported_headers", "flow_map_full", "owner_misses", "ring_losses", "ipc_send_failures"
    };
    private static readonly HashSet<string> FlowFrameProperties = new(StringComparer.Ordinal)
    {
        "schema_version", "helper_version", "epoch", "sequence", "type", "event_code", "family", "protocol", "direction",
        "local_ip", "local_port", "remote_ip", "remote_port", "process_id", "user_id", "process_name", "attribution_source",
        "first_seen_unix_ns", "last_seen_unix_ns", "packet_count_delta", "byte_count_delta", "tcp_flags_mask",
        "parse_failures", "unsupported_headers", "flow_map_full", "owner_misses", "ring_losses", "ipc_send_failures"
    };
    private readonly LinuxAgentOptions options = configured.Value;

    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        await runtime.InitializeAsync(cancellationToken);
        var plan = runtime.Plan;
        if (!options.KernelNetworkTelemetry.Enabled || !plan.ApprovalHashMatches) return;
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            await runtime.ObserveErrorAsync("kernel_network_architecture_unsupported", cancellationToken);
            return;
        }
        if (options.KernelNetworkTelemetry.StartupDelaySeconds > 0)
            await Task.Delay(TimeSpan.FromSeconds(options.KernelNetworkTelemetry.StartupDelaySeconds), cancellationToken);

        var retrySeconds = 1;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var socket = new Socket(AddressFamily.Unix, SocketType.Seqpacket, ProtocolType.Unspecified);
                socket.ReceiveBufferSize = LinuxKernelNetworkConstants.MaximumFrameBytes * 4;
                ValidateSocketPath(options.KernelNetworkTelemetry.SocketPath);
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(options.KernelNetworkTelemetry.SocketPath), cancellationToken);
                ValidatePeer(socket);
                var hello = await ReceiveFrameAsync(socket, cancellationToken);
                ValidateHello(hello);
                await runtime.ObserveHelloAsync(hello, cancellationToken);
                retrySeconds = 1;
                await ReceiveFlowsAsync(socket, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is SocketException or IOException or JsonException or InvalidDataException or UnauthorizedAccessException)
            {
                var error = ex switch
                {
                    UnauthorizedAccessException => "helper_peer_identity_rejected",
                    InvalidDataException invalid => ProtocolErrorCode(invalid),
                    JsonException => "helper_json_rejected",
                    _ => "helper_ipc_unavailable"
                };
                await runtime.ObserveConnectionFailureAsync(error, cancellationToken);
                logger.LogWarning("Kernel network source connection failed ({ErrorType}); no privileged fallback or payload collection was attempted.", ex.GetType().Name);
                await Task.Delay(TimeSpan.FromSeconds(retrySeconds), cancellationToken);
                retrySeconds = Math.Min(30, retrySeconds * 2);
            }
        }
    }

    private async Task ReceiveFlowsAsync(Socket socket, CancellationToken cancellationToken)
    {
        var queuePaused = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            if (await queue.CountAsync(cancellationToken) >= options.KernelNetworkTelemetry.QueuePauseDepth - LinuxKernelNetworkConstants.MaximumRecordsPerDrain)
            {
                if (!queuePaused)
                {
                    await runtime.ObserveQueuePressureAsync(true, cancellationToken);
                    queuePaused = true;
                }
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                continue;
            }
            if (queuePaused)
            {
                await runtime.ObserveQueuePressureAsync(false, cancellationToken);
                queuePaused = false;
            }
            var drain = await ReceiveDrainAsync(socket, cancellationToken);
            await PersistDrainAsync(drain, cancellationToken);
        }
    }

    internal async Task<LinuxKernelNetworkDrain> ReceiveDrainAsync(Socket socket, CancellationToken cancellationToken)
    {
        var startedAt = timeProvider.GetTimestamp();
        var flows = new List<LinuxKernelNetworkReceivedFlow>(LinuxKernelNetworkConstants.MaximumRecordsPerDrain);
        while (!cancellationToken.IsCancellationRequested)
        {
            var frame = await ReceiveFrameAsync(socket, cancellationToken);
            if (frame.Type == "health")
            {
                ValidateHealth(frame);
                return new(flows, frame, ElapsedMilliseconds(startedAt));
            }
            ValidateFlow(frame);
            if (flows.Count >= LinuxKernelNetworkConstants.MaximumRecordsPerDrain)
                throw new InvalidDataException("helper_flow_batch_rejected");
            var firstSeen = FromUnixNanoseconds(frame.FirstSeenUnixNanoseconds);
            var lastSeen = FromUnixNanoseconds(frame.LastSeenUnixNanoseconds);
            var now = timeProvider.GetUtcNow();
            if (firstSeen > lastSeen || lastSeen > now.AddMinutes(5) || firstSeen < now.AddDays(-8))
                throw new InvalidDataException("Helper timestamps are outside the bounded acceptance window.");
            flows.Add(new(frame, firstSeen, lastSeen));
        }
        throw new OperationCanceledException(cancellationToken);
    }

    internal async Task PersistDrainAsync(LinuxKernelNetworkDrain drain, CancellationToken cancellationToken)
    {
        var persistStartedAt = timeProvider.GetTimestamp();
        if (drain.Flows.Count == 0)
        {
            await runtime.ObserveHealthAsync(
                drain.Health,
                new(0, 0, 0, 0, drain.ReceiveDurationMilliseconds, ElapsedMilliseconds(persistStartedAt)),
                cancellationToken);
            return;
        }

        var processCache = new Dictionary<ProcessIdentity, LinuxKernelProcessMetadata>();
        var processes = new LinuxKernelProcessMetadata[drain.Flows.Count];
        for (var index = 0; index < drain.Flows.Count; index++)
        {
            var frame = drain.Flows[index].Frame;
            var identity = new ProcessIdentity(frame.ProcessId, frame.UserId, frame.ProcessName!, frame.AttributionSource!);
            if (!processCache.TryGetValue(identity, out var process))
            {
                process = await processEnricher.EnrichAsync(frame, cancellationToken);
                processCache.Add(identity, process);
            }
            processes[index] = process;
        }

        var collected = drain.Flows
            .Select(item => new LinuxKernelNetworkPendingFrame(item.Frame, item.LastSeen))
            .ToArray();
        await runtime.CollectDrainAsync(
            collected,
            drain.Health,
            async (assignments, finalizeChunk) =>
            {
                var envelopes = assignments.Select((assignment, index) =>
                {
                    var item = drain.Flows[index];
                    return BuildEvent(
                        item.Frame,
                        processes[index],
                        item.FirstSeen,
                        item.LastSeen,
                        assignment.AgentSequence,
                        assignment.HelperGap);
                }).ToArray();
                var serializedBytes = envelopes.Sum(envelope =>
                    (long)Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(envelope, JsonDefaults.Options)));
                var completed = 0;
                foreach (var batch in EventQueueBatcher.Partition(envelopes))
                {
                    await queue.EnqueueBatchAsync(batch, cancellationToken);
                    completed += batch.Count;
                    var diagnostics = completed == envelopes.Length
                        ? new LinuxKernelNetworkDrainDiagnostics(
                            envelopes.Length,
                            serializedBytes,
                            processCache.Count,
                            envelopes.Length - processCache.Count,
                            drain.ReceiveDurationMilliseconds,
                            ElapsedMilliseconds(persistStartedAt))
                        : null;
                    await finalizeChunk(completed, diagnostics);
                }
            },
            cancellationToken);
    }

    private static async Task<LinuxKernelNetworkFrame> ReceiveFrameAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[LinuxKernelNetworkConstants.MaximumFrameBytes + 1];
        var received = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
        if (received <= 0) throw new IOException("The helper closed its sequence-packet channel.");
        if (received > LinuxKernelNetworkConstants.MaximumFrameBytes) throw new InvalidDataException("The helper frame exceeded its fixed bound.");
        return ParseFrame(buffer.AsMemory(0, received));
    }

    internal static LinuxKernelNetworkFrame ParseFrame(ReadOnlyMemory<byte> content)
    {
        if (content.Length is <= 0 or > LinuxKernelNetworkConstants.MaximumFrameBytes)
            throw new InvalidDataException("The helper frame length is outside the fixed bound.");
        using var document = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 4, CommentHandling = JsonCommentHandling.Disallow });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("The helper frame is not an object.");
        var observed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!AllowedFrameProperties.Contains(property.Name) || !observed.Add(property.Name))
                throw new InvalidDataException("The helper frame contains an unknown or duplicate property.");
        }
        var frame = document.RootElement.Deserialize<LinuxKernelNetworkFrame>(JsonDefaults.Options)
            ?? throw new InvalidDataException("The helper frame could not be deserialized.");
        return frame with { PresentProperties = observed };
    }

    internal static LinuxKernelNetworkFrame ParseFrame(string content) =>
        ParseFrame(Encoding.UTF8.GetBytes(content));

    internal static void ValidateHello(LinuxKernelNetworkFrame frame)
    {
        ValidateCommon(frame);
        if (!frame.PresentProperties.SetEquals(HelloFrameProperties)
            || frame.Type != "hello" || frame.PayloadCapture
            || frame.FlowCapacity != LinuxKernelNetworkConstants.FlowMapEntries
            || frame.OwnerCapacity != LinuxKernelNetworkConstants.OwnerMapEntries
            || frame.RingBytes != LinuxKernelNetworkConstants.RingBytes
            || frame.DrainSeconds != 10
            || frame.MaxRecordsPerDrain != LinuxKernelNetworkConstants.MaximumRecordsPerDrain)
            throw new InvalidDataException("The helper hello frame does not match the fixed plan.");
    }

    internal static void ValidateHealth(LinuxKernelNetworkFrame frame)
    {
        ValidateCommon(frame);
        if (!frame.PresentProperties.SetEquals(HealthFrameProperties)
            || frame.Type != "health" || frame.PayloadCapture)
            throw new InvalidDataException("The helper health frame does not match the fixed protocol.");
    }

    internal static void ValidateFlow(LinuxKernelNetworkFrame frame)
    {
        ValidateCommon(frame);
        if (!frame.PresentProperties.SetEquals(FlowFrameProperties) || frame.Type != "flow")
            throw new InvalidDataException("helper_flow_shape_rejected");
        if (frame.Family is not (4 or 6) || frame.Protocol is not ("tcp" or "udp")
            || frame.Direction is not ("inbound" or "outbound" or "unknown")
            || frame.EventCode is not ("network_flow_started" or "network_flow_sample" or "network_flow_closed"))
            throw new InvalidDataException("helper_flow_identity_rejected");
        if (frame.AttributionSource is not ("current_task" or "recent_socket_owner" or "unattributed")
            || frame.AttributionSource != "unattributed" && frame.ProcessId == 0)
            throw new InvalidDataException("helper_flow_attribution_rejected");
        if (frame.ProcessName is null || frame.ProcessName.Length > 16 || frame.ProcessName.Any(char.IsControl))
            throw new InvalidDataException("helper_flow_process_name_rejected");
        if (frame.LocalPort is < 1 or > 65_535 || frame.RemotePort is < 1 or > 65_535)
            throw new InvalidDataException("helper_flow_port_rejected");
        if (!IPAddress.TryParse(frame.LocalIp, out var local) || !IPAddress.TryParse(frame.RemoteIp, out var remote)
            || frame.Family == 4 && (local.AddressFamily != AddressFamily.InterNetwork || remote.AddressFamily != AddressFamily.InterNetwork)
            || frame.Family == 6 && (local.AddressFamily != AddressFamily.InterNetworkV6 || remote.AddressFamily != AddressFamily.InterNetworkV6))
            throw new InvalidDataException("helper_flow_address_rejected");
        if (frame.FirstSeenUnixNanoseconds == 0 || frame.LastSeenUnixNanoseconds == 0)
            throw new InvalidDataException("helper_flow_timestamp_rejected");
        if (frame.EventCode != "network_flow_closed" && frame.PacketCountDelta == 0
            || frame.TcpFlagsMask > byte.MaxValue)
            throw new InvalidDataException("helper_flow_counter_rejected");
    }

    private static void ValidateCommon(LinuxKernelNetworkFrame frame)
    {
        if (frame.SchemaVersion != 1
            || frame.HelperVersion != LinuxKernelNetworkConstants.HelperVersion
            || frame.Sequence == 0
            || frame.Epoch.Length != 32
            || frame.Epoch.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidDataException("The helper protocol identity is invalid.");
    }

    private static string ProtocolErrorCode(InvalidDataException exception) => exception.Message switch
    {
        "helper_flow_shape_rejected" or "helper_flow_identity_rejected" or "helper_flow_attribution_rejected"
            or "helper_flow_process_name_rejected" or "helper_flow_port_rejected" or "helper_flow_address_rejected"
            or "helper_flow_timestamp_rejected" or "helper_flow_counter_rejected" or "helper_flow_batch_rejected" => exception.Message,
        "Helper timestamps are outside the bounded acceptance window." => "helper_flow_time_window_rejected",
        "The helper hello frame does not match the fixed plan." => "helper_hello_rejected",
        "The helper health frame does not match the fixed protocol." => "helper_health_rejected",
        "The helper protocol identity is invalid." => "helper_protocol_identity_rejected",
        "The helper frame contains an unknown or duplicate property." => "helper_frame_property_rejected",
        "The helper frame exceeded its fixed bound." or "The helper frame length is outside the fixed bound." => "helper_frame_size_rejected",
        _ => "helper_protocol_rejected"
    };

    private static void ValidatePeer(Socket socket)
    {
        var expectedUid = ReadAccountUid("challenger-siem-ebpf");
        var length = (uint)Marshal.SizeOf<LinuxPeerCredentials>();
        if (getsockopt(socket.SafeHandle.DangerousGetHandle(), 1, 17, out var credentials, ref length) != 0
            || length != Marshal.SizeOf<LinuxPeerCredentials>())
            throw new UnauthorizedAccessException("SO_PEERCRED was unavailable.");
        var dedicatedHelper = credentials.ProcessId > 0 && credentials.UserId == expectedUid;
        var socketActivatedSystemd = credentials.ProcessId == 1
            && credentials.UserId == 0
            && credentials.GroupId == 0
            && Directory.Exists("/run/systemd/system")
            && string.Equals(File.ReadAllText("/proc/1/comm").Trim(), "systemd", StringComparison.Ordinal);
        if (!dedicatedHelper && !socketActivatedSystemd)
            throw new UnauthorizedAccessException("The helper peer identity did not match.");
    }

    private static void ValidateSocketPath(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Kernel network IPC is Linux-only.");
        var directoryPath = Path.GetDirectoryName(path) ?? throw new UnauthorizedAccessException("The helper socket directory is unavailable.");
        var directory = new DirectoryInfo(directoryPath);
        var socket = new FileInfo(path);
        if (!directory.Exists || directory.LinkTarget is not null || socket.LinkTarget is not null)
            throw new UnauthorizedAccessException("The helper socket path is missing or linked.");
        if (File.GetUnixFileMode(directoryPath) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute)
            || File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite))
            throw new UnauthorizedAccessException("The helper socket path permissions do not match the fixed profile.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct LinuxPeerCredentials
    {
        public readonly int ProcessId;
        public readonly uint UserId;
        public readonly uint GroupId;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(
        IntPtr socket,
        int level,
        int option,
        out LinuxPeerCredentials value,
        ref uint length);

    private static uint ReadAccountUid(string account)
    {
        var info = new FileInfo("/etc/passwd");
        if (!info.Exists || info.Length is <= 0 or > 256 * 1024) throw new UnauthorizedAccessException("The local account database is unavailable.");
        foreach (var line in File.ReadLines(info.FullName))
        {
            var fields = line.Split(':');
            if (fields.Length >= 7 && fields[0] == account && uint.TryParse(fields[2], out var uid) && uid > 0) return uid;
        }
        throw new UnauthorizedAccessException("The expected helper account is unavailable.");
    }

    internal static LinuxKernelProcessMetadata SanitizeProcessMetadata(
        LinuxKernelNetworkFrame frame,
        string? executable,
        string? commandLine,
        string? userId,
        bool truncated,
        int maximumExecutableCharacters,
        int maximumCommandLineCharacters)
    {
        var executableText = TelemetryTextSanitizer.SanitizeAndRedact(executable, maximumExecutableCharacters);
        var commandText = TelemetryTextSanitizer.SanitizeAndRedact(commandLine, maximumCommandLineCharacters);
        var processNameText = TelemetryTextSanitizer.SanitizeAndRedact(frame.ProcessName, 16);
        executable = executableText.Dropped ? null : NullIfEmpty(executableText.Value);
        commandLine = commandText.Dropped ? null : NullIfEmpty(commandText.Value);
        var processName = processNameText.Dropped ? null : NullIfEmpty(processNameText.Value);
        var procfsEnriched = executable is not null || commandLine is not null;
        executable ??= processName;
        var redacted = executableText.Redacted || commandText.Redacted || processNameText.Redacted;
        truncated |= executableText.Truncated || commandText.Truncated || processNameText.Truncated;
        var basis = frame.AttributionSource == "current_task" ? "kernel_current_task"
            : frame.AttributionSource == "recent_socket_owner" ? "kernel_recent_socket_owner"
            : "unattributed";
        var confidence = procfsEnriched ? basis + "_procfs_enriched"
            : processName is not null ? basis + "_kernel_comm"
            : basis + "_pid_only";
        return new(executable, commandLine, userId, redacted, truncated, confidence);
    }

    private EventEnvelope BuildEvent(
        LinuxKernelNetworkFrame frame,
        LinuxKernelProcessMetadata process,
        DateTimeOffset firstSeen,
        DateTimeOffset lastSeen,
        long sequence,
        bool helperGap)
    {
        var flags = TcpFlags(frame.TcpFlagsMask);
        var eventCode = frame.EventCode!;
        var action = eventCode switch
        {
            "network_flow_started" => "flow_started",
            "network_flow_closed" => "flow_closed",
            _ => "flow_sample"
        };
        var rawValues = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = "linux-network-flow-summary-v1",
            ["evidence_mode"] = "kernel_flow",
            ["payload_capture"] = false,
            ["event_code"] = eventCode,
            ["direction"] = frame.Direction,
            ["protocol"] = frame.Protocol,
            ["family"] = frame.Family,
            ["local_ip"] = frame.LocalIp,
            ["local_port"] = frame.LocalPort,
            ["remote_ip"] = frame.RemoteIp,
            ["remote_port"] = frame.RemotePort,
            ["process_id"] = frame.ProcessId == 0 ? null : frame.ProcessId,
            ["process_name"] = frame.ProcessName,
            ["process_image"] = process.Executable,
            ["process_command_line"] = process.CommandLine,
            ["user_id"] = process.UserId,
            ["attribution_source"] = frame.AttributionSource,
            ["attribution_confidence"] = process.Confidence,
            ["first_seen_utc"] = firstSeen,
            ["last_seen_utc"] = lastSeen,
            ["packet_count_delta"] = Clamp(frame.PacketCountDelta),
            ["byte_count_delta"] = Clamp(frame.ByteCountDelta),
            ["tcp_flags"] = flags,
            ["helper_epoch"] = frame.Epoch,
            ["helper_sequence"] = frame.Sequence,
            ["helper_sequence_gap"] = helperGap,
            ["parse_failures"] = Clamp(frame.ParseFailures),
            ["unsupported_headers"] = Clamp(frame.UnsupportedHeaders),
            ["flow_map_full"] = Clamp(frame.FlowMapFull),
            ["owner_misses"] = Clamp(frame.OwnerMisses),
            ["ring_losses"] = Clamp(frame.RingLosses),
            ["ipc_send_failures"] = Clamp(frame.IpcSendFailures)
        };
        var raw = JsonSerializer.SerializeToElement(rawValues, JsonDefaults.Options);
        var rawBytes = JsonSerializer.SerializeToUtf8Bytes(raw, JsonDefaults.Options).Length;
        var envelope = new EventEnvelope
        {
            AgentId = options.AgentId,
            Hostname = Environment.MachineName,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.InventoryDiff,
            SourceId = LinuxTelemetrySourceIds.NetworkFlowSummary,
            EventCode = eventCode,
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = lastSeen, RecordedAt = timeProvider.GetUtcNow() },
            EventTime = lastSeen,
            Severity = "information",
            Message = eventCode switch
            {
                "network_flow_started" => "Linux kernel network flow started.",
                "network_flow_closed" => "Linux kernel network flow closed or became inactive.",
                _ => "Linux kernel network flow active interval observed."
            },
            Normalized = new NormalizedEventFields
            {
                Category = "network",
                Action = action,
                Outcome = "unknown",
                SourceIp = frame.LocalIp,
                SourcePort = frame.LocalPort.ToString(),
                DestinationIp = frame.RemoteIp,
                DestinationPort = frame.RemotePort.ToString(),
                Protocol = frame.Protocol,
                ProcessId = frame.ProcessId == 0 ? null : frame.ProcessId.ToString(),
                ProcessImage = process.Executable,
                ProcessCommandLine = process.CommandLine,
                Process = frame.ProcessId == 0 ? null : new ProcessTelemetryConcept
                {
                    Pid = frame.ProcessId.ToString(),
                    Executable = process.Executable,
                    CommandLine = process.CommandLine
                },
                User = process.UserId is null ? null : new UserTelemetryConcept { Id = process.UserId },
                Network = new NetworkTelemetryConcept
                {
                    SourceIp = frame.LocalIp,
                    SourcePort = frame.LocalPort,
                    DestinationIp = frame.RemoteIp,
                    DestinationPort = frame.RemotePort,
                    Protocol = frame.Protocol,
                    LocalIp = frame.LocalIp,
                    LocalPort = frame.LocalPort,
                    RemoteIp = frame.RemoteIp,
                    RemotePort = frame.RemotePort,
                    Direction = frame.Direction,
                    PacketCountDelta = Clamp(frame.PacketCountDelta),
                    ByteCountDelta = Clamp(frame.ByteCountDelta),
                    IntervalStartedAt = firstSeen,
                    IntervalEndedAt = lastSeen,
                    TcpFlags = flags,
                    EvidenceMode = "kernel_flow",
                    AttributionConfidence = process.Confidence
                },
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["evidence_mode"] = "kernel_flow",
                    ["payload_capture"] = "false",
                    ["network.direction"] = frame.Direction!,
                    ["network.attribution_confidence"] = process.Confidence,
                    ["telemetry.sensitivity"] = "high"
                }
            },
            Raw = raw,
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = rawBytes,
                OriginalSizeBytes = process.Truncated ? rawBytes + 1 : null,
                RedactionApplied = process.Redacted,
                RedactedFields = process.Redacted ? ["process_command_line"] : [],
                TruncationApplied = process.Truncated,
                TruncatedFields = process.Truncated ? ["process_command_line"] : []
            }
        };
        var rawHash = DeterministicEventIdentity.ComputeRawSha256(raw);
        envelope = envelope with
        {
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode, DeduplicationInputs.RawSha256],
                RawSha256 = rawHash
            }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private static DateTimeOffset FromUnixNanoseconds(ulong value)
    {
        var seconds = checked((long)(value / 1_000_000_000UL));
        var ticks = checked((long)(value % 1_000_000_000UL) / 100);
        return DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(ticks);
    }

    private static IReadOnlyList<string> TcpFlags(uint mask)
    {
        var flags = new List<string>(8);
        if ((mask & 0x01) != 0) flags.Add("fin");
        if ((mask & 0x02) != 0) flags.Add("syn");
        if ((mask & 0x04) != 0) flags.Add("rst");
        if ((mask & 0x08) != 0) flags.Add("psh");
        if ((mask & 0x10) != 0) flags.Add("ack");
        if ((mask & 0x20) != 0) flags.Add("urg");
        if ((mask & 0x40) != 0) flags.Add("ece");
        if ((mask & 0x80) != 0) flags.Add("cwr");
        return flags;
    }

    private static long Clamp(ulong value) => value > long.MaxValue ? long.MaxValue : (long)value;
    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
    private long ElapsedMilliseconds(long startedAt) =>
        Math.Max(0, (long)Math.Ceiling(timeProvider.GetElapsedTime(startedAt).TotalMilliseconds));

    private sealed record ProcessIdentity(
        uint ProcessId,
        uint UserId,
        string KernelCommand,
        string AttributionBasis);
}
