using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxPassiveTelemetryStateStore(string configuredPath, string? allowedRoot = null)
{
    public const int MaximumStateBytes = 8 * 1024 * 1024;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly string path = ValidatePath(configuredPath, allowedRoot);

    public async Task<PassiveStateReadResult> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var info = new FileInfo(path);
            if (info.LinkTarget is not null || Directory.Exists(path)) return new(new(), "state_path_not_regular");
            if (!info.Exists) return new(new(), "none");
            if (!IsSafeRegularFile(info)) return new(new(), "state_path_not_regular");
            if (!HasPrivatePermissions(path)) return new(new(), "state_permissions_not_private");
            if (info.Length is < 0 or > MaximumStateBytes) return new(new(), "state_too_large");
            try
            {
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
                var state = await JsonSerializer.DeserializeAsync<LinuxPassiveTelemetryState>(stream, JsonDefaults.Options, cancellationToken);
                return state is null
                    ? new(new(), "state_empty")
                    : IsValid(state) ? new(state, "none") : new(new(), "state_invalid");
            }
            catch (JsonException)
            {
                return new(new(), "state_malformed");
            }
            catch (IOException)
            {
                return new(new(), "state_unreadable");
            }
            catch (UnauthorizedAccessException)
            {
                return new(new(), "state_unreadable");
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task WriteAsync(LinuxPassiveTelemetryState state, CancellationToken cancellationToken)
    {
        if (!IsValid(state)) throw new InvalidOperationException("Passive telemetry state failed structural validation.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, JsonDefaults.Options);
        if (bytes.Length > MaximumStateBytes)
            throw new InvalidOperationException("Passive telemetry state exceeds its configured safety limit.");

        await gate.WaitAsync(cancellationToken);
        try
        {
            EnsureTargetSafe();
            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrWhiteSpace(directory)) throw new InvalidOperationException("Passive telemetry state requires a parent directory.");
            Directory.CreateDirectory(directory);
            var directoryInfo = new DirectoryInfo(directory);
            if (directoryInfo.LinkTarget is not null) throw new InvalidOperationException("Passive telemetry state directory may not be a symbolic link.");
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var temporary = $"{path}.tmp.{Guid.NewGuid():N}";
            try
            {
                var streamOptions = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 4096,
                    Options = FileOptions.Asynchronous | FileOptions.WriteThrough
                };
                if (OperatingSystem.IsLinux()) streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                await using (var stream = new FileStream(temporary, streamOptions))
                {
                    await stream.WriteAsync(bytes, cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                    stream.Flush(flushToDisk: true);
                }
                if (OperatingSystem.IsLinux()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                EnsureTargetSafe();
                File.Move(temporary, path, overwrite: true);
                if (OperatingSystem.IsLinux()) FlushDirectory(directory);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var info = new FileInfo(path);
            if (info.LinkTarget is not null || Directory.Exists(path))
                throw new InvalidOperationException("Passive telemetry state path is not a regular file.");
            if (info.Exists)
            {
                if (!IsSafeRegularFile(info)) throw new InvalidOperationException("Passive telemetry state path is not a regular no-follow file.");
                File.Delete(path);
                if (OperatingSystem.IsLinux() && Path.GetDirectoryName(path) is { } directory)
                    FlushDirectory(directory);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private void EnsureTargetSafe()
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || Directory.Exists(path))
            throw new InvalidOperationException("Passive telemetry state path is not a regular file.");
        if (info.Exists && !IsSafeRegularFile(info))
            throw new InvalidOperationException("Passive telemetry state path is not a regular no-follow file.");
    }

    private static bool IsSafeRegularFile(FileInfo info) =>
        info.Exists
            && info.LinkTarget is null
            && (info.Attributes & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) == 0;

    private static bool HasPrivatePermissions(string candidate)
    {
        if (!OperatingSystem.IsLinux()) return true;
        try
        {
            return File.GetUnixFileMode(candidate) == (UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void FlushDirectory(string directory)
    {
        const int readOnly = 0;
        const int closeOnExec = 0x80000;
        const int directoryOnly = 0x10000;
        var descriptor = NativeOpen(directory, readOnly | closeOnExec | directoryOnly);
        if (descriptor < 0)
            throw new IOException("Unable to open passive telemetry state directory for durability sync.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        try
        {
            if (NativeFsync(descriptor) != 0)
                throw new IOException("Unable to durability-sync passive telemetry state directory.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        }
        finally
        {
            _ = NativeClose(descriptor);
        }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int NativeOpen(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int NativeFsync(int descriptor);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int NativeClose(int descriptor);

    private static string ValidatePath(string configuredPath, string? allowedRoot)
    {
        if (string.IsNullOrWhiteSpace(configuredPath) || !Path.IsPathFullyQualified(configuredPath))
            throw new ArgumentException("Passive telemetry state path must be absolute.", nameof(configuredPath));
        var fullPath = Path.GetFullPath(configuredPath);
        if (!string.IsNullOrWhiteSpace(allowedRoot))
        {
            var root = Path.GetFullPath(allowedRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!fullPath.StartsWith(root, StringComparison.Ordinal))
                throw new ArgumentException("Passive telemetry state path escaped its allowed root.", nameof(configuredPath));
        }
        return fullPath;
    }

    private static bool IsValid(LinuxPassiveTelemetryState state)
    {
        if (state.SchemaVersion != LinuxPassiveTelemetryLimits.StateSchemaVersion
            || state.Process is null
            || state.Network is null
            || state.Metrics is null
            || state.Process.Progress is null
            || state.Network.Progress is null
            || state.Metrics.Progress is null
            || state.Process.Baseline is null
            || state.Network.Baseline is null
            || state.Process.Baseline.Count > LinuxPassiveTelemetryLimits.MaximumProcesses
            || state.Network.Baseline.Count > LinuxPassiveTelemetryLimits.MaximumSockets
            || (state.BootIdentitySha256 is not null && !IsSha256(state.BootIdentitySha256))
            || (state.BootIdentitySha256 is null
                && (state.Process.BaselineEstablished
                    || state.Network.BaselineEstablished
                    || state.Process.Baseline.Count > 0
                    || state.Network.Baseline.Count > 0
                    || state.Metrics.Previous is not null))
            || !ValidProgress(state.Process.Progress, ProcessFamilies)
            || !ValidProgress(state.Network.Progress, NetworkFamilies)
            || !ValidProgress(state.Metrics.Progress, MetricsFamilies))
        {
            return false;
        }

        foreach (var item in state.Process.Baseline)
        {
            if (!IsSha256(item.Key)
                || item.Value is null
                || !IsSha256(item.Value.Signature)
                || item.Value.ProcessId <= 0
                || item.Value.ParentProcessId < 0
                || item.Value.MissedPartialScans is < 0 or >= LinuxPassiveTelemetryLimits.PartialBaselineMissLimit)
            {
                return false;
            }
        }

        foreach (var item in state.Network.Baseline)
        {
            var value = item.Value;
            if (!IsSha256(item.Key)
                || value is null
                || !IsSha256(value.Signature)
                || value.Protocol is not ("tcp" or "udp")
                || !NetworkStates.Contains(value.State)
                || !IPAddress.TryParse(value.LocalAddress, out _)
                || value.LocalPort is < 0 or > 65_535
                || value.RemoteAddress is not null && !IPAddress.TryParse(value.RemoteAddress, out _)
                || value.RemotePort is < 0 or > 65_535
                || value.Inode < 0
                || value.UserId is not null && !uint.TryParse(value.UserId, NumberStyles.None, CultureInfo.InvariantCulture, out _)
                || value.Count <= 0
                || value.MissedPartialScans is < 0 or >= LinuxPassiveTelemetryLimits.PartialBaselineMissLimit)
            {
                return false;
            }
        }

        return state.Metrics.Previous is null || ValidMetrics(state.Metrics.Previous);
    }

    private static bool ValidProgress(PassiveSourceProgress progress, IReadOnlySet<string> allowedFamilies)
    {
        if (progress.NextSequence is < 1 or > LinuxPassiveTelemetryLimits.MaximumSequence
            || progress.CollectedSequence < 0
            || progress.CollectedSequence >= progress.NextSequence
            || progress.AcknowledgedSequence < 0
            || progress.AcknowledgedSequence > progress.CollectedSequence
            || progress.AbandonedSequenceCount < 0
            || progress.CumulativeGapCount < 0
            || progress.CumulativeReadSkipCount < 0
            || progress.CumulativeDroppedCount < 0
            || progress.CumulativeSampledCount < 0
            || progress.CumulativePressureScanCount < 0
            || progress.DeferredCount < 0
            || !HealthStatuses.Contains(progress.LastHealthStatus)
            || string.IsNullOrWhiteSpace(progress.LastHealthErrorCode)
            || progress.LastHealthErrorCode.Length > 128
            || progress.LastHealthErrorCode.Any(char.IsControl)
            || progress.LastHealthDetails is null
            || progress.LastHealthDetails.Count > LinuxPassiveTelemetryLimits.MaximumHealthDetailEntries
            || progress.LastHealthDetails.Any(item => string.IsNullOrWhiteSpace(item.Key)
                || item.Key.Length > 64
                || item.Key.Any(char.IsControl)
                || item.Value is null
                || item.Value.Length > 256
                || item.Value.Any(char.IsControl))
            || !HealthTransitions.Contains(progress.HealthTransitionState)
            || progress.LastQueueDepthAtPressure < 0
            || progress.LastQueueBytesAtPressure < 0
            || progress.FamilyCounts is null
            || progress.FamilyCounts.Count > LinuxPassiveTelemetryLimits.MaximumFamilyCountEntries
            || progress.FamilyCounts.Any(item => !allowedFamilies.Contains(item.Key) || item.Value < 0))
        {
            return false;
        }

        if (progress.PendingReservationStart.HasValue != progress.PendingReservationEnd.HasValue) return false;
        if (progress.PendingReservationStart is { } start && progress.PendingReservationEnd is { } end
            && (start <= progress.CollectedSequence || end < start || end >= progress.NextSequence))
        {
            return false;
        }
        return true;
    }

    private static bool ValidMetrics(LinuxHostMetricsObservation value)
    {
        long?[] fields =
        [
            value.UptimeSeconds, value.Load1Milli, value.Load5Milli, value.Load15Milli,
            value.MemoryTotalBytes, value.MemoryAvailableBytes, value.SwapFreeBytes,
            value.ProcessesRunning, value.ProcessesBlocked, value.CpuTotalTicks, value.CpuIdleTicks,
            value.DiskReadSectors, value.DiskWrittenSectors, value.NetworkReceiveBytes,
            value.NetworkTransmitBytes, value.CpuPressureSomeAvg10Milli,
            value.MemoryPressureSomeAvg10Milli, value.IoPressureSomeAvg10Milli
        ];
        return fields.All(item => !item.HasValue || item.Value >= 0);
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    private static readonly IReadOnlySet<string> ProcessFamilies = new HashSet<string>(StringComparer.Ordinal)
    {
        "process_baseline", "process_baseline_disappeared", "process_observed", "process_changed", "process_disappeared"
    };

    private static readonly IReadOnlySet<string> NetworkFamilies = new HashSet<string>(StringComparer.Ordinal)
    {
        "socket_baseline", "socket_baseline_disappeared", "socket_observed", "socket_changed", "socket_disappeared"
    };

    private static readonly IReadOnlySet<string> MetricsFamilies = new HashSet<string>(StringComparer.Ordinal)
    {
        "host_metrics_sample"
    };

    private static readonly IReadOnlySet<string> NetworkStates = new HashSet<string>(StringComparer.Ordinal)
    {
        "established", "syn_sent", "syn_received", "fin_wait_1", "fin_wait_2", "time_wait",
        "closed", "close_wait", "last_ack", "listen", "closing", "new_syn_received",
        "unconnected", "unknown"
    };

    private static readonly IReadOnlySet<string> HealthStatuses = new HashSet<string>(StringComparer.Ordinal)
    {
        SourceHealthStatuses.Healthy,
        SourceHealthStatuses.Degraded,
        SourceHealthStatuses.Error,
        SourceHealthStatuses.PermissionDenied,
        SourceHealthStatuses.Missing
    };

    private static readonly IReadOnlySet<string> HealthTransitions = new HashSet<string>(StringComparer.Ordinal)
    {
        HealthTransitionStates.Unknown,
        HealthTransitionStates.Healthy,
        HealthTransitionStates.Degraded
    };
}
