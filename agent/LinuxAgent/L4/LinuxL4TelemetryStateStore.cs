using System.Runtime.InteropServices;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.LinuxAgent.L4;

public sealed class LinuxL4TelemetryStateStore(string configuredPath, string? allowedRoot = null)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly string path = ValidatePath(configuredPath, allowedRoot);

    public async Task<LinuxL4StateReadResult> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return await ReadUnsafeAsync(cancellationToken); }
        finally { gate.Release(); }
    }

    public async Task WriteAsync(LinuxL4TelemetryState state, CancellationToken cancellationToken)
    {
        if (!IsValid(state)) throw new InvalidOperationException("L4 telemetry state failed structural validation.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, JsonDefaults.Options);
        if (bytes.Length > LinuxL4TelemetryLimits.MaximumStateBytes)
            throw new InvalidOperationException("L4 telemetry state exceeds its safety limit.");

        await gate.WaitAsync(cancellationToken);
        try
        {
            EnsureTargetSafe();
            var directory = Path.GetDirectoryName(path)
                ?? throw new InvalidOperationException("L4 telemetry state requires a parent directory.");
            Directory.CreateDirectory(directory);
            if (new DirectoryInfo(directory).LinkTarget is not null)
                throw new InvalidOperationException("L4 telemetry state directory may not be a symbolic link.");
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
        finally { gate.Release(); }
    }

    public async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var info = new FileInfo(path);
            if (info.LinkTarget is not null || Directory.Exists(path) || info.Exists && !IsSafeRegularFile(info))
                throw new InvalidOperationException("L4 telemetry state path is not a safe regular file.");
            if (!info.Exists) return;
            File.Delete(path);
            if (OperatingSystem.IsLinux() && Path.GetDirectoryName(path) is { } directory) FlushDirectory(directory);
        }
        finally { gate.Release(); }
    }

    private async Task<LinuxL4StateReadResult> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || Directory.Exists(path)) return new(new(), "state_path_not_regular");
        if (!info.Exists) return new(new(), "none");
        if (!IsSafeRegularFile(info)) return new(new(), "state_path_not_regular");
        if (OperatingSystem.IsLinux() && File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            return new(new(), "state_permissions_not_private");
        if (info.Length is < 0 or > LinuxL4TelemetryLimits.MaximumStateBytes) return new(new(), "state_too_large");
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var state = await JsonSerializer.DeserializeAsync<LinuxL4TelemetryState>(stream, JsonDefaults.Options, cancellationToken);
            return state is not null && IsValid(state) ? new(state, "none") : new(new(), "state_invalid");
        }
        catch (JsonException) { return new(new(), "state_malformed"); }
        catch (IOException) { return new(new(), "state_unreadable"); }
        catch (UnauthorizedAccessException) { return new(new(), "state_unreadable"); }
    }

    private void EnsureTargetSafe()
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || Directory.Exists(path) || info.Exists && !IsSafeRegularFile(info))
            throw new InvalidOperationException("L4 telemetry state path is not a safe regular file.");
    }

    private static bool IsSafeRegularFile(FileInfo info) => info.Exists
        && info.LinkTarget is null
        && (info.Attributes & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) == 0;

    private static bool IsValid(LinuxL4TelemetryState state)
    {
        if (state.SchemaVersion != LinuxL4TelemetryLimits.StateSchemaVersion
            || state.Policy is null || state.Slo is null
            || state.Policy.Progress is null || state.Slo.Progress is null
            || state.Policy.BaselineSignatures is null || state.Policy.CurrentSignatures is null || state.Slo.Samples is null
            || state.Policy.BaselineSignatures.Count > LinuxL4TelemetryLimits.MaximumPolicySnapshots
            || state.Policy.CurrentSignatures.Count > LinuxL4TelemetryLimits.MaximumPolicySnapshots
            || state.Slo.Samples.Count > LinuxL4TelemetryLimits.MaximumSloSamples
            || state.Slo.PreviousProcessStartTimeUtcTicks is <= 0
            || !ValidProgress(state.Policy.Progress) || !ValidProgress(state.Slo.Progress)) return false;

        if (state.Policy.ApprovedBaselineHash is not null && !IsSha256(state.Policy.ApprovedBaselineHash)) return false;
        if (state.Policy.BaselineEstablished && state.Policy.BaselineSignatures.Count == 0) return false;
        if (state.Policy.BaselineSignatures.Concat(state.Policy.CurrentSignatures)
            .Any(pair => string.IsNullOrWhiteSpace(pair.Key) || pair.Key.Length > 128 || !IsSha256(pair.Value))) return false;
        return state.Slo.Samples.All(sample => sample is not null
            && sample.ObservedAt != default
            && sample.CpuPercentMilli is null or >= 0 and <= 100_000
            && sample.RssBytes is null or >= 0
            && sample.ManagedMemoryBytes is null or >= 0
            && sample.WriteBytesPerSecond is null or >= 0);
    }

    private static bool ValidProgress(LinuxL4SourceProgress progress) =>
        progress.NextSequence is >= 1 and <= LinuxL4TelemetryLimits.MaximumSequence
        && progress.CollectedSequence >= 0 && progress.CollectedSequence < progress.NextSequence
        && progress.AcknowledgedSequence >= 0 && progress.AcknowledgedSequence <= progress.CollectedSequence
        && progress.AbandonedThroughSequence >= 0 && progress.AbandonedThroughSequence < progress.NextSequence
        && progress.RecoveryGapSequence is null or >= 1
        && (progress.RecoveryGapSequence is null || progress.RecoveryGapSequence < progress.NextSequence)
        && progress.GapCount >= 0 && progress.DroppedCount >= 0
        && (progress.PendingReservationStart is null && progress.PendingReservationEnd is null
            || progress.PendingReservationStart is >= 1
                && progress.PendingReservationEnd >= progress.PendingReservationStart
                && progress.PendingReservationEnd < progress.NextSequence);

    private static bool IsSha256(string value) => value.Length == 71
        && value.StartsWith("sha256:", StringComparison.Ordinal)
        && value.AsSpan(7).ToString().All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string ValidatePath(string configuredPath, string? allowedRoot)
    {
        if (string.IsNullOrWhiteSpace(configuredPath) || !Path.IsPathFullyQualified(configuredPath))
            throw new ArgumentException("L4 telemetry state path must be absolute.", nameof(configuredPath));
        var fullPath = Path.GetFullPath(configuredPath);
        if (!string.IsNullOrWhiteSpace(allowedRoot))
        {
            var root = Path.GetFullPath(allowedRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!fullPath.StartsWith(root, StringComparison.Ordinal))
                throw new ArgumentException("L4 telemetry state path escaped its allowed root.", nameof(configuredPath));
        }
        return fullPath;
    }

    private static void FlushDirectory(string directory)
    {
        const int readOnly = 0;
        const int closeOnExec = 0x80000;
        const int directoryOnly = 0x10000;
        var descriptor = NativeOpen(directory, readOnly | closeOnExec | directoryOnly);
        if (descriptor < 0) throw new IOException("Unable to open L4 telemetry state directory for sync.");
        try { if (NativeFsync(descriptor) != 0) throw new IOException("Unable to sync L4 telemetry state directory."); }
        finally { _ = NativeClose(descriptor); }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int NativeOpen(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int NativeFsync(int descriptor);
    [DllImport("libc", EntryPoint = "close", SetLastError = true)] private static extern int NativeClose(int descriptor);
}
