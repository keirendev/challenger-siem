using System.Runtime.InteropServices;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V2;

namespace Challenger.Siem.LinuxAgent.Package;

public sealed class LinuxPackageInventoryDiffStateStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly string path;

    public LinuxPackageInventoryDiffStateStore(string path = LinuxPackageInventoryDiffConstants.StatePath, string? allowedRoot = "/var/lib/challenger-siem-agent")
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("Package inventory state path must be absolute.", nameof(path));
        this.path = Path.GetFullPath(path);
        if (allowedRoot is not null)
        {
            var root = Path.GetFullPath(allowedRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!this.path.StartsWith(root, StringComparison.Ordinal))
                throw new ArgumentException("Package inventory state path escaped its allowed root.", nameof(path));
        }
    }

    public async Task<LinuxPackageStateReadResult> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return await ReadUnsafeAsync(cancellationToken); }
        finally { gate.Release(); }
    }

    public async Task WriteAsync(LinuxPackageInventoryDiffState state, CancellationToken cancellationToken)
    {
        if (!IsValid(state)) throw new InvalidOperationException("Package inventory state failed structural validation.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, JsonDefaults.Options);
        if (bytes.Length > LinuxPackageInventoryDiffConstants.MaximumStateBytes)
            throw new InvalidOperationException("Package inventory state exceeds its safety limit.");

        await gate.WaitAsync(cancellationToken);
        try
        {
            EnsureTargetSafe();
            var directory = Path.GetDirectoryName(path)
                ?? throw new InvalidOperationException("Package inventory state requires a parent directory.");
            Directory.CreateDirectory(directory);
            if (new DirectoryInfo(directory).LinkTarget is not null)
                throw new InvalidOperationException("Package inventory state directory may not be a symbolic link.");
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var temporary = $"{path}.tmp.{Guid.NewGuid():N}";
            try
            {
                var options = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 4096,
                    Options = FileOptions.Asynchronous | FileOptions.WriteThrough
                };
                if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                await using (var stream = new FileStream(temporary, options))
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

    private async Task<LinuxPackageStateReadResult> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || Directory.Exists(path)) return new(new(), "state_path_not_regular");
        if (!info.Exists) return new(new(), "none");
        if (!IsSafeRegularFile(info)) return new(new(), "state_path_not_regular");
        if (OperatingSystem.IsLinux() && File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
            return new(new(), "state_permissions_not_private");
        if (info.Length is < 0 or > LinuxPackageInventoryDiffConstants.MaximumStateBytes) return new(new(), "state_too_large");
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var state = await JsonSerializer.DeserializeAsync<LinuxPackageInventoryDiffState>(stream, JsonDefaults.Options, cancellationToken);
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
            throw new InvalidOperationException("Package inventory state path is not a safe regular file.");
    }

    private static bool IsSafeRegularFile(FileInfo info) => info.Exists
        && info.LinkTarget is null
        && (info.Attributes & (FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) == 0;

    private static bool IsValid(LinuxPackageInventoryDiffState state) =>
        state.SchemaVersion == LinuxPackageInventoryDiffConstants.StateSchemaVersion
        && state.NextSequence is >= 1 and <= LinuxPackageInventoryDiffConstants.MaximumSequence
        && state.CollectedSequence >= 0 && state.CollectedSequence < state.NextSequence
        && state.AcknowledgedSequence >= 0 && state.AcknowledgedSequence <= state.CollectedSequence
        && state.AbandonedThroughSequence >= 0 && state.AbandonedThroughSequence < state.NextSequence
        && (state.PendingReservationStart is null && state.PendingReservationEnd is null
            || state.PendingReservationStart is >= 1
                && state.PendingReservationEnd >= state.PendingReservationStart
                && state.PendingReservationEnd < state.NextSequence)
        && state.GapCount >= 0 && state.DroppedCount >= 0
        && state.Baseline.Count <= AssetInventoryPaging.MaxItemsPerSource
        && state.Baseline.All(pair => pair.Key.Length is >= 1 and <= 512
            && pair.Value is not null
            && pair.Value.Name.Length is >= 1 and <= 512
            && pair.Value.Version.Length is >= 1 and <= 512)
        && state.FamilyCounts.Count <= 8
        && state.FamilyCounts.All(pair => pair.Key.Length is >= 1 and <= 64 && pair.Value >= 0);

    private static void FlushDirectory(string directory)
    {
        const int readOnly = 0;
        const int closeOnExec = 0x80000;
        const int directoryOnly = 0x10000;
        var descriptor = NativeOpen(directory, readOnly | closeOnExec | directoryOnly);
        if (descriptor < 0) throw new IOException("Unable to open package inventory state directory for sync.");
        try { if (NativeFsync(descriptor) != 0) throw new IOException("Unable to sync package inventory state directory."); }
        finally { _ = NativeClose(descriptor); }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)] private static extern int NativeOpen(string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)] private static extern int NativeFsync(int descriptor);
    [DllImport("libc", EntryPoint = "close", SetLastError = true)] private static extern int NativeClose(int descriptor);
}
