using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Challenger.Siem.LinuxAgent.SelfIntegrity;

public interface ILinuxSelfIntegritySource
{
    Task<SelfIntegrityObservation> ObserveAsync(SelfIntegrityAllowlistEntry entry, CancellationToken cancellationToken);
}

public sealed class LinuxSelfIntegritySource(string root = "/") : ILinuxSelfIntegritySource
{
    public Task<SelfIntegrityObservation> ObserveAsync(SelfIntegrityAllowlistEntry entry, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = Resolve(entry.AbsolutePath);
        try
        {
            var metadata = NativeMethods.LStat(path);
            if (metadata is null)
            {
                var error = Marshal.GetLastPInvokeError();
                return Task.FromResult(error == NativeMethods.AccessDenied
                    ? Denied(entry, "permission_denied")
                    : Missing(entry));
            }

            if (metadata.Value.SymbolicLink)
            {
                return Task.FromResult(Unreadable(entry, "symlink_rejected", "symlink", metadata.Value));
            }

            if (entry.Kind == SelfIntegrityEntryKind.Directory)
            {
                return Task.FromResult(metadata.Value.Directory
                    ? Success(entry, "directory", metadata.Value, null)
                    : Unreadable(entry, "path_type_not_directory", metadata.Value.TypeName, metadata.Value));
            }

            if (!metadata.Value.Regular || metadata.Value.LinkCount != 1)
            {
                return Task.FromResult(Unreadable(entry, metadata.Value.Regular ? "hardlink_rejected" : "path_type_not_regular", metadata.Value.TypeName, metadata.Value));
            }
            if (entry.MaxBytes > 0 && metadata.Value.Size > entry.MaxBytes)
            {
                return Task.FromResult(Unreadable(entry, "file_too_large", "regular_file", metadata.Value));
            }
            if (!entry.HashContent)
            {
                return Task.FromResult(Success(entry, "regular_file", metadata.Value, null));
            }

            return HashAsync(entry, path, metadata.Value, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            return Task.FromResult(Denied(entry, "permission_denied"));
        }
        catch (IOException)
        {
            return Task.FromResult(Unreadable(entry, "io_error", "unknown", null));
        }
    }

    private async Task<SelfIntegrityObservation> HashAsync(SelfIntegrityAllowlistEntry entry, string path, FileMetadata before, CancellationToken cancellationToken)
    {
        var descriptor = NativeMethods.Open(path, NativeMethods.ReadOnly | NativeMethods.CloseOnExec | NativeMethods.NoFollow);
        if (descriptor < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return error switch
            {
                NativeMethods.AccessDenied => Denied(entry, "permission_denied"),
                NativeMethods.SymbolicLink => Unreadable(entry, "symlink_rejected", "symlink", before),
                NativeMethods.NoSuchFile => Missing(entry),
                _ => Unreadable(entry, "open_failed", before.TypeName, before)
            };
        }

        using var handle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        var opened = NativeMethods.FStat(descriptor);
        if (opened is null || !opened.Value.Regular || opened.Value.LinkCount != 1 || (entry.MaxBytes > 0 && opened.Value.Size > entry.MaxBytes))
        {
            return Unreadable(entry, "open_metadata_changed", opened?.TypeName ?? "unknown", opened);
        }

        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var stream = new FileStream(handle, FileAccess.Read, 8192, isAsync: false);
        var buffer = new byte[8192];
        long readTotal = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            readTotal += read;
            if (readTotal > entry.MaxBytes) return Unreadable(entry, "file_too_large", "regular_file", opened.Value);
            hasher.AppendData(buffer, 0, read);
        }
        var digest = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        return Success(entry, "regular_file", opened.Value, digest);
    }

    private string Resolve(string absolutePath)
    {
        if (!absolutePath.StartsWith('/')) throw new InvalidOperationException("Self-integrity allowlist paths must be absolute.");
        var rooted = root == "/" ? absolutePath : Path.Combine(root, absolutePath.TrimStart('/'));
        var fullRoot = Path.GetFullPath(root == "/" ? "/" : root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(rooted);
        if (root != "/" && !fullPath.StartsWith(fullRoot, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Self-integrity allowlist path escaped the configured root.");
        }
        return fullPath;
    }

    private static SelfIntegrityObservation Success(SelfIntegrityAllowlistEntry entry, string type, FileMetadata metadata, string? sha256) => new(
        entry, LinuxSelfIntegrityStates.Unchanged, "none", type, metadata.OwnerId, metadata.GroupId, (UnixFileMode)(metadata.Mode & 0x0fff), metadata.Size,
        DateTimeOffset.FromUnixTimeSeconds(metadata.MtimeSeconds), sha256);

    private static SelfIntegrityObservation Missing(SelfIntegrityAllowlistEntry entry) => new(
        entry, LinuxSelfIntegrityStates.Deleted, "missing", "missing", null, null, null, null, null, null);

    private static SelfIntegrityObservation Denied(SelfIntegrityAllowlistEntry entry, string code) => new(
        entry, LinuxSelfIntegrityStates.Unreadable, code, "unknown", null, null, null, null, null, null);

    private static SelfIntegrityObservation Unreadable(SelfIntegrityAllowlistEntry entry, string code, string type, FileMetadata? metadata) => new(
        entry, LinuxSelfIntegrityStates.Unreadable, code, type, metadata?.OwnerId, metadata?.GroupId,
        metadata.HasValue ? (UnixFileMode)(metadata.Value.Mode & 0x0fff) : null,
        metadata?.Size,
        metadata.HasValue ? DateTimeOffset.FromUnixTimeSeconds(metadata.Value.MtimeSeconds) : null,
        null);

    private readonly record struct FileMetadata(uint Mode, long LinkCount, uint OwnerId, uint GroupId, long Size, long MtimeSeconds)
    {
        public bool Regular => (Mode & 0xf000) == 0x8000;
        public bool Directory => (Mode & 0xf000) == 0x4000;
        public bool SymbolicLink => (Mode & 0xf000) == 0xa000;
        public string TypeName => Regular ? "regular_file" : Directory ? "directory" : SymbolicLink ? "symlink" : "special_file";
    }

    private static class NativeMethods
    {
        public const int ReadOnly = 0;
        public const int NoFollow = 0x20000;
        public const int CloseOnExec = 0x80000;
        public const int NoSuchFile = 2;
        public const int AccessDenied = 13;
        public const int SymbolicLink = 40;

        [DllImport("libc", EntryPoint = "open", SetLastError = true)] public static extern int Open(string path, int flags);
        [DllImport("libc", EntryPoint = "lstat", SetLastError = true)] private static extern int LStatNative(string path, IntPtr buffer);
        [DllImport("libc", EntryPoint = "fstat", SetLastError = true)] private static extern int FStatNative(int descriptor, IntPtr buffer);

        public static FileMetadata? LStat(string path) => ReadStat(buffer => LStatNative(path, buffer));
        public static FileMetadata? FStat(int descriptor) => ReadStat(buffer => FStatNative(descriptor, buffer));

        private static FileMetadata? ReadStat(Func<IntPtr, int> call)
        {
            var offsets = Offsets.ForCurrentArchitecture();
            if (offsets is null) return null;
            var buffer = Marshal.AllocHGlobal(256);
            try
            {
                if (call(buffer) != 0) return null;
                var mode = unchecked((uint)Marshal.ReadInt32(buffer, offsets.Value.Mode));
                var linkCount = offsets.Value.LinkCount64 ? Marshal.ReadInt64(buffer, offsets.Value.LinkCount) : Marshal.ReadInt32(buffer, offsets.Value.LinkCount);
                var ownerId = unchecked((uint)Marshal.ReadInt32(buffer, offsets.Value.Owner));
                var groupId = unchecked((uint)Marshal.ReadInt32(buffer, offsets.Value.Group));
                var size = Marshal.ReadInt64(buffer, offsets.Value.Size);
                var mtime = Marshal.ReadInt64(buffer, offsets.Value.Mtime);
                return new(mode, linkCount, ownerId, groupId, size, mtime);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private readonly record struct Offsets(int LinkCount, bool LinkCount64, int Mode, int Owner, int Group, int Size, int Mtime)
        {
            public static Offsets? ForCurrentArchitecture() => RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => new Offsets(16, true, 24, 28, 32, 48, 88),
                Architecture.Arm64 => new Offsets(20, false, 16, 24, 28, 48, 88),
                _ => null
            };
        }
    }
}
