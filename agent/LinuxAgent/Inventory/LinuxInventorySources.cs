using System.Collections.Frozen;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Challenger.Siem.LinuxAgent.Inventory;

public enum LinuxInventoryOperation
{
    OsReleaseEtc,
    OsReleaseUsrLib,
    Kernel,
    Users,
    Groups,
    InitSystem,
    Services,
    Units,
    Timers,
    DpkgPackages,
    RpmPackages,
    AptUpdates,
    DnfUpdates,
    Interfaces,
    Listeners,
    Mounts,
    Nftables,
    Firewalld,
    Ufw,
    SshConfig,
    AppArmor,
    Selinux,
    SecureBoot,
    AgentConfig,
    AgentExecutable
}

public enum InventorySourceState
{
    Success,
    Unavailable,
    NotApplicable,
    PermissionDenied,
    Timeout,
    Malformed
}

public sealed record InventorySourceResult(
    InventorySourceState State,
    string ErrorCode,
    string? Content = null,
    bool Truncated = false,
    UnixFileMode? FileMode = null,
    long? FileSize = null,
    uint? FileOwnerId = null,
    int? ExitCode = null,
    string? Sha256 = null)
{
    public static InventorySourceResult Success(string? content = null, bool truncated = false, UnixFileMode? mode = null, long? size = null, uint? ownerId = null, int? exitCode = null, string? sha256 = null) =>
        new(InventorySourceState.Success, "none", content, truncated, mode, size, ownerId, exitCode, sha256);
}

public enum InventorySourceKind { Command, File, FileMetadata }

public sealed record InventorySourcePolicy(
    LinuxInventoryOperation Operation,
    InventorySourceKind Kind,
    IReadOnlyList<string> ExecutablePaths,
    IReadOnlyList<string> Arguments,
    string? FilePath,
    TimeSpan Timeout,
    int MaxOutputBytes,
    IReadOnlySet<int> AcceptedExitCodes);

public static class LinuxInventoryCatalog
{
    private static readonly IReadOnlyDictionary<LinuxInventoryOperation, InventorySourcePolicy> Policies = Build();

    public static IReadOnlyCollection<InventorySourcePolicy> All => Policies.Values.ToArray();

    public static InventorySourcePolicy Get(LinuxInventoryOperation operation) => Policies[operation];

    private static IReadOnlyDictionary<LinuxInventoryOperation, InventorySourcePolicy> Build()
    {
        const int small = 16 * 1024;
        const int listing = 64 * 1024;
        var result = new Dictionary<LinuxInventoryOperation, InventorySourcePolicy>();
        void Command(LinuxInventoryOperation operation, string[] paths, string[] arguments, int bytes = listing, int seconds = 10, params int[] exitCodes) =>
            result.Add(operation, new(operation, InventorySourceKind.Command, Array.AsReadOnly(paths), Array.AsReadOnly(arguments), null, TimeSpan.FromSeconds(seconds), bytes,
                (exitCodes.Length == 0 ? new[] { 0 } : exitCodes).ToFrozenSet()));
        void File(LinuxInventoryOperation operation, string path, int bytes = small, bool metadata = false) =>
            result.Add(operation, new(operation, metadata ? InventorySourceKind.FileMetadata : InventorySourceKind.File,
                Array.Empty<string>(), Array.Empty<string>(), path, TimeSpan.FromSeconds(5), bytes, Array.Empty<int>().ToFrozenSet()));

        File(LinuxInventoryOperation.OsReleaseEtc, "/etc/os-release");
        File(LinuxInventoryOperation.OsReleaseUsrLib, "/usr/lib/os-release");
        Command(LinuxInventoryOperation.Kernel, new[] { "/usr/bin/uname", "/bin/uname" }, new[] { "-srmo" }, small);
        Command(LinuxInventoryOperation.Users, new[] { "/usr/bin/getent", "/bin/getent" }, new[] { "passwd" });
        Command(LinuxInventoryOperation.Groups, new[] { "/usr/bin/getent", "/bin/getent" }, new[] { "group" });
        Command(LinuxInventoryOperation.InitSystem, new[] { "/usr/bin/systemctl", "/bin/systemctl" }, new[] { "is-system-running" }, small, 5, 0, 1);
        Command(LinuxInventoryOperation.Services, new[] { "/usr/bin/systemctl", "/bin/systemctl" }, new[] { "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain" });
        Command(LinuxInventoryOperation.Units, new[] { "/usr/bin/systemctl", "/bin/systemctl" }, new[] { "list-units", "--all", "--no-legend", "--no-pager", "--plain" });
        Command(LinuxInventoryOperation.Timers, new[] { "/usr/bin/systemctl", "/bin/systemctl" }, new[] { "list-unit-files", "--type=timer", "--no-legend", "--no-pager" });
        Command(LinuxInventoryOperation.DpkgPackages, new[] { "/usr/bin/dpkg-query" }, new[] { "-W", "-f=${binary:Package}\t${Version}\n" });
        Command(LinuxInventoryOperation.RpmPackages, new[] { "/usr/bin/rpm", "/bin/rpm" }, new[] { "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n" });
        Command(LinuxInventoryOperation.AptUpdates, new[] { "/usr/bin/apt", "/bin/apt" }, new[] { "list", "--upgradable" });
        Command(LinuxInventoryOperation.DnfUpdates, new[] { "/usr/bin/dnf", "/bin/dnf" }, new[] { "--cacheonly", "check-update", "--quiet" }, listing, 20, 0, 100);
        Command(LinuxInventoryOperation.Interfaces, new[] { "/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip" }, new[] { "-o", "link", "show" });
        Command(LinuxInventoryOperation.Listeners, new[] { "/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss" }, new[] { "-H", "-lntu" });
        Command(LinuxInventoryOperation.Mounts, new[] { "/usr/bin/findmnt", "/bin/findmnt" }, new[] { "--raw", "--noheadings", "--output", "FSTYPE" });
        Command(LinuxInventoryOperation.Nftables, new[] { "/usr/sbin/nft", "/sbin/nft" }, new[] { "list", "tables" });
        Command(LinuxInventoryOperation.Firewalld, new[] { "/usr/bin/firewall-cmd", "/bin/firewall-cmd" }, new[] { "--state" }, small);
        Command(LinuxInventoryOperation.Ufw, new[] { "/usr/sbin/ufw", "/sbin/ufw" }, new[] { "status" }, small);
        File(LinuxInventoryOperation.SshConfig, "/etc/ssh/sshd_config");
        Command(LinuxInventoryOperation.AppArmor, new[] { "/usr/sbin/aa-status", "/sbin/aa-status" }, new[] { "--enabled" }, small, 5, 0, 1);
        Command(LinuxInventoryOperation.Selinux, new[] { "/usr/sbin/getenforce", "/sbin/getenforce" }, Array.Empty<string>(), small);
        Command(LinuxInventoryOperation.SecureBoot, new[] { "/usr/bin/mokutil", "/bin/mokutil" }, new[] { "--sb-state" }, small, 5, 0, 1);
        File(LinuxInventoryOperation.AgentConfig, "/etc/challenger-siem-agent/agentsettings.json", bytes: 64 * 1024, metadata: true);
        File(LinuxInventoryOperation.AgentExecutable, "/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent", bytes: 64 * 1024 * 1024, metadata: true);
        return result;
    }
}

public interface ILinuxInventorySource
{
    Task<InventorySourceResult> ReadAsync(LinuxInventoryOperation operation, CancellationToken cancellationToken);
}

public sealed class LinuxInventorySource : ILinuxInventorySource
{
    public Task<InventorySourceResult> ReadAsync(LinuxInventoryOperation operation, CancellationToken cancellationToken)
    {
        var policy = LinuxInventoryCatalog.Get(operation);
        return policy.Kind == InventorySourceKind.Command
            ? RunCommandAsync(policy, cancellationToken)
            : ReadFileAsync(policy, cancellationToken);
    }

    private static async Task<InventorySourceResult> RunCommandAsync(InventorySourcePolicy policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var executable = policy.ExecutablePaths.FirstOrDefault(path =>
        {
            var info = new FileInfo(path);
            return info.Exists && info.LinkTarget is null && (info.Attributes & FileAttributes.Directory) == 0;
        });
        if (executable is null)
            return new(InventorySourceState.Unavailable, "command_missing");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        process.StartInfo.Environment.Clear();
        process.StartInfo.Environment["LANG"] = "C";
        process.StartInfo.Environment["LC_ALL"] = "C";
        process.StartInfo.Environment["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin";
        foreach (var argument in policy.Arguments) process.StartInfo.ArgumentList.Add(argument);

        try
        {
            if (!process.Start()) return new(InventorySourceState.Unavailable, "command_start_failed");
            try { process.PriorityClass = ProcessPriorityClass.BelowNormal; }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode is 13)
        {
            return new(InventorySourceState.PermissionDenied, "command_permission_denied");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new(InventorySourceState.Unavailable, "command_start_failed");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(policy.Timeout);
        var stdout = ReadBoundedAsync(process.StandardOutput.BaseStream, policy.MaxOutputBytes, process, timeout.Token);
        var stderr = ReadBoundedAsync(process.StandardError.BaseStream, policy.MaxOutputBytes, process, timeout.Token);
        try
        {
            await Task.WhenAll(process.WaitForExitAsync(timeout.Token), stdout, stderr);
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            await WaitAfterKillAsync(process);
            if (cancellationToken.IsCancellationRequested) throw;
            return new(InventorySourceState.Timeout, "command_timeout");
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            Kill(process);
            await WaitAfterKillAsync(process);
            return new(InventorySourceState.Malformed, "command_io_failed");
        }

        var output = await stdout;
        var errorOutput = await stderr;
        var truncated = output.Truncated || errorOutput.Truncated;
        if (!policy.AcceptedExitCodes.Contains(process.ExitCode) && !truncated)
        {
            return ClassifyCommandFailure(policy.Operation, process.ExitCode, Encoding.UTF8.GetString(errorOutput.Bytes)) == InventorySourceState.PermissionDenied
                ? new(InventorySourceState.PermissionDenied, "command_permission_denied")
                : new(InventorySourceState.Unavailable, "command_failed");
        }
        return InventorySourceResult.Success(Encoding.UTF8.GetString(output.Bytes), truncated, exitCode: process.ExitCode);
    }

    private static async Task<(byte[] Bytes, bool Truncated)> ReadBoundedAsync(Stream stream, int maxBytes, Process process, CancellationToken cancellationToken)
    {
        using var memory = new MemoryStream(Math.Min(maxBytes, 16 * 1024));
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0) return (memory.ToArray(), false);
            var retained = Math.Min(read, maxBytes - (int)memory.Length);
            if (retained > 0) memory.Write(buffer, 0, retained);
            if (retained < read)
            {
                Kill(process);
                return (memory.ToArray(), true);
            }
        }
    }

    private static async Task<InventorySourceResult> ReadFileAsync(InventorySourcePolicy policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var path = policy.FilePath!;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return new(InventorySourceState.Unavailable, "file_missing");
            if (info.LinkTarget is not null || (info.Attributes & FileAttributes.Directory) != 0)
                return new(InventorySourceState.Malformed, "file_not_regular");
            var descriptor = NativeMethods.Open(path, NativeMethods.ReadOnly | NativeMethods.CloseOnExec | NativeMethods.NoFollow | NativeMethods.NonBlocking);
            if (descriptor < 0)
            {
                var error = Marshal.GetLastPInvokeError();
                return error switch
                {
                    NativeMethods.AccessDenied => new(InventorySourceState.PermissionDenied, "file_permission_denied"),
                    NativeMethods.SymbolicLink => new(InventorySourceState.Malformed, "file_not_regular"),
                    NativeMethods.NoSuchFile => new(InventorySourceState.Unavailable, "file_missing"),
                    _ => new(InventorySourceState.Unavailable, "file_open_failed")
                };
            }
            var handle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
            var metadata = NativeMethods.GetMetadata(descriptor);
            if (metadata is null)
            {
                handle.Dispose();
                return new(InventorySourceState.Unavailable, "file_metadata_failed");
            }
            if (!metadata.Value.Regular)
            {
                handle.Dispose();
                return new(InventorySourceState.Malformed, "file_not_regular");
            }
            UnixFileMode? mode = (UnixFileMode)(metadata.Value.Mode & 0x0fff);
            await using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: true);
            if (policy.Kind == InventorySourceKind.FileMetadata && policy.Operation == LinuxInventoryOperation.AgentConfig)
                return InventorySourceResult.Success(mode: mode, size: metadata.Value.Size, ownerId: metadata.Value.OwnerId);
            if (metadata.Value.Size > policy.MaxOutputBytes)
                return new(InventorySourceState.Malformed, "file_too_large", Truncated: true, FileMode: mode, FileSize: metadata.Value.Size);
            using var memory = policy.Kind == InventorySourceKind.File ? new MemoryStream(Math.Min(policy.MaxOutputBytes, 4096)) : null;
            using var hasher = policy.Operation == LinuxInventoryOperation.AgentExecutable
                ? System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256)
                : null;
            var buffer = new byte[4096];
            long bytesRead = 0;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(policy.Timeout);
            while (true)
            {
                var count = await stream.ReadAsync(buffer, timeout.Token);
                if (count == 0) break;
                bytesRead += count;
                if (bytesRead > policy.MaxOutputBytes)
                    return new(InventorySourceState.Malformed, "file_too_large", Truncated: true, FileMode: mode, FileSize: metadata.Value.Size);
                if (hasher is not null) hasher.AppendData(buffer, 0, count);
                else memory!.Write(buffer, 0, count);
            }
            if (hasher is not null)
            {
                var hash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
                return InventorySourceResult.Success(mode: mode, size: metadata.Value.Size, ownerId: metadata.Value.OwnerId, sha256: hash);
            }
            return InventorySourceResult.Success(Encoding.UTF8.GetString(memory!.ToArray()), mode: mode, size: metadata.Value.Size, ownerId: metadata.Value.OwnerId);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(InventorySourceState.Timeout, "file_timeout");
        }
        catch (UnauthorizedAccessException)
        {
            return new(InventorySourceState.PermissionDenied, "file_permission_denied");
        }
        catch (IOException)
        {
            return new(InventorySourceState.Unavailable, "file_unavailable");
        }
    }

    internal static InventorySourceState ClassifyCommandFailure(LinuxInventoryOperation operation, int exitCode, string boundedStandardError)
    {
        if (exitCode is 13 or 126) return InventorySourceState.PermissionDenied;
        var permissionMarker = operation switch
        {
            LinuxInventoryOperation.Nftables => boundedStandardError.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase),
            LinuxInventoryOperation.Ufw => boundedStandardError.Contains("need to be root", StringComparison.OrdinalIgnoreCase),
            LinuxInventoryOperation.Firewalld => boundedStandardError.Contains("authorization failed", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
        return permissionMarker ? InventorySourceState.PermissionDenied : InventorySourceState.Unavailable;
    }

    private static void Kill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static async Task WaitAfterKillAsync(Process process)
    {
        try { await process.WaitForExitAsync(CancellationToken.None); }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static class NativeMethods
    {
        public const int ReadOnly = 0;
        public const int NonBlocking = 0x800;
        public const int NoFollow = 0x20000;
        public const int CloseOnExec = 0x80000;
        public const int NoSuchFile = 2;
        public const int AccessDenied = 13;
        public const int SymbolicLink = 40;

        [DllImport("libc", EntryPoint = "open", SetLastError = true)]
        public static extern int Open(string path, int flags);

        [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
        private static extern int FStat(int descriptor, IntPtr buffer);

        public static (uint Mode, uint OwnerId, long Size, bool Regular)? GetMetadata(int descriptor)
        {
            var modeOffset = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => 24,
                Architecture.Arm64 => 16,
                _ => -1
            };
            if (modeOffset < 0) return null;
            var buffer = Marshal.AllocHGlobal(256);
            try
            {
                if (FStat(descriptor, buffer) != 0) return null;
                var mode = unchecked((uint)Marshal.ReadInt32(buffer, modeOffset));
                var linkCount = RuntimeInformation.ProcessArchitecture == Architecture.X64
                    ? Marshal.ReadInt64(buffer, 16)
                    : Marshal.ReadInt32(buffer, 20);
                var ownerOffset = RuntimeInformation.ProcessArchitecture == Architecture.X64 ? 28 : 24;
                var ownerId = unchecked((uint)Marshal.ReadInt32(buffer, ownerOffset));
                var size = Marshal.ReadInt64(buffer, 48);
                return (mode, ownerId, size, (mode & 0xf000) == 0x8000 && linkCount == 1);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
