using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public sealed class LinuxKernelNetworkStateStore(string path)
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<LinuxKernelNetworkState> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return await ReadUnsafeAsync(cancellationToken); }
        finally { gate.Release(); }
    }

    public async Task WriteAsync(LinuxKernelNetworkState state, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Kernel network state directory is unavailable.");
            Directory.CreateDirectory(directory);
            var temporary = path + ".tmp";
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(state, JsonDefaults.Options), cancellationToken);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, path, true);
        }
        finally { gate.Release(); }
    }

    private async Task<LinuxKernelNetworkState> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path)) return new();
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var state = await JsonSerializer.DeserializeAsync<LinuxKernelNetworkState>(stream, JsonDefaults.Options, cancellationToken);
            return state is { SchemaVersion: 1 or 2, NextSequence: > 0 }
                ? state with { SchemaVersion = 2 }
                : new();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return new LinuxKernelNetworkState() with { LastError = "state_unreadable" };
        }
    }
}
