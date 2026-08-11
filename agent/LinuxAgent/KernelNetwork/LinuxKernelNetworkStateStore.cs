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
            if (state is not { SchemaVersion: 1 or 2 or 3, NextSequence: > 0 }) return new();
            return state.CounterHelperEpoch is not null || state.LastHelperEpoch is null
                ? state with { SchemaVersion = 3 }
                : state with
                {
                    SchemaVersion = 3,
                    CounterHelperEpoch = state.LastHelperEpoch,
                    RawParseFailures = state.ParseFailures,
                    RawUnsupportedHeaders = state.UnsupportedHeaders,
                    RawFlowMapFull = state.FlowMapFull,
                    RawKernelFlowMapUpdateFailures = state.KernelFlowMapUpdateFailures,
                    RawTrackedFlowTableFull = state.TrackedFlowTableFull,
                    RawOwnerMisses = state.OwnerMisses,
                    RawRingLosses = state.RingLosses,
                    RawIpcSendFailures = state.IpcSendFailures,
                    RawKernelDrainCappedTicks = state.KernelDrainCappedTicks,
                    RawKernelDrainBacklogTicks = state.KernelDrainBacklogTicks
                };
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return new LinuxKernelNetworkState() with { LastError = "state_unreadable" };
        }
    }
}
