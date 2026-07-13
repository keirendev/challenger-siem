using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;

namespace Challenger.Siem.LinuxAgent.SelfIntegrity;

public sealed class LinuxSelfIntegrityStateStore(string path)
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<LinuxSelfIntegrityState> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return await ReadUnsafeAsync(cancellationToken); }
        finally { gate.Release(); }
    }

    public async Task WriteCollectedAsync(IReadOnlyDictionary<string, string> signatures, long nextSequence, long? collectedSequence, DateTimeOffset collectedAt, CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with
        {
            Signatures = new Dictionary<string, string>(signatures, StringComparer.Ordinal),
            NextSequence = nextSequence,
            CollectedSequence = collectedSequence,
            CollectedAt = collectedAt,
            LastSuccessfulScanAt = collectedAt
        }, cancellationToken);

    public async Task WriteAcknowledgedAsync(long acknowledgedSequence, DateTimeOffset acknowledgedAt, CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with { AcknowledgedSequence = acknowledgedSequence, AcknowledgedAt = acknowledgedAt }, cancellationToken);

    public async Task CleanupAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        finally { gate.Release(); }
    }

    private async Task UpdateAsync(Func<LinuxSelfIntegrityState, LinuxSelfIntegrityState> update, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var state = update(await ReadUnsafeAsync(cancellationToken));
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            var temporary = path + ".tmp";
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(state, JsonDefaults.Options), cancellationToken);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, path, true);
        }
        finally { gate.Release(); }
    }

    private async Task<LinuxSelfIntegrityState> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path)) return new();
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            return await JsonSerializer.DeserializeAsync<LinuxSelfIntegrityState>(stream, JsonDefaults.Options, cancellationToken) ?? new();
        }
        catch (JsonException) { return new(); }
        catch (IOException) { return new(); }
    }
}
