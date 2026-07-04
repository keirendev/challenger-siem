using System.Text.Json;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Serialization;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.WindowsAgent.State;

public sealed class JsonChannelStateStore(IOptions<AgentOptions> options, ILogger<JsonChannelStateStore> logger) : IChannelStateStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly string path = options.Value.State.Path;
    private Dictionary<string, long>? cache;

    public async Task<IReadOnlyDictionary<string, long>> LoadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            cache ??= await LoadUnsafeAsync(cancellationToken);
            return new Dictionary<string, long>(cache, StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<long?> GetLastRecordIdAsync(string channel, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            cache ??= await LoadUnsafeAsync(cancellationToken);
            return cache.TryGetValue(channel, out var recordId) ? recordId : null;
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task SetLastRecordIdAsync(string channel, long recordId, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            cache ??= await LoadUnsafeAsync(cancellationToken);
            cache[channel] = recordId;
            await SaveUnsafeAsync(cache, cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<Dictionary<string, long>> LoadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        }

        try
        {
            await using var stream = File.OpenRead(path);
            var state = await JsonSerializer.DeserializeAsync<Dictionary<string, long>>(stream, JsonDefaults.Options, cancellationToken);
            return state is null
                ? new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, long>(state, StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Agent state file is invalid JSON. Starting with empty state: {Path}", path);
            return new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private async Task SaveUnsafeAsync(IReadOnlyDictionary<string, long> state, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = path + ".tmp";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, state, JsonDefaults.Options, cancellationToken);
        }

        File.Move(tempPath, path, overwrite: true);
    }
}
