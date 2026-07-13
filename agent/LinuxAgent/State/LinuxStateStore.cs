using System.Text.Json;
using System.Text.Json.Serialization;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.LinuxAgent.Journal;

namespace Challenger.Siem.LinuxAgent.State;

public sealed class LinuxStateStore(string path)
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task WriteEnrollmentAsync(string agentId, CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with { AgentId = agentId, EnrolledAt = DateTimeOffset.UtcNow }, cancellationToken);

    public async Task<JournalCheckpointState> ReadJournalAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return (await ReadUnsafeAsync(cancellationToken)).Journal ?? new(); }
        finally { gate.Release(); }
    }

    public async Task WriteCollectedJournalAsync(string cursor, DateTimeOffset eventTime, CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with
        {
            Journal = (state.Journal ?? new()) with { CollectedCursor = cursor, CollectedEventTime = eventTime }
        }, cancellationToken);

    public async Task WriteAcknowledgedJournalAsync(string cursor, DateTimeOffset eventTime, CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with
        {
            Journal = (state.Journal ?? new()) with { AcknowledgedCursor = cursor, AcknowledgedEventTime = eventTime }
        }, cancellationToken);

    private async Task UpdateAsync(Func<LinuxAgentState, LinuxAgentState> update, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var state = update(await ReadUnsafeAsync(cancellationToken));
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            var temporary = path + ".tmp";
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(state, JsonDefaults.Options), cancellationToken);
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, path, true);
        }
        finally { gate.Release(); }
    }

    private async Task<LinuxAgentState> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path)) return new();
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            return await JsonSerializer.DeserializeAsync<LinuxAgentState>(stream, JsonDefaults.Options, cancellationToken) ?? new();
        }
        catch (JsonException) { return new(); }
    }

    private sealed record LinuxAgentState
    {
        [JsonPropertyName("agent_id")] public string? AgentId { get; init; }
        [JsonPropertyName("enrolled_at")] public DateTimeOffset? EnrolledAt { get; init; }
        [JsonPropertyName("journal")] public JournalCheckpointState? Journal { get; init; }
    }
}
