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

    public async Task WriteCollectedJournalAsync(
        string cursor,
        DateTimeOffset eventTime,
        CancellationToken cancellationToken,
        string? sourceId = null,
        string? eventFamily = null,
        IReadOnlyCollection<JournalSourceEvidence>? additionalEvidence = null,
        bool activeGap = false,
        string gapState = "none",
        long cumulativeGapCount = 0,
        string? configuredScope = null,
        bool clearObservedEvidence = false) =>
        await UpdateAsync(state => state with
        {
            Journal = AddEvidence(AddEvidence((state.Journal ?? new()) with
            {
                CollectedCursor = cursor,
                CollectedEventTime = eventTime,
                ActiveGap = activeGap,
                GapState = gapState,
                CumulativeGapCount = cumulativeGapCount,
                ConfiguredScope = configuredScope ?? state.Journal?.ConfiguredScope,
                ObservedSourceIds = clearObservedEvidence ? Array.Empty<string>() : state.Journal?.ObservedSourceIds,
                ObservedFamilies = clearObservedEvidence
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    : state.Journal?.ObservedFamilies
            }, sourceId, eventFamily), additionalEvidence)
        }, cancellationToken);

    public async Task WriteJournalReadObservationAsync(
        DateTimeOffset observedAt,
        bool activeGap,
        string gapState,
        long cumulativeGapCount,
        string configuredScope,
        bool clearObservedEvidence,
        CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with
        {
            Journal = (state.Journal ?? new()) with
            {
                LastSuccessfulReadAt = observedAt,
                ActiveGap = activeGap,
                GapState = gapState,
                CumulativeGapCount = cumulativeGapCount,
                ConfiguredScope = configuredScope,
                ObservedSourceIds = clearObservedEvidence ? Array.Empty<string>() : state.Journal?.ObservedSourceIds,
                ObservedFamilies = clearObservedEvidence
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    : state.Journal?.ObservedFamilies
            }
        }, cancellationToken);

    public async Task ResetCollectedJournalCursorAsync(
        string configuredScope,
        bool activeGap,
        string gapState,
        long cumulativeGapCount,
        bool clearObservedEvidence,
        CancellationToken cancellationToken) =>
        await UpdateAsync(state => state with
        {
            Journal = (state.Journal ?? new()) with
            {
                CollectedCursor = null,
                CollectedEventTime = null,
                ConfiguredScope = configuredScope,
                ActiveGap = activeGap,
                GapState = gapState,
                CumulativeGapCount = cumulativeGapCount,
                ObservedSourceIds = clearObservedEvidence ? Array.Empty<string>() : state.Journal?.ObservedSourceIds,
                ObservedFamilies = clearObservedEvidence
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    : state.Journal?.ObservedFamilies
            }
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

    private static JournalCheckpointState AddEvidence(JournalCheckpointState journal, string? sourceId, string? eventFamily)
    {
        if (string.IsNullOrWhiteSpace(sourceId) || string.IsNullOrWhiteSpace(eventFamily)) return journal;
        var sources = (journal.ObservedSourceIds ?? Array.Empty<string>()).ToHashSet(StringComparer.Ordinal);
        sources.Add(sourceId);
        var families = (journal.ObservedFamilies ?? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal))
            .ToDictionary(pair => pair.Key, pair => pair.Value.ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal);
        if (!families.TryGetValue(sourceId, out var sourceFamilies)) families[sourceId] = sourceFamilies = new(StringComparer.Ordinal);
        sourceFamilies.Add(eventFamily);
        return journal with
        {
            ObservedSourceIds = sources.Order(StringComparer.Ordinal).ToArray(),
            ObservedFamilies = families.ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlyList<string>)pair.Value.Order(StringComparer.Ordinal).ToArray(),
                StringComparer.Ordinal)
        };
    }

    private static JournalCheckpointState AddEvidence(
        JournalCheckpointState journal,
        IReadOnlyCollection<JournalSourceEvidence>? evidence)
    {
        if (evidence is null) return journal;
        foreach (var item in evidence.Take(8)) journal = AddEvidence(journal, item.SourceId, item.EventFamily);
        return journal;
    }

    private sealed record LinuxAgentState
    {
        [JsonPropertyName("agent_id")] public string? AgentId { get; init; }
        [JsonPropertyName("enrolled_at")] public DateTimeOffset? EnrolledAt { get; init; }
        [JsonPropertyName("journal")] public JournalCheckpointState? Journal { get; init; }
    }
}
