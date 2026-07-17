using System.Reflection;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed class LinuxJournalService(
    IOptions<LinuxAgentOptions> configured,
    ILinuxJournalSource source,
    LinuxJournalNormalizer normalizer,
    LinuxJournalRuntime runtime,
    IEventQueue queue,
    TimeProvider timeProvider,
    ILogger<LinuxJournalService> logger) : BackgroundService
{
    private readonly LinuxAgentOptions options = configured.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
        var configHash = AgentConfigurationHasher.ComputeConfigurationHash(
            Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json");
        await queue.InitializeAsync(stoppingToken);
        await runtime.InitializeAsync(version, configHash, stoppingToken);
        if (!options.Journal.Enabled) return;

        var cursor = runtime.CollectedCursor;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                cursor = await CollectOnceAsync(cursor, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                runtime.RecordThrottle("journal_collector_failure");
                logger.LogWarning("Journal collection cycle failed ({ErrorType}); cursor was not advanced.", ex.GetType().Name);
            }
            await Task.Delay(TimeSpan.FromSeconds(options.Journal.PollIntervalSeconds), stoppingToken);
        }
    }

    public async Task<string?> CollectOnceAsync(string? cursor, CancellationToken cancellationToken)
    {
        if (await queue.CountAsync(cancellationToken) >= options.Journal.QueuePauseDepth)
        {
            runtime.RecordThrottle("journal_queue_pressure");
            return cursor;
        }

        var result = await source.ReadAsync(cursor, options.Journal.MaxRecordsPerPoll, options.Journal.MaxInputRecordBytes, cancellationToken);
        runtime.RecordReadResult(result);
        if (result.Status == JournalReadStatus.InvalidCursor)
        {
            await runtime.PersistInvalidCursorResetAsync(cancellationToken);
            return null;
        }
        if (result.Status != JournalReadStatus.Success) return cursor;
        if (cursor is null && result.Records.Count >= options.Journal.MaxRecordsPerPoll)
            runtime.RecordGap("bounded_history_window");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in result.Records)
        {
            if (!normalizer.TryNormalize(raw, options, timeProvider.GetUtcNow(), out var record, out var errorCode) || record is null)
            {
                runtime.RecordMalformed(errorCode);
                continue;
            }
            if (record.BinaryOrInvalidText) runtime.RecordBinaryOrInvalidText();
            if (!seen.Add(record.Cursor) || string.Equals(record.Cursor, cursor, StringComparison.Ordinal))
            {
                runtime.RecordDuplicate();
                continue;
            }

            // This await is the reliability boundary: state can advance only after SQLite commits.
            await queue.EnqueueAsync(record.Envelope, cancellationToken);
            if (runtime.CollectedEventTime is { } collectedTime && record.Envelope.EventTime < collectedTime)
            {
                runtime.RecordReordered();
            }

            // Cursor advances after durable enqueue even when event time moves backward so reordered
            // tails cannot stall collection or force endless replay of already-queued records.
            await runtime.RecordCollectedAsync(record, cancellationToken);
            cursor = record.Cursor;
        }
        await runtime.RecordSuccessfulReadObservationAsync(cancellationToken);
        return cursor;
    }
}
