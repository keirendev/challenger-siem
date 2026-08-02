using System.Reflection;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Services;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed class LinuxJournalService(
    IOptions<LinuxAgentOptions> configured,
    ILinuxJournalSource source,
    LinuxJournalNormalizer normalizer,
    LinuxAuditRouter auditRouter,
    LinuxJournalRuntime runtime,
    IEventQueue queue,
    TimeProvider timeProvider,
    ILogger<LinuxJournalService> logger) : BackgroundService
{
    public LinuxJournalService(
        IOptions<LinuxAgentOptions> configured,
        ILinuxJournalSource source,
        LinuxJournalNormalizer normalizer,
        LinuxJournalRuntime runtime,
        IEventQueue queue,
        TimeProvider timeProvider,
        ILogger<LinuxJournalService> logger)
        : this(
            configured,
            source,
            normalizer,
            new LinuxAuditRouter(
                configured.Value,
                timeProvider,
                new LinuxAuditRouterRuntime(),
                new LinuxAuditStateStore(
                    Path.Combine(Path.GetDirectoryName(configured.Value.State.Path) ?? Path.GetTempPath(), "audit-router-test-state.wal"),
                    enforceFixedPath: false)),
            runtime,
            queue,
            timeProvider,
            logger)
    {
    }

    private static readonly TimeSpan FailureLogInterval = TimeSpan.FromMinutes(1);
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly RuntimeWarningThrottle failureLog = new(timeProvider, FailureLogInterval);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
        var configHash = AgentConfigurationHasher.ComputeConfigurationHash(
            Environment.GetEnvironmentVariable("CHALLENGER_SIEM_AGENT_CONFIG") ?? "/etc/challenger-siem-agent/agentsettings.json");
        await queue.InitializeAsync(stoppingToken);
        await runtime.InitializeAsync(version, configHash, stoppingToken);
        await auditRouter.InitializeAsync(stoppingToken);
        if (!options.Journal.Enabled) return;

        foreach (var replayBatch in EventQueueBatcher.Partition(
            auditRouter.ReplayQueued(options.AgentId, Environment.MachineName)))
            await queue.EnqueueBatchAsync(replayBatch, stoppingToken);

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
                if (failureLog.TryAcquire())
                {
                    logger.LogWarning("Journal collection cycle failed ({ErrorType}); cursor was not advanced.", ex.GetType().Name);
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(options.Journal.PollIntervalSeconds), stoppingToken);
        }
    }

    public async Task<string?> CollectOnceAsync(string? cursor, CancellationToken cancellationToken)
    {
        var queueDepth = await queue.CountAsync(cancellationToken);
        if (queueDepth >= options.Journal.QueuePauseDepth)
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
        var pendingL1 = new List<NormalizedJournalRecord>();
        async Task FlushPendingL1Async()
        {
            if (pendingL1.Count == 0) return;
            foreach (var batch in EventQueueBatcher.Partition(pendingL1, record => record.Envelope))
            {
                // The router marker and queue transaction are both durable before this chunk's
                // collected cursor moves. A crash between them can only replay deterministic IDs.
                await auditRouter.RecordL1QueuedBatchAsync(batch, cancellationToken);
                await queue.EnqueueBatchAsync(
                    batch.Select(record => record.Envelope).ToArray(),
                    cancellationToken);
                var previousEventTime = runtime.CollectedEventTime;
                foreach (var record in batch)
                {
                    if (previousEventTime.HasValue && record.Envelope.EventTime < previousEventTime.Value)
                        runtime.RecordReordered();
                    previousEventTime = record.Envelope.EventTime;
                }
                await runtime.RecordCollectedBatchAsync(batch, cancellationToken);
                queueDepth += batch.Count;
                cursor = batch[^1].Cursor;
            }
            pendingL1.Clear();
        }

        foreach (var raw in result.Records)
        {
            if (LinuxAuditRouter.IsAuditTransport(raw))
            {
                await FlushPendingL1Async();
                var audit = await auditRouter.RouteAsync(raw, options.AgentId, Environment.MachineName, cancellationToken, queueDepth);
                if (audit.Kind == LinuxAuditRouteKind.Stop || audit.Cursor is null || !audit.EventTime.HasValue)
                {
                    runtime.RecordThrottle(audit.ErrorCode ?? "journal_audit_router_stopped");
                    return cursor;
                }
                foreach (var batch in EventQueueBatcher.Partition(audit.Events))
                {
                    try
                    {
                        await queue.EnqueueBatchAsync(batch, cancellationToken);
                        queueDepth += batch.Count;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        foreach (var envelope in batch)
                            await auditRouter.RecordQueueInsertionFailureAsync(envelope, cancellationToken);
                        runtime.RecordThrottle("journal_audit_queue_insertion_gap");
                    }
                }
                await runtime.RecordRoutedPhysicalAsync(audit.Cursor, audit.EventTime.Value, cancellationToken);
                cursor = audit.Cursor;
                continue;
            }

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
            pendingL1.Add(record);
        }
        await FlushPendingL1Async();
        await runtime.RecordSuccessfulReadObservationAsync(cancellationToken);
        await auditRouter.RecordSuccessfulPhysicalReadAsync(cancellationToken);
        if (await auditRouter.TryCreateQuietRecoveryAsync(options.AgentId, Environment.MachineName, queueDepth, cancellationToken) is { } recovery)
        {
            try
            {
                await queue.EnqueueAsync(recovery, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await auditRouter.RecordQueueInsertionFailureAsync(recovery, cancellationToken);
                runtime.RecordThrottle("journal_audit_queue_insertion_gap");
            }
        }
        return cursor;
    }
}
