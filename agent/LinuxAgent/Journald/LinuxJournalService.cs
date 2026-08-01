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

        foreach (var replay in auditRouter.ReplayQueued(options.AgentId, Environment.MachineName))
            await queue.EnqueueAsync(replay, stoppingToken);

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
        foreach (var raw in result.Records)
        {
            var audit = await auditRouter.RouteAsync(raw, options.AgentId, Environment.MachineName, cancellationToken, queueDepth);
            if (audit.Kind != LinuxAuditRouteKind.NotAudit)
            {
                if (audit.Kind == LinuxAuditRouteKind.Stop || audit.Cursor is null || !audit.EventTime.HasValue)
                {
                    runtime.RecordThrottle(audit.ErrorCode ?? "journal_audit_router_stopped");
                    return cursor;
                }
                foreach (var envelope in audit.Events)
                {
                    try
                    {
                        await queue.EnqueueAsync(envelope, cancellationToken);
                        queueDepth++;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
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

            // This await is the reliability boundary: state can advance only after SQLite commits.
            await auditRouter.RecordL1QueuedAsync(record, cancellationToken);
            await queue.EnqueueAsync(record.Envelope, cancellationToken);
            queueDepth++;
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
        await auditRouter.RecordSuccessfulPhysicalReadAsync(cancellationToken);
        if (await auditRouter.TryCreateQuietRecoveryAsync(options.AgentId, Environment.MachineName, queueDepth, cancellationToken) is { } recovery)
            await queue.EnqueueAsync(recovery, cancellationToken);
        return cursor;
    }
}
