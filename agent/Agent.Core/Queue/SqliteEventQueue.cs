using System.Globalization;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Agent.Core.Reliability;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace Challenger.Siem.Agent.Core.Queue;

public sealed class SqliteEventQueue(AgentQueueOptions options, ILogger<SqliteEventQueue> logger) : IEventQueue
{
    internal const int MaximumEventsPerTransaction = 100;
    internal const int MaximumPayloadBytesPerTransaction = 1024 * 1024;
    private static readonly TimeSpan QueueWarningInterval = TimeSpan.FromMinutes(5);
    private const int MaximumAttributedSources = 64;
    private const string OtherSource = "_other";
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object workSync = new();
    private readonly Dictionary<string, QueueSourceWorkCounters> workBySource = new(StringComparer.Ordinal);
    private readonly string workGenerationId = Guid.NewGuid().ToString("N");

    private bool initialized;
    private DateTimeOffset lastQueueWarningAt = DateTimeOffset.MinValue;

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) =>
        EnqueueBatchAsync([envelope], cancellationToken);

    public async Task EnqueueBatchAsync(
        IReadOnlyCollection<EventEnvelope> envelopes,
        CancellationToken cancellationToken)
    {
        if (envelopes.Count == 0) return;
        if (envelopes.Count > MaximumEventsPerTransaction)
            throw new InvalidOperationException("Queue batch exceeds the durable transaction event limit.");

        var pending = new List<PendingEnqueue>(envelopes.Count);
        long pendingPayloadBytes = 0;
        foreach (var envelope in envelopes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var payloadJson = JsonSerializer.Serialize(envelope, JsonDefaults.Options);
            pendingPayloadBytes += Encoding.UTF8.GetByteCount(payloadJson);
            if (pendingPayloadBytes > MaximumPayloadBytesPerTransaction)
                throw new InvalidOperationException("Queue batch exceeds the durable transaction payload limit.");
            pending.Add(new(envelope.EventId.ToString(), envelope.AgentId, envelope.SourceId ?? envelope.Source, payloadJson,
                Encoding.UTF8.GetByteCount(payloadJson)));
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            await InsertBatchUnsafeAsync(pending, cancellationToken);
            RecordEnqueuedWork(pending);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            if (maxEvents <= 0) return Array.Empty<QueuedEvent>();
            await using var connection = OpenConnection();
            var results = new List<QueuedEvent>(Math.Max(1, maxEvents));
            var blockedSequentialSources = new HashSet<string>(StringComparer.Ordinal);
            var now = DateTimeOffset.UtcNow;
            var scanLimit = Math.Max(maxEvents, maxEvents * 10);
            long lastScannedQueueId = 0;
            while (results.Count < maxEvents)
            {
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    select id, payload_json, send_attempts, last_attempt_at
                    from queued_events
                    where id > $after_id
                    order by id
                    limit $scan_limit;
                    """;
                command.Parameters.AddWithValue("$after_id", lastScannedQueueId);
                command.Parameters.AddWithValue("$scan_limit", scanLimit);

                var scanned = 0;
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken) && results.Count < maxEvents)
                {
                    scanned++;
                    var queueId = reader.GetInt64(0);
                    lastScannedQueueId = queueId;
                    var payloadJson = reader.GetString(1);
                    var sendAttempts = reader.GetInt32(2);
                    var lastAttemptAt = reader.IsDBNull(3) ? null : ParseTimestamp(reader.GetString(3));
                    var envelope = JsonSerializer.Deserialize<EventEnvelope>(payloadJson, JsonDefaults.Options);
                    if (envelope is null)
                    {
                        logger.LogWarning("Queued event {QueueId} could not be deserialized.", queueId);
                        continue;
                    }
                    var sequentialSource = SequentialSourceKey(envelope);
                    if (!IsReadyForAttempt(sendAttempts, lastAttemptAt, options.MaxBackoffSeconds, now))
                    {
                        if (sequentialSource is not null) blockedSequentialSources.Add(sequentialSource);
                        continue;
                    }
                    if (sequentialSource is not null && blockedSequentialSources.Contains(sequentialSource)) continue;

                    results.Add(new QueuedEvent(queueId, envelope, sendAttempts, lastAttemptAt, Encoding.UTF8.GetByteCount(payloadJson)));
                }
                if (scanned < scanLimit) break;
            }

            return results;
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken)
    {
        if (queueIds.Count == 0)
        {
            return;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            await using var connection = OpenConnection();
            await using var transaction = connection.BeginTransaction();
            var now = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

            foreach (var queueId in queueIds)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    update queued_events
                    set send_attempts = send_attempts + 1,
                        last_attempt_at = $last_attempt_at
                    where id = $id;
                    """;
                command.Parameters.AddWithValue("$id", queueId);
                command.Parameters.AddWithValue("$last_attempt_at", now);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken)
    {
        if (queueIds.Count == 0)
        {
            return;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            await using var connection = OpenConnection();
            await using var transaction = connection.BeginTransaction();

            var distinctIds = queueIds.Distinct().ToArray();
            var parameterNames = new List<string>(distinctIds.Length);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            var index = 0;
            foreach (var queueId in distinctIds)
            {
                var name = $"$id_{index++}";
                parameterNames.Add(name);
                command.Parameters.AddWithValue(name, queueId);
            }

            command.CommandText = $"delete from queued_events where id in ({string.Join(',', parameterNames)});";
            await command.ExecuteNonQueryAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken)
    {
        if (queueIds.Count == 0)
        {
            return;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            await using var connection = OpenConnection();
            await using var transaction = connection.BeginTransaction();
            var poisonedAt = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

            foreach (var queueId in queueIds)
            {
                await using (var insertCommand = connection.CreateCommand())
                {
                    insertCommand.Transaction = transaction;
                    insertCommand.CommandText = """
                        insert into poison_events (
                            original_queue_id,
                            event_id,
                            agent_id,
                            payload_json,
                            send_attempts,
                            last_attempt_at,
                            poisoned_at,
                            reason
                        )
                        select id, event_id, agent_id, payload_json, send_attempts, last_attempt_at, $poisoned_at, $reason
                        from queued_events
                        where id = $id;
                        """;
                    insertCommand.Parameters.AddWithValue("$id", queueId);
                    insertCommand.Parameters.AddWithValue("$poisoned_at", poisonedAt);
                    insertCommand.Parameters.AddWithValue("$reason", Truncate(reason, 200));
                    await insertCommand.ExecuteNonQueryAsync(cancellationToken);
                }

                await using var deleteCommand = connection.CreateCommand();
                deleteCommand.Transaction = transaction;
                deleteCommand.CommandText = "delete from queued_events where id = $id;";
                deleteCommand.Parameters.AddWithValue("$id", queueId);
                await deleteCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<int> CountAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            await using var connection = OpenConnection();
            await using var command = connection.CreateCommand();
            command.CommandText = "select count(*) from queued_events;";
            var result = await command.ExecuteScalarAsync(cancellationToken);
            return Convert.ToInt32(result, CultureInfo.InvariantCulture);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            await using var connection = OpenConnection();
            var queueDepth = await CountRowsAsync(connection, "queued_events", cancellationToken);
            var poisonDepth = await CountRowsAsync(connection, "poison_events", cancellationToken);
            DateTimeOffset? oldestQueuedAt = null;
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "select enqueued_at from queued_events order by id limit 1;";
                var result = await command.ExecuteScalarAsync(cancellationToken);
                if (result is string value)
                {
                    oldestQueuedAt = ParseTimestamp(value);
                }
            }

            var queueBytes = QueueFileBytes();
            var maxBytes = options.MaxSizeMb * 1024L * 1024L;
            decimal? usedPercent = maxBytes > 0 ? Math.Round(queueBytes * 100m / maxBytes, 3, MidpointRounding.AwayFromZero) : null;
            return new QueueSloMetrics
            {
                QueueDepth = queueDepth,
                PoisonDepth = poisonDepth,
                OldestQueuedAgeSeconds = oldestQueuedAt.HasValue
                    ? Math.Max(0, (long)Math.Floor((DateTimeOffset.UtcNow - oldestQueuedAt.Value).TotalSeconds))
                    : null,
                QueueSizeBytes = queueBytes,
                MaxSizeBytes = maxBytes,
                UsedPercent = usedPercent,
                PressureState = QueuePressureState(queueBytes, maxBytes),
                SendState = queueDepth == 0 ? QueueSendStates.Idle : QueueSendStates.Unknown,
                LastSuccessfulSendTime = lastSuccessfulSendTime,
                PoisonEventsTotal = poisonDepth,
                DroppedEventsTotal = 0,
                MaxSizeMb = options.MaxSizeMb,
                WarningSizePercent = options.WarningSizePercent
            };
        }
        finally
        {
            gate.Release();
        }
    }

    public QueueWorkSnapshot GetWorkSnapshot()
    {
        lock (workSync)
        {
            return new(workGenerationId,
                workBySource.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));
        }
    }

    public void RecordAcknowledgedWork(IReadOnlyCollection<QueuedEvent> events)
    {
        lock (workSync)
        {
            foreach (var item in events)
            {
                var source = AttributedSource(item.Envelope.SourceId ?? item.Envelope.Source);
                var current = workBySource.GetValueOrDefault(source) ?? new(0, 0, 0, 0);
                workBySource[source] = current with
                {
                    AcknowledgedEvents = SaturatingAdd(current.AcknowledgedEvents, 1),
                    AcknowledgedPayloadBytes = SaturatingAdd(current.AcknowledgedPayloadBytes, Math.Max(0, item.SerializedPayloadBytes))
                };
            }
        }
    }

    public static TimeSpan BackoffDelayForAttempts(int sendAttempts, int maxBackoffSeconds)
    {
        return RetrySchedule.Exponential(sendAttempts, maxBackoffSeconds);
    }

    private static string? SequentialSourceKey(EventEnvelope envelope) =>
        envelope.Checkpoint?.Sequence.HasValue == true && !string.IsNullOrWhiteSpace(envelope.SourceId)
            ? $"{envelope.AgentId}\n{envelope.SourceId}"
            : null;

    private async Task InitializeUnsafeAsync(CancellationToken cancellationToken)
    {
        if (initialized)
        {
            return;
        }

        var directory = Path.GetDirectoryName(options.Path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using var connection = OpenConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            pragma journal_mode = wal;

            create table if not exists queued_events (
                id integer primary key autoincrement,
                event_id text not null,
                agent_id text not null,
                payload_json text not null,
                enqueued_at text not null,
                send_attempts integer not null default 0,
                last_attempt_at text null,
                unique (agent_id, event_id)
            );

            drop index if exists idx_queued_events_enqueued_at;
            drop index if exists idx_queued_events_attempt;

            create table if not exists poison_events (
                id integer primary key autoincrement,
                original_queue_id integer not null,
                event_id text not null,
                agent_id text not null,
                payload_json text not null,
                send_attempts integer not null,
                last_attempt_at text null,
                poisoned_at text not null,
                reason text not null
            );

            create index if not exists idx_poison_events_agent_id on poison_events(agent_id);
            create index if not exists idx_poison_events_poisoned_at on poison_events(poisoned_at);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);

        await EnsureColumnAsync(connection, "queued_events", "send_attempts", "integer not null default 0", cancellationToken);
        await EnsureColumnAsync(connection, "queued_events", "last_attempt_at", "text null", cancellationToken);
        initialized = true;
    }

    private async Task InsertBatchUnsafeAsync(
        IReadOnlyList<PendingEnqueue> pending,
        CancellationToken cancellationToken)
    {
        EnforceQueueSizeLimit();
        await using var connection = OpenConnection();
        await using var transaction = connection.BeginTransaction();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var values = new List<string>(pending.Count);
        var enqueuedAt = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        for (var index = 0; index < pending.Count; index++)
        {
            var item = pending[index];
            var eventName = $"$event_id_{index}";
            var agentName = $"$agent_id_{index}";
            var payloadName = $"$payload_json_{index}";
            var timeName = $"$enqueued_at_{index}";
            values.Add($"({eventName},{agentName},{payloadName},{timeName})");
            command.Parameters.Add(eventName, SqliteType.Text).Value = item.EventId;
            command.Parameters.Add(agentName, SqliteType.Text).Value = item.AgentId;
            command.Parameters.Add(payloadName, SqliteType.Text).Value = item.PayloadJson;
            command.Parameters.Add(timeName, SqliteType.Text).Value = enqueuedAt;
        }
        command.CommandText = $"insert or ignore into queued_events (event_id, agent_id, payload_json, enqueued_at) values {string.Join(',', values)};";
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private void RecordEnqueuedWork(IReadOnlyCollection<PendingEnqueue> pending)
    {
        lock (workSync)
        {
            foreach (var item in pending)
            {
                var source = AttributedSource(item.SourceId);
                var current = workBySource.GetValueOrDefault(source) ?? new(0, 0, 0, 0);
                workBySource[source] = current with
                {
                    EnqueuedEvents = SaturatingAdd(current.EnqueuedEvents, 1),
                    EnqueuedPayloadBytes = SaturatingAdd(current.EnqueuedPayloadBytes, item.PayloadBytes)
                };
            }
        }
    }

    private string AttributedSource(string? sourceId)
    {
        var bounded = string.IsNullOrWhiteSpace(sourceId) || sourceId.Length > 128 ? "unknown" : sourceId;
        return workBySource.ContainsKey(bounded) || workBySource.Count < MaximumAttributedSources
            ? bounded
            : OtherSource;
    }

    private static long SaturatingAdd(long left, long right) =>
        left > long.MaxValue - right ? long.MaxValue : left + right;

    private static async Task<int> CountRowsAsync(SqliteConnection connection, string tableName, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"select count(*) from {tableName};";
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, CultureInfo.InvariantCulture);
    }

    private SqliteConnection OpenConnection()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = options.Path,
            Mode = SqliteOpenMode.ReadWriteCreate
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        // Keep the existing power-loss durability boundary explicit on every pooled connection;
        // write amplification is reduced by transactions, never by relaxing synchronous mode.
        using var synchronous = connection.CreateCommand();
        synchronous.CommandText = "pragma synchronous = full;";
        synchronous.ExecuteNonQuery();
        return connection;
    }

    private long QueueFileBytes()
    {
        long total = 0;
        foreach (var suffix in new[] { string.Empty, "-wal", "-shm" })
        {
            var path = options.Path + suffix;
            if (File.Exists(path))
            {
                total += new FileInfo(path).Length;
            }
        }
        return total;
    }

    private string QueuePressureState(long currentBytes, long maxBytes)
    {
        if (maxBytes <= 0) return QueuePressureStates.Unknown;
        if (currentBytes >= maxBytes) return QueuePressureStates.Full;
        var percent = currentBytes * 100m / maxBytes;
        if (percent >= 95) return QueuePressureStates.Critical;
        if (percent >= 85) return QueuePressureStates.High;
        if (percent >= Math.Clamp(options.WarningSizePercent, 1, 100)) return QueuePressureStates.Warning;
        return QueuePressureStates.Normal;
    }

    private void EnforceQueueSizeLimit()
    {
        if (!File.Exists(options.Path))
        {
            return;
        }

        var maxBytes = options.MaxSizeMb * 1024L * 1024L;
        var currentBytes = QueueFileBytes();
        if (currentBytes <= maxBytes)
        {
            WarnOnQueuePressure(currentBytes, maxBytes);
            return;
        }

        // WAL can temporarily account for most allocated bytes. Checkpoint it before deciding
        // that the hard bound is exhausted. SQLite does not shrink the main file after deletes;
        // free pages are safe to reuse without increasing physical allocation, so a recovered
        // empty/drained queue must not become permanently unable to collect.
        var reusablePages = CheckpointAndGetReusablePageCount();
        currentBytes = QueueFileBytes();
        if (currentBytes <= maxBytes || reusablePages > 0)
        {
            WarnOnQueuePressure(currentBytes, maxBytes);
            return;
        }

        throw new InvalidOperationException($"Agent queue has exceeded its configured size limit of {options.MaxSizeMb} MB.");
    }

    private long CheckpointAndGetReusablePageCount()
    {
        using var connection = OpenConnection();
        using (var checkpoint = connection.CreateCommand())
        {
            checkpoint.CommandText = "pragma wal_checkpoint(truncate);";
            checkpoint.ExecuteNonQuery();
        }

        using var freePages = connection.CreateCommand();
        freePages.CommandText = "pragma freelist_count;";
        return Convert.ToInt64(freePages.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private void WarnOnQueuePressure(long currentBytes, long maxBytes)
    {
        var warnAtBytes = maxBytes * Math.Clamp(options.WarningSizePercent, 1, 100) / 100;
        var now = DateTimeOffset.UtcNow;
        if (currentBytes < warnAtBytes || now - lastQueueWarningAt < QueueWarningInterval)
        {
            return;
        }

        lastQueueWarningAt = now;
        logger.LogWarning(
            "Agent queue allocation is at {CurrentBytes} bytes, approaching configured limit of {MaxBytes} bytes.",
            currentBytes,
            maxBytes);
    }

    private static bool IsReadyForAttempt(int sendAttempts, DateTimeOffset? lastAttemptAt, int maxBackoffSeconds, DateTimeOffset now)
    {
        if (!lastAttemptAt.HasValue)
        {
            return true;
        }

        return now - lastAttemptAt.Value >= BackoffDelayForAttempts(sendAttempts, maxBackoffSeconds);
    }

    private static DateTimeOffset? ParseTimestamp(string value)
    {
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed.ToUniversalTime()
            : null;
    }

    private static async Task EnsureColumnAsync(
        SqliteConnection connection,
        string tableName,
        string columnName,
        string definition,
        CancellationToken cancellationToken)
    {
        await using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = $"pragma table_info({tableName});";
            await using var reader = await pragma.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }
        }

        await using var alter = connection.CreateCommand();
        alter.CommandText = $"alter table {tableName} add column {columnName} {definition};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private sealed record PendingEnqueue(string EventId, string AgentId, string SourceId, string PayloadJson, int PayloadBytes);
}

public static class EventQueueBatcher
{
    public static IReadOnlyList<IReadOnlyList<T>> Partition<T>(
        IReadOnlyCollection<T> items,
        Func<T, EventEnvelope> envelopeSelector)
    {
        if (items.Count == 0) return Array.Empty<IReadOnlyList<T>>();

        var result = new List<IReadOnlyList<T>>();
        var pending = new List<T>(Math.Min(items.Count, SqliteEventQueue.MaximumEventsPerTransaction));
        long pendingPayloadBytes = 0;
        foreach (var item in items)
        {
            var payloadBytes = Encoding.UTF8.GetByteCount(
                JsonSerializer.Serialize(envelopeSelector(item), JsonDefaults.Options));
            if (payloadBytes > SqliteEventQueue.MaximumPayloadBytesPerTransaction)
                throw new InvalidOperationException("A serialized event exceeds the durable queue transaction limit.");
            if (pending.Count > 0
                && (pending.Count >= SqliteEventQueue.MaximumEventsPerTransaction
                    || pendingPayloadBytes + payloadBytes > SqliteEventQueue.MaximumPayloadBytesPerTransaction))
            {
                result.Add(pending.ToArray());
                pending.Clear();
                pendingPayloadBytes = 0;
            }
            pending.Add(item);
            pendingPayloadBytes += payloadBytes;
        }
        if (pending.Count > 0) result.Add(pending.ToArray());
        return result;
    }

    public static IReadOnlyList<IReadOnlyList<EventEnvelope>> Partition(IReadOnlyCollection<EventEnvelope> envelopes) =>
        Partition(envelopes, envelope => envelope);
}
