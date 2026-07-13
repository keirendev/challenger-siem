using System.Globalization;
using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Agent.Core.Reliability;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace Challenger.Siem.Agent.Core.Queue;

public sealed class SqliteEventQueue(AgentQueueOptions options, ILogger<SqliteEventQueue> logger) : IEventQueue
{
    private readonly SemaphoreSlim gate = new(1, 1);

    private bool initialized;

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

    public async Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            await InitializeUnsafeAsync(cancellationToken);
            EnforceQueueSizeLimit();

            await using var connection = OpenConnection();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                insert or ignore into queued_events (event_id, agent_id, payload_json, enqueued_at)
                values ($event_id, $agent_id, $payload_json, $enqueued_at);
                """;
            command.Parameters.AddWithValue("$event_id", envelope.EventId.ToString());
            command.Parameters.AddWithValue("$agent_id", envelope.AgentId);
            command.Parameters.AddWithValue("$payload_json", JsonSerializer.Serialize(envelope, JsonDefaults.Options));
            command.Parameters.AddWithValue("$enqueued_at", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await command.ExecuteNonQueryAsync(cancellationToken);
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
            await using var connection = OpenConnection();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                select id, payload_json, send_attempts, last_attempt_at
                from queued_events
                order by id
                limit $scan_limit;
                """;
            command.Parameters.AddWithValue("$scan_limit", Math.Max(maxEvents, maxEvents * 10));

            var results = new List<QueuedEvent>(Math.Max(1, maxEvents));
            var now = DateTimeOffset.UtcNow;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken) && results.Count < maxEvents)
            {
                var queueId = reader.GetInt64(0);
                var payloadJson = reader.GetString(1);
                var sendAttempts = reader.GetInt32(2);
                var lastAttemptAt = reader.IsDBNull(3) ? null : ParseTimestamp(reader.GetString(3));
                if (!IsReadyForAttempt(sendAttempts, lastAttemptAt, options.MaxBackoffSeconds, now))
                {
                    continue;
                }

                var envelope = JsonSerializer.Deserialize<EventEnvelope>(payloadJson, JsonDefaults.Options);
                if (envelope is null)
                {
                    logger.LogWarning("Queued event {QueueId} could not be deserialized.", queueId);
                    continue;
                }

                results.Add(new QueuedEvent(queueId, envelope, sendAttempts, lastAttemptAt));
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

            foreach (var queueId in queueIds)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = "delete from queued_events where id = $id;";
                command.Parameters.AddWithValue("$id", queueId);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

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
                command.CommandText = "select min(enqueued_at) from queued_events;";
                var result = await command.ExecuteScalarAsync(cancellationToken);
                if (result is string value)
                {
                    oldestQueuedAt = ParseTimestamp(value);
                }
            }

            return new QueueSloMetrics
            {
                QueueDepth = queueDepth,
                PoisonDepth = poisonDepth,
                OldestQueuedAgeSeconds = oldestQueuedAt.HasValue
                    ? Math.Max(0, (long)Math.Floor((DateTimeOffset.UtcNow - oldestQueuedAt.Value).TotalSeconds))
                    : null,
                LastSuccessfulSendTime = lastSuccessfulSendTime,
                MaxSizeMb = options.MaxSizeMb,
                WarningSizePercent = options.WarningSizePercent
            };
        }
        finally
        {
            gate.Release();
        }
    }

    public static TimeSpan BackoffDelayForAttempts(int sendAttempts, int maxBackoffSeconds)
    {
        return RetrySchedule.Exponential(sendAttempts, maxBackoffSeconds);
    }

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

            create index if not exists idx_queued_events_enqueued_at on queued_events(enqueued_at);
            create index if not exists idx_queued_events_attempt on queued_events(last_attempt_at, send_attempts);

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
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        return connection;
    }

    private void EnforceQueueSizeLimit()
    {
        if (!File.Exists(options.Path))
        {
            return;
        }

        var maxBytes = options.MaxSizeMb * 1024L * 1024L;
        var currentBytes = new FileInfo(options.Path).Length;
        if (currentBytes <= maxBytes)
        {
            var warnAtBytes = maxBytes * Math.Clamp(options.WarningSizePercent, 1, 100) / 100;
            if (currentBytes >= warnAtBytes)
            {
                logger.LogWarning(
                    "Agent queue file is at {CurrentBytes} bytes, approaching configured limit of {MaxBytes} bytes.",
                    currentBytes,
                    maxBytes);
            }

            return;
        }

        throw new InvalidOperationException($"Agent queue has exceeded its configured size limit of {options.MaxSizeMb} MB.");
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
}
