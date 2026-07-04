using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Serialization;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.WindowsAgent.Queue;

public sealed class SqliteEventQueue(IOptions<AgentOptions> options, ILogger<SqliteEventQueue> logger) : IEventQueue
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly AgentOptions options = options.Value;
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
            command.Parameters.AddWithValue("$enqueued_at", DateTimeOffset.UtcNow.ToString("O"));
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
                select id, payload_json
                from queued_events
                order by id
                limit $limit;
                """;
            command.Parameters.AddWithValue("$limit", maxEvents);

            var results = new List<QueuedEvent>(Math.Max(1, maxEvents));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var queueId = reader.GetInt64(0);
                var payloadJson = reader.GetString(1);
                var envelope = JsonSerializer.Deserialize<EventEnvelope>(payloadJson, JsonDefaults.Options);
                if (envelope is null)
                {
                    logger.LogWarning("Queued event {QueueId} could not be deserialized.", queueId);
                    continue;
                }

                results.Add(new QueuedEvent(queueId, envelope));
            }

            return results;
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
            return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task InitializeUnsafeAsync(CancellationToken cancellationToken)
    {
        if (initialized)
        {
            return;
        }

        var directory = Path.GetDirectoryName(options.Queue.Path);
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
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        initialized = true;
    }

    private SqliteConnection OpenConnection()
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = options.Queue.Path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        return connection;
    }

    private void EnforceQueueSizeLimit()
    {
        if (!File.Exists(options.Queue.Path))
        {
            return;
        }

        var maxBytes = options.Queue.MaxSizeMb * 1024L * 1024L;
        var currentBytes = new FileInfo(options.Queue.Path).Length;
        if (currentBytes <= maxBytes)
        {
            return;
        }

        throw new InvalidOperationException($"Agent queue has exceeded its configured size limit of {options.Queue.MaxSizeMb} MB.");
    }
}
