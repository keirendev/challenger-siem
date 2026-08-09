using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V2;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class SqliteQueuePressureTests
{
    [Fact]
    public async Task SmallBatchIsOneAtomicFullDurabilityTransactionAndPreservesOrder()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-batch-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "queue.sqlite");
            var queue = new SqliteEventQueue(new AgentQueueOptions { Path = path }, new CountingLogger());
            await queue.InitializeAsync(default);
            var first = Event(1);
            var second = Event(2);

            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate
            }.ToString();
            await using var connection = new SqliteConnection(connectionString);
            await connection.OpenAsync();
            await using (var trigger = connection.CreateCommand())
            {
                trigger.CommandText = $"""
                    create trigger synthetic_batch_failure
                    before insert on queued_events
                    when new.event_id = '{second.EventId:D}'
                    begin
                        select raise(abort, 'synthetic batch failure');
                    end;
                    """;
                await trigger.ExecuteNonQueryAsync();
            }

            await Assert.ThrowsAsync<SqliteException>(() => queue.EnqueueBatchAsync([first, second], default));
            Assert.Equal(0, await queue.CountAsync(default));

            await using (var drop = connection.CreateCommand())
            {
                drop.CommandText = "drop trigger synthetic_batch_failure;";
                await drop.ExecuteNonQueryAsync();
            }
            await queue.EnqueueBatchAsync([first, second], default);

            var batch = await queue.DequeueBatchAsync(10, default);
            Assert.Equal([first.EventId, second.EventId], batch.Select(item => item.Envelope.EventId).ToArray());
            await using var durability = connection.CreateCommand();
            durability.CommandText = "pragma synchronous;";
            Assert.Equal(2L, (long)(await durability.ExecuteScalarAsync())!);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task QueueWorkCountersAreBoundedPerSourceAndAcknowledgementCountsOnlyAfterDelete()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-work-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var queue = new SqliteEventQueue(new AgentQueueOptions { Path = Path.Combine(root, "queue.sqlite") }, new CountingLogger());
            var first = Event(1, 128) with { SourceId = LinuxTelemetrySourceIds.PackageInventoryDiff };
            var second = Event(2, 256) with { SourceId = LinuxTelemetrySourceIds.NetworkFlowSummary };
            await queue.EnqueueBatchAsync([first, second], default);

            var afterEnqueue = queue.GetWorkSnapshot();
            Assert.NotEqual("unavailable", afterEnqueue.GenerationId);
            Assert.Equal(1, afterEnqueue.Sources[LinuxTelemetrySourceIds.PackageInventoryDiff].EnqueuedEvents);
            Assert.True(afterEnqueue.Sources[LinuxTelemetrySourceIds.PackageInventoryDiff].EnqueuedPayloadBytes > 128);
            Assert.Equal(0, afterEnqueue.Sources[LinuxTelemetrySourceIds.PackageInventoryDiff].AcknowledgedEvents);

            var batch = await queue.DequeueBatchAsync(10, default);
            await queue.DeleteAsync([batch[0].QueueId], default);
            Assert.Equal(0, queue.GetWorkSnapshot().Sources[LinuxTelemetrySourceIds.PackageInventoryDiff].AcknowledgedEvents);
            queue.RecordAcknowledgedWork([batch[0]]);

            var afterAcknowledgement = queue.GetWorkSnapshot();
            Assert.Equal(1, afterAcknowledgement.Sources[LinuxTelemetrySourceIds.PackageInventoryDiff].AcknowledgedEvents);
            Assert.Equal(batch[0].SerializedPayloadBytes,
                afterAcknowledgement.Sources[LinuxTelemetrySourceIds.PackageInventoryDiff].AcknowledgedPayloadBytes);
            Assert.Equal(0, afterAcknowledgement.Sources[LinuxTelemetrySourceIds.NetworkFlowSummary].AcknowledgedEvents);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SetBasedDeleteIsAtomicWhenOneRowTriggersFailure()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-delete-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "queue.sqlite");
            var queue = new SqliteEventQueue(new AgentQueueOptions { Path = path }, new CountingLogger());
            await queue.EnqueueBatchAsync([Event(1, 64), Event(2, 64)], default);
            var batch = await queue.DequeueBatchAsync(10, default);
            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
            await connection.OpenAsync();
            await using (var trigger = connection.CreateCommand())
            {
                trigger.CommandText = $"create trigger synthetic_delete_failure before delete on queued_events when old.id = {batch[1].QueueId} begin select raise(abort, 'synthetic delete failure'); end;";
                await trigger.ExecuteNonQueryAsync();
            }

            await Assert.ThrowsAsync<SqliteException>(() => queue.DeleteAsync(batch.Select(item => item.QueueId).ToArray(), default));
            Assert.Equal(2, await queue.CountAsync(default));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task QueueUpgradeDropsOnlyUnusedIndexesAndPreservesRowsAttemptsPoisonAndOldestIdAge()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-upgrade-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "queue.sqlite");
            var options = new AgentQueueOptions { Path = path, MaxBackoffSeconds = 300 };
            var legacy = new SqliteEventQueue(options, new CountingLogger());
            await legacy.InitializeAsync(default);
            await legacy.EnqueueBatchAsync([Event(1, 64), Event(2, 64), Event(3, 64)], default);
            var initial = await legacy.DequeueBatchAsync(10, default);
            Assert.Equal(3, initial.Count);
            await legacy.MarkAttemptAsync([initial[0].QueueId], default);
            await legacy.MarkPoisonAsync([initial[1].QueueId], "synthetic poison", default);

            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate
            }.ToString();
            await using (var connection = new SqliteConnection(connectionString))
            {
                await connection.OpenAsync();
                await using var prepare = connection.CreateCommand();
                prepare.CommandText = """
                    create index idx_queued_events_enqueued_at on queued_events(enqueued_at);
                    create index idx_queued_events_attempt on queued_events(last_attempt_at, send_attempts);
                    update queued_events
                    set enqueued_at = case id
                        when $first_id then $first_time
                        else $later_id_older_time
                    end;
                    """;
                prepare.Parameters.AddWithValue("$first_id", initial[0].QueueId);
                prepare.Parameters.AddWithValue("$first_time", DateTimeOffset.UtcNow.AddSeconds(-100).ToString("O"));
                prepare.Parameters.AddWithValue("$later_id_older_time", DateTimeOffset.UtcNow.AddSeconds(-200).ToString("O"));
                await prepare.ExecuteNonQueryAsync();
            }

            var upgraded = new SqliteEventQueue(options, new CountingLogger());
            await upgraded.InitializeAsync(default);

            Assert.Equal(2, await upgraded.CountAsync(default));
            var metrics = await upgraded.GetMetricsAsync(null, default);
            Assert.Equal(1, metrics.PoisonDepth);
            Assert.InRange(metrics.OldestQueuedAgeSeconds!.Value, 90, 130);
            var ready = Assert.Single(await upgraded.DequeueBatchAsync(10, default));
            Assert.Equal(initial[2].Envelope.EventId, ready.Envelope.EventId);

            await using var verify = new SqliteConnection(connectionString);
            await verify.OpenAsync();
            await using (var indexes = verify.CreateCommand())
            {
                indexes.CommandText = """
                    select count(*) from sqlite_master
                    where type = 'index'
                      and name in ('idx_queued_events_enqueued_at', 'idx_queued_events_attempt');
                    """;
                Assert.Equal(0L, (long)(await indexes.ExecuteScalarAsync())!);
            }
            await using (var rows = verify.CreateCommand())
            {
                rows.CommandText = """
                    select
                        (select send_attempts from queued_events where id = $first_id),
                        (select count(*) from poison_events where original_queue_id = $poison_id);
                    """;
                rows.Parameters.AddWithValue("$first_id", initial[0].QueueId);
                rows.Parameters.AddWithValue("$poison_id", initial[1].QueueId);
                await using var reader = await rows.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal(1L, reader.GetInt64(0));
                Assert.Equal(1L, reader.GetInt64(1));
            }
            await using (var rollback = verify.CreateCommand())
            {
                rollback.CommandText = """
                    create index idx_queued_events_enqueued_at on queued_events(enqueued_at);
                    create index idx_queued_events_attempt on queued_events(last_attempt_at, send_attempts);
                    """;
                await rollback.ExecuteNonQueryAsync();
            }
            await using (var durability = verify.CreateCommand())
            {
                durability.CommandText = "pragma synchronous;";
                Assert.Equal(2L, (long)(await durability.ExecuteScalarAsync())!);
            }
            Assert.Equal(2, await upgraded.CountAsync(default));
            Assert.Equal(1, (await upgraded.GetMetricsAsync(null, default)).PoisonDepth);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task LargeCollectionPartitionsIntoBoundedAtomicTransactions()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-partition-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "queue.sqlite");
            var queue = new SqliteEventQueue(new AgentQueueOptions { Path = path }, new CountingLogger());
            var events = Enumerable.Range(1, 101).Select(sequence => Event(sequence, 64)).ToArray();
            var batches = EventQueueBatcher.Partition(events);
            var payloadBatches = EventQueueBatcher.Partition(
                Enumerable.Range(1_000, 20).Select(sequence => Event(sequence, 60 * 1024)).ToArray());

            Assert.Equal([100, 1], batches.Select(batch => batch.Count));
            Assert.True(payloadBatches.Count > 1);
            Assert.All(batches, batch => Assert.InRange(batch.Count, 1, 100));
            Assert.All(payloadBatches, batch => Assert.InRange(
                batch.Sum(item => (long)Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(item, JsonDefaults.Options))),
                1,
                1024 * 1024));
            Assert.Equal(events.Select(item => item.EventId), batches.SelectMany(batch => batch).Select(item => item.EventId));
            await Assert.ThrowsAsync<InvalidOperationException>(() => queue.EnqueueBatchAsync(events, default));
            Assert.Equal(0, await queue.CountAsync(default));
            foreach (var batch in batches) await queue.EnqueueBatchAsync(batch, default);

            Assert.Equal(events.Length, await queue.CountAsync(default));
            Assert.Equal(
                events.Select(item => item.EventId),
                (await queue.DequeueBatchAsync(events.Length, default)).Select(item => item.Envelope.EventId));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task DrainedQueueReusesAllocatedPagesAfterPhysicalLimitWithoutWarningFeedback()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-pressure-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "queue.sqlite");
            var logger = new CountingLogger();
            var queue = new SqliteEventQueue(new AgentQueueOptions
            {
                Path = path,
                MaxSizeMb = 1,
                WarningSizePercent = 50,
                MaxBackoffSeconds = 1
            }, logger);
            await queue.InitializeAsync(default);

            var inserted = 0;
            while (inserted < 200)
            {
                try
                {
                    await queue.EnqueueAsync(Event(inserted), default);
                    inserted++;
                }
                catch (InvalidOperationException)
                {
                    break;
                }
            }

            Assert.InRange(inserted, 1, 199);
            Assert.InRange(logger.WarningCount, 0, 1);
            while (await queue.CountAsync(default) > 0)
            {
                var batch = await queue.DequeueBatchAsync(100, default);
                await queue.DeleteAsync(batch.Select(item => item.QueueId).ToArray(), default);
            }

            var allocatedBeforeReuse = QueueBytes(path);
            await queue.EnqueueAsync(Event(10_000), default);

            Assert.Equal(1, await queue.CountAsync(default));
            Assert.True(QueueBytes(path) <= allocatedBeforeReuse + 64 * 1024,
                "Recovered enqueue unexpectedly grew the queue allocation instead of reusing freed pages.");
            Assert.InRange(logger.WarningCount, 0, 1);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task BackedOffSequenceBlocksOnlyLaterRowsFromTheSameCheckpointSource()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-order-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var queue = new SqliteEventQueue(new AgentQueueOptions
            {
                Path = Path.Combine(root, "queue.sqlite"),
                MaxBackoffSeconds = 300
            }, new CountingLogger());
            await queue.InitializeAsync(default);
            await queue.EnqueueAsync(SequencedEvent(1), default);
            await queue.EnqueueAsync(SequencedEvent(2), default);
            await queue.EnqueueAsync(Event(3) with { SourceId = LinuxTelemetrySourceIds.JournalL1 }, default);
            var initial = await queue.DequeueBatchAsync(10, default);
            Assert.Equal(3, initial.Count);
            await queue.MarkAttemptAsync([initial[0].QueueId], default);

            var retry = await queue.DequeueBatchAsync(10, default);

            var remaining = Assert.Single(retry);
            Assert.Equal(LinuxTelemetrySourceIds.JournalL1, remaining.Envelope.SourceId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task BackedOffSequenceDoesNotHideReadySourcesBeyondTheFirstScanPage()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-queue-page-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var queue = new SqliteEventQueue(new AgentQueueOptions
            {
                Path = Path.Combine(root, "queue.sqlite"),
                MaxBackoffSeconds = 300
            }, new CountingLogger());
            await queue.InitializeAsync(default);
            await queue.EnqueueAsync(SequencedEvent(1), default);
            var head = Assert.Single(await queue.DequeueBatchAsync(1, default));
            await queue.MarkAttemptAsync([head.QueueId], default);
            for (var sequence = 2; sequence <= 11; sequence++)
                await queue.EnqueueAsync(SequencedEvent(sequence), default);
            await queue.EnqueueAsync(Event(12) with { SourceId = LinuxTelemetrySourceIds.JournalL1 }, default);

            var retry = Assert.Single(await queue.DequeueBatchAsync(1, default));

            Assert.Equal(LinuxTelemetrySourceIds.JournalL1, retry.Envelope.SourceId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static EventEnvelope Event(int sequence, int paddingBytes = 48 * 1024) => new()
    {
        EventId = Guid.NewGuid(),
        AgentId = "synthetic-pressure-agent",
        Hostname = "synthetic-pressure-host",
        Platform = "linux",
        Source = EventSources.AgentHealth,
        SourceId = LinuxTelemetrySourceIds.AgentPerformanceSlo,
        EventTime = DateTimeOffset.UtcNow,
        Message = $"synthetic queue pressure {sequence}",
        Raw = JsonSerializer.SerializeToElement(new { padding = new string('x', paddingBytes) })
    };

    private static EventEnvelope SequencedEvent(long sequence) => Event((int)sequence) with
    {
        Checkpoint = new SourceCheckpoint
        {
            Sequence = sequence,
            EventTime = DateTimeOffset.UtcNow,
            RecordedAt = DateTimeOffset.UtcNow
        }
    };

    private static long QueueBytes(string path) => new[] { path, path + "-wal", path + "-shm" }
        .Where(File.Exists)
        .Sum(file => new FileInfo(file).Length);

    private sealed class CountingLogger : ILogger<SqliteEventQueue>
    {
        public int WarningCount { get; private set; }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                WarningCount++;
            }
        }
    }
}
