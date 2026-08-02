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
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Shared
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
