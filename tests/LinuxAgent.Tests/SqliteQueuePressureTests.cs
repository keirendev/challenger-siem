using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Contracts.V2;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class SqliteQueuePressureTests
{
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

    private static EventEnvelope Event(int sequence) => new()
    {
        EventId = Guid.NewGuid(),
        AgentId = "synthetic-pressure-agent",
        Hostname = "synthetic-pressure-host",
        Platform = "linux",
        Source = EventSources.AgentHealth,
        SourceId = LinuxTelemetrySourceIds.AgentPerformanceSlo,
        EventTime = DateTimeOffset.UtcNow,
        Message = $"synthetic queue pressure {sequence}",
        Raw = JsonSerializer.SerializeToElement(new { padding = new string('x', 48 * 1024) })
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
