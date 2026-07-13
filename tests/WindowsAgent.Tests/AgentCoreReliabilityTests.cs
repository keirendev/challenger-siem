using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Reliability;
using Challenger.Siem.Contracts.V1;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Challenger.Siem.WindowsAgent.Tests;

public sealed class AgentCoreReliabilityTests
{
    [Fact]
    public void PartialAcknowledgementDeletesOnlyAcceptedAndDuplicateEvents()
    {
        var accepted = QueueItem(1, Guid.NewGuid());
        var duplicate = QueueItem(2, Guid.NewGuid());
        var unacknowledged = QueueItem(3, Guid.NewGuid());
        var response = new IngestBatchResponse
        {
            Accepted = 1,
            Duplicates = 1,
            AcceptedEventIds = new[] { accepted.Envelope.EventId },
            DuplicateEventIds = new[] { duplicate.Envelope.EventId }
        };

        Assert.Equal(new long[] { 1, 2 }, IngestAcknowledgement.AcknowledgedQueueIds(new[] { accepted, duplicate, unacknowledged }, response));
    }

    [Fact]
    public async Task QueueSurvivesCoreInstanceRestartAndSuppressesDuplicateReplay()
    {
        var path = Path.Combine(Path.GetTempPath(), $"challenger-core-{Guid.NewGuid():N}.sqlite");
        try
        {
            var envelope = QueueItem(0, Guid.NewGuid()).Envelope;
            var first = CreateQueue(path);
            await first.EnqueueAsync(envelope, CancellationToken.None);
            await first.EnqueueAsync(envelope, CancellationToken.None);

            var restarted = CreateQueue(path);
            var batch = await restarted.DequeueBatchAsync(10, CancellationToken.None);
            Assert.Single(batch);
            Assert.Equal(envelope.EventId, batch[0].Envelope.EventId);
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" }) File.Delete(path + suffix);
        }
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 2)]
    [InlineData(20, 30)]
    public void RetryScheduleIsBounded(int attempts, int expectedSeconds) =>
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), RetrySchedule.Exponential(attempts, 30));

    private static SqliteEventQueue CreateQueue(string path) => new(
        new AgentQueueOptions { Path = path, MaxSizeMb = 16, MaxSendAttempts = 3, MaxBackoffSeconds = 30, WarningSizePercent = 80 },
        NullLogger<SqliteEventQueue>.Instance);

    private static QueuedEvent QueueItem(long id, Guid eventId) => new(id, new EventEnvelope
    {
        EventId = eventId,
        AgentId = "synthetic-agent",
        Hostname = "SYNTHETIC-WIN-01",
        Source = EventSources.WindowsEventLog,
        Channel = "System",
        Provider = "SyntheticProvider",
        WindowsEventId = 1,
        RecordId = id + 1,
        EventTime = DateTimeOffset.UtcNow,
        Message = "synthetic",
        Raw = System.Text.Json.JsonDocument.Parse("{}").RootElement.Clone()
    }, 0, null);
}
