using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Collectors;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.WindowsAgent.Queue;
using Challenger.Siem.WindowsAgent.State;
using Challenger.Siem.WindowsAgent.Util;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.WindowsAgent.Tests;

public sealed class AgentCoreTests
{
    [Fact]
    public void DeterministicGuidUsesStableIdentityFields()
    {
        var first = DeterministicGuid.Create("agent-1", "System", "42", "Provider", "6005");
        var second = DeterministicGuid.Create("agent-1", "System", "42", "Provider", "6005");
        var different = DeterministicGuid.Create("agent-1", "System", "43", "Provider", "6005");

        Assert.Equal(first, second);
        Assert.NotEqual(first, different);
    }

    [Theory]
    [InlineData(1, "critical")]
    [InlineData(2, "error")]
    [InlineData(3, "warning")]
    [InlineData(4, "information")]
    [InlineData(5, "verbose")]
    public void SeverityMapperMapsWindowsLevels(int level, string expected)
    {
        Assert.Equal(expected, WindowsEventSeverityMapper.Map(level, Array.Empty<string>()));
    }

    [Fact]
    public void SeverityMapperPrefersAuditKeywords()
    {
        Assert.Equal("audit_success", WindowsEventSeverityMapper.Map(4, new[] { "Audit Success" }));
        Assert.Equal("audit_failure", WindowsEventSeverityMapper.Map(4, new[] { "Audit Failure" }));
    }

    [Fact]
    public async Task SqliteQueueEnqueuesDeduplicatesMarksAttemptsAndDeletes()
    {
        using var temp = new TempDirectory();
        var queue = CreateQueue(Path.Combine(temp.Path, "queue.sqlite"));
        var envelope = CreateEvent(Guid.NewGuid());

        await queue.InitializeAsync(CancellationToken.None);
        await queue.EnqueueAsync(envelope, CancellationToken.None);
        await queue.EnqueueAsync(envelope, CancellationToken.None);

        Assert.Equal(1, await queue.CountAsync(CancellationToken.None));
        var batch = await queue.DequeueBatchAsync(10, CancellationToken.None);
        var queued = Assert.Single(batch);
        Assert.Equal(0, queued.SendAttempts);

        await queue.MarkAttemptAsync(new[] { queued.QueueId }, CancellationToken.None);
        var delayed = await queue.DequeueBatchAsync(10, CancellationToken.None);
        Assert.Empty(delayed);

        await queue.DeleteAsync(new[] { queued.QueueId }, CancellationToken.None);
        Assert.Equal(0, await queue.CountAsync(CancellationToken.None));
    }

    [Fact]
    public async Task SqliteQueueQuarantinesPoisonEventsWithoutCountingThemAsActiveDepth()
    {
        using var temp = new TempDirectory();
        var queue = CreateQueue(Path.Combine(temp.Path, "queue.sqlite"));
        var envelope = CreateEvent(Guid.NewGuid());

        await queue.EnqueueAsync(envelope, CancellationToken.None);
        var queued = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));
        await queue.MarkPoisonAsync(new[] { queued.QueueId }, "unit-test", CancellationToken.None);

        Assert.Equal(0, await queue.CountAsync(CancellationToken.None));
    }

    [Fact]
    public async Task SqliteQueueEnforcesSizeLimit()
    {
        using var temp = new TempDirectory();
        var queuePath = Path.Combine(temp.Path, "queue.sqlite");
        var queue = CreateQueue(queuePath, maxSizeMb: 1);
        await queue.InitializeAsync(CancellationToken.None);
        await File.WriteAllBytesAsync(queuePath, new byte[1024 * 1024 + 1], CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() => queue.EnqueueAsync(CreateEvent(Guid.NewGuid()), CancellationToken.None));
    }

    [Fact]
    public async Task JsonChannelStateStoreReadsAndWritesPerChannelRecordIds()
    {
        using var temp = new TempDirectory();
        var statePath = Path.Combine(temp.Path, "state.json");
        var store = new JsonChannelStateStore(
            Options.Create(new AgentOptions { State = new StateOptions { Path = statePath } }),
            NullLogger<JsonChannelStateStore>.Instance);

        Assert.Null(await store.GetLastRecordIdAsync("System", CancellationToken.None));
        await store.SetLastRecordIdAsync("System", 123, CancellationToken.None);
        await store.SetLastRecordIdAsync("Application", 456, CancellationToken.None);

        var state = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(123, state["System"]);
        Assert.Equal(456, state["Application"]);
    }

    private static SqliteEventQueue CreateQueue(string path, int maxSizeMb = 512)
    {
        return new SqliteEventQueue(
            Options.Create(new AgentOptions
            {
                Queue = new QueueOptions
                {
                    Path = path,
                    MaxSizeMb = maxSizeMb,
                    MaxSendAttempts = 3,
                    MaxBackoffSeconds = 300,
                    WarningSizePercent = 80
                }
            }),
            NullLogger<SqliteEventQueue>.Instance);
    }

    private static EventEnvelope CreateEvent(Guid eventId)
    {
        return new EventEnvelope
        {
            EventId = eventId,
            AgentId = "agent-unit-test",
            Hostname = "UNIT-HOST",
            Source = EventSources.WindowsEventLog,
            Channel = "System",
            Provider = "UnitProvider",
            WindowsEventId = 6005,
            RecordId = 42,
            EventTime = DateTimeOffset.UtcNow,
            Severity = "information",
            Message = "unit test event",
            Raw = JsonSerializer.SerializeToElement(new { unit = true })
        };
    }

    private sealed class TempDirectory : IDisposable
    {
        public TempDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "challenger-siem-agent-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
