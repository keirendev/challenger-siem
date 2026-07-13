using System.Text.Json;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.WindowsAgent.Collectors;
using Challenger.Siem.WindowsAgent.Config;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.WindowsAgent.State;
using Challenger.Siem.WindowsAgent.Time;
using Challenger.Siem.Agent.Core.Util;
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
    public async Task SqliteQueuePreservesHostTimezoneMetadata()
    {
        using var temp = new TempDirectory();
        var queue = CreateQueue(Path.Combine(temp.Path, "queue.sqlite"));
        var envelope = CreateEvent(Guid.NewGuid()) with
        {
            HostTimezone = new HostTimezoneMetadata
            {
                Id = "Pacific Standard Time",
                DisplayName = "(UTC-08:00) Pacific Time (US & Canada)",
                BaseUtcOffsetMinutes = -480,
                UtcOffsetMinutes = -420,
                IsDaylightSavingTime = true
            }
        };

        await queue.EnqueueAsync(envelope, CancellationToken.None);
        var queued = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));

        Assert.Equal("Pacific Standard Time", queued.Envelope.HostTimezone?.Id);
        Assert.Equal(-420, queued.Envelope.HostTimezone?.UtcOffsetMinutes);
    }

    [Fact]
    public void HostTimezoneProviderTreatsUnspecifiedEventRecordTimesAsHostLocal()
    {
        var timeZone = TimeZoneInfo.CreateCustomTimeZone("Synthetic UTC+02", TimeSpan.FromHours(2), "Synthetic UTC+02", "Synthetic UTC+02");
        var localHostTime = new DateTime(2026, 1, 15, 10, 30, 0, DateTimeKind.Unspecified);

        var utc = HostTimezoneProvider.ToUtc(localHostTime, timeZone);

        Assert.Equal(new DateTimeOffset(2026, 1, 15, 8, 30, 0, TimeSpan.Zero), utc);
    }

    [Fact]
    public void HostTimezoneProviderCapturesEventSpecificDstOffset()
    {
        var pacific = CreatePacificLikeTimeZone();

        var summer = HostTimezoneProvider.ForInstant(new DateTimeOffset(2026, 7, 4, 12, 0, 0, TimeSpan.Zero), pacific);
        var winter = HostTimezoneProvider.ForInstant(new DateTimeOffset(2026, 1, 4, 12, 0, 0, TimeSpan.Zero), pacific);

        Assert.Equal("Pacific Standard Time", summer.Id);
        Assert.Equal(-420, summer.UtcOffsetMinutes);
        Assert.True(summer.IsDaylightSavingTime);
        Assert.Equal(-480, winter.UtcOffsetMinutes);
        Assert.False(winter.IsDaylightSavingTime);
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
            new AgentQueueOptions
            {
                Path = path,
                MaxSizeMb = maxSizeMb,
                MaxSendAttempts = 3,
                MaxBackoffSeconds = 300,
                WarningSizePercent = 80
            },
            NullLogger<SqliteEventQueue>.Instance);
    }

    private static TimeZoneInfo CreatePacificLikeTimeZone()
    {
        var daylightStart = TimeZoneInfo.TransitionTime.CreateFloatingDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            3,
            2,
            DayOfWeek.Sunday);
        var daylightEnd = TimeZoneInfo.TransitionTime.CreateFloatingDateRule(
            new DateTime(1, 1, 1, 2, 0, 0),
            11,
            1,
            DayOfWeek.Sunday);
        var rule = TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(
            new DateTime(2020, 1, 1),
            new DateTime(2030, 12, 31),
            TimeSpan.FromHours(1),
            daylightStart,
            daylightEnd);

        return TimeZoneInfo.CreateCustomTimeZone(
            "Pacific Standard Time",
            TimeSpan.FromHours(-8),
            "(UTC-08:00) Pacific Time (US & Canada)",
            "Pacific Standard Time",
            "Pacific Daylight Time",
            new[] { rule });
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
