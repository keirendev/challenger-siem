using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Challenger.Siem.LinuxAgent.Services;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxJournalTests
{
    [Fact]
    public void NormalizationIsBoundedRedactedClassifiedAndServerCompatible()
    {
        var records = FixtureRecords();
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions("unused", "unused");
        Assert.True(normalizer.TryNormalize(records[0], options, DateTimeOffset.UtcNow, out var kernel, out _));
        Assert.Equal("kernel", kernel!.Envelope.Normalized!.Category);
        Assert.True(normalizer.TryNormalize(records[1], options, DateTimeOffset.UtcNow, out var service, out _));
        Assert.Equal("service", service!.Envelope.Normalized!.Category);
        Assert.Contains("<redacted>", service.Envelope.Message);
        Assert.True(service.Envelope.DataHandling!.RedactionApplied);
        Assert.Equal(service.Envelope.EventId, DeterministicEventIdentity.ComputeSha256Uuid(service.Envelope));
        Assert.True(service.Envelope.DataHandling.RawSizeBytes <= ContractLimits.RawPayloadMaxUtf8Bytes);
        Assert.True(normalizer.TryNormalize(records[2], options, DateTimeOffset.UtcNow, out var authentication, out _));
        Assert.Equal("authentication", authentication!.Envelope.Normalized!.Category);
        Assert.True(normalizer.TryNormalize(records[3], options, DateTimeOffset.UtcNow, out var boot, out _));
        Assert.Equal("boot", boot!.Envelope.Normalized!.Category);
        Assert.True(normalizer.TryNormalize(records[4], options, DateTimeOffset.UtcNow, out var system, out _));
        Assert.Equal("system", system!.Envelope.Normalized!.Category);

        var oversizedMessage = new string('x', 30000);
        var oversized = Record("large", 1783944003000000, oversizedMessage);
        Assert.True(normalizer.TryNormalize(oversized, options, DateTimeOffset.UtcNow, out var bounded, out _));
        Assert.Equal(20000, bounded!.Envelope.Message.Length);
        Assert.True(bounded.Envelope.DataHandling!.TruncationApplied);
    }

    [Fact]
    public void MalformedBinaryAndInvalidTextAreExplicitAndDoNotCrash()
    {
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions("unused", "unused");
        Assert.False(normalizer.TryNormalize("{not-json", options, DateTimeOffset.UtcNow, out _, out var malformed));
        Assert.Equal("journal_record_malformed", malformed);
        var binary = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["__CURSOR"] = "binary-cursor", ["__REALTIME_TIMESTAMP"] = "1783944000000000",
            ["_BOOT_ID"] = "fakeboot", ["_TRANSPORT"] = "journal", ["MESSAGE"] = new[] { 0, 255, 1 }
        });
        Assert.True(normalizer.TryNormalize(binary, options, DateTimeOffset.UtcNow, out var record, out _));
        Assert.True(record!.Envelope.DataHandling!.RedactionApplied);
        Assert.Contains("raw.MESSAGE", record.Envelope.DataHandling.RedactedFields);
        var control = Record("control", 1783944000000001, "safe\u0001text");
        Assert.True(normalizer.TryNormalize(control, options, DateTimeOffset.UtcNow, out var sanitized, out _));
        Assert.Contains('\uFFFD', sanitized!.Envelope.Message);
    }

    [Fact]
    public async Task QueueCommitAlwaysPrecedesCollectedCheckpointAndRestartResumesCursor()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var queue = CreateQueue(temporary.Queue);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var service = Service(options, new FakeSource(new(JournalReadStatus.Success, FixtureRecords())), runtime, queue);
        var cursor = await service.CollectOnceAsync(null, default);
        Assert.Equal("s=synthetic;i=5;b=fake", cursor);
        Assert.Equal(5, await queue.CountAsync(default));
        Assert.Equal(cursor, (await state.ReadJournalAsync(default)).CollectedCursor);

        var restarted = Runtime(options, new LinuxStateStore(temporary.State));
        await restarted.InitializeAsync("test", "config", default);
        Assert.Equal(cursor, restarted.CollectedCursor);

        using var failure = new TemporaryPaths();
        var failureOptions = TestOptions(failure.Queue, failure.State);
        var failureState = new LinuxStateStore(failure.State);
        var failureRuntime = Runtime(failureOptions, failureState);
        await failureRuntime.InitializeAsync("test", "config", default);
        var failing = new ThrowingQueue();
        await Assert.ThrowsAsync<IOException>(() => Service(failureOptions, new FakeSource(new(JournalReadStatus.Success, [FixtureRecords()[0]])), failureRuntime, failing).CollectOnceAsync(null, default));
        Assert.Null((await failureState.ReadJournalAsync(default)).CollectedCursor);
    }

    [Theory]
    [InlineData(JournalGapKind.Rotation, "rotation")]
    [InlineData(JournalGapKind.Vacuum, "vacuum")]
    [InlineData(JournalGapKind.InvalidCursor, "invalid_cursor")]
    public async Task RotationVacuumAndInvalidCursorProduceExplicitGapHealth(JournalGapKind gap, string expected)
    {
        using var temporary = new TemporaryPaths();
        var runtime = Runtime(TestOptions(temporary.Queue, temporary.State), new LinuxStateStore(temporary.State));
        await runtime.InitializeAsync("test", "config", default);
        runtime.RecordReadResult(new(JournalReadStatus.InvalidCursor, Array.Empty<string>(), gap, "journal_cursor_invalid"));
        var snapshot = runtime.Snapshot();
        Assert.True(snapshot.Health.GapDetected);
        Assert.Equal(expected, snapshot.Health.Details["gap_state"]);
        Assert.Equal(SourceHealthStatuses.Error, snapshot.Health.Status);
    }

    [Fact]
    public async Task PermissionEmptyMalformedDuplicateReorderAndThrottleStatesAreVisible()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var runtime = Runtime(options, new LinuxStateStore(temporary.State));
        await runtime.InitializeAsync("test", "config", default);
        runtime.RecordReadResult(new(JournalReadStatus.Success, Array.Empty<string>()));
        Assert.Equal("empty", runtime.Snapshot().Health.Details["collector_state"]);
        runtime.RecordReadResult(new(JournalReadStatus.PermissionDenied, Array.Empty<string>(), ErrorCode: "journal_permission_denied"));
        Assert.Equal("denied", runtime.Snapshot().Health.Details["permission_state"]);

        var reordered = new[] { FixtureRecords()[1], FixtureRecords()[0], FixtureRecords()[1], BinaryRecord(), "malformed" };
        var queue = CreateQueue(temporary.Queue);
        await Service(options, new FakeSource(new(JournalReadStatus.Success, reordered)), runtime, queue).CollectOnceAsync(null, default);
        var health = runtime.Snapshot().Health;
        Assert.Equal("1", health.Details["duplicate_records"]);
        Assert.Equal("1", health.Details["reordered_records"]);
        Assert.Equal("1", health.Details["malformed_records"]);
        Assert.Equal("1", health.Details["binary_or_invalid_text_records"]);
        Assert.True(health.GapDetected);

        var pressureQueue = new CountQueue(options.Journal.QueuePauseDepth);
        await Service(options, new FakeSource(new(JournalReadStatus.Success, FixtureRecords())), runtime, pressureQueue).CollectOnceAsync(runtime.CollectedCursor, default);
        Assert.Equal("active", runtime.Snapshot().Health.Details["throttle_state"]);
        Assert.Equal(0, pressureQueue.EnqueueCalls);
    }

    [Fact]
    public async Task OutageLeavesReplayDurableAndAcknowledgementAdvancesBeforeDeletion()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var queue = CreateQueue(temporary.Queue, 0);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        await Service(options, new FakeSource(new(JournalReadStatus.Success, [FixtureRecords()[0]])), runtime, queue).CollectOnceAsync(null, default);

        var handler = new SwitchingHandler();
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://siem.synthetic") };
        var drainer = new LinuxQueueDrainer(Options.Create(options), queue, new SiemIngestClient(http, options), runtime);
        await Assert.ThrowsAsync<HttpRequestException>(() => drainer.DrainAsync(default));
        Assert.Equal(1, await queue.CountAsync(default));
        Assert.Null((await state.ReadJournalAsync(default)).AcknowledgedCursor);

        handler.Fail = false;
        await drainer.DrainAsync(default);
        Assert.Equal(0, await queue.CountAsync(default));
        Assert.Equal("s=synthetic;i=1;b=fake", (await state.ReadJournalAsync(default)).AcknowledgedCursor);
    }

    [Fact]
    public void BoundedSyntheticHighVolumeBenchmarkMeetsL1MemoryAndThroughputGuardrails()
    {
        var normalizer = new LinuxJournalNormalizer();
        var options = TestOptions("unused", "unused");
        const int count = 5000;
        var beforeMemory = GC.GetTotalAllocatedBytes(true);
        var stopwatch = Stopwatch.StartNew();
        for (var index = 0; index < count; index++)
        {
            Assert.True(normalizer.TryNormalize(Record($"bench-{index}", 1783944000000000L + index, "bounded synthetic benchmark"), options, DateTimeOffset.UtcNow, out var record, out _));
            Assert.True(record!.Envelope.DataHandling!.RawSizeBytes < 4096);
        }
        stopwatch.Stop();
        var allocated = GC.GetTotalAllocatedBytes(true) - beforeMemory;
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), $"Synthetic normalization took {stopwatch.Elapsed}.");
        Assert.True(allocated < 250L * 1024 * 1024, $"Synthetic normalization allocated {allocated} bytes.");
        Assert.True(count / stopwatch.Elapsed.TotalSeconds >= 500, "Synthetic normalization throughput fell below 500 records/s.");
    }

    private static LinuxJournalRuntime Runtime(LinuxAgentOptions options, LinuxStateStore state) => new(Options.Create(options), state, TimeProvider.System);
    private static LinuxJournalService Service(LinuxAgentOptions options, ILinuxJournalSource source, LinuxJournalRuntime runtime, IEventQueue queue) =>
        new(Options.Create(options), source, new LinuxJournalNormalizer(), runtime, queue, TimeProvider.System, NullLogger<LinuxJournalService>.Instance);
    private static SqliteEventQueue CreateQueue(string path, int maxBackoff = 0) => new(new AgentQueueOptions { Path = path, MaxBackoffSeconds = maxBackoff }, NullLogger<SqliteEventQueue>.Instance);
    private static LinuxAgentOptions TestOptions(string queue, string state) => new()
    {
        AgentId = "linux-synthetic-001", ApiToken = "fake-test-token", ServerBaseUrl = new Uri("https://siem.synthetic"),
        DrainBatchSize = 100, Queue = new QueueOptions { Path = queue }, State = new StateOptions { Path = state }
    };
    private static string[] FixtureRecords()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "synthetic-journal-cases.json")));
        return document.RootElement.EnumerateArray().Select(item => item.GetRawText()).ToArray();
    }
    private static string BinaryRecord() => JsonSerializer.Serialize(new Dictionary<string, object>
    {
        ["__CURSOR"] = "binary-health", ["__REALTIME_TIMESTAMP"] = "1783944005000000",
        ["_BOOT_ID"] = "00000000000000000000000000000001", ["_TRANSPORT"] = "journal", ["MESSAGE"] = new[] { 0, 255 }
    });
    private static string Record(string cursor, long timestamp, string message) => JsonSerializer.Serialize(new Dictionary<string, string>
    {
        ["__CURSOR"] = cursor, ["__REALTIME_TIMESTAMP"] = timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["_BOOT_ID"] = "00000000000000000000000000000001", ["_TRANSPORT"] = "journal", ["PRIORITY"] = "6", ["MESSAGE"] = message
    });

    private sealed class FakeSource(JournalReadResult result) : ILinuxJournalSource
    {
        public Task<JournalReadResult> ReadAsync(string? afterCursor, int maxRecords, int maxRecordBytes, CancellationToken cancellationToken) => Task.FromResult(result);
    }
    private sealed class TemporaryPaths : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "challenger-journal-test-" + Guid.NewGuid().ToString("N"));
        public TemporaryPaths() => Directory.CreateDirectory(root);
        public string Queue => Path.Combine(root, "queue.sqlite");
        public string State => Path.Combine(root, "state.json");
        public void Dispose() => Directory.Delete(root, true);
    }
    private class CountQueue(int count) : IEventQueue
    {
        public int EnqueueCalls { get; private set; }
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public virtual Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) { EnqueueCalls++; return Task.CompletedTask; }
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<QueuedEvent>>(Array.Empty<QueuedEvent>());
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(count);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) => Task.FromResult(new QueueSloMetrics { QueueDepth = count });
    }
    private sealed class ThrowingQueue : CountQueue
    {
        public ThrowingQueue() : base(0) { }
        public override Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) => throw new IOException("synthetic queue failure");
    }
    private sealed class SwitchingHandler : HttpMessageHandler
    {
        public bool Fail { get; set; } = true;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Fail) return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("synthetic outage") };
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            var batchId = document.RootElement.GetProperty("batch_id").GetString();
            var ids = document.RootElement.GetProperty("events").EnumerateArray().Select(item => item.GetProperty("event_id").GetString()).ToArray();
            var json = JsonSerializer.Serialize(new { batch_id = batchId, accepted = ids.Length, rejected = 0, duplicates = 0, accepted_event_ids = ids, duplicate_event_ids = Array.Empty<string>(), rejected_event_ids = Array.Empty<string>() });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }
}
