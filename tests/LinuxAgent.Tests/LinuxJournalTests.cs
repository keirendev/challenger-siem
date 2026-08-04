using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Transport;
using Challenger.Siem.Contracts.V2;
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
    public void JournalProcessArgumentsKeepBothScopesFixedAndBounded()
    {
        var system = LinuxJournalProcessSource.BuildReadStartInfo(
            "/usr/bin/journalctl", false, null, 500);
        var systemArguments = system.ArgumentList.ToArray();
        Assert.Contains("--system", systemArguments);
        Assert.Equal(1, systemArguments.Count(value => value == "--system"));
        Assert.Contains("--lines=500", systemArguments);
        Assert.Contains(systemArguments, value => value.StartsWith("--output-fields=", StringComparison.Ordinal)
            && value.Contains("_AUDIT_ID", StringComparison.Ordinal)
            && value.Contains("_AUDIT_TYPE_NAME", StringComparison.Ordinal));
        Assert.DoesNotContain(systemArguments, value => value.StartsWith("--after-cursor=", StringComparison.Ordinal));

        var accessible = LinuxJournalProcessSource.BuildReadStartInfo(
            "/usr/bin/journalctl", true, "s=synthetic;i=42;b=fake", 500);
        var accessibleArguments = accessible.ArgumentList.ToArray();
        Assert.DoesNotContain("--system", accessibleArguments);
        Assert.DoesNotContain("--user", accessibleArguments);
        Assert.DoesNotContain("--merge", accessibleArguments);
        Assert.Contains("--after-cursor=s=synthetic;i=42;b=fake", accessibleArguments);
        Assert.DoesNotContain(accessibleArguments, value => value.StartsWith("--lines=", StringComparison.Ordinal));
        Assert.All(accessibleArguments, value =>
        {
            Assert.DoesNotContain("--directory", value, StringComparison.Ordinal);
            Assert.DoesNotContain("--file", value, StringComparison.Ordinal);
            Assert.DoesNotContain("--root", value, StringComparison.Ordinal);
            Assert.DoesNotContain("--namespace", value, StringComparison.Ordinal);
        });
        Assert.False(accessible.UseShellExecute);
        Assert.True(accessible.RedirectStandardOutput);
        Assert.True(accessible.RedirectStandardError);
        Assert.Equal(["LANG", "LC_ALL"], accessible.Environment.Keys.Order(StringComparer.Ordinal).ToArray());

        var probe = LinuxJournalProcessSource.BuildSystemVisibilityProbeStartInfo("/usr/bin/journalctl");
        Assert.Contains("--system", probe.ArgumentList);
        Assert.Contains("--output-fields=__CURSOR", probe.ArgumentList);
        Assert.Contains("--lines=1", probe.ArgumentList);
        Assert.DoesNotContain("--quiet", probe.ArgumentList);

        Assert.Equal(
            SystemJournalVisibility.PermissionDenied,
            LinuxJournalProcessSource.ClassifySystemVisibilityProbe(
                1,
                string.Empty,
                "No journal files were opened due to insufficient permissions."));
        Assert.Equal(
            SystemJournalVisibility.PermissionDenied,
            LinuxJournalProcessSource.ClassifySystemVisibilityProbe(
                0,
                "{\"__CURSOR\":\"s=fake\"}",
                "Hint: You are currently not seeing messages from other users."));
        Assert.Equal(
            SystemJournalVisibility.Verified,
            LinuxJournalProcessSource.ClassifySystemVisibilityProbe(
                0,
                "{\"__CURSOR\":\"s=fake\"}",
                string.Empty));
        Assert.Equal(
            SystemJournalVisibility.Unknown,
            LinuxJournalProcessSource.ClassifySystemVisibilityProbe(0, string.Empty, string.Empty));
        Assert.True(LinuxJournalProcessSource.DiagnosticIndicatesDefinitePermissionDenial(
            "No journal files were opened due to insufficient permissions."));
        Assert.False(LinuxJournalProcessSource.DiagnosticIndicatesDefinitePermissionDenial(
            "Hint: You are currently not seeing messages from other users."));
    }

    [Fact]
    public async Task OversizedReaderPreservesBoundedIdentityAfterDiscardingContent()
    {
        const int inputLimit = 128 * 1024;
        const string cursor = "s=synthetic;i=oversized;b=fake";
        const string bootId = "00000000000000000000000000000042";
        const long timestamp = 1783944000123456;
        var raw = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["MESSAGE"] = new string('x', inputLimit + 1024)
                + " embedded untrusted text: \"__CURSOR\":\"s=forged\"",
            ["_SYSTEMD_USER_UNIT"] = "synthetic-producer.service",
            ["__CURSOR"] = cursor,
            ["__REALTIME_TIMESTAMP"] = timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["_BOOT_ID"] = bootId
        });
        var encoded = Encoding.UTF8.GetBytes(raw + "\n");
        await using var stream = new MemoryStream(encoded);

        var (records, limitReached) = await LinuxJournalProcessSource.ReadBoundedRecordsAsync(
            stream,
            maxRecords: 10,
            maxRecordBytes: inputLimit,
            default);

        var input = Assert.Single(records);
        Assert.False(limitReached);
        Assert.Null(input.RawJson);
        Assert.Null(input.UnrecoverableOversizedBytes);
        var omitted = Assert.IsType<OversizedJournalRecord>(input.Oversized);
        Assert.Equal(cursor, omitted.Cursor);
        Assert.Equal(bootId, omitted.BootId);
        Assert.Equal(timestamp, omitted.RealtimeMicroseconds);
        Assert.Equal(encoded.LongLength - 1, omitted.RecordBytes);
        Assert.True(omitted.RecordBytes > inputLimit);
    }

    [Fact]
    public async Task OversizedBurstCreatesOneDurableGapAndResumesAfterItsLastCursor()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var queue = CreateQueue(temporary.Queue);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        const string startingCursor = "s=synthetic;i=0;b=fake";
        var oversized = Enumerable.Range(1, 500)
            .Select(index => JournalInputRecord.OmitOversized(OversizedRecord(index)))
            .ToArray();
        var source = new RecordingSource(new JournalReadResult(JournalReadStatus.Success, oversized));

        var cursor = await Service(options, source, runtime, queue).CollectOnceAsync(startingCursor, default);

        Assert.Equal("s=synthetic;i=500;b=fake", cursor);
        Assert.Equal([startingCursor], source.AfterCursors);
        Assert.Equal(0, await queue.CountAsync(default));
        var persisted = await state.ReadJournalAsync(default);
        Assert.Equal(cursor, persisted.CollectedCursor);
        Assert.True(persisted.ActiveGap);
        Assert.Equal("oversized_record_omitted", persisted.GapState);
        Assert.Equal(1, persisted.CumulativeGapCount);
        Assert.Equal(500, persisted.OversizedRecordCount);
        Assert.Equal(500L * (128 * 1024 + 1024), persisted.OversizedRecordBytes);
        Assert.Equal("00000000000000000000000000000042", persisted.LastOversizedRecord?.BootId);
        Assert.Equal(cursor, persisted.LastOversizedRecord?.Cursor);
        Assert.Equal(1783944000000500L, persisted.LastOversizedRecord?.RealtimeMicroseconds);
        var health = L1Health(runtime);
        Assert.Equal(SourceHealthStatuses.Error, health.Status);
        Assert.Equal("journal_oversized_record_omitted_gap", health.ErrorCode);
        Assert.Equal("0", health.Details["malformed_records"]);
        Assert.Equal("500", health.Details["oversized_records"]);
        Assert.Equal("omitted", health.Details["oversized_content_handling"]);

        var restarted = Runtime(options, new LinuxStateStore(temporary.State));
        await restarted.InitializeAsync("test", "config", default);
        var recoverySource = new RecordingSource(new JournalReadResult(
            JournalReadStatus.Success,
            [Record("s=synthetic;i=501;b=fake", 1783944001000000, "bounded recovery")]));
        var recoveredCursor = await Service(options, recoverySource, restarted, queue)
            .CollectOnceAsync(restarted.CollectedCursor, default);

        Assert.Equal([cursor], recoverySource.AfterCursors);
        Assert.Equal("s=synthetic;i=501;b=fake", recoveredCursor);
        Assert.Equal(1, await queue.CountAsync(default));
        var recoveredState = await new LinuxStateStore(temporary.State).ReadJournalAsync(default);
        Assert.False(recoveredState.ActiveGap);
        Assert.Equal("none", recoveredState.GapState);
        Assert.Equal(1, recoveredState.CumulativeGapCount);
        Assert.Equal(500, recoveredState.OversizedRecordCount);
        Assert.False(L1Health(restarted).GapDetected);
    }

    [Fact]
    public async Task AdjacentOversizedPollsRemainOneContinuityGap()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var source = new RecordingSource(
            new JournalReadResult(JournalReadStatus.Success, [JournalInputRecord.OmitOversized(OversizedRecord(1))]),
            new JournalReadResult(JournalReadStatus.Success, [JournalInputRecord.OmitOversized(OversizedRecord(2))]));
        var service = Service(options, source, runtime, CreateQueue(temporary.Queue));

        var cursor = await service.CollectOnceAsync("s=synthetic;i=0;b=fake", default);
        cursor = await service.CollectOnceAsync(cursor, default);

        Assert.Equal("s=synthetic;i=2;b=fake", cursor);
        Assert.Equal(1, L1Health(runtime).GapCount);
        Assert.Equal("2", L1Health(runtime).Details["oversized_records"]);
        var persisted = await state.ReadJournalAsync(default);
        Assert.Equal(1, persisted.CumulativeGapCount);
        Assert.Equal(2, persisted.OversizedRecordCount);
        Assert.True(persisted.ActiveGap);
    }

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
    public async Task OutOfRangeTimestampIsMalformedAndDoesNotStallLaterValidRecords()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var queue = CreateQueue(temporary.Queue);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var bad = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["__CURSOR"] = "s=synthetic;i=bad;b=fake",
            ["__REALTIME_TIMESTAMP"] = "253402300800000000",
            ["_BOOT_ID"] = "fakeboot",
            ["_TRANSPORT"] = "journal",
            ["MESSAGE"] = "bad-time"
        });
        var good = FixtureRecords()[0];
        var cursor = await Service(options, new FakeSource(new(JournalReadStatus.Success, [bad, good])), runtime, queue)
            .CollectOnceAsync(null, default);
        Assert.Equal("s=synthetic;i=1;b=fake", cursor);
        Assert.Equal(1, await queue.CountAsync(default));
        Assert.Equal("1", L1Health(runtime).Details["malformed_records"]);
        Assert.True(L1Health(runtime).GapDetected);
        Assert.Equal(cursor, (await state.ReadJournalAsync(default)).CollectedCursor);
        Assert.False(new LinuxJournalNormalizer().TryNormalize(bad, options, DateTimeOffset.UtcNow, out _, out var code));
        Assert.Equal("journal_timestamp_malformed", code);
    }

    [Fact]
    public async Task BackwardTimestampStillAdvancesCollectedCursorAndAcknowledgementOrder()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var queue = CreateQueue(temporary.Queue);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var records = new[]
        {
            Record("s=synthetic;i=1;b=fake", 1783944010000000, "later-first"),
            Record("s=synthetic;i=2;b=fake", 1783944000000000, "earlier-second")
        };
        var cursor = await Service(options, new FakeSource(new(JournalReadStatus.Success, records)), runtime, queue)
            .CollectOnceAsync(null, default);
        Assert.Equal("s=synthetic;i=2;b=fake", cursor);
        Assert.Equal(2, await queue.CountAsync(default));
        Assert.Equal("1", L1Health(runtime).Details["reordered_records"]);

        var batch = await queue.DequeueBatchAsync(10, default);
        await runtime.RecordAcknowledgedAsync(batch.Select(item => item.Envelope).Reverse().ToArray(), default);
        Assert.Equal("s=synthetic;i=1;b=fake", (await state.ReadJournalAsync(default)).AcknowledgedCursor);
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

    [Fact]
    public async Task JournalPollUsesOneBatchBeforeAdvancingItsFinalCursor()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var queue = new BatchCountingQueue();

        var cursor = await Service(
            options,
            new FakeSource(new(JournalReadStatus.Success, FixtureRecords())),
            runtime,
            queue).CollectOnceAsync(null, default);

        Assert.Equal(1, queue.BatchCalls);
        Assert.Equal([5], queue.BatchSizes);
        Assert.Equal(0, queue.EnqueueCalls);
        Assert.Equal("s=synthetic;i=5;b=fake", cursor);
        Assert.Equal(cursor, (await state.ReadJournalAsync(default)).CollectedCursor);
    }

    [Fact]
    public async Task AuditTransportSplitsAdjacentL1BatchesWithoutReorderingTheCursor()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var queue = new BatchCountingQueue();
        var observedAt = DateTimeOffset.Parse("2026-08-01T00:00:00Z");
        var records = new[]
        {
            Record("s=synthetic;i=1;b=fake", observedAt.ToUnixTimeMilliseconds() * 1000, "first-l1"),
            AuditRecord("2", observedAt.AddMilliseconds(1), "suppressed audit transport"),
            Record("s=synthetic;i=3;b=fake", observedAt.AddMilliseconds(2).ToUnixTimeMilliseconds() * 1000, "second-l1")
        };

        var cursor = await Service(
            options,
            new FakeSource(new(JournalReadStatus.Success, records)),
            runtime,
            queue).CollectOnceAsync(null, default);

        Assert.Equal(2, queue.BatchCalls);
        Assert.Equal([1, 1], queue.BatchSizes);
        Assert.Equal("s=synthetic;i=3;b=fake", cursor);
        Assert.Equal(cursor, (await state.ReadJournalAsync(default)).CollectedCursor);
    }

    [Fact]
    public async Task QueueBatchReplaysWithoutDuplicatesWhenFinalCursorWriteFails()
    {
        using var temporary = new TemporaryPaths();
        var invalidStatePath = Path.Combine(Path.GetDirectoryName(temporary.State)!, "state-directory");
        Directory.CreateDirectory(invalidStatePath);
        var options = TestOptions(temporary.Queue, invalidStatePath);
        var queue = CreateQueue(temporary.Queue);
        var interruptedRuntime = Runtime(options, new LinuxStateStore(invalidStatePath));
        await interruptedRuntime.InitializeAsync("test", "config", default);

        await Assert.ThrowsAsync<IOException>(() => Service(
            options,
            new FakeSource(new(JournalReadStatus.Success, FixtureRecords())),
            interruptedRuntime,
            queue).CollectOnceAsync(null, default));

        Assert.Equal(5, await queue.CountAsync(default));
        Assert.Null(interruptedRuntime.CollectedCursor);

        var recoveredOptions = TestOptions(temporary.Queue, temporary.State);
        var recoveredState = new LinuxStateStore(temporary.State);
        var recoveredRuntime = Runtime(recoveredOptions, recoveredState);
        await recoveredRuntime.InitializeAsync("test", "config", default);
        var cursor = await Service(
            recoveredOptions,
            new FakeSource(new(JournalReadStatus.Success, FixtureRecords())),
            recoveredRuntime,
            queue).CollectOnceAsync(null, default);

        Assert.Equal(5, await queue.CountAsync(default));
        Assert.Equal("s=synthetic;i=5;b=fake", cursor);
        Assert.Equal(cursor, (await recoveredState.ReadJournalAsync(default)).CollectedCursor);
    }

    [Fact]
    public async Task FailedQuietRecoveryEnqueueIsFinalizedAndRetriedWithoutRestart()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.Audit = new AuditOptions
        {
            Enabled = true,
            FacilityDeclaration = "present_enabled",
            StatePath = temporary.AuditState
        };
        options.Audit.ApprovedPlanHash = LinuxAuditRouter.ComputePlanHash(options);
        var clock = new MutableTimeProvider(DateTimeOffset.Parse("2026-08-01T00:00:00Z"));
        var auditRuntime = new LinuxAuditRouterRuntime();
        var auditRouter = new LinuxAuditRouter(
            options,
            clock,
            auditRuntime,
            new LinuxAuditStateStore(temporary.AuditState, enforceFixedPath: false));
        var gap = await auditRouter.RouteAsync(
            AuditRecord("gap", clock.GetUtcNow(), "type=SYSCALL malformed"),
            options.AgentId,
            "SYNTHETIC-LINUX-01",
            default);
        Assert.Equal(LinuxAuditRouteKind.Gap, gap.Kind);
        clock.Advance(TimeSpan.FromSeconds(6));

        var state = new LinuxStateStore(temporary.State);
        var runtime = new LinuxJournalRuntime(Options.Create(options), state, clock);
        await runtime.InitializeAsync("test", "config", default);
        var queue = new FailOnceQueue();
        var service = new LinuxJournalService(
            Options.Create(options),
            new FakeSource(new(JournalReadStatus.Success, Array.Empty<string>())),
            new LinuxJournalNormalizer(),
            auditRouter,
            runtime,
            queue,
            clock,
            NullLogger<LinuxJournalService>.Instance);

        await service.CollectOnceAsync(null, default);
        Assert.Equal(1, queue.Attempts);
        Assert.Equal("audit_queue_insertion_failed", auditRuntime.Current.ErrorCode);
        Assert.Empty(auditRouter.ReplayQueued(options.AgentId, "SYNTHETIC-LINUX-01"));

        await service.CollectOnceAsync(null, default);
        var recovery = Assert.IsType<EventEnvelope>(queue.Enqueued);
        Assert.Equal(2, queue.Attempts);
        Assert.Equal("audit_source_recovery", recovery.EventCode);
        Assert.Single(auditRouter.ReplayQueued(options.AgentId, "SYNTHETIC-LINUX-01"));

        await auditRouter.RecordAcknowledgedAsync([recovery], default);
        Assert.Equal(2, auditRuntime.Current.AcknowledgedSequence);
        Assert.False(auditRuntime.Current.ActiveGap);
    }

    [Fact]
    public async Task SharedAuditInterfaceRequiresFreshHealthyKernelStatus()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.Journal.TargetCoverageLevel = CoverageLevel.L2;
        options.Journal.IncludeAccessibleUserJournals = true;
        options.Audit = new AuditOptions
        {
            Enabled = true,
            Interface = LinuxAuditConstants.SharedJournalInterface,
            FacilityDeclaration = "present_enabled",
            StatePath = temporary.AuditState
        };
        options.Audit.ApprovedPlanHash = LinuxAuditRouter.ComputePlanHash(options);
        var clock = new MutableTimeProvider(DateTimeOffset.Parse("2026-08-01T00:00:00Z"));
        var auditRuntime = new LinuxAuditRouterRuntime();
        var runtime = new LinuxJournalRuntime(Options.Create(options), new LinuxStateStore(temporary.State), clock, auditRuntime);
        await runtime.InitializeAsync("test", "config", default);

        auditRuntime.Publish(new(true, true, clock.GetUtcNow(), clock.GetUtcNow(), 1, 1, 0, 0, 0, false, "healthy", null));
        var missing = Assert.Single(runtime.Snapshot().Health, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        Assert.Equal(SourceHealthStatuses.Missing, missing.Status);
        Assert.Equal("audit_kernel_health_not_observed", missing.ErrorCode);
        Assert.Equal("not_collected", missing.Details["kernel_health_status"]);

        auditRuntime.Publish(new(true, true, clock.GetUtcNow(), clock.GetUtcNow(), 2, 2, 0, 0, 0, false, "healthy", null,
            clock.GetUtcNow(), "healthy", 0, 0, 8192));
        var healthy = Assert.Single(runtime.Snapshot().Health, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        Assert.Equal(SourceHealthStatuses.Healthy, healthy.Status);
        Assert.Equal("0", healthy.Details["kernel_lost_records"]);

        clock.Advance(TimeSpan.FromMinutes(4));
        var stale = Assert.Single(runtime.Snapshot().Health, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        Assert.Equal(SourceHealthStatuses.Stale, stale.Status);
        Assert.Equal("audit_kernel_health_stale", stale.ErrorCode);

        auditRuntime.Publish(new(true, true, clock.GetUtcNow(), clock.GetUtcNow(), 3, 2, 0, 0, 0, false, "degraded", "audit_kernel_health_degraded",
            clock.GetUtcNow(), "degraded", 1, 7000, 8192));
        var degraded = Assert.Single(runtime.Snapshot().Health, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        Assert.Equal(SourceHealthStatuses.Degraded, degraded.Status);
        Assert.Equal("audit_kernel_health_degraded", degraded.ErrorCode);
    }

    [Fact]
    public async Task LegacyAuditInterfaceReportsMatchingUnsupportedApplicabilityForAccessibleScope()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.Journal.TargetCoverageLevel = CoverageLevel.L2;
        options.Journal.IncludeAccessibleUserJournals = true;
        options.Audit.Enabled = false;
        options.Audit.Interface = LinuxAuditConstants.SystemOnlyInterface;
        options.Audit.FacilityDeclaration = "undeclared";
        var runtime = new LinuxJournalRuntime(
            Options.Create(options),
            new LinuxStateStore(temporary.State),
            TimeProvider.System);
        await runtime.InitializeAsync("test", "config", default);

        var snapshot = runtime.Snapshot();
        var manifest = Assert.Single(snapshot.Manifest, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        var health = Assert.Single(snapshot.Health, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);

        Assert.Equal(SourceApplicabilityStatuses.Unsupported, manifest.Applicability);
        Assert.Equal(LinuxAuditConstants.IncompatibleJournalScopeReason, manifest.ApplicabilityReason);
        Assert.Equal(manifest.Applicability, health.Applicability);
        Assert.Equal(manifest.ApplicabilityReason, health.ApplicabilityReason);
        Assert.Equal(SourceHealthStatuses.Unsupported, health.Status);
    }

    [Fact]
    public async Task DeclaredAbsentAuditFacilityRemainsNotApplicableAcrossJournalScopes()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.Journal.TargetCoverageLevel = CoverageLevel.L2;
        options.Journal.IncludeAccessibleUserJournals = true;
        options.Audit.Enabled = false;
        options.Audit.Interface = LinuxAuditConstants.SystemOnlyInterface;
        options.Audit.FacilityDeclaration = "absent";
        var runtime = new LinuxJournalRuntime(
            Options.Create(options),
            new LinuxStateStore(temporary.State),
            TimeProvider.System);
        await runtime.InitializeAsync("test", "config", default);

        var snapshot = runtime.Snapshot();
        var manifest = Assert.Single(snapshot.Manifest, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);
        var health = Assert.Single(snapshot.Health, source => source.SourceId == LinuxTelemetrySourceIds.AuditFramework);

        Assert.Equal(SourceApplicabilityStatuses.NotApplicable, manifest.Applicability);
        Assert.Equal(manifest.Applicability, health.Applicability);
        Assert.Equal(SourceHealthStatuses.NotApplicable, health.Status);
    }

    [Fact]
    public async Task AccessibleScopePreservesCursorAndInvalidCursorResetSurvivesRestart()
    {
        using var temporary = new TemporaryPaths();
        var initialOptions = TestOptions(temporary.Queue, temporary.State);
        var initialState = new LinuxStateStore(temporary.State);
        var initialRuntime = Runtime(initialOptions, initialState);
        await initialRuntime.InitializeAsync("test", "config", default);
        Assert.True(new LinuxJournalNormalizer().TryNormalize(
            FixtureRecords()[0], initialOptions, DateTimeOffset.UtcNow, out var record, out _));
        await initialRuntime.RecordCollectedAsync(record!, default);
        var originalCursor = initialRuntime.CollectedCursor;
        Assert.NotNull(originalCursor);

        var expandedOptions = TestOptions(temporary.Queue, temporary.State);
        expandedOptions.Journal.IncludeAccessibleUserJournals = true;
        var expandedRuntime = Runtime(expandedOptions, new LinuxStateStore(temporary.State));
        await expandedRuntime.InitializeAsync("test", "config", default);
        Assert.Equal(originalCursor, expandedRuntime.CollectedCursor);
        Assert.Equal("pending_expansion", L1Health(expandedRuntime).Details["scope_transition"]);

        var queue = CreateQueue(temporary.Queue);
        await queue.InitializeAsync(default);
        var invalid = new JournalReadResult(
            JournalReadStatus.InvalidCursor,
            Array.Empty<string>(),
            JournalGapKind.InvalidCursor,
            "journal_cursor_invalid",
            SystemJournalVisibility.Verified);
        var resumed = await Service(expandedOptions, new FakeSource(invalid), expandedRuntime, queue)
            .CollectOnceAsync(originalCursor, default);
        Assert.Null(resumed);
        var resetState = await new LinuxStateStore(temporary.State).ReadJournalAsync(default);
        Assert.Null(resetState.CollectedCursor);
        Assert.Null(resetState.CollectedEventTime);
        Assert.Equal(LinuxJournalScopes.AllAccessibleLocal, resetState.ConfiguredScope);
        Assert.True(resetState.ActiveGap);

        var restarted = Runtime(expandedOptions, new LinuxStateStore(temporary.State));
        await restarted.InitializeAsync("test", "config", default);
        Assert.Null(restarted.CollectedCursor);
        Assert.True(L1Health(restarted).GapDetected);
        Assert.Equal("invalid_cursor", L1Health(restarted).Details["gap_state"]);
    }

    [Fact]
    public async Task Pre19StateKeepsExpansionPendingUntilAReadSucceeds()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.Journal.IncludeAccessibleUserJournals = true;
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);

        await runtime.InitializeAsync("test", "config", default);
        Assert.Equal("pending_expansion", L1Health(runtime).Details["scope_transition"]);
        Assert.Null((await state.ReadJournalAsync(default)).ConfiguredScope);

        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.Success,
            Array.Empty<string>(),
            SystemJournalVisibility: SystemJournalVisibility.Verified));
        await runtime.RecordSuccessfulReadObservationAsync(default);
        Assert.Equal(LinuxJournalScopes.AllAccessibleLocal, (await state.ReadJournalAsync(default)).ConfiguredScope);
    }

    [Fact]
    public async Task ScopeContractionClearsEvidenceThatMayHaveComeFromUserJournals()
    {
        using var temporary = new TemporaryPaths();
        var state = new LinuxStateStore(temporary.State);
        var observedAt = DateTimeOffset.UtcNow;
        await state.WriteCollectedJournalAsync(
            "s=broad;i=1;b=fake",
            observedAt,
            default,
            LinuxTelemetrySourceIds.Privilege,
            "privilege_escalation",
            configuredScope: LinuxJournalScopes.AllAccessibleLocal);

        var options = TestOptions(temporary.Queue, temporary.State);
        options.Journal.TargetCoverageLevel = CoverageLevel.L2;
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        Assert.Equal("pending_contraction", L1Health(runtime).Details["scope_transition"]);
        Assert.Equal(
            SourceHealthStatuses.Missing,
            Assert.Single(runtime.Snapshot().Health, source => source.SourceId == LinuxTelemetrySourceIds.Privilege).Status);

        runtime.RecordReadResult(new JournalReadResult(JournalReadStatus.Success, Array.Empty<string>()));
        await runtime.RecordSuccessfulReadObservationAsync(default);

        var persisted = await state.ReadJournalAsync(default);
        Assert.DoesNotContain(LinuxTelemetrySourceIds.Privilege, persisted.ObservedSourceIds ?? Array.Empty<string>());
        Assert.False((persisted.ObservedFamilies ?? new Dictionary<string, IReadOnlyList<string>>())
            .ContainsKey(LinuxTelemetrySourceIds.Privilege));
        Assert.Equal(
            SourceHealthStatuses.Degraded,
            Assert.Single(runtime.Snapshot().Health, source => source.SourceId == LinuxTelemetrySourceIds.Privilege).Status);
    }

    [Fact]
    public async Task AccessibleScopeCannotHideMissingSystemJournalVisibility()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.Journal.IncludeAccessibleUserJournals = true;
        var runtime = Runtime(options, new LinuxStateStore(temporary.State));
        await runtime.InitializeAsync("test", "config", default);
        Assert.True(new LinuxJournalNormalizer().TryNormalize(
            FixtureRecords()[0], options, DateTimeOffset.UtcNow, out var record, out _));
        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.Success,
            [FixtureRecords()[0]],
            SystemJournalVisibility: SystemJournalVisibility.PermissionDenied));
        await runtime.RecordCollectedAsync(record!, default);

        var denied = L1Health(runtime);
        Assert.Equal(SourceHealthStatuses.PermissionDenied, denied.Status);
        Assert.Equal("system_journal_permission_denied", denied.ErrorCode);
        Assert.Equal(LinuxJournalScopes.AllAccessibleLocal, denied.Details["configured_journal_scope"]);
        Assert.Equal("permission_denied", denied.Details["system_journal_visibility"]);

        runtime.RecordReadResult(new JournalReadResult(
            JournalReadStatus.Success,
            Array.Empty<string>(),
            SystemJournalVisibility: SystemJournalVisibility.Verified));
        var recovered = L1Health(runtime);
        Assert.Equal(SourceHealthStatuses.Healthy, recovered.Status);
        Assert.Equal("verified", recovered.Details["system_journal_visibility"]);
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
        var health = L1Health(snapshot);
        Assert.True(health.GapDetected);
        Assert.Equal(expected, health.Details["gap_state"]);
        Assert.Equal(SourceHealthStatuses.Error, health.Status);
    }

    [Fact]
    public async Task PermissionEmptyMalformedDuplicateReorderAndThrottleStatesAreVisible()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var runtime = Runtime(options, new LinuxStateStore(temporary.State));
        await runtime.InitializeAsync("test", "config", default);
        runtime.RecordReadResult(new(JournalReadStatus.Success, Array.Empty<string>()));
        Assert.Equal("empty", L1Health(runtime).Details["collector_state"]);
        runtime.RecordReadResult(new(JournalReadStatus.PermissionDenied, Array.Empty<string>(), ErrorCode: "journal_permission_denied"));
        Assert.Equal("denied", L1Health(runtime).Details["permission_state"]);
        Assert.Equal(SourceHealthStatuses.PermissionDenied, L1Health(runtime).Status);

        var reordered = new[] { FixtureRecords()[1], FixtureRecords()[0], FixtureRecords()[1], BinaryRecord(), "malformed" };
        var queue = CreateQueue(temporary.Queue);
        await Service(options, new FakeSource(new(JournalReadStatus.Success, reordered)), runtime, queue).CollectOnceAsync(null, default);
        var health = L1Health(runtime);
        Assert.Equal("1", health.Details["duplicate_records"]);
        Assert.Equal("1", health.Details["reordered_records"]);
        Assert.Equal("1", health.Details["malformed_records"]);
        Assert.Equal("1", health.Details["binary_or_invalid_text_records"]);
        Assert.True(health.GapDetected);

        var pressureQueue = new CountQueue(options.Journal.QueuePauseDepth);
        await Service(options, new FakeSource(new(JournalReadStatus.Success, FixtureRecords())), runtime, pressureQueue).CollectOnceAsync(runtime.CollectedCursor, default);
        Assert.Equal("active", L1Health(runtime).Details["throttle_state"]);
        Assert.Equal(0, pressureQueue.EnqueueCalls);
    }

    [Fact]
    public async Task OutageLeavesReplayDurableAndAcknowledgementAdvancesBeforeDeletion()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        var queue = new AttemptRecordingQueue(CreateQueue(temporary.Queue, 0));
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        await Service(options, new FakeSource(new(JournalReadStatus.Success, [FixtureRecords()[0]])), runtime, queue).CollectOnceAsync(null, default);

        var handler = new SwitchingHandler();
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://siem.synthetic") };
        var drainer = new LinuxQueueDrainer(Options.Create(options), queue, new SiemIngestClient(http, options), runtime);
        await Assert.ThrowsAsync<HttpRequestException>(() => drainer.DrainAsync(default));
        Assert.Equal(1, await queue.CountAsync(default));
        Assert.Single(queue.MarkedBatches);
        Assert.Single(queue.MarkedBatches[0]);
        Assert.Null((await state.ReadJournalAsync(default)).AcknowledgedCursor);

        handler.Fail = false;
        await drainer.DrainAsync(default);
        Assert.Equal(0, await queue.CountAsync(default));
        Assert.Single(queue.MarkedBatches);
        Assert.Equal("s=synthetic;i=1;b=fake", (await state.ReadJournalAsync(default)).AcknowledgedCursor);
    }

    [Fact]
    public async Task FullDeliveryBatchUsesBoundedBacklogPacingUntilQueueIsCaughtUp()
    {
        using var temporary = new TemporaryPaths();
        var options = TestOptions(temporary.Queue, temporary.State);
        options.DrainBatchSize = 2;
        var queue = CreateQueue(temporary.Queue, 0);
        var state = new LinuxStateStore(temporary.State);
        var runtime = Runtime(options, state);
        await runtime.InitializeAsync("test", "config", default);
        var records = new[]
        {
            Record("s=synthetic;i=1;b=fake", 1783944000000000, "first"),
            Record("s=synthetic;i=2;b=fake", 1783944001000000, "second"),
            Record("s=synthetic;i=3;b=fake", 1783944002000000, "third")
        };
        await Service(options, new FakeSource(new(JournalReadStatus.Success, records)), runtime, queue)
            .CollectOnceAsync(null, default);

        var handler = new SwitchingHandler { Fail = false };
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://siem.synthetic") };
        var drainer = new LinuxQueueDrainer(Options.Create(options), queue, new SiemIngestClient(http, options), runtime);

        Assert.True(await drainer.DrainAsync(default));
        Assert.Equal(TimeSpan.FromMilliseconds(250), LinuxAgentWorker.DrainDelay(likelyBacklog: true));
        Assert.Equal(1, await queue.CountAsync(default));

        Assert.False(await drainer.DrainAsync(default));
        Assert.Equal(TimeSpan.FromSeconds(5), LinuxAgentWorker.DrainDelay(likelyBacklog: false));
        Assert.Equal(0, await queue.CountAsync(default));
        Assert.Equal("s=synthetic;i=3;b=fake", (await state.ReadJournalAsync(default)).AcknowledgedCursor);
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

    private static SourceHealthReport L1Health(LinuxJournalRuntime runtime) => L1Health(runtime.Snapshot());
    private static SourceHealthReport L1Health(JournalRuntimeSnapshot snapshot) => Assert.Single(snapshot.Health, source => source.SourceId == LinuxTelemetrySourceIds.JournalL1);
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
    private static string AuditRecord(string cursor, DateTimeOffset observedAt, string message) => JsonSerializer.Serialize(new Dictionary<string, string>
    {
        ["__CURSOR"] = $"s=synthetic;i={cursor}",
        ["__REALTIME_TIMESTAMP"] = (observedAt.ToUnixTimeMilliseconds() * 1000).ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["_BOOT_ID"] = "00000000000000000000000000000001",
        ["_TRANSPORT"] = "audit",
        ["AUDIT_TYPE_NAME"] = "SYSCALL",
        ["MESSAGE"] = message
    });

    private static OversizedJournalRecord OversizedRecord(int index)
    {
        Assert.True(OversizedJournalRecord.TryCreate(
            $"s=synthetic;i={index};b=fake",
            "00000000000000000000000000000042",
            1783944000000000L + index,
            128 * 1024 + 1024,
            out var record));
        return record!;
    }

    private sealed class FakeSource(JournalReadResult result) : ILinuxJournalSource
    {
        public Task<JournalReadResult> ReadAsync(string? afterCursor, int maxRecords, int maxRecordBytes, CancellationToken cancellationToken) => Task.FromResult(result);
    }
    private sealed class RecordingSource(params JournalReadResult[] results) : ILinuxJournalSource
    {
        private readonly Queue<JournalReadResult> pending = new(results);
        public List<string?> AfterCursors { get; } = new();

        public Task<JournalReadResult> ReadAsync(
            string? afterCursor,
            int maxRecords,
            int maxRecordBytes,
            CancellationToken cancellationToken)
        {
            AfterCursors.Add(afterCursor);
            return Task.FromResult(pending.Dequeue());
        }
    }
    private sealed class TemporaryPaths : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "challenger-journal-test-" + Guid.NewGuid().ToString("N"));
        public TemporaryPaths() => Directory.CreateDirectory(root);
        public string Queue => Path.Combine(root, "queue.sqlite");
        public string State => Path.Combine(root, "state.json");
        public string AuditState => Path.Combine(root, "audit-router.wal");
        public void Dispose() => Directory.Delete(root, true);
    }
    private class CountQueue(int count) : IEventQueue
    {
        public int EnqueueCalls { get; private set; }
        public Task InitializeAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public virtual Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) { EnqueueCalls++; return Task.CompletedTask; }
        public virtual async Task EnqueueBatchAsync(IReadOnlyCollection<EventEnvelope> envelopes, CancellationToken cancellationToken)
        {
            foreach (var envelope in envelopes) await EnqueueAsync(envelope, cancellationToken);
        }
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<QueuedEvent>>(Array.Empty<QueuedEvent>());
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> CountAsync(CancellationToken cancellationToken) => Task.FromResult(count);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) => Task.FromResult(new QueueSloMetrics { QueueDepth = count });
    }
    private sealed class AttemptRecordingQueue(IEventQueue inner) : IEventQueue
    {
        public List<long[]> MarkedBatches { get; } = [];
        public Task InitializeAsync(CancellationToken cancellationToken) => inner.InitializeAsync(cancellationToken);
        public Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) => inner.EnqueueAsync(envelope, cancellationToken);
        public Task EnqueueBatchAsync(IReadOnlyCollection<EventEnvelope> envelopes, CancellationToken cancellationToken) => inner.EnqueueBatchAsync(envelopes, cancellationToken);
        public Task<IReadOnlyList<QueuedEvent>> DequeueBatchAsync(int maxEvents, CancellationToken cancellationToken) => inner.DequeueBatchAsync(maxEvents, cancellationToken);
        public Task MarkAttemptAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken)
        {
            MarkedBatches.Add(queueIds.ToArray());
            return inner.MarkAttemptAsync(queueIds, cancellationToken);
        }
        public Task DeleteAsync(IReadOnlyCollection<long> queueIds, CancellationToken cancellationToken) => inner.DeleteAsync(queueIds, cancellationToken);
        public Task MarkPoisonAsync(IReadOnlyCollection<long> queueIds, string reason, CancellationToken cancellationToken) => inner.MarkPoisonAsync(queueIds, reason, cancellationToken);
        public Task<int> CountAsync(CancellationToken cancellationToken) => inner.CountAsync(cancellationToken);
        public Task<QueueSloMetrics> GetMetricsAsync(DateTimeOffset? lastSuccessfulSendTime, CancellationToken cancellationToken) => inner.GetMetricsAsync(lastSuccessfulSendTime, cancellationToken);
    }
    private sealed class BatchCountingQueue : CountQueue
    {
        public BatchCountingQueue() : base(0) { }
        public int BatchCalls { get; private set; }
        public List<int> BatchSizes { get; } = new();
        public override Task EnqueueBatchAsync(IReadOnlyCollection<EventEnvelope> envelopes, CancellationToken cancellationToken)
        {
            BatchCalls++;
            BatchSizes.Add(envelopes.Count);
            return Task.CompletedTask;
        }
    }
    private sealed class ThrowingQueue : CountQueue
    {
        public ThrowingQueue() : base(0) { }
        public override Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken) => throw new IOException("synthetic queue failure");
    }
    private sealed class FailOnceQueue : CountQueue
    {
        public FailOnceQueue() : base(0) { }
        public int Attempts { get; private set; }
        public EventEnvelope? Enqueued { get; private set; }
        public override Task EnqueueAsync(EventEnvelope envelope, CancellationToken cancellationToken)
        {
            Attempts++;
            if (Attempts == 1) throw new IOException("synthetic first queue failure");
            Enqueued = envelope;
            return Task.CompletedTask;
        }
    }
    private sealed class MutableTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset current = value;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan by) => current += by;
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
