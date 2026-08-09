using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.Package;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxPackageInventoryDiffTests
{
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-08-08T10:00:00Z");

    [Fact]
    public async Task CompleteInventoriesEmitBaselineAndDeterministicInstallUpdateRemoveEvidence()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, tracker) = Runtime(temporary.Path, clock);

        await runtime.ObserveInventoryAsync([Snapshot(Start, ("alpha", "1"), ("remove-me", "1"))], CancellationToken.None);
        var baseline = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));
        Assert.Equal("package_inventory_baseline", baseline.Envelope.EventCode);
        Assert.Equal("baseline", baseline.Envelope.Normalized!.Action);
        await AcknowledgeAndDelete(runtime, queue, [baseline]);

        tracker.Record(PackageJournalEvent(Start.AddMinutes(30), "update", "alpha"));
        clock.Set(Start.AddHours(1));
        await runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), ("alpha", "2"), ("installed", "1"))], CancellationToken.None);
        var changes = await queue.DequeueBatchAsync(10, CancellationToken.None);
        Assert.Equal(["package_inventory_update", "package_inventory_install", "package_inventory_remove"],
            changes.Select(item => item.Envelope.EventCode!).ToArray());
        Assert.All(changes, item =>
        {
            Assert.Equal(EventSources.InventoryDiff, item.Envelope.Source);
            Assert.Equal(LinuxTelemetrySourceIds.PackageInventoryDiff, item.Envelope.SourceId);
            Assert.Equal("unknown", item.Envelope.Normalized!.Outcome);
            Assert.Equal(item.Envelope.EventId, DeterministicEventIdentity.ComputeSha256Uuid(item.Envelope));
        });
        Assert.True(tracker.Status().ActiveGap);
        Assert.Equal(2, tracker.Status().MissingChangeCount);
        Assert.Equal(SourceHealthStatuses.Healthy, runtime.Health().Status);
    }

    [Fact]
    public async Task DirectJournalEvidenceMatchesTheSamePackageActionWithinTheObservationBoundary()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, tracker) = Runtime(temporary.Path, clock);
        await runtime.ObserveInventoryAsync([Snapshot(Start, ("alpha", "1"))], CancellationToken.None);
        await AcknowledgeAndDelete(runtime, queue, await queue.DequeueBatchAsync(10, CancellationToken.None));

        tracker.Record(PackageJournalEvent(Start.AddMinutes(10), "update", "alpha"));
        clock.Set(Start.AddHours(1));
        await runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), ("alpha", "2"))], CancellationToken.None);

        Assert.False(tracker.Status().ActiveGap);
        Assert.Equal(0, tracker.Status().MissingChangeCount);
        Assert.Equal("package_inventory_update", Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None)).Envelope.EventCode);
    }

    [Fact]
    public async Task EventCapEmitsExplicitGapAdvancesBaselineAndRecoversOnNextCompleteObservation()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, _) = Runtime(temporary.Path, clock);
        await runtime.ObserveInventoryAsync([Snapshot(Start, ("base", "1"))], CancellationToken.None);
        await AcknowledgeAndDelete(runtime, queue, await queue.DequeueBatchAsync(10, CancellationToken.None));

        clock.Set(Start.AddHours(1));
        var expanded = Enumerable.Range(0, 250).Select(index => ($"package-{index:D3}", "1"))
            .Append(("base", "1")).ToArray();
        await runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), expanded)], CancellationToken.None);
        var capped = await queue.DequeueBatchAsync(250, CancellationToken.None);
        Assert.Equal(LinuxPackageInventoryDiffConstants.MaximumEventsPerObservation, capped.Count);
        Assert.Equal("package_inventory_gap", capped[^1].Envelope.EventCode);
        Assert.Equal(SourceHealthStatuses.Degraded, runtime.Health().Status);
        Assert.True(runtime.Health().GapDetected);
        Assert.Equal(51, runtime.Health().DroppedEvents);
        await AcknowledgeAndDelete(runtime, queue, capped);

        clock.Set(Start.AddHours(2));
        await runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), expanded)], CancellationToken.None);
        var recovery = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));
        Assert.Equal("package_inventory_recovery", recovery.Envelope.EventCode);
        Assert.Equal(SourceHealthStatuses.Healthy, runtime.Health().Status);
        Assert.False(runtime.Health().GapDetected);
    }

    [Fact]
    public async Task PartialOrAmbiguousInventoryDoesNotReplaceLastCompleteBaseline()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, _) = Runtime(temporary.Path, clock);
        await runtime.ObserveInventoryAsync([Snapshot(Start, ("alpha", "1"))], CancellationToken.None);
        await AcknowledgeAndDelete(runtime, queue, await queue.DequeueBatchAsync(10, CancellationToken.None));

        clock.Set(Start.AddHours(1));
        await runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), true, ("alpha", "2"))], CancellationToken.None);
        var gap = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));
        Assert.Equal("package_inventory_gap", gap.Envelope.EventCode);
        Assert.Equal("package_inventory_snapshot_incomplete", runtime.Health().ErrorCode);
        await AcknowledgeAndDelete(runtime, queue, [gap]);

        clock.Set(Start.AddHours(2));
        await runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), ("alpha", "2"))], CancellationToken.None);
        var recovered = await queue.DequeueBatchAsync(10, CancellationToken.None);
        Assert.Equal(["package_inventory_recovery", "package_inventory_update"], recovered.Select(item => item.Envelope.EventCode!).ToArray());

        using var ambiguousDirectory = new TemporaryDirectory();
        var (ambiguous, ambiguousQueue, _) = Runtime(ambiguousDirectory.Path, clock);
        var duplicate = Snapshot(clock.GetUtcNow(), ("alpha", "1"), ("alpha", "2"));
        await ambiguous.ObserveInventoryAsync([duplicate], CancellationToken.None);
        Assert.Equal("package_inventory_identity_ambiguous", ambiguous.Health().ErrorCode);
        Assert.DoesNotContain(ambiguous.Health().Details, item => item.Key == "baseline_item_count" && item.Value != "0");
        Assert.Equal("package_inventory_gap", Assert.Single(await ambiguousQueue.DequeueBatchAsync(10, CancellationToken.None)).Envelope.EventCode);
    }

    [Fact]
    public async Task RejectedSequenceBecomesAnExplicitDurableGap()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, _) = Runtime(temporary.Path, clock);
        await runtime.ObserveInventoryAsync([Snapshot(Start, ("alpha", "1"))], CancellationToken.None);
        var baseline = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));
        await runtime.RecordRejectedAsync([baseline.Envelope], CancellationToken.None);
        Assert.Equal("package_inventory_event_rejected", runtime.Health().ErrorCode);
        Assert.True(runtime.Health().GapDetected);
        Assert.Equal(1, runtime.Health().DroppedEvents);
    }

    [Fact]
    public async Task AcknowledgedBaselineSurvivesRestartWithoutDuplicateChangeEvidence()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, _) = Runtime(temporary.Path, clock);
        await runtime.ObserveInventoryAsync([Snapshot(Start, ("alpha", "1"))], CancellationToken.None);
        var baseline = Assert.Single(await queue.DequeueBatchAsync(10, CancellationToken.None));
        await AcknowledgeAndDelete(runtime, queue, [baseline]);
        Assert.Equal(1, runtime.Health().AcknowledgedCheckpoint!.Sequence);

        var (restarted, restartedQueue, _) = Runtime(temporary.Path, clock);
        await restarted.InitializeAsync(CancellationToken.None);
        Assert.Equal("1", restarted.Health().Details["baseline_item_count"]);
        Assert.Equal(1, restarted.Health().AcknowledgedCheckpoint!.Sequence);

        clock.Set(Start.AddHours(1));
        await restarted.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), ("alpha", "1"))], CancellationToken.None);
        Assert.Empty(await restartedQueue.DequeueBatchAsync(10, CancellationToken.None));
        Assert.Equal(SourceHealthStatuses.Healthy, restarted.Health().Status);
    }

    [Fact]
    public async Task FailedEnqueueDoesNotAdvanceBaselineAndRestartReportsReservedSequenceGap()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, _) = Runtime(temporary.Path, clock);
        await queue.InitializeAsync(CancellationToken.None);
        await using (var connection = new SqliteConnection($"Data Source={Path.Combine(temporary.Path, "queue.db")}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "create trigger synthetic_package_enqueue_failure before insert on queued_events begin select raise(abort, 'synthetic failure'); end;";
            await command.ExecuteNonQueryAsync();
        }

        await Assert.ThrowsAsync<SqliteException>(() =>
            runtime.ObserveInventoryAsync([Snapshot(Start, ("alpha", "1"))], CancellationToken.None));
        Assert.Equal("0", runtime.Health().Details["baseline_item_count"]);

        await using (var connection = new SqliteConnection($"Data Source={Path.Combine(temporary.Path, "queue.db")}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "drop trigger synthetic_package_enqueue_failure;";
            await command.ExecuteNonQueryAsync();
        }

        var (restarted, restartedQueue, _) = Runtime(temporary.Path, clock);
        await restarted.InitializeAsync(CancellationToken.None);
        Assert.True(restarted.Health().GapDetected);
        Assert.Equal("interrupted_sequence_reservation", restarted.Health().ErrorCode);
        Assert.Equal("0", restarted.Health().Details["baseline_item_count"]);

        clock.Set(Start.AddHours(1));
        await restarted.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), ("alpha", "1"))], CancellationToken.None);
        var recovered = await restartedQueue.DequeueBatchAsync(10, CancellationToken.None);
        Assert.Equal(["package_inventory_recovery", "package_inventory_baseline"],
            recovered.Select(item => item.Envelope.EventCode!).ToArray());
        Assert.Equal("1", restarted.Health().Details["baseline_item_count"]);
    }

    [Fact]
    public async Task QueuedPrefixFromInterruptedMultiBatchObservationCanBeAcknowledgedAfterRestart()
    {
        using var temporary = new TemporaryDirectory();
        var clock = new MutableTimeProvider(Start);
        var (runtime, queue, _) = Runtime(temporary.Path, clock);
        await runtime.ObserveInventoryAsync([Snapshot(Start, ("base", "1"))], CancellationToken.None);
        await AcknowledgeAndDelete(runtime, queue, await queue.DequeueBatchAsync(10, CancellationToken.None));

        await using (var connection = new SqliteConnection($"Data Source={Path.Combine(temporary.Path, "queue.db")}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "create trigger synthetic_second_batch_failure before insert on queued_events when (select count(*) from queued_events) >= 100 begin select raise(abort, 'synthetic second batch failure'); end;";
            await command.ExecuteNonQueryAsync();
        }
        clock.Set(Start.AddHours(1));
        var expanded = Enumerable.Range(0, 250).Select(index => ($"package-{index:D3}", "1"))
            .Append(("base", "1")).ToArray();
        await Assert.ThrowsAsync<SqliteException>(() =>
            runtime.ObserveInventoryAsync([Snapshot(clock.GetUtcNow(), expanded)], CancellationToken.None));
        Assert.Equal(100, await queue.CountAsync(CancellationToken.None));

        await using (var connection = new SqliteConnection($"Data Source={Path.Combine(temporary.Path, "queue.db")}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "drop trigger synthetic_second_batch_failure;";
            await command.ExecuteNonQueryAsync();
        }
        var (restarted, restartedQueue, _) = Runtime(temporary.Path, clock);
        await restarted.InitializeAsync(CancellationToken.None);
        var prefix = await restartedQueue.DequeueBatchAsync(100, CancellationToken.None);
        await restarted.RecordAcknowledgedAsync(prefix.Select(item => item.Envelope).ToArray(), CancellationToken.None);
        await restartedQueue.DeleteAsync(prefix.Select(item => item.QueueId).ToArray(), CancellationToken.None);

        Assert.Equal(1, restarted.Health().AcknowledgedCheckpoint!.Sequence);
        Assert.True(restarted.Health().GapDetected);
        Assert.Equal(0, await restartedQueue.CountAsync(CancellationToken.None));
    }

    private static (LinuxPackageInventoryDiffRuntime Runtime, SqliteEventQueue Queue, LinuxPackageJournalEvidenceTracker Tracker) Runtime(
        string root,
        TimeProvider clock)
    {
        var options = new LinuxAgentOptions
        {
            AgentId = "linux-synthetic-package-agent",
            Journal = new JournalOptions { TargetCoverageLevel = CoverageLevel.L2 },
            Queue = new QueueOptions { Path = Path.Combine(root, "queue.db"), MaxSizeMb = 16 }
        };
        var queue = new SqliteEventQueue(new AgentQueueOptions
        {
            Path = options.Queue.Path,
            MaxSizeMb = options.Queue.MaxSizeMb,
            MaxBackoffSeconds = options.Queue.MaxBackoffSeconds,
            MaxSendAttempts = options.Queue.MaxSendAttempts,
            WarningSizePercent = options.Queue.WarningSizePercent
        }, NullLogger<SqliteEventQueue>.Instance);
        var tracker = new LinuxPackageJournalEvidenceTracker();
        var store = new LinuxPackageInventoryDiffStateStore(Path.Combine(root, "package-state.json"), root);
        return (new(Options.Create(options), store, tracker, queue, clock), queue, tracker);
    }

    private static AssetInventorySnapshot Snapshot(DateTimeOffset at, params (string Name, string Version)[] packages) =>
        Snapshot(at, false, packages);

    private static AssetInventorySnapshot Snapshot(DateTimeOffset at, bool truncated, params (string Name, string Version)[] packages) => new()
    {
        AgentId = "linux-synthetic-package-agent",
        Hostname = "synthetic-host",
        SnapshotType = LinuxPackageManagementInventoryEvidence.SnapshotType,
        CollectedAt = at,
        Items = packages.Select(item => new InventoryItem
        {
            Kind = "package",
            Name = item.Name,
            Status = "installed",
            Metadata = new Dictionary<string, string>(StringComparer.Ordinal) { ["version"] = item.Version }
        }).ToArray(),
        Summary = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["state"] = "success",
            ["error_code"] = "none",
            ["truncated"] = truncated ? "true" : "false",
            [LinuxPackageManagementInventoryEvidence.StateKey] = LinuxPackageManagementInventoryStates.Supported,
            [LinuxPackageManagementInventoryEvidence.ProducerKey] = "pacman",
            [LinuxPackageManagementInventoryEvidence.ReasonKey] = "supported_package_manager_inventory"
        }
    };

    private static EventEnvelope PackageJournalEvent(DateTimeOffset at, string action, string packageName) => new()
    {
        Source = EventSources.LinuxJournal,
        SourceId = LinuxTelemetrySourceIds.PackageManagement,
        EventTime = at,
        Normalized = new NormalizedEventFields { Category = "package", Action = action, PackageName = packageName }
    };

    private static async Task AcknowledgeAndDelete(
        LinuxPackageInventoryDiffRuntime runtime,
        SqliteEventQueue queue,
        IReadOnlyCollection<QueuedEvent> events)
    {
        await runtime.RecordAcknowledgedAsync(events.Select(item => item.Envelope).ToArray(), CancellationToken.None);
        await queue.DeleteAsync(events.Select(item => item.QueueId).ToArray(), CancellationToken.None);
        queue.RecordAcknowledgedWork(events);
    }

    private sealed class MutableTimeProvider(DateTimeOffset current) : TimeProvider
    {
        private DateTimeOffset current = current;
        public override DateTimeOffset GetUtcNow() => current;
        public void Set(DateTimeOffset value) => current = value;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"challenger-package-synthetic-{Guid.NewGuid():N}");
        public TemporaryDirectory() => Directory.CreateDirectory(Path);
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
