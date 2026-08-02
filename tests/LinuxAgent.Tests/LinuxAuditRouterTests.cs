using System.Text;
using System.Text.Json;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Journal;
using Xunit;

namespace Challenger.Siem.LinuxAgent.Tests;

public sealed class LinuxAuditRouterTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-08-01T00:00:00Z");
    private const string BootId = "11111111111111111111111111111111";

    [Fact]
    public async Task DisabledRouterInterceptsTrustedAuditWithoutInspectingOrPersistingMessage()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: false);
        var runtime = new LinuxAuditRouterRuntime();
        var router = Router(options, state, new MutableTimeProvider(Now), runtime);

        var result = await router.RouteAsync(
            Record("disabled", Now, "SYSCALL", "type=SYSCALL msg=unparseable SYNTHETIC_SECRET_CANARY a0=never-retain"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);

        Assert.Equal(LinuxAuditRouteKind.Suppressed, result.Kind);
        Assert.Empty(result.Events);
        Assert.Equal(1, runtime.Current.SuppressedCount);
        var durable = await File.ReadAllBytesAsync(state.Path);
        Assert.StartsWith("CSARWAL1", Encoding.ASCII.GetString(durable, 0, 8));
        Assert.DoesNotContain("SYNTHETIC_SECRET_CANARY", Encoding.UTF8.GetString(durable), StringComparison.Ordinal);
        Assert.DoesNotContain("never-retain", Encoding.UTF8.GetString(durable), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisabledRouterOwnsOversizedTrustedAuditBeforeGenericNormalization()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: false);
        options.Journal.MaxInputRecordBytes = 4096;
        var router = Router(options, state, new MutableTimeProvider(Now), new LinuxAuditRouterRuntime());
        var oversized = "SYNTHETIC_SECRET_CANARY" + new string('x', 5000);

        var result = await router.RouteAsync(
            Record("oversized-disabled", Now, "SYSCALL", $"type=SYSCALL msg=invalid {oversized}"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);

        Assert.Equal(LinuxAuditRouteKind.Suppressed, result.Kind);
        Assert.DoesNotContain("SYNTHETIC_SECRET_CANARY", Encoding.UTF8.GetString(await File.ReadAllBytesAsync(state.Path)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompoundEventIsAllowlistedCrashStableAndAcknowledgedContiguously()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: true);
        var clock = new MutableTimeProvider(Now);
        var runtime = new LinuxAuditRouterRuntime();
        var router = Router(options, state, clock, runtime);

        var syscall = await router.RouteAsync(Record("one", Now, "SYSCALL",
            "type=SYSCALL msg=audit(1785542400.000:7) arch=c000003e syscall=59 success=yes pid=4242 ppid=41 uid=1001 auid=1001 exe=\"/usr/bin/synthetic\" a0=SYNTHETIC_SECRET_CANARY vendor_secret=never-retain"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.Equal(LinuxAuditRouteKind.Pending, syscall.Kind);
        var execve = await router.RouteAsync(Record("two", Now.AddMilliseconds(1), "EXECVE",
            "type=EXECVE msg=audit(1785542400.000:7) argc=2 a0=\"SYNTHETIC_SECRET_CANARY\" a1=\"never-retain\""),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.Equal(LinuxAuditRouteKind.Pending, execve.Kind);
        var completed = await router.RouteAsync(Record("three", Now.AddMilliseconds(2), "EOE",
            "type=EOE msg=audit(1785542400.000:7)"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);

        var envelope = Assert.Single(completed.Events);
        Assert.Equal("process_execution", envelope.EventCode);
        Assert.Equal("success", envelope.Normalized!.Outcome);
        var serialized = JsonSerializer.Serialize(envelope);
        Assert.DoesNotContain("SYNTHETIC_SECRET_CANARY", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("never-retain", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("a0", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("proctitle", serialized, StringComparison.OrdinalIgnoreCase);

        var restarted = Router(options, state, clock, new LinuxAuditRouterRuntime());
        await restarted.InitializeAsync(default);
        var replay = Assert.Single(restarted.ReplayQueued("synthetic-agent", "SYNTHETIC-LINUX-01"));
        Assert.Equal(envelope.EventId, replay.EventId);
        await restarted.RecordAcknowledgedAsync([replay], default);
        Assert.Empty(restarted.ReplayQueued("synthetic-agent", "SYNTHETIC-LINUX-01"));
        Assert.Equal(1, replay.Checkpoint!.Sequence);
    }

    [Fact]
    public async Task MandatoryL1ReserveTurnsAuditAdmissionIntoExplicitPressureGap()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: true);
        options.Journal.QueuePauseDepth = 1_000;
        options.Audit.ApprovedPlanHash = LinuxAuditRouter.ComputePlanHash(options);
        var runtime = new LinuxAuditRouterRuntime();
        var router = Router(options, state, new MutableTimeProvider(Now), runtime);

        await router.RouteAsync(Record("pressure-one", Now, "CONFIG_CHANGE",
            "type=CONFIG_CHANGE msg=audit(1785542400.000:8) auid=1001 success=yes action=changed"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default, queueDepth: 750);
        var result = await router.RouteAsync(Record("pressure-two", Now.AddMilliseconds(1), "EOE",
            "type=EOE msg=audit(1785542400.000:8)"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default, queueDepth: 750);

        Assert.Equal(LinuxAuditRouteKind.Gap, result.Kind);
        Assert.Equal("audit_l1_reserve_protected", result.ErrorCode);
        Assert.Empty(result.Events);
        Assert.True(runtime.Current.ActiveGap);
    }

    [Fact]
    public async Task QuietRecoveryIsAContentFreeQueueRowAndGapClearsOnlyAfterAcknowledgement()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: true);
        var clock = new MutableTimeProvider(Now);
        var runtime = new LinuxAuditRouterRuntime();
        var router = Router(options, state, clock, runtime);

        var gap = await router.RouteAsync(Record("bad", Now, "SYSCALL", "type=SYSCALL malformed"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.Equal(LinuxAuditRouteKind.Gap, gap.Kind);
        Assert.True(runtime.Current.ActiveGap);
        clock.Advance(TimeSpan.FromSeconds(6));

        var recovery = Assert.IsType<EventEnvelope>(await router.TryCreateQuietRecoveryAsync(
            "synthetic-agent", "SYNTHETIC-LINUX-01", 0, default));
        Assert.Equal("audit_source_recovery", recovery.EventCode);
        Assert.Equal("Linux audit source continuity recovered without collecting audit activity.", recovery.Message);
        Assert.Equal("source_health", recovery.Normalized!.Category);
        Assert.Empty(recovery.Normalized.Labels);
        var raw = recovery.Raw;
        Assert.False(raw.GetProperty("content_collected").GetBoolean());
        Assert.Equal(7, raw.EnumerateObject().Count());
        Assert.True(runtime.Current.ActiveGap);

        await router.RecordAcknowledgedAsync([recovery], default);
        Assert.False(runtime.Current.ActiveGap);
    }

    [Fact]
    public async Task CompletionBoundaryReturnsEveryExpiredEnvelopeBeforeCurrentCursorAdvances()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: true);
        var router = Router(options, state, new MutableTimeProvider(Now), new LinuxAuditRouterRuntime());

        await router.RouteAsync(Record("old", Now, "USER_AUTH",
            "type=USER_AUTH msg=audit(1785542400.000:20) uid=1001 auid=1001 res=success"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        var boundary = await router.RouteAsync(Record("new", Now.AddSeconds(6), "USER_AUTH",
            "type=USER_AUTH msg=audit(1785542406.000:21) uid=1002 auid=1002 res=success"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);

        var expired = Assert.Single(boundary.Events);
        Assert.Equal("authentication_session", expired.EventCode);
        Assert.Equal(LinuxAuditRouteKind.Pending, boundary.Kind);
    }

    [Fact]
    public async Task DisablementFinalizesPendingGroupAsGapAndSuppressesLaterRecords()
    {
        using var state = new TemporaryAuditState();
        var enabled = Options(enabled: true);
        var first = Router(enabled, state, new MutableTimeProvider(Now), new LinuxAuditRouterRuntime());
        Assert.Equal(LinuxAuditRouteKind.Pending, (await first.RouteAsync(
            Record("pending-before-disable", Now, "SYSCALL", "type=SYSCALL msg=audit(1785542400.000:30) syscall=59 uid=1001"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default)).Kind);

        var runtime = new LinuxAuditRouterRuntime();
        var disabled = Router(Options(enabled: false), state, new MutableTimeProvider(Now.AddSeconds(1)), runtime);
        await disabled.InitializeAsync(default);

        Assert.True(runtime.Current.ActiveGap);
        Assert.Equal("audit_disabled_with_pending_group", runtime.Current.ErrorCode);
        var later = await disabled.RouteAsync(
            Record("after-disable", Now.AddSeconds(2), "SYSCALL", "type=SYSCALL msg=unparseable SYNTHETIC_SECRET_CANARY"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        Assert.Equal(LinuxAuditRouteKind.Suppressed, later.Kind);
    }

    [Fact]
    public async Task PoisonAndQueueFailureRemainCoverageGapsRatherThanAcknowledgements()
    {
        using var poisonState = new TemporaryAuditState();
        var poisonRuntime = new LinuxAuditRouterRuntime();
        var poisonRouter = Router(Options(enabled: true), poisonState, new MutableTimeProvider(Now), poisonRuntime);
        await poisonRouter.RouteAsync(Record("poison-one", Now, "CONFIG_CHANGE",
            "type=CONFIG_CHANGE msg=audit(1785542400.000:40) auid=1001 success=yes action=changed"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        var poisonEnvelope = Assert.Single((await poisonRouter.RouteAsync(Record("poison-two", Now.AddMilliseconds(1), "EOE",
            "type=EOE msg=audit(1785542400.000:40)"), "synthetic-agent", "SYNTHETIC-LINUX-01", default)).Events);

        await poisonRouter.RecordRejectedAsync([poisonEnvelope], default);
        Assert.True(poisonRuntime.Current.ActiveGap);
        Assert.Equal(0, poisonRuntime.Current.AcknowledgedSequence);
        Assert.Empty(poisonRouter.ReplayQueued("synthetic-agent", "SYNTHETIC-LINUX-01"));

        using var queueState = new TemporaryAuditState();
        var queueRuntime = new LinuxAuditRouterRuntime();
        var queueRouter = Router(Options(enabled: true), queueState, new MutableTimeProvider(Now), queueRuntime);
        await queueRouter.RouteAsync(Record("queue-one", Now, "CONFIG_CHANGE",
            "type=CONFIG_CHANGE msg=audit(1785542400.000:41) auid=1001 success=yes action=changed"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        var queueEnvelope = Assert.Single((await queueRouter.RouteAsync(Record("queue-two", Now.AddMilliseconds(1), "EOE",
            "type=EOE msg=audit(1785542400.000:41)"), "synthetic-agent", "SYNTHETIC-LINUX-01", default)).Events);

        await queueRouter.RecordQueueInsertionFailureAsync(queueEnvelope, default);
        Assert.True(queueRuntime.Current.ActiveGap);
        Assert.Equal("audit_queue_insertion_failed", queueRuntime.Current.ErrorCode);
        Assert.Empty(queueRouter.ReplayQueued("synthetic-agent", "SYNTHETIC-LINUX-01"));
    }

    [Fact]
    public async Task PermanentlyRejectedSequenceDoesNotBlockLaterAcceptedProgress()
    {
        using var state = new TemporaryAuditState();
        var options = Options(enabled: true);
        var clock = new MutableTimeProvider(Now);
        var runtime = new LinuxAuditRouterRuntime();
        var router = Router(options, state, clock, runtime);

        async Task<EventEnvelope> QueueAsync(string cursor, int serial)
        {
            await router.RouteAsync(Record($"{cursor}-one", clock.GetUtcNow(), "CONFIG_CHANGE",
                $"type=CONFIG_CHANGE msg=audit(1785542400.000:{serial}) auid=1001 success=yes action=changed"),
                "synthetic-agent", "SYNTHETIC-LINUX-01", default);
            return Assert.Single((await router.RouteAsync(Record($"{cursor}-two", clock.GetUtcNow().AddMilliseconds(1), "EOE",
                $"type=EOE msg=audit(1785542400.000:{serial})"),
                "synthetic-agent", "SYNTHETIC-LINUX-01", default)).Events);
        }

        var rejected = await QueueAsync("rejected", 60);
        var accepted = await QueueAsync("accepted", 61);
        await router.RecordAcknowledgedAsync([accepted], default);
        Assert.Equal(0, runtime.Current.AcknowledgedSequence);

        runtime = new LinuxAuditRouterRuntime();
        router = Router(options, state, clock, runtime);
        await router.InitializeAsync(default);
        Assert.Equal(0, runtime.Current.AcknowledgedSequence);
        await router.RecordRejectedAsync([rejected], default);
        Assert.Equal(2, runtime.Current.AcknowledgedSequence);
        Assert.True(runtime.Current.ActiveGap);

        var restartedRuntime = new LinuxAuditRouterRuntime();
        router = Router(options, state, clock, restartedRuntime);
        await router.InitializeAsync(default);
        Assert.Equal(2, restartedRuntime.Current.AcknowledgedSequence);

        clock.Advance(TimeSpan.FromSeconds(1));
        var next = await QueueAsync("next", 62);
        await router.RecordAcknowledgedAsync([next], default);
        Assert.Equal(3, restartedRuntime.Current.AcknowledgedSequence);
        Assert.False(restartedRuntime.Current.ActiveGap);
    }

    [Fact]
    public async Task CorruptOrOverexposedPrivateStateFailsClosed()
    {
        using var state = new TemporaryAuditState();
        await File.WriteAllTextAsync(state.Path, "invalid-state");
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(state.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var corruptRuntime = new LinuxAuditRouterRuntime();
        var corrupt = Router(Options(enabled: true), state, new MutableTimeProvider(Now), corruptRuntime);
        await corrupt.InitializeAsync(default);
        Assert.False(corruptRuntime.Current.StateHealthy);
        Assert.Equal(LinuxAuditRouteKind.Stop, (await corrupt.RouteAsync(
            Record("corrupt", Now, "SYSCALL", "type=SYSCALL msg=audit(1785542400.000:50) syscall=59"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default)).Kind);

        File.Delete(state.Path);
        var healthy = Router(Options(enabled: false), state, new MutableTimeProvider(Now), new LinuxAuditRouterRuntime());
        await healthy.RouteAsync(Record("mode", Now, "SYSCALL", "type=SYSCALL msg=ignored"),
            "synthetic-agent", "SYNTHETIC-LINUX-01", default);
        if (!OperatingSystem.IsLinux()) return;
        File.SetUnixFileMode(state.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        var modeRuntime = new LinuxAuditRouterRuntime();
        await Router(Options(enabled: false), state, new MutableTimeProvider(Now), modeRuntime).InitializeAsync(default);
        Assert.False(modeRuntime.Current.StateHealthy);
    }

    [Theory]
    [InlineData("audit(01785542400.000:1)")]
    [InlineData("audit(1785542400.00:1)")]
    [InlineData("audit(1785542400.000:01)")]
    [InlineData("audit(1785542400.1000:1)")]
    public void AuditIdentityRejectsNonCanonicalOrOutOfRangeInputs(string identity)
    {
        Assert.False(LinuxAuditRouter.TryAuditIdentity($"type=SYSCALL msg={identity}", out _, out _));
    }

    private static LinuxAuditRouter Router(
        LinuxAgentOptions options,
        TemporaryAuditState state,
        TimeProvider clock,
        LinuxAuditRouterRuntime runtime) =>
        new(options, clock, runtime, new LinuxAuditStateStore(state.Path, enforceFixedPath: false));

    private static LinuxAgentOptions Options(bool enabled)
    {
        var options = new LinuxAgentOptions
        {
            AgentId = "synthetic-agent",
            Journal = new JournalOptions { Enabled = true, QueuePauseDepth = 10_000, MaxInputRecordBytes = 131_072 },
            Audit = new AuditOptions
            {
                Enabled = enabled,
                FacilityDeclaration = enabled ? "present_enabled" : "undeclared"
            }
        };
        if (enabled) options.Audit.ApprovedPlanHash = LinuxAuditRouter.ComputePlanHash(options);
        return options;
    }

    private static string Record(string cursor, DateTimeOffset observedAt, string type, string message) =>
        JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["__CURSOR"] = $"s=synthetic;i={cursor}",
            ["__REALTIME_TIMESTAMP"] = (observedAt.ToUnixTimeMilliseconds() * 1000).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["_BOOT_ID"] = BootId,
            ["_TRANSPORT"] = "audit",
            ["AUDIT_TYPE_NAME"] = type,
            ["MESSAGE"] = message
        });

    private sealed class MutableTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset current = value;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan by) => current += by;
    }

    private sealed class TemporaryAuditState : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"challenger-audit-synthetic-{Guid.NewGuid():N}");
        public TemporaryAuditState()
        {
            Directory.CreateDirectory(directory);
            Path = System.IO.Path.Combine(directory, "router.wal");
        }
        public string Path { get; }
        public void Dispose() => Directory.Delete(directory, recursive: true);
    }
}
