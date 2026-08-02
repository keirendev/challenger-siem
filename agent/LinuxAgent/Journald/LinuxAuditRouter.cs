using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Services;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

public static class LinuxAuditConstants
{
    public const string Interface = "systemd_journal_audit_v1";
    public const string StatePath = "/var/lib/challenger-siem-agent/audit-router-state.json";
    public const string RouterVersion = "systemd-journal-audit-router-v1";
    public const int MaxInputBytes = 131_072;
    public const int MaxMessageBytes = 65_536;
    public const int MaxRecordsPerGroup = 64;
    public const int MaxPendingGroups = 128;
    public const int MaxGroupBytes = 64 * 1024;
    public const int MaxAssemblyBytes = 8 * 1024 * 1024;
    public const int MaxWalRecords = 16_384;
    public const long MaxWalBytes = 64L * 1024 * 1024;
    public const int MaxWalRecordBytes = 4096;
    public const int MaxCursorBytes = 1024;
    public const int MaxRawBytes = 32 * 1024;
}

public sealed record LinuxAuditPlan(
    string PlanHash,
    bool Enabled,
    bool ApprovalHashMatches,
    string Interface,
    string FacilityDeclaration,
    string StatePath,
    string RequiredPrivileges,
    string HostChanges,
    string Privacy,
    IReadOnlyDictionary<string, long> Bounds);

public sealed record LinuxAuditRouterSnapshot(
    bool RouterAttested,
    bool StateHealthy,
    DateTimeOffset? LastPhysicalObservationAt,
    DateTimeOffset? LastEventAt,
    long CollectedSequence,
    long AcknowledgedSequence,
    long SuppressedCount,
    long UnsupportedTypeCount,
    long GapCount,
    bool ActiveGap,
    string Status,
    string? ErrorCode);

public sealed class LinuxAuditRouterRuntime
{
    private LinuxAuditRouterSnapshot current = new(true, true, null, null, 0, 0, 0, 0, 0, false, "starting", null);
    public LinuxAuditRouterSnapshot Current => Volatile.Read(ref current);
    internal void Publish(LinuxAuditRouterSnapshot value) => Volatile.Write(ref current, value);
}

public enum LinuxAuditRouteKind { NotAudit, Suppressed, Filtered, Pending, Queued, Gap, Stop }

public sealed record LinuxAuditRouteResult(
    LinuxAuditRouteKind Kind,
    string? Cursor = null,
    DateTimeOffset? EventTime = null,
    EventEnvelope? Envelope = null,
    string? ErrorCode = null,
    IReadOnlyList<EventEnvelope>? PriorEnvelopes = null)
{
    public IReadOnlyList<EventEnvelope> Events => PriorEnvelopes is { Count: > 0 }
        ? Envelope is null ? PriorEnvelopes : PriorEnvelopes.Append(Envelope).ToArray()
        : Envelope is null ? Array.Empty<EventEnvelope>() : [Envelope];
}

public sealed class LinuxAuditRouter : ILinuxAcknowledgementObserver
{
    private static readonly IReadOnlyDictionary<string, string> Families = BuildFamilies();
    private static readonly IReadOnlySet<string> ExplicitlyExcludedTypes = new HashSet<string>(StringComparer.Ordinal)
    { "TTY", "USER_TTY", "USER_CMD" };
    private static readonly IReadOnlySet<string> AllowedFields = new HashSet<string>(StringComparer.Ordinal)
    {
        "uid", "gid", "auid", "ses", "pid", "ppid", "arch", "syscall", "success", "res", "exit",
        "exe", "key", "acct", "terminal", "service", "action", "scontext", "tcontext", "tclass", "perm",
        "item", "nametype", "dev", "inode", "mode", "name", "addr", "port"
    };

    private readonly LinuxAgentOptions options;
    private readonly TimeProvider timeProvider;
    private readonly LinuxAuditStateStore stateStore;
    private readonly LinuxAuditRouterRuntime runtime;
    private readonly LinuxJournalRuntime? journalRuntime;
    private LinuxAuditPrivateState state = new();
    private bool initialized;
    private readonly SemaphoreSlim stateGate = new(1, 1);
    private double admissionTokens = 500;
    private DateTimeOffset? lastTokenRefill;
    private DateTimeOffset? lastObservationPersistedAt;

    public LinuxAuditRouter(
        IOptions<LinuxAgentOptions> configured,
        TimeProvider timeProvider,
        LinuxAuditRouterRuntime runtime,
        LinuxJournalRuntime? journalRuntime = null)
    {
        options = configured.Value;
        this.timeProvider = timeProvider;
        this.runtime = runtime;
        this.journalRuntime = journalRuntime;
        stateStore = new(options.Audit.StatePath);
    }

    internal LinuxAuditRouter(
        LinuxAgentOptions configured,
        TimeProvider timeProvider,
        LinuxAuditRouterRuntime runtime,
        LinuxAuditStateStore stateStore)
    {
        options = configured;
        this.timeProvider = timeProvider;
        this.runtime = runtime;
        journalRuntime = null;
        this.stateStore = stateStore;
    }

    public string PlanHash => ComputePlanHash(options);
    public bool IsEnabledAndApproved => options.Audit.Enabled
        && options.Audit.FacilityDeclaration == "present_enabled"
        && string.Equals(options.Audit.ApprovedPlanHash, PlanHash, StringComparison.Ordinal);

    internal static bool IsAuditTransport(string rawJournalJson)
    {
        try
        {
            using var document = JsonDocument.Parse(rawJournalJson, new JsonDocumentOptions { MaxDepth = 8 });
            return TryString(document.RootElement, "_TRANSPORT", out var transport) && transport == "audit";
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static string ComputePlanHash(LinuxAgentOptions configured)
    {
        var auditRows = AuditRowCapacity(configured.Journal.QueuePauseDepth);
        var canonical = string.Join('\n',
            LinuxAuditConstants.RouterVersion,
            $"source_id={LinuxTelemetrySourceIds.AuditFramework}",
            $"interface={configured.Audit.Interface}",
            $"facility={configured.Audit.FacilityDeclaration}",
            $"journal_scope={LinuxJournalScopes.Configured(configured.Journal)}",
            $"state_path={configured.Audit.StatePath}",
            $"input_bytes={Math.Min(configured.Journal.MaxInputRecordBytes, LinuxAuditConstants.MaxInputBytes)}",
            $"message_bytes={LinuxAuditConstants.MaxMessageBytes}",
            $"records_per_group={LinuxAuditConstants.MaxRecordsPerGroup}",
            $"pending_groups={LinuxAuditConstants.MaxPendingGroups}",
            $"assembly_bytes={LinuxAuditConstants.MaxAssemblyBytes}",
            $"wal_records={LinuxAuditConstants.MaxWalRecords}",
            $"wal_bytes={LinuxAuditConstants.MaxWalBytes}",
            $"audit_rows={auditRows}",
            "discard=raw_message,arguments,proctitle,environments,tty,unknown_fields");
        return "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public LinuxAuditPlan Preflight() => new(
        PlanHash,
        options.Audit.Enabled,
        IsEnabledAndApproved,
        options.Audit.Interface,
        options.Audit.FacilityDeclaration,
        options.Audit.StatePath,
        "Existing unprivileged journal access only; no audit capabilities, groups, ACLs, packages, rules, or service control.",
        "None. The router only intercepts trusted audit transport in the existing system-journal stream and writes agent-owned private state.",
        "Only allowlisted normalized fields are queueable. Raw audit messages, arguments, proctitles, environments, TTY data, and unknown fields are discarded before durable queueing.",
        new Dictionary<string, long>(StringComparer.Ordinal)
        {
            ["max_input_bytes"] = Math.Min(options.Journal.MaxInputRecordBytes, LinuxAuditConstants.MaxInputBytes),
            ["max_message_bytes"] = LinuxAuditConstants.MaxMessageBytes,
            ["max_records_per_group"] = LinuxAuditConstants.MaxRecordsPerGroup,
            ["max_pending_groups"] = LinuxAuditConstants.MaxPendingGroups,
            ["max_assembly_bytes"] = LinuxAuditConstants.MaxAssemblyBytes,
            ["max_wal_records"] = LinuxAuditConstants.MaxWalRecords,
            ["max_wal_bytes"] = LinuxAuditConstants.MaxWalBytes,
            ["audit_row_capacity"] = AuditRowCapacity(options.Journal.QueuePauseDepth)
        });

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await stateGate.WaitAsync(cancellationToken);
        try { await InitializeCoreAsync(cancellationToken); }
        finally { stateGate.Release(); }
    }

    private async Task InitializeCoreAsync(CancellationToken cancellationToken)
    {
        if (initialized) return;
        try
        {
            state = await stateStore.ReadAsync(cancellationToken);
            lastObservationPersistedAt = state.LastPhysicalObservationAt;
            initialized = true;
            var generationChanged = IsEnabledAndApproved
                && state.ActivePlanHash is not null
                && !string.Equals(state.ActivePlanHash, PlanHash, StringComparison.Ordinal);
            if ((!IsEnabledAndApproved || generationChanged) && state.Pending.Count > 0)
            {
                foreach (var group in state.Pending.Values.OrderBy(item => item.FirstPhysicalIndex).ToArray())
                    await FinalizePendingGapAsync(group, "audit_disabled_with_pending_group", "audit_disabled_pending_gap", cancellationToken);
            }
            if (IsEnabledAndApproved && !string.Equals(state.ActivePlanHash, PlanHash, StringComparison.Ordinal))
            {
                state = state with { ActivePlanHash = PlanHash };
                await PersistAsync(cancellationToken);
            }
            Publish(state.ActiveGap ? "degraded" : IsEnabledAndApproved ? "ready" : "disabled", state.ErrorCode);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            initialized = true;
            state = new() { StateHealthy = false, ActiveGap = true, GapCount = 1, ErrorCode = "audit_state_invalid" };
            Publish("error", "audit_state_invalid");
        }
    }

    public async Task<LinuxAuditRouteResult> RouteAsync(
        string rawJournalJson,
        string agentId,
        string hostname,
        CancellationToken cancellationToken,
        int queueDepth = 0)
    {
        await stateGate.WaitAsync(cancellationToken);
        try
        {
            if (!initialized) await InitializeCoreAsync(cancellationToken);
            return await RouteCoreAsync(rawJournalJson, agentId, hostname, cancellationToken, queueDepth);
        }
        finally { stateGate.Release(); }
    }

    private async Task<LinuxAuditRouteResult> RouteCoreAsync(
        string rawJournalJson,
        string agentId,
        string hostname,
        CancellationToken cancellationToken,
        int queueDepth)
    {
        var inputBytes = Encoding.UTF8.GetByteCount(rawJournalJson);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(rawJournalJson, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            // Without a parseable trusted transport field this record cannot be
            // classified as audit. The ordinary journal normalizer records the
            // malformed-input gap without exposing the input.
            return new(LinuxAuditRouteKind.NotAudit);
        }
        using (document)
        {
        var root = document.RootElement;
        if (!TryString(root, "_TRANSPORT", out var transport) || transport != "audit") return new(LinuxAuditRouteKind.NotAudit);
        if (!TryJournalIdentity(root, out var cursor, out var bootId, out var journalTime))
            return await GapAsync(null, null, "audit_journal_identity_invalid", cancellationToken);

        if (state.Queued.TryGetValue(cursor, out var replay))
            return new(LinuxAuditRouteKind.Queued, cursor, replay.EventTime,
                BuildQueuedEnvelope(replay, agentId, hostname));
        if (string.Equals(state.CollectedCursor, cursor, StringComparison.Ordinal))
            return new(LinuxAuditRouteKind.Suppressed, cursor, journalTime);

        if (state.Wal.Count >= LinuxAuditConstants.MaxWalRecords
            || SafeEncodedSize() >= LinuxAuditConstants.MaxWalBytes - LinuxAuditConstants.MaxWalRecordBytes)
        {
            state = state with { StateHealthy = false, ErrorCode = "journal_router_wal_full" };
            Publish("error", "journal_router_wal_full");
            return new(LinuxAuditRouteKind.Stop, ErrorCode: "journal_router_wal_full");
        }

        state = state with { LastPhysicalObservationAt = timeProvider.GetUtcNow() };
        if (!state.StateHealthy)
        {
            Publish("error", state.ErrorCode ?? "audit_state_invalid");
            return new(LinuxAuditRouteKind.Stop, ErrorCode: state.ErrorCode ?? "audit_state_invalid");
        }
        if (!IsEnabledAndApproved)
        {
            state = state with { SuppressedCount = SaturatingIncrement(state.SuppressedCount) };
            AppendWal("audit_suppressed", cursor, cursor, null, "disabled_or_unapproved", true);
            await PersistAsync(cancellationToken);
            Publish("disabled", null);
            return new(LinuxAuditRouteKind.Suppressed, cursor, journalTime);
        }

        if (inputBytes > Math.Min(options.Journal.MaxInputRecordBytes, LinuxAuditConstants.MaxInputBytes))
            return await GapAsync(cursor, journalTime, "audit_input_oversized", cancellationToken);

        if (!TryString(root, "MESSAGE", out var message)
            || Encoding.UTF8.GetByteCount(message) > LinuxAuditConstants.MaxMessageBytes
            || !TryAuditIdentity(message, out var auditTime, out var serial)
            || !TryRecordType(root, message, out var recordType))
            return await GapAsync(cursor, journalTime, "audit_input_invalid", cancellationToken);

        if (ExplicitlyExcludedTypes.Contains(recordType) || !Families.ContainsKey(recordType) && recordType is not "EOE" and not "EXECVE" and not "PROCTITLE" and not "PATH" and not "SOCKADDR")
        {
            state = state with { UnsupportedTypeCount = SaturatingIncrement(state.UnsupportedTypeCount) };
            AppendWal("audit_contract_filtered", cursor, cursor, null, "record_type_filtered", true);
            await PersistAsync(cancellationToken);
            Publish("healthy", null);
            return new(LinuxAuditRouteKind.Filtered, cursor, journalTime);
        }

        var identity = $"{bootId}:{serial.ToString(CultureInfo.InvariantCulture)}";
        var expiredEvents = await FinalizeExpiredAsync(journalTime, agentId, hostname, queueDepth, cancellationToken);
        if (!state.Pending.TryGetValue(identity, out var group))
        {
            if (state.Pending.Count >= LinuxAuditConstants.MaxPendingGroups)
            {
                var oldest = state.Pending.Values.OrderBy(value => value.FirstPhysicalIndex).First();
                state.Pending.Remove(oldest.Identity);
                await FinalizePendingGapAsync(oldest, "audit_pending_group_evicted", "audit_pressure_gap", cancellationToken);
            }
            group = new LinuxAuditPendingGroup
            {
                Identity = identity,
                BootId = bootId,
                Serial = serial,
                EventTime = auditTime,
                FirstObservedAt = journalTime,
                FirstPhysicalIndex = state.PhysicalRecordCount,
                FirstCursor = cursor,
                LastCursor = cursor
            };
            state.Pending[identity] = group;
        }
        group.LastCursor = cursor;
        group.RecordCount++;
        group.Types.Add(recordType);
        state = state with { PhysicalRecordCount = SaturatingIncrement(state.PhysicalRecordCount) };
        if (group.RecordCount > LinuxAuditConstants.MaxRecordsPerGroup || group.Types.Count > 16)
        {
            state.Pending.Remove(identity);
            return WithPrior(await FinalizePendingGapAsync(group, "audit_group_bound_exceeded", "audit_input_gap", cancellationToken), expiredEvents);
        }
        if (recordType is not "EOE" and not "EXECVE" and not "PROCTITLE") ExtractAllowedFields(root, message, recordType, group);
        if (JsonSerializer.SerializeToUtf8Bytes(group, JsonDefaults.Options).Length > LinuxAuditConstants.MaxGroupBytes
            || state.Pending.Values.Sum(item => (long)JsonSerializer.SerializeToUtf8Bytes(item, JsonDefaults.Options).Length) > LinuxAuditConstants.MaxAssemblyBytes)
        {
            state.Pending.Remove(identity);
            return WithPrior(await FinalizePendingGapAsync(group, "audit_assembly_bound_exceeded", "audit_pressure_gap", cancellationToken), expiredEvents);
        }
        AppendWal("audit_pending", group.FirstCursor, cursor, null, null, false, group.Identity);
        if (recordType != "EOE")
        {
            await PersistAsync(cancellationToken);
            Publish("healthy", null);
            return new(LinuxAuditRouteKind.Pending, cursor, journalTime, PriorEnvelopes: expiredEvents);
        }
        return WithPrior(await FinalizeGroupAsync(group, partial: false, agentId, hostname, queueDepth, cancellationToken), expiredEvents);
        }
    }

    public IReadOnlyList<EventEnvelope> ReplayQueued(string agentId, string hostname)
    {
        stateGate.Wait();
        try
        {
            return state.Queued.Values.OrderBy(item => item.Sequence)
                .Select(item => BuildQueuedEnvelope(item, agentId, hostname)).ToArray();
        }
        finally { stateGate.Release(); }
    }

    public async Task<EventEnvelope?> TryCreateQuietRecoveryAsync(
        string agentId,
        string hostname,
        int queueDepth,
        CancellationToken cancellationToken)
    {
        await stateGate.WaitAsync(cancellationToken);
        try
        {
            if (!initialized) await InitializeCoreAsync(cancellationToken);
            return await TryCreateQuietRecoveryCoreAsync(agentId, hostname, queueDepth, cancellationToken);
        }
        finally { stateGate.Release(); }
    }

    public async Task RecordSuccessfulPhysicalReadAsync(CancellationToken cancellationToken)
    {
        await stateGate.WaitAsync(cancellationToken);
        try
        {
            if (!initialized) await InitializeCoreAsync(cancellationToken);
            if (!state.StateHealthy) return;
            var now = timeProvider.GetUtcNow();
            state = state with { LastPhysicalObservationAt = now };
            if (lastObservationPersistedAt is null || now - lastObservationPersistedAt >= TimeSpan.FromMinutes(1))
            {
                await PersistAsync(cancellationToken);
                lastObservationPersistedAt = now;
            }
            Publish(!IsEnabledAndApproved ? "disabled" : state.ActiveGap ? "degraded" : "healthy", state.ErrorCode);
        }
        finally { stateGate.Release(); }
    }

    private async Task<EventEnvelope?> TryCreateQuietRecoveryCoreAsync(
        string agentId,
        string hostname,
        int queueDepth,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        if (!IsEnabledAndApproved || !state.StateHealthy || !state.ActiveGap
            || state.GapStartedAt is not { } gapStarted || now - gapStarted < TimeSpan.FromSeconds(5)
            || state.CollectedCursor is null || state.Pending.Count > 0
            || state.Queued.Values.Any(item => item.ClearsGap)
            || !TryAdmit(queueDepth, out _)) return null;
        var sequence = state.NextSequence;
        var envelope = BuildRecoveryEnvelope(agentId, hostname, sequence, now, state.ActiveGapIdHash ?? HashText("audit-gap"));
        state = state with { NextSequence = checked(sequence + 1), CollectedSequence = sequence, LastEventAt = now };
        AppendWal("audit_queued", state.CollectedCursor, state.CollectedCursor, sequence, "audit_source_recovery", false);
        state.Queued[$"{state.CollectedCursor}#recovery#{sequence.ToString(CultureInfo.InvariantCulture)}"] =
            new(null, "source_health_recovery", false, sequence, true, envelope);
        await PersistAsync(cancellationToken);
        Publish("recovering", state.ErrorCode);
        return envelope;
    }

    private async Task<IReadOnlyList<EventEnvelope>> FinalizeExpiredAsync(
        DateTimeOffset journalTime,
        string agentId,
        string hostname,
        int queueDepth,
        CancellationToken cancellationToken)
    {
        var events = new List<EventEnvelope>();
        var expired = state.Pending.Values.Where(group => journalTime - group.FirstObservedAt >= TimeSpan.FromSeconds(5)
            || state.PhysicalRecordCount - group.FirstPhysicalIndex >= 500).OrderBy(group => group.FirstPhysicalIndex).ToArray();
        foreach (var group in expired)
        {
            var result = await FinalizeGroupAsync(group, partial: !IsSingleRecordCandidate(group), agentId, hostname, queueDepth + events.Count, cancellationToken);
            if (result.Envelope is not null) events.Add(result.Envelope);
        }
        return events;
    }

    private async Task<LinuxAuditRouteResult> FinalizeGroupAsync(
        LinuxAuditPendingGroup group,
        bool partial,
        string agentId,
        string hostname,
        int queueDepth,
        CancellationToken cancellationToken)
    {
        state.Pending.Remove(group.Identity);
        var family = DetermineFamily(group.Types);
        if (family is null)
        {
            FinalizePendingWal(group.Identity);
            AppendWal("audit_contract_filtered", group.FirstCursor, group.LastCursor, null, "no_allowlisted_family", true);
            await PersistAsync(cancellationToken);
            return new(LinuxAuditRouteKind.Filtered, group.LastCursor, group.EventTime);
        }
        if (!TryAdmit(queueDepth, out var pressureReason))
            return await FinalizePendingGapAsync(group, pressureReason, "audit_pressure_gap", cancellationToken);
        var sequence = state.NextSequence;
        state = state with { NextSequence = checked(sequence + 1), CollectedSequence = sequence };
        FinalizePendingWal(group.Identity);
        AppendWal("audit_queued", group.FirstCursor, group.LastCursor, sequence, null, false);
        state.Queued[group.LastCursor] = new(group, family, partial, sequence, state.ActiveGap && !partial);
        state = state with { LastEventAt = group.EventTime };
        await PersistAsync(cancellationToken);
        var envelope = BuildEnvelope(group, family, partial, sequence, agentId, hostname);
        Publish("healthy", null);
        return new(LinuxAuditRouteKind.Queued, group.LastCursor, group.EventTime, envelope);
    }

    private bool TryAdmit(int queueDepth, out string reason)
    {
        var reserve = MandatoryL1Reserve(options.Journal.QueuePauseDepth);
        var auditCapacity = AuditRowCapacity(options.Journal.QueuePauseDepth);
        if (auditCapacity <= 0) { reason = "audit_row_capacity_zero"; return false; }
        if (state.Queued.Count >= auditCapacity) { reason = "audit_row_capacity_reached"; return false; }
        if (queueDepth >= options.Journal.QueuePauseDepth - reserve) { reason = "audit_l1_reserve_protected"; return false; }
        if (state.Wal.Count >= LinuxAuditConstants.MaxWalRecords * 3 / 4
            || SafeEncodedSize() >= LinuxAuditConstants.MaxWalBytes * 3 / 4)
        {
            reason = "audit_wal_pressure";
            return false;
        }
        var now = timeProvider.GetUtcNow();
        if (lastTokenRefill is { } last)
            admissionTokens = Math.Min(500, admissionTokens + Math.Max(0, (now - last).TotalSeconds) * 100);
        lastTokenRefill = now;
        if (admissionTokens < 1) { reason = "audit_rate_limited"; return false; }
        admissionTokens -= 1;
        reason = "none";
        return true;
    }

    private long SafeEncodedSize()
    {
        try { return stateStore.EncodedSize(state); }
        catch (InvalidDataException) { return LinuxAuditConstants.MaxWalBytes; }
    }

    private async Task<LinuxAuditRouteResult> FinalizePendingGapAsync(
        LinuxAuditPendingGroup group,
        string reason,
        string disposition,
        CancellationToken cancellationToken)
    {
        state.Pending.Remove(group.Identity);
        FinalizePendingWal(group.Identity);
        state = state with
        {
            GapCount = SaturatingIncrement(state.GapCount),
            ActiveGap = true,
            ActiveGapIdHash = state.ActiveGapIdHash ?? HashText($"{reason}:{state.GapCount + 1}"),
            GapStartedAt = state.GapStartedAt ?? timeProvider.GetUtcNow(),
            ErrorCode = reason
        };
        AppendWal(disposition, group.FirstCursor, group.LastCursor, null, reason, true);
        await PersistAsync(cancellationToken);
        Publish("degraded", reason);
        return new(LinuxAuditRouteKind.Gap, group.LastCursor, group.EventTime, ErrorCode: reason);
    }

    private void FinalizePendingWal(string identity)
    {
        foreach (var entry in state.Wal.Where(item => item.Disposition == "audit_pending" && item.GroupIdentity == identity))
            entry.Final = true;
    }

    private static LinuxAuditRouteResult WithPrior(LinuxAuditRouteResult result, IReadOnlyList<EventEnvelope> prior) =>
        prior.Count == 0 ? result : result with { PriorEnvelopes = prior };

    private EventEnvelope BuildEnvelope(LinuxAuditPendingGroup group, string family, bool partial, long sequence, string agentId, string hostname)
    {
        var result = NormalizeResult(group.Fields);
        var rawValues = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = LinuxAuditConstants.RouterVersion,
            ["event_time"] = group.EventTime,
            ["audit_serial"] = group.Serial.ToString(CultureInfo.InvariantCulture),
            ["boot_id"] = group.BootId,
            ["family"] = family,
            ["record_types"] = group.Types.Where(type => type != "EOE").Order(StringComparer.Ordinal).Take(16).ToArray(),
            ["result"] = result,
            ["fields"] = group.Fields.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
            ["paths"] = group.Paths.OrderBy(path => path.Item).Take(8).ToArray(),
            ["partial"] = partial,
            ["truncated"] = group.Truncated,
            ["input_record_count"] = group.RecordCount,
            ["retained_record_count"] = group.RetainedRecordCount,
            ["duplicate_field_count"] = group.DuplicateFieldCount,
            ["field_drop_count"] = group.FieldDropCount
        };
        var raw = JsonSerializer.SerializeToElement(rawValues, JsonDefaults.Options);
        var rawBytes = JsonSerializer.SerializeToUtf8Bytes(raw, JsonDefaults.Options).Length;
        if (rawBytes > LinuxAuditConstants.MaxRawBytes) throw new InvalidDataException("audit_normalized_raw_too_large");
        var normalized = new NormalizedEventFields
        {
            Category = family == "audit_policy_tamper" ? "audit_policy" : family,
            Action = family == "audit_policy_tamper" ? "audit_policy_change" : "observed",
            Outcome = result,
            ProcessId = group.Fields.GetValueOrDefault("pid"),
            ParentProcessId = group.Fields.GetValueOrDefault("ppid"),
            ProcessImage = group.Fields.GetValueOrDefault("exe"),
            User = group.Fields.GetValueOrDefault("uid") is { } uid ? new UserTelemetryConcept { Id = uid } : null,
            Labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["audit.partial"] = partial ? "true" : "false",
                ["audit.routed_interface"] = LinuxAuditConstants.Interface
            }
        };
        var rawHash = DeterministicEventIdentity.ComputeRawSha256(raw);
        var withoutId = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.LinuxAudit,
            SourceId = LinuxTelemetrySourceIds.AuditFramework,
            EventCode = family,
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = group.EventTime, RecordedAt = timeProvider.GetUtcNow() },
            EventTime = group.EventTime,
            Severity = family == "audit_policy_tamper" ? "warning" : "audit_success",
            Message = $"Linux audit {family.Replace('_', ' ')} evidence normalized.",
            Normalized = normalized,
            Raw = raw,
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode, DeduplicationInputs.EventTime, DeduplicationInputs.RawSha256],
                RawSha256 = rawHash
            },
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = rawBytes,
                RedactionApplied = group.Redacted,
                RedactedFields = group.Redacted ? ["raw.fields"] : [],
                TruncationApplied = group.Truncated,
                TruncatedFields = group.Truncated ? ["raw.fields"] : []
            }
        };
        return withoutId with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(withoutId) };
    }

    private EventEnvelope BuildQueuedEnvelope(LinuxAuditQueuedGroup queued, string agentId, string hostname) =>
        queued.RecoveryEnvelope ?? BuildEnvelope(queued.Group!, queued.Family, queued.Partial, queued.Sequence, agentId, hostname);

    private EventEnvelope BuildRecoveryEnvelope(string agentId, string hostname, long sequence, DateTimeOffset observedAt, string gapIdHash)
    {
        var raw = JsonSerializer.SerializeToElement(new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = LinuxAuditConstants.RouterVersion,
            ["record_kind"] = "source_health_recovery",
            ["gap_id_hash"] = gapIdHash,
            ["reason_code"] = "audit_continuity_recovered",
            ["content_collected"] = false,
            ["routed_interface"] = LinuxAuditConstants.Interface,
            ["observation_time"] = observedAt
        }, JsonDefaults.Options);
        var rawBytes = JsonSerializer.SerializeToUtf8Bytes(raw, JsonDefaults.Options).Length;
        var withoutId = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.LinuxAudit,
            SourceId = LinuxTelemetrySourceIds.AuditFramework,
            EventCode = "audit_source_recovery",
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = observedAt, RecordedAt = observedAt },
            EventTime = observedAt,
            Severity = "information",
            Message = "Linux audit source continuity recovered without collecting audit activity.",
            Normalized = new NormalizedEventFields { Category = "source_health", Action = "recovered", Outcome = "success" },
            Raw = raw,
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode, DeduplicationInputs.EventTime, DeduplicationInputs.RawSha256],
                RawSha256 = DeterministicEventIdentity.ComputeRawSha256(raw)
            },
            DataHandling = new DataHandlingMetadata { RawSizeBytes = rawBytes }
        };
        return withoutId with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(withoutId) };
    }

    private async Task<LinuxAuditRouteResult> GapAsync(string? cursor, DateTimeOffset? time, string reason, CancellationToken cancellationToken)
    {
        state = state with
        {
            GapCount = SaturatingIncrement(state.GapCount),
            ActiveGap = true,
            ActiveGapIdHash = state.ActiveGapIdHash ?? HashText($"{reason}:{state.GapCount + 1}"),
            GapStartedAt = state.GapStartedAt ?? timeProvider.GetUtcNow(),
            ErrorCode = reason
        };
        if (cursor is not null) AppendWal("audit_input_gap", cursor, cursor, null, reason, true);
        await PersistAsync(cancellationToken);
        Publish("degraded", reason);
        return new(LinuxAuditRouteKind.Gap, cursor, time, ErrorCode: reason);
    }

    private void AppendWal(
        string disposition,
        string firstCursor,
        string lastCursor,
        long? sequence,
        string? reason,
        bool final,
        string? groupIdentity = null,
        string? rowId = null)
    {
        if (!IsSafeCursor(firstCursor) || !IsSafeCursor(lastCursor)) throw new InvalidDataException("audit_cursor_invalid");
        var entry = new LinuxAuditWalEntry
        {
            Disposition = disposition,
            FirstCursor = firstCursor,
            LastCursor = lastCursor,
            Sequence = sequence,
            Reason = reason,
            GroupIdentity = groupIdentity,
            RowId = rowId,
            GapIdHash = reason is null ? null : HashText($"{reason}:{state.GapCount}"),
            Count = 1,
            Final = final
        };
        if (JsonSerializer.SerializeToUtf8Bytes(entry, JsonDefaults.Options).Length > LinuxAuditConstants.MaxWalRecordBytes)
            throw new InvalidDataException("audit_wal_record_too_large");
        if (state.Wal.Count >= LinuxAuditConstants.MaxWalRecords)
            throw new InvalidDataException("journal_router_wal_full");
        state.Wal.Add(entry);
        state = state with { CollectedCursor = lastCursor };
        CompactWal();
    }

    private void CompactWal()
    {
        var remove = 0;
        while (remove < state.Wal.Count && state.Wal[remove].Final) remove++;
        if (remove == 0) return;
        state = state with
        {
            FinalizedCursor = state.Wal[remove - 1].LastCursor,
            Wal = state.Wal.Skip(remove).ToList()
        };
    }

    private async Task PersistAsync(CancellationToken cancellationToken) => await stateStore.WriteAsync(state, cancellationToken);

    private void Publish(string status, string? errorCode) => runtime.Publish(new(
        true,
        state.StateHealthy,
        state.LastPhysicalObservationAt,
        state.LastEventAt,
        state.CollectedSequence,
        state.AcknowledgedSequence,
        state.SuppressedCount,
        state.UnsupportedTypeCount,
        state.GapCount,
        state.ActiveGap,
        status,
        errorCode));

    private static void ExtractAllowedFields(JsonElement root, string message, string recordType, LinuxAuditPendingGroup group)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var token in Tokenize(message).Take(128))
        {
            var separator = token.IndexOf('=');
            if (separator <= 0) continue;
            var key = token[..separator];
            if (!AllowedFields.Contains(key) || key is "msg" || key is "a0" or "a1" or "a2" or "a3") continue;
            if (!values.TryAdd(key, token[(separator + 1)..].Trim('"'))) group.DuplicateFieldCount++;
        }
        foreach (var key in AllowedFields)
        {
            foreach (var candidate in new[] { key, key.ToUpperInvariant(), "AUDIT_" + key.ToUpperInvariant() })
            {
                if (!TryString(root, candidate, out var structured)) continue;
                values[key] = structured;
                break;
            }
        }

        if (recordType == "PATH")
        {
            if (group.Paths.Count >= 8 || !TryPath(values, out var path, out var pathTruncated, out var pathRedacted))
            {
                group.FieldDropCount++;
                group.Truncated = true;
            }
            else if (group.Paths.Any(item => item.Item == path.Item))
            {
                group.DuplicateFieldCount++;
            }
            else
            {
                group.Paths.Add(path);
                group.Truncated |= pathTruncated;
                group.Redacted |= pathRedacted;
            }
            group.RetainedRecordCount++;
            return;
        }

        foreach (var pair in values)
        {
            if (!TryNormalizeAuditField(pair.Key, pair.Value, out var normalized, out var truncated, out var redacted))
            {
                group.FieldDropCount++;
                group.Truncated = true;
                continue;
            }
            if (group.Fields.ContainsKey(pair.Key)) { group.DuplicateFieldCount++; continue; }
            group.Fields[pair.Key] = normalized;
            group.Redacted |= redacted;
            group.Truncated |= truncated;
        }
        group.RetainedRecordCount++;
    }

    private static bool TryNormalizeAuditField(
        string key,
        string value,
        out string normalized,
        out bool truncated,
        out bool redacted)
    {
        normalized = string.Empty;
        truncated = false;
        redacted = false;
        switch (key)
        {
            case "uid" or "gid" or "auid" or "ses":
                return TryCanonicalUInt32(value, out normalized);
            case "pid":
                return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) && pid >= 1
                    && (normalized = pid.ToString(CultureInfo.InvariantCulture)).Length > 0;
            case "ppid":
                return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var ppid) && ppid >= 0
                    && (normalized = ppid.ToString(CultureInfo.InvariantCulture)).Length > 0;
            case "arch":
                if (value.Length == 8 && value.All(char.IsAsciiHexDigit)) { normalized = value.ToLowerInvariant(); return true; }
                return false;
            case "syscall":
                return TryCanonicalUInt32(value, out normalized);
            case "success" or "res":
                normalized = value switch
                {
                    "yes" or "1" or "success" => "success",
                    "no" or "0" or "failed" or "failure" => "failure",
                    _ => string.Empty
                };
                return normalized.Length > 0;
            case "exit":
                return int.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var exit)
                    && (normalized = exit.ToString(CultureInfo.InvariantCulture)).Length > 0;
            case "port":
                return ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
                    && (normalized = port.ToString(CultureInfo.InvariantCulture)).Length > 0;
            case "addr":
                if (value.Length is < 1 or > 128 || value.Any(character => character > 0x7f || char.IsControl(character))) return false;
                normalized = value;
                return true;
            case "tclass":
                return TryAuditText(value, 64, out normalized, out truncated, out redacted);
            case "scontext" or "tcontext":
                return TryAuditText(value, 256, out normalized, out truncated, out redacted);
            case "exe":
                return TryAuditText(value, 512, out normalized, out truncated, out redacted);
            case "terminal" or "service" or "action":
                return TryAuditText(value, 64, out normalized, out truncated, out redacted);
            case "key" or "acct":
                return TryAuditText(value, 128, out normalized, out truncated, out redacted);
            case "perm":
                var permissions = value.Trim('{', '}').Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(item => item.Length is >= 1 and <= 32 && item.All(character => char.IsAsciiLetterOrDigit(character) || character == '_'))
                    .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Take(17).ToArray();
                if (permissions.Length is 0 or > 16) return false;
                normalized = string.Join(',', permissions);
                return true;
            default:
                return false;
        }
    }

    private static bool TryPath(
        IReadOnlyDictionary<string, string> values,
        out LinuxAuditPathValue path,
        out bool truncated,
        out bool redacted)
    {
        path = new();
        truncated = false;
        redacted = false;
        if (!uint.TryParse(values.GetValueOrDefault("item"), NumberStyles.None, CultureInfo.InvariantCulture, out var item)
            || !ulong.TryParse(values.GetValueOrDefault("inode"), NumberStyles.None, CultureInfo.InvariantCulture, out var inode)
            || !TryDevice(values.GetValueOrDefault("dev"), out var device)
            || !TryMode(values.GetValueOrDefault("mode"), out var mode)
            || values.GetValueOrDefault("nametype") is not { } nameType
            || nameType.Length is < 1 or > 32 || nameType.Any(character => (character < 'A' || character > 'Z') && character != '_')
            || values.GetValueOrDefault("name") is not { } rawPath
            || !TryAuditText(rawPath, 512, out var sanitizedPath, out truncated, out redacted)) return false;
        path = new LinuxAuditPathValue(item, nameType, device, inode.ToString(CultureInfo.InvariantCulture), mode, sanitizedPath);
        return true;
    }

    private static bool TryDevice(string? value, out string normalized)
    {
        normalized = string.Empty;
        var parts = value?.Split(':');
        if (parts is not { Length: 2 }
            || !uint.TryParse(parts[0], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var major)
            || !uint.TryParse(parts[1], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var minor)) return false;
        normalized = $"{major:x}:{minor:x}";
        return true;
    }

    private static bool TryMode(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (value == "00") { normalized = value; return true; }
        if (value is null || value.Length is < 6 or > 7 || value[0] != '0' || value.Any(character => character is < '0' or > '7')) return false;
        try
        {
            var numeric = Convert.ToUInt32(value, 8);
            if (numeric > 0xFFFF) return false;
            normalized = value;
            return true;
        }
        catch (FormatException) { return false; }
        catch (OverflowException) { return false; }
    }

    private static bool TryCanonicalUInt32(string value, out string normalized)
    {
        normalized = string.Empty;
        if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number)) return false;
        normalized = number.ToString(CultureInfo.InvariantCulture);
        return string.Equals(value, normalized, StringComparison.Ordinal);
    }

    private static bool TryAuditText(string value, int maxBytes, out string normalized, out bool truncated, out bool redacted)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maxBytes));
        var bytes = 0;
        truncated = false;
        foreach (var rune in value.EnumerateRunes())
        {
            var size = rune.Utf8SequenceLength;
            if (bytes + size > maxBytes) { truncated = true; break; }
            builder.Append(rune.ToString());
            bytes += size;
        }
        var sanitized = TelemetryTextSanitizer.SanitizeAndRedact(builder.ToString(), Math.Max(1, builder.Length));
        normalized = sanitized.Value;
        redacted = sanitized.Redacted;
        truncated |= sanitized.Truncated;
        return !sanitized.Dropped && normalized.Length > 0;
    }

    private static IEnumerable<string> Tokenize(string value)
    {
        var current = new StringBuilder();
        var quoted = false;
        foreach (var character in value)
        {
            if (character == '"') quoted = !quoted;
            if (char.IsWhiteSpace(character) && !quoted)
            {
                if (current.Length > 0) { yield return current.ToString(); current.Clear(); }
                continue;
            }
            if (current.Length < 1024) current.Append(character);
        }
        if (current.Length > 0) yield return current.ToString();
    }

    internal static bool TryAuditIdentity(string message, out DateTimeOffset eventTime, out ulong serial)
    {
        eventTime = default;
        serial = 0;
        var marker = message.IndexOf("msg=audit(", StringComparison.Ordinal);
        if (marker < 0) return false;
        var start = marker + 10;
        var dot = message.IndexOf('.', start);
        var colon = dot < 0 ? -1 : message.IndexOf(':', dot + 1);
        var close = colon < 0 ? -1 : message.IndexOf(')', colon + 1);
        var secondsText = dot > start ? message.AsSpan(start, dot - start) : default;
        var millisText = colon > dot + 1 ? message.AsSpan(dot + 1, colon - dot - 1) : default;
        var serialText = close > colon + 1 ? message.AsSpan(colon + 1, close - colon - 1) : default;
        if (dot <= start || colon <= dot + 1 || close <= colon + 1
            || secondsText.Length > 1 && secondsText[0] == '0'
            || millisText.Length != 3
            || serialText.Length > 1 && serialText[0] == '0'
            || !ulong.TryParse(secondsText, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            || seconds > 253402300799UL
            || !uint.TryParse(millisText, NumberStyles.None, CultureInfo.InvariantCulture, out var millis)
            || millis > 999
            || !ulong.TryParse(serialText, NumberStyles.None, CultureInfo.InvariantCulture, out serial)) return false;
        try { eventTime = DateTimeOffset.FromUnixTimeSeconds((long)seconds).AddMilliseconds(millis); return true; }
        catch (ArgumentOutOfRangeException) { return false; }
    }

    private static bool TryRecordType(JsonElement root, string message, out string type)
    {
        foreach (var key in new[] { "AUDIT_TYPE_NAME", "_AUDIT_TYPE_NAME", "TYPE" })
            if (TryString(root, key, out var structured) && IsType(structured)) { type = structured; return true; }
        var marker = message.IndexOf("type=", StringComparison.Ordinal);
        var end = marker < 0 ? -1 : message.IndexOfAny([' ', '\t'], marker + 5);
        var candidate = marker < 0 ? string.Empty : message[(marker + 5)..(end < 0 ? message.Length : end)];
        type = candidate;
        return IsType(candidate);
    }

    private static bool IsType(string value) => value.Length is >= 1 and <= 32 && value.All(character => character is >= 'A' and <= 'Z' or '_' or >= '0' and <= '9');
    private static string? DetermineFamily(IReadOnlySet<string> types)
    {
        if (types.Contains("SYSCALL")) return types.Contains("EXECVE") || types.Contains("PROCTITLE") ? "process_execution" : "authorization_syscall";
        return types.Select(type => Families.GetValueOrDefault(type)).FirstOrDefault(value => value is not null);
    }
    private static bool IsSingleRecordCandidate(LinuxAuditPendingGroup group) => group.RecordCount == 1 && group.Types.SingleOrDefault() is { } type && Families.ContainsKey(type) && type != "SYSCALL";
    private static string NormalizeResult(IReadOnlyDictionary<string, string> fields) =>
        fields.GetValueOrDefault("success") ?? fields.GetValueOrDefault("res") ?? "unknown";
    private static bool TryJournalIdentity(JsonElement root, out string cursor, out string boot, out DateTimeOffset time)
    {
        cursor = string.Empty;
        boot = string.Empty;
        time = default;
        if (!TryString(root, "__CURSOR", out cursor) || !IsSafeCursor(cursor)
            || !TryString(root, "_BOOT_ID", out boot) || boot.Length != 32 || !boot.All(char.IsAsciiHexDigit)
            || !TryString(root, "__REALTIME_TIMESTAMP", out var micros)
            || micros.Length > 1 && micros[0] == '0'
            || !long.TryParse(micros, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < 0) return false;
        boot = boot.ToLowerInvariant();
        try { time = DateTimeOffset.FromUnixTimeMilliseconds(value / 1000); return true; } catch (ArgumentOutOfRangeException) { return false; }
    }
    private static bool TryString(JsonElement root, string name, out string value)
    {
        value = string.Empty;
        return root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var property)
            && property.ValueKind == JsonValueKind.String && (value = property.GetString() ?? string.Empty).Length > 0;
    }
    private static bool IsSafeCursor(string cursor) => Encoding.UTF8.GetByteCount(cursor) <= LinuxAuditConstants.MaxCursorBytes && cursor.All(character => character is >= ' ' and <= '~');
    private static int MandatoryL1Reserve(int queuePauseDepth) =>
        Math.Min(queuePauseDepth, Math.Max(100, (int)Math.Ceiling(queuePauseDepth / 4m)));

    internal static long AuditRowCapacity(int queuePauseDepth)
    {
        var reserve = MandatoryL1Reserve(queuePauseDepth);
        return Math.Min(10_000, Math.Max(0, queuePauseDepth - reserve) / 10);
    }
    private static long SaturatingIncrement(long value) => value == long.MaxValue ? value : value + 1;

    private static LinuxAuditPrivateState ReconcileSequenceProgress(LinuxAuditPrivateState value)
    {
        var cursor = Math.Max(value.AcknowledgedSequence, value.AbandonedThroughSequence);
        var acknowledged = value.AcknowledgedSequence;
        var abandonedThrough = value.AbandonedThroughSequence;
        value.AcceptedSequences.RemoveWhere(sequence => sequence <= cursor);
        value.AbandonedSequences.RemoveWhere(sequence => sequence <= cursor);
        while (cursor < value.CollectedSequence && cursor < long.MaxValue)
        {
            var next = cursor + 1;
            if (value.AcceptedSequences.Remove(next))
            {
                cursor = next;
                acknowledged = next;
                value.AbandonedSequences.Remove(next);
                continue;
            }
            if (value.AbandonedSequences.Remove(next))
            {
                cursor = next;
                abandonedThrough = next;
                continue;
            }
            break;
        }
        return value with
        {
            AcknowledgedSequence = acknowledged,
            AbandonedThroughSequence = abandonedThrough
        };
    }

    private static string HashText(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static IReadOnlyDictionary<string, string> BuildFamilies()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        void Add(string family, params string[] types) { foreach (var type in types) result[type] = family; }
        Add("authentication_session", "USER_AUTH", "USER_ACCT", "USER_LOGIN", "USER_START", "USER_END", "CRED_ACQ", "CRED_DISP");
        Add("authorization_syscall", "SYSCALL");
        Add("mandatory_access_control", "AVC", "USER_AVC", "SELINUX_ERR", "MAC_STATUS", "MAC_POLICY_LOAD");
        Add("audit_policy_tamper", "CONFIG_CHANGE", "FEATURE_CHANGE", "DAEMON_START", "DAEMON_END", "DAEMON_ABORT", "DAEMON_CONFIG");
        Add("integrity", "INTEGRITY_RULE", "INTEGRITY_DATA", "INTEGRITY_METADATA", "INTEGRITY_STATUS", "INTEGRITY_HASH", "INTEGRITY_PCR");
        return result;
    }

    private static readonly IReadOnlySet<string> RoutedSourceIds = LinuxTelemetrySourceCatalog.All
        .Where(item => item.SourceKind is TelemetrySourceKinds.LinuxJournal or TelemetrySourceKinds.LinuxAudit)
        .Select(item => item.SourceId).ToHashSet(StringComparer.Ordinal);

    public bool HandlesSource(string? sourceId) => sourceId is not null && RoutedSourceIds.Contains(sourceId);

    public Task RecordL1QueuedAsync(NormalizedJournalRecord record, CancellationToken cancellationToken) =>
        RecordL1QueuedBatchAsync([record], cancellationToken);

    public async Task RecordL1QueuedBatchAsync(
        IReadOnlyCollection<NormalizedJournalRecord> records,
        CancellationToken cancellationToken)
    {
        if (records.Count == 0) return;

        await stateGate.WaitAsync(cancellationToken);
        try
        {
            if (!initialized) await InitializeCoreAsync(cancellationToken);
            var existing = state.Wal
                .Where(item => item.Disposition == "l1_queued" && item.RowId is not null)
                .Select(item => item.RowId!)
                .ToHashSet(StringComparer.Ordinal);
            var pending = records
                .Where(record => existing.Add(record.Envelope.EventId.ToString("D")))
                .ToArray();
            if (pending.Length == 0) return;

            var previousState = state with { Wal = state.Wal.ToList() };
            try
            {
                foreach (var record in pending)
                {
                    AppendWal(
                        "l1_queued",
                        record.Cursor,
                        record.Cursor,
                        null,
                        null,
                        false,
                        rowId: record.Envelope.EventId.ToString("D"));
                }
                await PersistAsync(cancellationToken);
            }
            catch
            {
                state = previousState;
                throw;
            }
        }
        finally { stateGate.Release(); }
    }

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await stateGate.WaitAsync(cancellationToken);
        try
        {
        var sequences = events.Where(item => item.Source == EventSources.LinuxAudit
                && string.Equals(item.SourceId, LinuxTelemetrySourceIds.AuditFramework, StringComparison.Ordinal)
                && item.Checkpoint?.Sequence is not null)
            .Select(item => item.Checkpoint!.Sequence!.Value).ToHashSet();
        var l1RowIds = events.Where(item => item.Source == EventSources.LinuxJournal)
            .Select(item => item.EventId.ToString("D")).ToHashSet(StringComparer.Ordinal);
        if (sequences.Count == 0 && l1RowIds.Count == 0) return;
        var clearsGap = state.Queued.Values.Any(item => item.ClearsGap && sequences.Contains(item.Sequence));
        foreach (var entry in state.Wal.Where(entry => entry.Sequence.HasValue && sequences.Contains(entry.Sequence.Value)))
            entry.Final = true;
        foreach (var entry in state.Wal.Where(entry => entry.RowId is not null && l1RowIds.Contains(entry.RowId)))
            entry.Final = true;
        foreach (var pair in state.Queued.Where(pair => sequences.Contains(pair.Value.Sequence)).ToArray()) state.Queued.Remove(pair.Key);
        foreach (var sequence in sequences.Where(sequence => sequence <= state.CollectedSequence))
            state.AcceptedSequences.Add(sequence);
        state = ReconcileSequenceProgress(state);
        state = state with
        {
            ActiveGap = clearsGap ? false : state.ActiveGap,
            ActiveGapIdHash = clearsGap ? null : state.ActiveGapIdHash,
            GapStartedAt = clearsGap ? null : state.GapStartedAt,
            ErrorCode = clearsGap ? null : state.ErrorCode
        };
        CompactWal();
        await PersistAsync(cancellationToken);
        Publish(state.ActiveGap ? "degraded" : "healthy", state.ErrorCode);
        }
        finally { stateGate.Release(); }
    }

    public async Task RecordRejectedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await stateGate.WaitAsync(cancellationToken);
        try
        {
        var sequences = events.Where(item => item.Source == EventSources.LinuxAudit
                && string.Equals(item.SourceId, LinuxTelemetrySourceIds.AuditFramework, StringComparison.Ordinal)
                && item.Checkpoint?.Sequence is not null)
            .Select(item => item.Checkpoint!.Sequence!.Value).ToHashSet();
        var l1RowIds = events.Where(item => item.Source == EventSources.LinuxJournal)
            .Select(item => item.EventId.ToString("D")).ToHashSet(StringComparer.Ordinal);
        if (sequences.Count == 0 && l1RowIds.Count == 0) return;
        foreach (var entry in state.Wal.Where(item => item.RowId is not null && l1RowIds.Contains(item.RowId)))
        {
            entry.Disposition = "l1_poison_gap";
            entry.Reason = "server_permanent_rejection";
            entry.Final = true;
        }
        if (l1RowIds.Count > 0) journalRuntime?.RecordGap("l1_poison_gap");
        foreach (var entry in state.Wal.Where(entry => entry.Sequence.HasValue && sequences.Contains(entry.Sequence.Value)))
        {
            entry.Disposition = "audit_poison_gap";
            entry.Reason = "server_permanent_rejection";
            entry.Final = true;
        }
        foreach (var pair in state.Queued.Where(pair => sequences.Contains(pair.Value.Sequence)).ToArray()) state.Queued.Remove(pair.Key);
        foreach (var sequence in sequences.Where(sequence => sequence <= state.CollectedSequence))
            state.AbandonedSequences.Add(sequence);
        if (sequences.Count > 0) state = state with
        {
            ActiveGap = true,
            ActiveGapIdHash = state.ActiveGapIdHash ?? HashText($"audit_poison_gap:{state.GapCount + 1}"),
            GapStartedAt = state.GapStartedAt ?? timeProvider.GetUtcNow(),
            GapCount = SaturatingIncrement(state.GapCount),
            ErrorCode = "audit_poison_gap"
        };
        state = ReconcileSequenceProgress(state);
        CompactWal();
        await PersistAsync(cancellationToken);
        Publish(state.ActiveGap ? "degraded" : "healthy", state.ErrorCode);
        }
        finally { stateGate.Release(); }
    }

    public async Task RecordQueueInsertionFailureAsync(EventEnvelope envelope, CancellationToken cancellationToken)
    {
        if (!HandlesSource(envelope.SourceId) || envelope.Checkpoint?.Sequence is not { } sequence) return;
        await stateGate.WaitAsync(cancellationToken);
        try
        {
            foreach (var entry in state.Wal.Where(item => item.Sequence == sequence))
            {
                entry.Disposition = "audit_pressure_gap";
                entry.Reason = "audit_queue_insertion_failed";
                entry.Final = true;
            }
            foreach (var pair in state.Queued.Where(item => item.Value.Sequence == sequence).ToArray()) state.Queued.Remove(pair.Key);
            if (sequence <= state.CollectedSequence) state.AbandonedSequences.Add(sequence);
            state = state with
            {
                ActiveGap = true,
                ActiveGapIdHash = state.ActiveGapIdHash ?? HashText($"audit_queue_insertion_failed:{state.GapCount + 1}"),
                GapStartedAt = state.GapStartedAt ?? timeProvider.GetUtcNow(),
                GapCount = SaturatingIncrement(state.GapCount),
                ErrorCode = "audit_queue_insertion_failed"
            };
            state = ReconcileSequenceProgress(state);
            CompactWal();
            await PersistAsync(cancellationToken);
            Publish("degraded", state.ErrorCode);
        }
        finally { stateGate.Release(); }
    }

    public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events)
    {
        if (!events.Any(item => HandlesSource(item.SourceId))) return;
        if (events.Any(item => item.Source == EventSources.LinuxJournal)) journalRuntime?.RecordGap("l1_acknowledgement_state_failed");
        if (!events.Any(item => item.Source == EventSources.LinuxAudit)) return;
        stateGate.Wait();
        try
        {
        state = state with
        {
            ActiveGap = true,
            ActiveGapIdHash = state.ActiveGapIdHash ?? HashText($"audit_acknowledgement_state_failed:{state.GapCount + 1}"),
            GapStartedAt = state.GapStartedAt ?? timeProvider.GetUtcNow(),
            ErrorCode = "audit_acknowledgement_state_failed"
        };
        Publish("error", state.ErrorCode);
        }
        finally { stateGate.Release(); }
    }
}

internal sealed record LinuxAuditPrivateState
{
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; init; } = 1;
    [JsonPropertyName("state_healthy")] public bool StateHealthy { get; init; } = true;
    [JsonPropertyName("next_sequence")] public long NextSequence { get; init; } = 1;
    [JsonPropertyName("collected_sequence")] public long CollectedSequence { get; init; }
    [JsonPropertyName("acknowledged_sequence")] public long AcknowledgedSequence { get; init; }
    [JsonPropertyName("abandoned_through_sequence")] public long AbandonedThroughSequence { get; init; }
    [JsonPropertyName("accepted_sequences")] public SortedSet<long> AcceptedSequences { get; init; } = new();
    [JsonPropertyName("abandoned_sequences")] public SortedSet<long> AbandonedSequences { get; init; } = new();
    [JsonPropertyName("collected_cursor")] public string? CollectedCursor { get; init; }
    [JsonPropertyName("finalized_cursor")] public string? FinalizedCursor { get; init; }
    [JsonPropertyName("physical_record_count")] public long PhysicalRecordCount { get; init; }
    [JsonPropertyName("suppressed_count")] public long SuppressedCount { get; init; }
    [JsonPropertyName("unsupported_type_count")] public long UnsupportedTypeCount { get; init; }
    [JsonPropertyName("gap_count")] public long GapCount { get; init; }
    [JsonPropertyName("active_gap")] public bool ActiveGap { get; init; }
    [JsonPropertyName("active_gap_id_hash")] public string? ActiveGapIdHash { get; init; }
    [JsonPropertyName("gap_started_at")] public DateTimeOffset? GapStartedAt { get; init; }
    [JsonPropertyName("error_code")] public string? ErrorCode { get; init; }
    [JsonPropertyName("active_plan_hash")] public string? ActivePlanHash { get; init; }
    [JsonPropertyName("last_physical_observation_at")] public DateTimeOffset? LastPhysicalObservationAt { get; init; }
    [JsonPropertyName("last_event_at")] public DateTimeOffset? LastEventAt { get; init; }
    [JsonPropertyName("pending")] public Dictionary<string, LinuxAuditPendingGroup> Pending { get; init; } = new(StringComparer.Ordinal);
    [JsonPropertyName("queued")] public Dictionary<string, LinuxAuditQueuedGroup> Queued { get; init; } = new(StringComparer.Ordinal);
    [JsonPropertyName("wal")] public List<LinuxAuditWalEntry> Wal { get; init; } = new();
}

internal sealed record LinuxAuditPendingGroup
{
    public string Identity { get; init; } = string.Empty;
    public string BootId { get; init; } = string.Empty;
    public ulong Serial { get; init; }
    public DateTimeOffset EventTime { get; init; }
    public DateTimeOffset FirstObservedAt { get; init; }
    public long FirstPhysicalIndex { get; init; }
    public string FirstCursor { get; init; } = string.Empty;
    public string LastCursor { get; set; } = string.Empty;
    public int RecordCount { get; set; }
    public int RetainedRecordCount { get; set; }
    public int DuplicateFieldCount { get; set; }
    public int FieldDropCount { get; set; }
    public bool Truncated { get; set; }
    public bool Redacted { get; set; }
    public HashSet<string> Types { get; init; } = new(StringComparer.Ordinal);
    public Dictionary<string, string> Fields { get; init; } = new(StringComparer.Ordinal);
    public List<LinuxAuditPathValue> Paths { get; init; } = new();
}

internal sealed record LinuxAuditPathValue(
    uint Item = 0,
    string NameType = "",
    string Device = "",
    string Inode = "",
    string Mode = "",
    string Path = "");

internal sealed record LinuxAuditWalEntry
{
    public string Disposition { get; set; } = string.Empty;
    public string FirstCursor { get; init; } = string.Empty;
    public string LastCursor { get; init; } = string.Empty;
    public long? Sequence { get; init; }
    public string? GroupIdentity { get; init; }
    public string? RowId { get; init; }
    public string? Reason { get; set; }
    public string? GapIdHash { get; init; }
    public int Count { get; init; }
    public bool Final { get; set; }
}

internal sealed record LinuxAuditQueuedGroup(
    LinuxAuditPendingGroup? Group,
    string Family,
    bool Partial,
    long Sequence,
    bool ClearsGap = false,
    EventEnvelope? RecoveryEnvelope = null)
{
    [JsonIgnore]
    public DateTimeOffset EventTime => RecoveryEnvelope?.EventTime ?? Group?.EventTime ?? DateTimeOffset.MinValue;
}

internal sealed class LinuxAuditStateStore
{
    private static readonly byte[] Magic = "CSARWAL1"u8.ToArray();
    private readonly string path;
    private readonly bool enforceFixedPath;

    public LinuxAuditStateStore(string path, bool enforceFixedPath = true)
    {
        this.path = path;
        this.enforceFixedPath = enforceFixedPath;
    }

    public async Task<LinuxAuditPrivateState> ReadAsync(CancellationToken cancellationToken)
    {
        ValidatePath();
        if (!File.Exists(path)) return new();
        byte[] bytes;
        if (OperatingSystem.IsLinux())
        {
            var descriptor = NativeMethods.open(path, NativeMethods.O_RDONLY | NativeMethods.O_CLOEXEC | NativeMethods.O_NOFOLLOW);
            if (descriptor < 0)
            {
                var error = Marshal.GetLastPInvokeError();
                if (error == NativeMethods.ENOENT) return new();
                if (error == NativeMethods.EACCES) throw new UnauthorizedAccessException("audit_state_access_denied");
                throw new IOException("audit_state_open_failed");
            }
            using var handle = new Microsoft.Win32.SafeHandles.SafeFileHandle((nint)descriptor, ownsHandle: true);
            if (NativeMethods.statx(descriptor, string.Empty,
                    NativeMethods.AT_EMPTY_PATH | NativeMethods.AT_SYMLINK_NOFOLLOW,
                    NativeMethods.STATX_BASIC_STATS, out var status) != 0
                || status.LinkCount != 1
                || status.UserId != NativeMethods.geteuid()
                || (status.Mode & NativeMethods.S_IFMT) != NativeMethods.S_IFREG
                || (status.Mode & NativeMethods.PERMISSION_MASK) != NativeMethods.OWNER_READ_WRITE
                || status.Size > LinuxAuditConstants.MaxWalBytes)
                throw new InvalidDataException("audit_state_owner_mode_invalid");
            await using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
            using var buffer = new MemoryStream((int)status.Size);
            await stream.CopyToAsync(buffer, cancellationToken);
            bytes = buffer.ToArray();
        }
        else
        {
            var info = new FileInfo(path);
            if (info.LinkTarget is not null || info.Length > LinuxAuditConstants.MaxWalBytes)
                throw new InvalidDataException("audit_state_invalid");
            bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        }
        if (bytes.Length < Magic.Length + sizeof(int) || !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("audit_state_format_invalid");
        var offset = Magic.Length;
        var metadataLength = ReadLength(bytes, ref offset);
        if (metadataLength <= 0 || metadataLength > LinuxAuditConstants.MaxWalBytes - offset || offset + metadataLength > bytes.Length)
            throw new InvalidDataException("audit_state_invalid");
        var state = JsonSerializer.Deserialize<LinuxAuditPrivateState>(bytes.AsSpan(offset, metadataLength), JsonDefaults.Options)
            ?? throw new InvalidDataException("audit_state_invalid");
        offset += metadataLength;
        var wal = new List<LinuxAuditWalEntry>();
        while (offset < bytes.Length)
        {
            var length = ReadLength(bytes, ref offset);
            if (length <= 0 || length > LinuxAuditConstants.MaxWalRecordBytes || offset + length > bytes.Length)
                throw new InvalidDataException("audit_wal_record_invalid");
            wal.Add(JsonSerializer.Deserialize<LinuxAuditWalEntry>(bytes.AsSpan(offset, length), JsonDefaults.Options)
                ?? throw new InvalidDataException("audit_wal_record_invalid"));
            offset += length;
            if (wal.Count > LinuxAuditConstants.MaxWalRecords) throw new InvalidDataException("audit_state_invalid");
        }
        state = state with { Wal = wal };
        if (state.SchemaVersion != 1 || state.Wal.Count > LinuxAuditConstants.MaxWalRecords || state.Pending.Count > LinuxAuditConstants.MaxPendingGroups
            || state.AcknowledgedSequence < 0 || state.AcknowledgedSequence > state.CollectedSequence
            || state.AbandonedThroughSequence < 0 || state.AbandonedThroughSequence > state.CollectedSequence
            || state.AcceptedSequences.Count + state.AbandonedSequences.Count > LinuxAuditConstants.MaxWalRecords
            || state.AcceptedSequences.Any(sequence => sequence <= 0 || sequence > state.CollectedSequence)
            || state.AbandonedSequences.Any(sequence => sequence <= 0 || sequence > state.CollectedSequence))
            throw new InvalidDataException("audit_state_invalid");
        return state;
    }

    public async Task WriteAsync(LinuxAuditPrivateState state, CancellationToken cancellationToken)
    {
        ValidatePath();
        var bytes = Encode(state);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + $".{Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant()}.tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                if (OperatingSystem.IsLinux()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }
            File.Move(temporary, path, true);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public long EncodedSize(LinuxAuditPrivateState state) => Encode(state).LongLength;

    private static byte[] Encode(LinuxAuditPrivateState state)
    {
        var metadata = JsonSerializer.SerializeToUtf8Bytes(state with { Wal = new() }, JsonDefaults.Options);
        using var stream = new MemoryStream(Math.Min((int)LinuxAuditConstants.MaxWalBytes, metadata.Length + 4096));
        stream.Write(Magic);
        WriteLength(stream, metadata.Length);
        stream.Write(metadata);
        foreach (var entry in state.Wal)
        {
            var encoded = JsonSerializer.SerializeToUtf8Bytes(entry, JsonDefaults.Options);
            if (encoded.Length > LinuxAuditConstants.MaxWalRecordBytes) throw new InvalidDataException("audit_wal_record_too_large");
            WriteLength(stream, encoded.Length);
            stream.Write(encoded);
            if (stream.Length > LinuxAuditConstants.MaxWalBytes) throw new InvalidDataException("journal_router_wal_full");
        }
        return stream.ToArray();
    }

    private static int ReadLength(byte[] bytes, ref int offset)
    {
        if (offset + sizeof(int) > bytes.Length) throw new InvalidDataException("audit_state_invalid");
        var value = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, sizeof(int)));
        offset += sizeof(int);
        return value;
    }

    private static void WriteLength(Stream stream, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        stream.Write(bytes);
    }

    private void ValidatePath()
    {
        if (enforceFixedPath && !string.Equals(Path.GetFullPath(path), LinuxAuditConstants.StatePath, StringComparison.Ordinal))
            throw new InvalidDataException("audit_state_path_invalid");
    }

    private static class NativeMethods
    {
        public const int O_RDONLY = 0;
        public const int O_CLOEXEC = 0x80000;
        public const int O_NOFOLLOW = 0x20000;
        public const int AT_SYMLINK_NOFOLLOW = 0x100;
        public const int AT_EMPTY_PATH = 0x1000;
        public const uint STATX_BASIC_STATS = 0x07ff;
        public const int ENOENT = 2;
        public const int EACCES = 13;
        public const ushort S_IFMT = 0xf000;
        public const ushort S_IFREG = 0x8000;
        public const ushort PERMISSION_MASK = 0x01ff;
        public const ushort OWNER_READ_WRITE = 0x0180;

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        public struct Statx
        {
            [FieldOffset(16)] public uint LinkCount;
            [FieldOffset(20)] public uint UserId;
            [FieldOffset(28)] public ushort Mode;
            [FieldOffset(40)] public ulong Size;
        }

        [DllImport("libc", SetLastError = true)]
        public static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags);

        [DllImport("libc", SetLastError = true)]
        public static extern int statx(int directoryFileDescriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname,
            int flags, uint mask, out Statx buffer);

        [DllImport("libc")]
        public static extern uint geteuid();
    }
}
