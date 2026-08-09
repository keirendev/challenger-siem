using System.Globalization;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Queue;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.L4;
using Challenger.Siem.LinuxAgent.Services;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Package;

public sealed class LinuxPackageInventoryDiffRuntime(
    IOptions<LinuxAgentOptions> configured,
    LinuxPackageInventoryDiffStateStore stateStore,
    LinuxPackageJournalEvidenceTracker journalEvidence,
    IEventQueue queue,
    TimeProvider timeProvider) : ILinuxInventoryObserver, ILinuxAcknowledgementObserver
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object sync = new();
    private LinuxPackageInventoryDiffState state = new();
    private string stateError = "not_initialized";
    private bool initialized;

    public SourceManifestEntry Manifest
    {
        get
        {
            var manifest = LinuxTelemetrySourceCatalog.Find(LinuxTelemetrySourceIds.PackageInventoryDiff)!;
            lock (sync)
            {
                if (state.Status == SourceHealthStatuses.Unsupported)
                    return manifest with { Applicability = SourceApplicabilityStatuses.Unsupported, ApplicabilityReason = state.ErrorCode };
                return manifest;
            }
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (initialized) return;
            var read = await stateStore.ReadAsync(cancellationToken);
            var recovered = RecoverReservation(read.State, timeProvider.GetUtcNow(), out var changed);
            if (changed) await stateStore.WriteAsync(recovered, cancellationToken);
            lock (sync)
            {
                state = recovered;
                stateError = read.ErrorCode;
                initialized = true;
            }
        }
        finally { gate.Release(); }
    }

    public async Task ObserveInventoryAsync(IReadOnlyList<AssetInventorySnapshot> snapshots, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        if (options.Journal.TargetCoverageLevel < CoverageLevel.L2) return;

        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState();
            current = RecoverReservation(current, timeProvider.GetUtcNow(), out var recovered);
            if (recovered)
            {
                await stateStore.WriteAsync(current, cancellationToken);
                SetState(current);
            }

            var evidence = LinuxPackageManagementInventoryEvidence.FromSnapshots(snapshots);
            var snapshot = snapshots.FirstOrDefault(item => string.Equals(
                item.SnapshotType, LinuxPackageManagementInventoryEvidence.SnapshotType, StringComparison.Ordinal));
            var invalid = InvalidSnapshotReason(snapshot, evidence);
            if (invalid is not null)
            {
                await CommitInvalidAsync(current, snapshot?.CollectedAt ?? timeProvider.GetUtcNow(), evidence, invalid, cancellationToken);
                return;
            }

            if (!TryBuildBaseline(snapshot!, out var baseline, out var baselineError))
            {
                await CommitInvalidAsync(current, snapshot!.CollectedAt, evidence, baselineError, cancellationToken);
                return;
            }

            var observedAt = snapshot!.CollectedAt.ToUniversalTime();
            var changes = current.BaselineCollectedAt.HasValue
                ? Diff(current.Baseline, baseline)
                : Array.Empty<LinuxPackageChange>();
            if (current.BaselineCollectedAt.HasValue)
            {
                journalEvidence.ObserveBoundary(
                    current.BaselineCollectedAt.Value,
                    observedAt,
                    changes.Select(item => (item.Action, item.PackageName)).ToArray());
            }

            var events = BuildEvents(current, changes, baseline.Count, evidence.Producer, observedAt);
            var capped = changes.Count + (current.ActiveGap ? 1 : 0) > LinuxPackageInventoryDiffConstants.MaximumEventsPerObservation;
            var dropped = capped
                ? Math.Max(0, changes.Count - Math.Max(0, LinuxPackageInventoryDiffConstants.MaximumEventsPerObservation - (current.ActiveGap ? 1 : 0) - 1))
                : 0;
            var activeGap = capped;
            var error = capped ? "package_change_event_cap_exceeded" : "none";
            var status = capped ? SourceHealthStatuses.Degraded : SourceHealthStatuses.Healthy;
            var familyCounts = AddFamilies(current.FamilyCounts, events);
            var result = current with
            {
                Baseline = baseline,
                BaselineCollectedAt = observedAt,
                LastObservedAt = observedAt,
                LastEventAt = events.Count > 0 ? observedAt : current.LastEventAt,
                Status = status,
                ErrorCode = error,
                ActiveGap = activeGap,
                GapCount = capped ? SaturatingAdd(current.GapCount, 1) : current.GapCount,
                DroppedCount = SaturatingAdd(current.DroppedCount, dropped),
                TransitionState = status == SourceHealthStatuses.Healthy
                    ? current.Status == SourceHealthStatuses.Healthy ? HealthTransitionStates.Healthy : HealthTransitionStates.Recovered
                    : HealthTransitionStates.Degraded,
                TransitionedAt = observedAt,
                Producer = evidence.Producer,
                FamilyCounts = familyCounts,
                NextSequence = events.Count == 0 ? current.NextSequence : events.Max(item => item.Checkpoint!.Sequence!.Value) + 1,
                CollectedSequence = events.Count == 0 ? current.CollectedSequence : events.Max(item => item.Checkpoint!.Sequence!.Value),
                PendingReservationStart = null,
                PendingReservationEnd = null
            };
            await CommitAsync(current, result, events, cancellationToken);
        }
        finally { gate.Release(); }
    }

    public SourceHealthReport Health()
    {
        lock (sync)
        {
            var manifest = Manifest;
            var requested = options.Journal.TargetCoverageLevel >= CoverageLevel.L2;
            var enabled = requested && manifest.Applicability != SourceApplicabilityStatuses.Unsupported;
            var now = timeProvider.GetUtcNow();
            var currentStatus = !requested ? SourceHealthStatuses.Disabled
                : stateError != "none" ? SourceHealthStatuses.Error
                : manifest.Applicability == SourceApplicabilityStatuses.Unsupported ? SourceHealthStatuses.Unsupported
                : state.Status;
            var error = !requested ? "source_above_configured_level"
                : stateError != "none" ? stateError
                : state.ErrorCode;
            return new SourceHealthReport
            {
                SourceId = manifest.SourceId,
                Platform = manifest.Platform,
                SourceKind = manifest.SourceKind,
                DisplayName = manifest.DisplayName,
                SourceNamespace = manifest.SourceNamespace,
                Applicability = manifest.Applicability,
                ApplicabilityReason = manifest.ApplicabilityReason,
                CoverageLevel = manifest.CoverageLevel,
                Status = currentStatus,
                Required = true,
                Requirement = SourceRequirementKinds.Mandatory,
                Enabled = enabled,
                ObservedAt = state.LastObservedAt,
                LastEventTime = state.LastEventAt,
                CollectedCheckpoint = new SourceCheckpoint { Sequence = state.CollectedSequence, EventTime = state.LastEventAt, RecordedAt = state.LastObservedAt },
                AcknowledgedCheckpoint = new SourceCheckpoint { Sequence = state.AcknowledgedSequence, EventTime = state.AcknowledgedAt, RecordedAt = state.AcknowledgedAt },
                LagSeconds = state.LastObservedAt.HasValue ? Math.Max(0, (long)(now - state.LastObservedAt.Value).TotalSeconds) : null,
                SilenceSeconds = state.LastEventAt.HasValue ? Math.Max(0, (long)(now - state.LastEventAt.Value).TotalSeconds) : null,
                EventRatePerMinute = 0,
                ErrorCode = error == "none" ? null : error,
                ErrorMessage = error == "none" ? null : error,
                GapDetected = state.ActiveGap,
                BookmarkGapDetected = state.ActiveGap,
                GapCount = state.GapCount,
                TransitionState = state.TransitionState,
                TransitionedAt = state.TransitionedAt,
                DroppedEvents = state.DroppedCount,
                PoisonEvents = 0,
                SourceVersion = LinuxPackageInventoryDiffConstants.CollectorVersion,
                PrerequisiteStatuses = manifest.Prerequisites.ToDictionary(item => item, item => item switch
                {
                    "bounded_package_inventory_available" => currentStatus switch
                    {
                        SourceHealthStatuses.Healthy => SourceEvidenceStatuses.Satisfied,
                        SourceHealthStatuses.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
                        SourceHealthStatuses.Unsupported => SourceEvidenceStatuses.Unsupported,
                        SourceHealthStatuses.Disabled => SourceEvidenceStatuses.Disabled,
                        SourceHealthStatuses.Missing => SourceEvidenceStatuses.Missing,
                        SourceHealthStatuses.Stale => SourceEvidenceStatuses.Stale,
                        _ => SourceEvidenceStatuses.Degraded
                    },
                    "complete_package_inventory_baseline" => state.BaselineCollectedAt.HasValue
                        ? state.ActiveGap ? SourceEvidenceStatuses.Degraded : SourceEvidenceStatuses.Satisfied
                        : SourceEvidenceStatuses.Missing,
                    _ => SourceEvidenceStatuses.Unknown
                }, StringComparer.Ordinal),
                EventFamilyStatuses = manifest.EventFamilies.ToDictionary(
                    item => item,
                    item => state.FamilyCounts.GetValueOrDefault(item) > 0 ? SourceEvidenceStatuses.Observed : SourceEvidenceStatuses.NotObserved,
                    StringComparer.Ordinal),
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["collector_state"] = enabled ? "enabled" : "disabled",
                    ["evidence_mode"] = "snapshot_diff",
                    ["producer"] = state.Producer,
                    ["baseline_state"] = state.BaselineCollectedAt.HasValue ? "established" : "not_established",
                    ["baseline_item_count"] = state.Baseline.Count.ToString(CultureInfo.InvariantCulture),
                    ["maximum_events_per_observation"] = LinuxPackageInventoryDiffConstants.MaximumEventsPerObservation.ToString(CultureInfo.InvariantCulture),
                    ["event_time_semantics"] = "inventory_observation_end",
                    ["state_read_status"] = stateError
                }
            };
        }
    }

    public bool HandlesSource(string? sourceId) =>
        string.Equals(sourceId, LinuxTelemetrySourceIds.PackageInventoryDiff, StringComparison.Ordinal);

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState();
            var accepted = events.Where(item => HandlesSource(item.SourceId) && item.Checkpoint?.Sequence is not null)
                .Select(item => item.Checkpoint!.Sequence!.Value).ToHashSet();
            // A crash can leave a durably queued prefix from a reservation whose baseline was
            // deliberately not committed. Those sequence numbers are already represented by
            // AbandonedThroughSequence; accepting their immutable rows must not move the
            // acknowledged checkpoint ahead of the last collected observation.
            if (current.CollectedSequence < current.AbandonedThroughSequence)
            {
                if (accepted.Any(sequence => sequence > current.AbandonedThroughSequence))
                    throw new InvalidOperationException("Package inventory acknowledgement exceeded the abandoned reservation.");
                return;
            }
            var cursor = Math.Max(current.AcknowledgedSequence, current.AbandonedThroughSequence);
            while (cursor < current.CollectedSequence && accepted.Contains(cursor + 1)) cursor++;
            if (accepted.Any(item => item > cursor))
                throw new InvalidOperationException("Package inventory acknowledgement was non-contiguous.");
            var updated = current with
            {
                AcknowledgedSequence = Math.Max(current.AcknowledgedSequence, cursor),
                AcknowledgedAt = cursor > current.AcknowledgedSequence ? timeProvider.GetUtcNow() : current.AcknowledgedAt
            };
            await stateStore.WriteAsync(updated, cancellationToken);
            SetState(updated);
        }
        finally { gate.Release(); }
    }

    public async Task RecordRejectedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var current = CurrentState();
            var rejected = events.Where(item => HandlesSource(item.SourceId) && item.Checkpoint?.Sequence is not null)
                .Select(item => item.Checkpoint!.Sequence!.Value)
                .Where(sequence => sequence > current.AbandonedThroughSequence)
                .Order().ToArray();
            if (rejected.Length == 0) return;
            var cursor = Math.Max(current.AcknowledgedSequence, current.AbandonedThroughSequence);
            foreach (var sequence in rejected)
            {
                if (sequence != cursor + 1)
                    throw new InvalidOperationException("Package inventory rejection was non-contiguous.");
                cursor = sequence;
            }
            var now = timeProvider.GetUtcNow();
            var updated = current with
            {
                AbandonedThroughSequence = Math.Max(current.AbandonedThroughSequence, cursor),
                ActiveGap = true,
                GapCount = SaturatingAdd(current.GapCount, rejected.Length),
                DroppedCount = SaturatingAdd(current.DroppedCount, rejected.Length),
                Status = SourceHealthStatuses.Degraded,
                ErrorCode = "package_inventory_event_rejected",
                TransitionState = HealthTransitionStates.Degraded,
                TransitionedAt = now
            };
            await stateStore.WriteAsync(updated, cancellationToken);
            SetState(updated);
        }
        finally { gate.Release(); }
    }

    public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events)
    {
        if (!events.Any(item => HandlesSource(item.SourceId))) return;
        lock (sync)
        {
            state = state with
            {
                ActiveGap = true,
                GapCount = SaturatingAdd(state.GapCount, 1),
                Status = SourceHealthStatuses.Error,
                ErrorCode = "package_inventory_acknowledgement_state_write_failed",
                TransitionState = HealthTransitionStates.Degraded,
                TransitionedAt = timeProvider.GetUtcNow()
            };
        }
    }

    private async Task CommitInvalidAsync(
        LinuxPackageInventoryDiffState current,
        DateTimeOffset observedAt,
        LinuxPackageManagementInventoryEvidence evidence,
        string reason,
        CancellationToken cancellationToken)
    {
        var status = evidence.State switch
        {
            LinuxPackageManagementInventoryStates.Unsupported => SourceHealthStatuses.Unsupported,
            LinuxPackageManagementInventoryStates.PermissionDenied => SourceHealthStatuses.PermissionDenied,
            LinuxPackageManagementInventoryStates.Timeout => SourceHealthStatuses.Stale,
            LinuxPackageManagementInventoryStates.Missing => SourceHealthStatuses.Missing,
            _ => SourceHealthStatuses.Degraded
        };
        var newlyActive = !current.ActiveGap || !string.Equals(current.ErrorCode, reason, StringComparison.Ordinal);
        var events = newlyActive && status != SourceHealthStatuses.Unsupported
            ? new[] { BuildEvent(current.NextSequence, observedAt, "package_inventory_gap", "gap", null, null, null,
                current.BaselineCollectedAt, evidence.Producer, reason, null) }
            : Array.Empty<EventEnvelope>();
        var result = current with
        {
            LastObservedAt = observedAt,
            LastEventAt = events.Length > 0 ? observedAt : current.LastEventAt,
            Status = status,
            ErrorCode = reason,
            ActiveGap = status != SourceHealthStatuses.Unsupported,
            GapCount = newlyActive && status != SourceHealthStatuses.Unsupported ? SaturatingAdd(current.GapCount, 1) : current.GapCount,
            TransitionState = HealthTransitionStates.Degraded,
            TransitionedAt = observedAt,
            Producer = evidence.Producer,
            FamilyCounts = AddFamilies(current.FamilyCounts, events),
            NextSequence = events.Length == 0 ? current.NextSequence : current.NextSequence + 1,
            CollectedSequence = events.Length == 0 ? current.CollectedSequence : current.NextSequence,
            PendingReservationStart = null,
            PendingReservationEnd = null
        };
        await CommitAsync(current, result, events, cancellationToken);
    }

    private async Task CommitAsync(
        LinuxPackageInventoryDiffState current,
        LinuxPackageInventoryDiffState result,
        IReadOnlyCollection<EventEnvelope> events,
        CancellationToken cancellationToken)
    {
        if (events.Count == 0)
        {
            await stateStore.WriteAsync(result, cancellationToken);
            SetState(result);
            return;
        }

        var start = events.Min(item => item.Checkpoint!.Sequence!.Value);
        var end = events.Max(item => item.Checkpoint!.Sequence!.Value);
        if (start != current.NextSequence)
            throw new InvalidOperationException("Package inventory sequence does not start at the durable next sequence.");
        var reserved = current with
        {
            NextSequence = end + 1,
            PendingReservationStart = start,
            PendingReservationEnd = end
        };
        await stateStore.WriteAsync(reserved, cancellationToken);
        SetState(reserved);
        foreach (var batch in EventQueueBatcher.Partition(events))
            await queue.EnqueueBatchAsync(batch, cancellationToken);
        await stateStore.WriteAsync(result, cancellationToken);
        SetState(result);
    }

    private IReadOnlyList<EventEnvelope> BuildEvents(
        LinuxPackageInventoryDiffState current,
        IReadOnlyList<LinuxPackageChange> changes,
        int baselineCount,
        string producer,
        DateTimeOffset observedAt)
    {
        var events = new List<EventEnvelope>(LinuxPackageInventoryDiffConstants.MaximumEventsPerObservation);
        var sequence = current.NextSequence;
        if (current.ActiveGap)
        {
            events.Add(BuildEvent(sequence++, observedAt, "package_inventory_recovery", "recovery", null, null, null,
                current.BaselineCollectedAt, producer, $"recovered_from_{current.ErrorCode}", null));
        }
        if (!current.BaselineCollectedAt.HasValue)
        {
            events.Add(BuildEvent(sequence, observedAt, "package_inventory_baseline", "baseline", null, null, null,
                null, producer, "initial_complete_inventory", baselineCount));
            return events;
        }

        var remaining = LinuxPackageInventoryDiffConstants.MaximumEventsPerObservation - events.Count;
        var capped = changes.Count > remaining;
        var changeLimit = capped ? Math.Max(0, remaining - 1) : changes.Count;
        foreach (var change in changes.Take(changeLimit))
        {
            events.Add(BuildEvent(sequence++, observedAt, $"package_inventory_{change.Action}", change.Action,
                change.PackageName, change.PreviousVersion, change.CurrentVersion,
                current.BaselineCollectedAt, producer, "complete_inventory_difference", null));
        }
        if (capped)
        {
            events.Add(BuildEvent(sequence, observedAt, "package_inventory_gap", "gap", null, null, null,
                current.BaselineCollectedAt, producer, "package_change_event_cap_exceeded", changes.Count - changeLimit));
        }
        return events;
    }

    private EventEnvelope BuildEvent(
        long sequence,
        DateTimeOffset observedAt,
        string eventCode,
        string action,
        string? packageName,
        string? previousVersion,
        string? currentVersion,
        DateTimeOffset? previousObservedAt,
        string producer,
        string reason,
        int? count)
    {
        var raw = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = LinuxPackageInventoryDiffConstants.CollectorVersion,
            ["evidence_mode"] = "snapshot_diff",
            ["action"] = action,
            ["package_name"] = packageName,
            ["previous_version"] = previousVersion,
            ["current_version"] = currentVersion,
            ["producer"] = producer,
            ["observation_start_at"] = previousObservedAt,
            ["observation_end_at"] = observedAt,
            ["reason"] = reason,
            ["count"] = count,
            ["exact_operation_time_known"] = false,
            ["actor_known"] = false,
            ["authorization_known"] = false
        }, JsonDefaults.Options), JsonDefaults.Options);
        var rawHash = DeterministicEventIdentity.ComputeRawSha256(raw);
        var envelope = new EventEnvelope
        {
            AgentId = options.AgentId,
            Hostname = Environment.MachineName,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.InventoryDiff,
            SourceId = LinuxTelemetrySourceIds.PackageInventoryDiff,
            EventCode = eventCode,
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = observedAt, RecordedAt = timeProvider.GetUtcNow() },
            EventTime = observedAt,
            Severity = action == "gap" ? "warning" : "information",
            Message = packageName is null ? $"Linux package inventory {action}." : $"Linux package inventory observed {action}: {packageName}.",
            Normalized = new NormalizedEventFields
            {
                Category = action is "install" or "update" or "remove" ? "package" : "package_inventory",
                Action = action,
                Outcome = "unknown",
                PackageName = packageName,
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["linux.source_pack"] = LinuxTelemetrySourceCatalog.L2PackId,
                    ["linux.evidence"] = "bounded_complete_inventory_diff",
                    ["linux.package_producer"] = producer
                }
            },
            Raw = raw,
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode, DeduplicationInputs.RawSha256],
                RawSha256 = rawHash
            },
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(raw, JsonDefaults.Options).Length,
                RedactionApplied = false,
                RedactedFields = [],
                TruncationApplied = false,
                TruncatedFields = []
            }
        };
        return envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
    }

    private static string? InvalidSnapshotReason(
        AssetInventorySnapshot? snapshot,
        LinuxPackageManagementInventoryEvidence evidence)
    {
        if (snapshot is null) return "package_inventory_snapshot_missing";
        if (evidence.State != LinuxPackageManagementInventoryStates.Supported) return evidence.Reason;
        if (AssetInventoryPaging.Read(snapshot.Summary, "generation_complete") is { } generationComplete)
        {
            if (!string.Equals(generationComplete, "true", StringComparison.OrdinalIgnoreCase)
                || !AssetInventoryPaging.ReadBoolean(snapshot.Summary, "source_complete", false)
                || AssetInventoryPaging.ReadBoolean(snapshot.Summary, "source_truncated", true))
                return "package_inventory_snapshot_incomplete";
        }
        else if (!string.Equals(snapshot.Summary.GetValueOrDefault("state"), "success", StringComparison.Ordinal)
            || AssetInventoryPaging.ReadBoolean(snapshot.Summary, "truncated", false))
        {
            return "package_inventory_snapshot_incomplete";
        }
        if (snapshot.Items.Count > AssetInventoryPaging.MaxItemsPerSource) return "package_inventory_item_limit_exceeded";
        return null;
    }

    private static bool TryBuildBaseline(
        AssetInventorySnapshot snapshot,
        out IReadOnlyDictionary<string, LinuxPackageBaselineEntry> baseline,
        out string error)
    {
        var values = new SortedDictionary<string, LinuxPackageBaselineEntry>(StringComparer.Ordinal);
        foreach (var item in snapshot.Items)
        {
            if (!string.Equals(item.Kind, "package", StringComparison.Ordinal)
                || item.Name.Length is < 1 or > 512
                || item.Identity is { Length: > 512 }
                || !item.Metadata.TryGetValue("version", out var version)
                || version.Length is < 1 or > 512)
            {
                baseline = new Dictionary<string, LinuxPackageBaselineEntry>();
                error = "package_inventory_item_malformed";
                return false;
            }
            var key = string.IsNullOrWhiteSpace(item.Identity) ? item.Name : item.Identity;
            if (!values.TryAdd(key!, new() { Name = item.Name, Version = version }))
            {
                baseline = new Dictionary<string, LinuxPackageBaselineEntry>();
                error = "package_inventory_identity_ambiguous";
                return false;
            }
        }
        baseline = values;
        error = "none";
        return true;
    }

    private static IReadOnlyList<LinuxPackageChange> Diff(
        IReadOnlyDictionary<string, LinuxPackageBaselineEntry> previous,
        IReadOnlyDictionary<string, LinuxPackageBaselineEntry> current)
    {
        var changes = new List<LinuxPackageChange>();
        foreach (var key in previous.Keys.Union(current.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            var hadPrevious = previous.TryGetValue(key, out var before);
            var hasCurrent = current.TryGetValue(key, out var after);
            if (!hadPrevious)
                changes.Add(new("install", key, after!.Name, null, after.Version));
            else if (!hasCurrent)
                changes.Add(new("remove", key, before!.Name, before.Version, null));
            else if (!string.Equals(before!.Version, after!.Version, StringComparison.Ordinal))
                changes.Add(new("update", key, after.Name, before.Version, after.Version));
        }
        return changes;
    }

    private static IReadOnlyDictionary<string, long> AddFamilies(
        IReadOnlyDictionary<string, long> current,
        IEnumerable<EventEnvelope> events)
    {
        var result = new Dictionary<string, long>(current, StringComparer.Ordinal);
        foreach (var family in events.Select(EventFamily))
            result[family] = SaturatingAdd(result.GetValueOrDefault(family), 1);
        return result;
    }

    private static string EventFamily(EventEnvelope envelope) => envelope.EventCode switch
    {
        "package_inventory_baseline" => "package_baseline",
        "package_inventory_install" => "package_install",
        "package_inventory_update" => "package_update",
        "package_inventory_remove" => "package_remove",
        "package_inventory_recovery" => "package_recovery",
        _ => "package_gap"
    };

    private static LinuxPackageInventoryDiffState RecoverReservation(
        LinuxPackageInventoryDiffState value,
        DateTimeOffset now,
        out bool changed)
    {
        changed = value.PendingReservationStart.HasValue;
        if (!changed) return value;
        var end = value.PendingReservationEnd!.Value;
        var abandoned = end - value.PendingReservationStart!.Value + 1;
        return value with
        {
            PendingReservationStart = null,
            PendingReservationEnd = null,
            AbandonedThroughSequence = Math.Max(value.AbandonedThroughSequence, end),
            ActiveGap = true,
            GapCount = SaturatingAdd(value.GapCount, abandoned),
            DroppedCount = SaturatingAdd(value.DroppedCount, abandoned),
            Status = SourceHealthStatuses.Degraded,
            ErrorCode = "interrupted_sequence_reservation",
            TransitionState = HealthTransitionStates.Degraded,
            TransitionedAt = now
        };
    }

    private LinuxPackageInventoryDiffState CurrentState()
    {
        lock (sync) return state;
    }

    private void SetState(LinuxPackageInventoryDiffState value)
    {
        lock (sync) state = value;
    }

    private static long SaturatingAdd(long left, long right) =>
        left > long.MaxValue - right ? long.MaxValue : left + right;
}
