using System.Globalization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Inventory;
using Challenger.Siem.LinuxAgent.Services;
using Challenger.Siem.LinuxAgent.L4;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed class LinuxJournalRuntime(IOptions<LinuxAgentOptions> configured, LinuxStateStore state, TimeProvider timeProvider) : ILinuxAcknowledgementObserver, ILinuxInventoryObserver
{
    private static readonly IReadOnlySet<string> AcknowledgedSourceIds = LinuxTelemetrySourceCatalog.All
        .Where(entry => entry.SourceKind is TelemetrySourceKinds.LinuxJournal or TelemetrySourceKinds.LinuxAudit)
        .Select(entry => entry.SourceId)
        .ToHashSet(StringComparer.Ordinal);
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly object sync = new();
    private readonly Dictionary<string, DateTimeOffset> latestBySource = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> observedFamilies = new(StringComparer.Ordinal);
    private readonly HashSet<string> observedSources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, EvidenceObservation> currentProducerObservations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, EvidenceObservation> inventoryObservations = new(StringComparer.Ordinal);
    private long evidenceObservationSequence;
    private JournalCheckpointState checkpoint = new();
    private string status = SourceHealthStatuses.Missing;
    private string? errorCode;
    private bool gap;
    private bool permissionDenied;
    private bool throttled;
    private DateTimeOffset? permissionDeniedSince;
    private DateTimeOffset? recoveredAt;
    private DateTimeOffset? transitionedAt;
    private string transitionState = HealthTransitionStates.Unknown;
    private string sourceState = "starting";
    private string gapState = "none";
    private long cumulativeGapCount;
    private long duplicateCount;
    private long reorderedCount;
    private long malformedCount;
    private long binaryOrInvalidTextCount;
    private long collectedCount;
    private DateTimeOffset? firstCollectedAt;
    private DateTimeOffset? latestEvent;
    private DateTimeOffset? lastSuccessfulReadAt;
    private DateTimeOffset? lastPersistedSuccessfulReadAt;
    private string version = "0.0.0";
    private string configHash = string.Empty;
    private SystemJournalVisibility systemJournalVisibility = SystemJournalVisibility.Unknown;
    private string scopeTransition = "steady";
    private bool clearObservedEvidenceOnScopeApply;
    private LinuxPackageManagementInventoryEvidence packageManagementInventory = new(
        LinuxPackageManagementInventoryStates.Unknown,
        "unknown",
        "package_manager_inventory_not_observed");
    private LinuxFirewallInventoryEvidence firewallInventory = new(
        LinuxFirewallInventoryStates.Unknown,
        "unknown",
        "firewall_inventory_not_observed");
    private LinuxSshInventoryEvidence sshInventory = LinuxSshInventoryEvidence.Unknown;

    public async Task InitializeAsync(string sourceVersion, string sourceConfigHash, CancellationToken cancellationToken)
    {
        var loaded = await state.ReadJournalAsync(cancellationToken);
        var configuredScope = LinuxJournalScopes.Configured(options.Journal);
        var priorScope = loaded.ConfiguredScope ?? LinuxJournalScopes.SystemOnly;
        scopeTransition = string.Equals(priorScope, configuredScope, StringComparison.Ordinal)
            ? "steady"
            : configuredScope == LinuxJournalScopes.AllAccessibleLocal
                ? "pending_expansion"
                : "pending_contraction";
        clearObservedEvidenceOnScopeApply = priorScope == LinuxJournalScopes.AllAccessibleLocal
            && configuredScope == LinuxJournalScopes.SystemOnly;
        lock (sync)
        {
            checkpoint = loaded;
            version = sourceVersion;
            configHash = sourceConfigHash;
            latestEvent = loaded.CollectedEventTime;
            if (loaded.CollectedEventTime.HasValue)
            {
                latestBySource[LinuxTelemetrySourceIds.JournalL1] = loaded.CollectedEventTime.Value;
            }
            sourceState = loaded.CollectedCursor is null ? "empty" : "restarted";
            lastSuccessfulReadAt = loaded.LastSuccessfulReadAt;
            lastPersistedSuccessfulReadAt = loaded.LastSuccessfulReadAt;
            gap = loaded.ActiveGap;
            gapState = string.IsNullOrWhiteSpace(loaded.GapState) ? "none" : loaded.GapState;
            cumulativeGapCount = Math.Max(0, loaded.CumulativeGapCount);
            foreach (var sourceId in loaded.ObservedSourceIds ?? Array.Empty<string>()) observedSources.Add(sourceId);
            foreach (var pair in loaded.ObservedFamilies ?? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal))
                observedFamilies[pair.Key] = pair.Value.ToHashSet(StringComparer.Ordinal);
        }
    }

    public async Task PersistInvalidCursorResetAsync(CancellationToken cancellationToken)
    {
        string configuredScope;
        bool activeGap;
        string currentGapState;
        long currentGapCount;
        bool clearObservedEvidence;
        lock (sync)
        {
            configuredScope = LinuxJournalScopes.Configured(options.Journal);
            activeGap = gap;
            currentGapState = gapState;
            currentGapCount = cumulativeGapCount;
            clearObservedEvidence = clearObservedEvidenceOnScopeApply;
        }
        await state.ResetCollectedJournalCursorAsync(
            configuredScope,
            activeGap,
            currentGapState,
            currentGapCount,
            clearObservedEvidence,
            cancellationToken);
        lock (sync)
        {
            if (clearObservedEvidence) ClearObservedEvidence();
            checkpoint = checkpoint with
            {
                CollectedCursor = null,
                CollectedEventTime = null,
                ObservedSourceIds = clearObservedEvidence ? Array.Empty<string>() : checkpoint.ObservedSourceIds,
                ObservedFamilies = clearObservedEvidence
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    : checkpoint.ObservedFamilies,
                ConfiguredScope = configuredScope
            };
            clearObservedEvidenceOnScopeApply = false;
            scopeTransition = "reset";
        }
    }

    public string? CollectedCursor { get { lock (sync) return checkpoint.CollectedCursor; } }
    public DateTimeOffset? CollectedEventTime { get { lock (sync) return checkpoint.CollectedEventTime; } }

    public async Task RecordCollectedAsync(NormalizedJournalRecord record, CancellationToken cancellationToken)
    {
        bool clearObservedEvidence;
        lock (sync) clearObservedEvidence = clearObservedEvidenceOnScopeApply;
        await state.WriteCollectedJournalAsync(
            record.Cursor,
            record.Envelope.EventTime,
            cancellationToken,
            record.Envelope.SourceId,
            record.EventFamily,
            record.AdditionalEvidence,
            gap,
            gapState,
            cumulativeGapCount,
            LinuxJournalScopes.Configured(options.Journal),
            clearObservedEvidence);
        lock (sync)
        {
            if (clearObservedEvidence) ClearObservedEvidence();
            checkpoint = checkpoint with
            {
                CollectedCursor = record.Cursor,
                CollectedEventTime = record.Envelope.EventTime,
                ObservedSourceIds = clearObservedEvidence ? Array.Empty<string>() : checkpoint.ObservedSourceIds,
                ObservedFamilies = clearObservedEvidence
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    : checkpoint.ObservedFamilies,
                ConfiguredScope = LinuxJournalScopes.Configured(options.Journal)
            };
            clearObservedEvidenceOnScopeApply = false;
            if (latestEvent is null || record.Envelope.EventTime > latestEvent)
            {
                latestEvent = record.Envelope.EventTime;
            }
            if (!latestBySource.TryGetValue(record.Envelope.SourceId!, out var sourceLatest)
                || record.Envelope.EventTime > sourceLatest)
            {
                latestBySource[record.Envelope.SourceId!] = record.Envelope.EventTime;
            }
            observedSources.Add(record.Envelope.SourceId!);
            RecordCurrentProducerObservation(record.Envelope.SourceId!, record.Envelope.EventTime);
            if (!observedFamilies.TryGetValue(record.Envelope.SourceId!, out var families))
            {
                families = new HashSet<string>(StringComparer.Ordinal);
                observedFamilies[record.Envelope.SourceId!] = families;
            }
            families.Add(record.EventFamily);
            foreach (var evidence in record.AdditionalEvidence ?? Array.Empty<JournalSourceEvidence>())
            {
                observedSources.Add(evidence.SourceId);
                RecordCurrentProducerObservation(evidence.SourceId, record.Envelope.EventTime);
                if (!observedFamilies.TryGetValue(evidence.SourceId, out var additionalFamilies))
                    observedFamilies[evidence.SourceId] = additionalFamilies = new(StringComparer.Ordinal);
                additionalFamilies.Add(evidence.EventFamily);
                if (!latestBySource.TryGetValue(evidence.SourceId, out var additionalLatest)
                    || record.Envelope.EventTime > additionalLatest)
                    latestBySource[evidence.SourceId] = record.Envelope.EventTime;
            }
            collectedCount++;
            firstCollectedAt ??= DateTimeOffset.UtcNow;
            if (status is not SourceHealthStatuses.Healthy)
            {
                recoveredAt = DateTimeOffset.UtcNow;
                transitionedAt = recoveredAt;
                transitionState = HealthTransitionStates.Recovered;
            }
            status = SourceHealthStatuses.Healthy;
            errorCode = null;
            sourceState = "collecting";
            permissionDenied = options.Journal.IncludeAccessibleUserJournals
                && systemJournalVisibility == SystemJournalVisibility.PermissionDenied;
        }
    }

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        // Advance by acknowledgement/queue order, not event-time sort, so reordered journal tails
        // still release durable queue rows and cannot regress the acknowledged cursor.
        var latest = events
            .Where(item => item.Source == EventSources.LinuxJournal && !string.IsNullOrEmpty(item.Checkpoint?.Cursor))
            .LastOrDefault();
        if (latest?.Checkpoint?.Cursor is not { } cursor) return;
        await state.WriteAcknowledgedJournalAsync(cursor, latest.EventTime, cancellationToken);
        lock (sync)
        {
            checkpoint = checkpoint with { AcknowledgedCursor = cursor, AcknowledgedEventTime = latest.EventTime };
            if (latestEvent is null || latest.EventTime > latestEvent)
            {
                latestEvent = latest.EventTime;
            }
        }
    }

    public bool HandlesSource(string? sourceId) => sourceId is not null && AcknowledgedSourceIds.Contains(sourceId);

    public Task ObserveInventoryAsync(IReadOnlyList<AssetInventorySnapshot> snapshots, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var packageEvidence = LinuxPackageManagementInventoryEvidence.FromSnapshots(snapshots);
        var firewallEvidence = LinuxFirewallInventoryEvidence.FromSnapshots(snapshots);
        var sshEvidence = LinuxSshInventoryEvidence.FromSnapshots(snapshots);
        var observedAt = timeProvider.GetUtcNow();
        var batchObservedAt = SnapshotObservationTime(snapshots, observedAt);
        var firewallObservedAt = SnapshotObservationTime(
            snapshots.Where(snapshot => string.Equals(
                snapshot.SnapshotType,
                LinuxFirewallInventoryEvidence.SnapshotType,
                StringComparison.Ordinal)),
            batchObservedAt);
        var sshObservedAt = SnapshotObservationTime(
            snapshots.Where(snapshot => snapshot.SnapshotType is
                LinuxSshInventoryEvidence.SshSnapshotType or LinuxSshInventoryEvidence.ServiceSnapshotType),
            batchObservedAt);
        lock (sync)
        {
            packageManagementInventory = packageEvidence;
            firewallInventory = firewallEvidence;
            sshInventory = sshEvidence;
            RecordInventoryObservation(LinuxTelemetrySourceIds.Firewall, firewallObservedAt);
            RecordInventoryObservation(LinuxTelemetrySourceIds.Ssh, sshObservedAt);
        }
        return Task.CompletedTask;
    }

    public void RecordAcknowledgementFailure(IReadOnlyCollection<EventEnvelope> events)
    {
        if (!events.Any(item => HandlesSource(item.SourceId))) return;
        lock (sync)
        {
            if (!gap || gapState != "acknowledgement_state_write_failed") cumulativeGapCount++;
            gap = true;
            gapState = "acknowledgement_state_write_failed";
            status = SourceHealthStatuses.Error;
            errorCode = "journal_acknowledgement_state_write_failed";
            transitionedAt = timeProvider.GetUtcNow();
            transitionState = HealthTransitionStates.Degraded;
        }
    }

    public void RecordReadResult(JournalReadResult result)
    {
        lock (sync)
        {
            throttled = false;
            var observedSystemVisibility = options.Journal.IncludeAccessibleUserJournals
                ? result.SystemJournalVisibility
                : result.Status switch
                {
                    JournalReadStatus.Success or JournalReadStatus.InvalidCursor => SystemJournalVisibility.Verified,
                    JournalReadStatus.PermissionDenied => SystemJournalVisibility.PermissionDenied,
                    JournalReadStatus.Unavailable => SystemJournalVisibility.Unavailable,
                    JournalReadStatus.Error => SystemJournalVisibility.Error,
                    _ => SystemJournalVisibility.Unknown
                };
            if (observedSystemVisibility != SystemJournalVisibility.Unknown)
                systemJournalVisibility = observedSystemVisibility;
            permissionDenied = result.Status == JournalReadStatus.PermissionDenied
                || systemJournalVisibility == SystemJournalVisibility.PermissionDenied;
            if (permissionDenied && permissionDeniedSince is null)
            {
                permissionDeniedSince = DateTimeOffset.UtcNow;
                transitionedAt = permissionDeniedSince;
                transitionState = HealthTransitionStates.Degraded;
            }
            gap |= result.GapKind != JournalGapKind.None || result.Status == JournalReadStatus.InvalidCursor;
            if (result.GapKind != JournalGapKind.None)
            {
                if (!gap || gapState != ToGapState(result.GapKind)) cumulativeGapCount++;
                gap = true;
                gapState = ToGapState(result.GapKind);
                status = SourceHealthStatuses.Stale;
                errorCode = $"journal_{gapState}_gap";
            }
            if (result.Status == JournalReadStatus.Success)
            {
                lastSuccessfulReadAt = timeProvider.GetUtcNow();
                if (scopeTransition is "pending_expansion" or "pending_contraction" or "reset")
                    scopeTransition = "recovered";
                if (gap && checkpoint.CollectedCursor is not null && result.GapKind == JournalGapKind.None)
                {
                    gap = false;
                    gapState = "none";
                    recoveredAt = timeProvider.GetUtcNow();
                    transitionedAt = recoveredAt;
                    transitionState = HealthTransitionStates.Recovered;
                }
                if (!gap && !permissionDenied && permissionDeniedSince.HasValue)
                {
                    recoveredAt = DateTimeOffset.UtcNow;
                    transitionedAt = recoveredAt;
                    transitionState = HealthTransitionStates.Recovered;
                    permissionDeniedSince = null;
                }
                if (result.Records.Count == 0)
                {
                    sourceState = checkpoint.CollectedCursor is null ? "empty" : "idle";
                    if (!gap)
                    {
                        status = checkpoint.CollectedCursor is null ? SourceHealthStatuses.Missing : SourceHealthStatuses.Healthy;
                        errorCode = checkpoint.CollectedCursor is null ? "journal_empty" : null;
                    }
                }
                else if (!gap)
                {
                    status = SourceHealthStatuses.Healthy;
                    errorCode = null;
                }
            }
            else
            {
                status = result.Status switch
                {
                    JournalReadStatus.Unavailable => SourceHealthStatuses.Missing,
                    JournalReadStatus.PermissionDenied => SourceHealthStatuses.PermissionDenied,
                    _ => SourceHealthStatuses.Error
                };
                sourceState = result.Status switch
                {
                    JournalReadStatus.PermissionDenied => "permission_denied",
                    JournalReadStatus.InvalidCursor => "cursor_invalid",
                    JournalReadStatus.Unavailable => "unavailable",
                    _ => "error"
                };
                errorCode = result.ErrorCode;
            }
        }
    }

    public async Task RecordSuccessfulReadObservationAsync(CancellationToken cancellationToken)
    {
        var observedAt = timeProvider.GetUtcNow();
        bool activeGap;
        string currentGapState;
        long gapCount;
        string configuredScope;
        bool clearObservedEvidence;
        lock (sync)
        {
            lastSuccessfulReadAt = observedAt;
            configuredScope = LinuxJournalScopes.Configured(options.Journal);
            clearObservedEvidence = clearObservedEvidenceOnScopeApply;
            if (lastPersistedSuccessfulReadAt.HasValue
                && observedAt - lastPersistedSuccessfulReadAt.Value < TimeSpan.FromMinutes(1)
                && string.Equals(checkpoint.ConfiguredScope, configuredScope, StringComparison.Ordinal)
                && !clearObservedEvidence) return;
            lastPersistedSuccessfulReadAt = observedAt;
            activeGap = gap;
            currentGapState = gapState;
            gapCount = cumulativeGapCount;
        }
        await state.WriteJournalReadObservationAsync(
            observedAt,
            activeGap,
            currentGapState,
            gapCount,
            configuredScope,
            clearObservedEvidence,
            cancellationToken);
        lock (sync)
        {
            if (clearObservedEvidence) ClearObservedEvidence();
            checkpoint = checkpoint with
            {
                LastSuccessfulReadAt = observedAt,
                ObservedSourceIds = clearObservedEvidence ? Array.Empty<string>() : checkpoint.ObservedSourceIds,
                ObservedFamilies = clearObservedEvidence
                    ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                    : checkpoint.ObservedFamilies,
                ConfiguredScope = configuredScope
            };
            clearObservedEvidenceOnScopeApply = false;
        }
    }

    public void RecordMalformed(string code)
    {
        lock (sync)
        {
            malformedCount++;
            cumulativeGapCount++;
            gap = true;
            gapState = "malformed_record";
            transitionedAt = DateTimeOffset.UtcNow;
            transitionState = HealthTransitionStates.Degraded;
            status = SourceHealthStatuses.Error;
            errorCode = code;
        }
    }

    public void RecordBinaryOrInvalidText() { lock (sync) binaryOrInvalidTextCount++; }
    public void RecordDuplicate() { lock (sync) duplicateCount++; }

    public void RecordReordered()
    {
        lock (sync)
        {
            reorderedCount++;
            cumulativeGapCount++;
            gap = true;
            gapState = "reordered_input";
            transitionedAt = DateTimeOffset.UtcNow;
            transitionState = HealthTransitionStates.Degraded;
        }
    }

    public void RecordGap(string stateValue)
    {
        lock (sync)
        {
            if (!gap || gapState != stateValue) cumulativeGapCount++;
            gap = true;
            gapState = stateValue;
            transitionedAt = DateTimeOffset.UtcNow;
            transitionState = HealthTransitionStates.Degraded;
            status = SourceHealthStatuses.Stale;
            errorCode = $"journal_{stateValue}_gap";
        }
    }

    public void RecordThrottle(string reason)
    {
        lock (sync)
        {
            throttled = true;
            sourceState = "throttled";
            transitionedAt = DateTimeOffset.UtcNow;
            transitionState = HealthTransitionStates.Degraded;
            status = SourceHealthStatuses.Degraded;
            errorCode = reason;
        }
    }

    public JournalRuntimeSnapshot Snapshot()
    {
        lock (sync)
        {
            var targetLevel = options.Journal.TargetCoverageLevel;
            var currentApplicabilityEvidence = observedSources
                .Where(sourceId => sourceId is not LinuxTelemetrySourceIds.Firewall and not LinuxTelemetrySourceIds.Ssh
                    || HasNewerDirectProducerEvidence(sourceId))
                .ToHashSet(StringComparer.Ordinal);
            var manifest = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
                    targetLevel,
                    options.Journal.DeclaredRoles,
                    currentApplicabilityEvidence)
                .Select(ResolveInventoryApplicability)
                .Where(entry => entry.SourceKind is TelemetrySourceKinds.LinuxJournal or TelemetrySourceKinds.LinuxAudit)
                .ToArray();
            var health = manifest.Select(BuildHealth).ToArray();
            return new(manifest, health, throttled, checkpoint.CollectedCursor, checkpoint.AcknowledgedCursor);
        }
    }

    private SourceHealthReport BuildHealth(SourceManifestEntry manifest)
    {
        var now = timeProvider.GetUtcNow();
        var inConfiguredLevel = manifest.CoverageLevel <= options.Journal.TargetCoverageLevel;
        var enabled = options.Journal.Enabled && inConfiguredLevel
            && manifest.Applicability is not SourceApplicabilityStatuses.Unsupported
            and not SourceApplicabilityStatuses.NotApplicable;
        if (manifest.CoverageLevel == WindowsCoverageLevel.L4
            && manifest.Requirement == SourceRequirementKinds.RoleSpecific)
        {
            enabled &= LinuxL4TelemetryCollector.IsConfigurationApproved(options);
        }
        var effectiveStatus = DetermineStatus(manifest, enabled);
        DateTimeOffset? sourceLatest = manifest.SourceId == LinuxTelemetrySourceIds.JournalL1
            ? latestEvent
            : latestBySource.TryGetValue(manifest.SourceId, out var observedLatest)
                ? observedLatest
                : null;
        var isJournalSource = manifest.SourceKind == TelemetrySourceKinds.LinuxJournal;
        var collected = isJournalSource ? Checkpoint(checkpoint.CollectedCursor, checkpoint.CollectedEventTime) : null;
        var acknowledged = isJournalSource ? Checkpoint(checkpoint.AcknowledgedCursor, checkpoint.AcknowledgedEventTime) : null;

        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["collector_state"] = sourceState,
            ["gap_state"] = gapState,
            ["rotation_state"] = gapState == "rotation" ? "gap" : "cursor_continuity_or_unknown",
            ["vacuum_state"] = gapState == "vacuum" ? "gap" : gapState == "invalid_cursor" ? "possible_gap" : "no_gap_observed",
            ["permission_state"] = permissionDenied ? "denied" : "allowed_or_unknown",
            ["throttle_state"] = throttled ? "active" : "inactive",
            ["duplicate_records"] = duplicateCount.ToString(CultureInfo.InvariantCulture),
            ["reordered_records"] = reorderedCount.ToString(CultureInfo.InvariantCulture),
            ["malformed_records"] = malformedCount.ToString(CultureInfo.InvariantCulture),
            ["binary_or_invalid_text_records"] = binaryOrInvalidTextCount.ToString(CultureInfo.InvariantCulture),
            ["configuration_state"] = enabled ? "enabled" : "disabled",
            ["configured_coverage_level"] = options.Journal.TargetCoverageLevel.ToString(),
            ["configured_journal_scope"] = LinuxJournalScopes.Configured(options.Journal),
            ["system_journal_visibility"] = VisibilityDetail(systemJournalVisibility),
            ["scope_transition"] = scopeTransition,
            ["collector_version"] = version
        };
        if (manifest.SourceId == LinuxTelemetrySourceIds.PackageManagement)
        {
            details["package_manager_inventory_state"] = packageManagementInventory.State;
            details["package_manager_producer"] = packageManagementInventory.Producer;
            details["package_manager_inventory_reason"] = packageManagementInventory.Reason;
            details["package_manager_journal_visibility"] = observedSources.Contains(manifest.SourceId)
                ? "observed"
                : "unverified";
            details["package_management_state"] = PackageManagementState();
        }
        if (manifest.SourceId == LinuxTelemetrySourceIds.Firewall)
        {
            details["firewall_inventory_state"] = firewallInventory.State;
            details["firewall_producer"] = firewallInventory.Producer;
            details["firewall_inventory_reason"] = firewallInventory.Reason;
            details["firewall_logging"] = firewallInventory.PrerequisiteStatus;
            details["firewall_journal_visibility"] = HasNewerDirectProducerEvidence(manifest.SourceId)
                ? "observed"
                : firewallInventory.State == LinuxFirewallInventoryStates.LoggingEnabled && lastSuccessfulReadAt.HasValue
                    ? "supported_quiet"
                    : "unverified";
        }
        if (manifest.SourceId == LinuxTelemetrySourceIds.Ssh)
        {
            details["ssh_inventory_state"] = sshInventory.State;
            details["ssh_inventory_producer"] = sshInventory.Producer;
            details["ssh_inventory_reason"] = sshInventory.Reason;
            details["ssh_journal_visibility"] = SshJournalVisibilityDetail(manifest);
        }
        if (LinuxTelemetrySourceCatalog.SuccessfulJournalObservationSourceIds.Contains(manifest.SourceId))
        {
            details["freshness_basis"] = "successful_journal_read";
            details["event_family_freshness"] = "independent_observation_state";
        }

        return new SourceHealthReport
        {
            SourceId = manifest.SourceId,
            Platform = manifest.Platform,
            SourceKind = manifest.SourceKind,
            DisplayName = manifest.DisplayName,
            SourceNamespace = manifest.SourceNamespace,
            Facility = manifest.Facility,
            Unit = manifest.Unit,
            Applicability = manifest.Applicability,
            ApplicabilityReason = manifest.ApplicabilityReason,
            CoverageLevel = manifest.CoverageLevel,
            Status = effectiveStatus,
            Required = manifest.Required,
            Requirement = manifest.Requirement,
            ApplicableRoles = manifest.ApplicableRoles,
            Enabled = enabled,
            LastEventTime = sourceLatest,
            ObservedAt = LinuxTelemetrySourceCatalog.SuccessfulJournalObservationSourceIds.Contains(manifest.SourceId)
                || (manifest.CoverageLevel == WindowsCoverageLevel.L4
                    && manifest.Requirement == SourceRequirementKinds.RoleSpecific)
                    ? lastSuccessfulReadAt
                    : now,
            CollectedCheckpoint = collected,
            AcknowledgedCheckpoint = acknowledged,
            LagSeconds = sourceLatest.HasValue ? Math.Max(0, (long)(now - sourceLatest.Value).TotalSeconds) : null,
            SilenceSeconds = sourceLatest.HasValue ? Math.Max(0, (long)(now - sourceLatest.Value).TotalSeconds) : null,
            EventRatePerMinute = EventRatePerMinute(now),
            ErrorCode = ErrorFor(manifest, effectiveStatus),
            ErrorMessage = ErrorFor(manifest, effectiveStatus),
            GapDetected = isJournalSource && gap,
            BookmarkGapDetected = isJournalSource && gap,
            GapCount = cumulativeGapCount,
            PermissionDeniedSince = permissionDenied ? permissionDeniedSince : null,
            RecoveredAt = recoveredAt,
            TransitionState = transitionState,
            TransitionedAt = transitionedAt,
            DroppedEvents = 0,
            PoisonEvents = 0,
            ConfigHash = configHash,
            SourceVersion = version,
            PrerequisiteStatuses = BuildPrerequisiteStatuses(manifest, enabled, effectiveStatus),
            EventFamilyStatuses = BuildEventFamilyStatuses(manifest, enabled, effectiveStatus),
            Details = details
        };
    }

    private SourceManifestEntry ResolveInventoryApplicability(SourceManifestEntry manifest)
    {
        if (manifest.SourceId == LinuxTelemetrySourceIds.PackageManagement)
        {
            if (observedSources.Contains(manifest.SourceId)) return manifest;
            return manifest with
            {
                Applicability = packageManagementInventory.Applicability,
                ApplicabilityReason = packageManagementInventory.Applicability == SourceApplicabilityStatuses.Applicable
                    ? null
                    : packageManagementInventory.Reason
            };
        }

        if (manifest.SourceId == LinuxTelemetrySourceIds.Firewall)
        {
            if (HasNewerDirectProducerEvidence(manifest.SourceId)) return manifest;
            return manifest with
            {
                Applicability = firewallInventory.Applicability,
                ApplicabilityReason = firewallInventory.Applicability == SourceApplicabilityStatuses.Applicable
                    ? null
                    : firewallInventory.Reason
            };
        }

        if (manifest.SourceId != LinuxTelemetrySourceIds.Ssh)
        {
            return manifest;
        }

        // Explicit non-SSH role declarations remain authoritative even when durable history
        // contains an older SSH record.
        if (manifest.Applicability == SourceApplicabilityStatuses.NotApplicable) return manifest;
        if (HasNewerDirectProducerEvidence(manifest.SourceId)) return manifest;

        if (options.Journal.DeclaredRoles.Length == 0)
        {
            var applicability = sshInventory.ApplicabilityWithoutDeclaredRole;
            return manifest with
            {
                Applicability = applicability,
                ApplicabilityReason = applicability switch
                {
                    SourceApplicabilityStatuses.Applicable => null,
                    SourceApplicabilityStatuses.Unsupported => sshInventory.Reason,
                    _ => "host_role_not_declared"
                }
            };
        }

        if (sshInventory.ApplicabilityWithoutDeclaredRole == SourceApplicabilityStatuses.Unsupported)
        {
            return manifest with
            {
                Applicability = SourceApplicabilityStatuses.Unsupported,
                ApplicabilityReason = sshInventory.Reason
            };
        }

        return manifest;
    }

    private string PackageManagementState()
    {
        if (observedSources.Contains(LinuxTelemetrySourceIds.PackageManagement)) return "supported_observed";
        return packageManagementInventory.State == LinuxPackageManagementInventoryStates.Supported
            ? "supported_quiet_visibility_unverified"
            : packageManagementInventory.State;
    }

    private string SshJournalVisibilityDetail(SourceManifestEntry manifest)
    {
        if (manifest.Applicability == SourceApplicabilityStatuses.NotApplicable) return "not_applicable";
        if (manifest.Applicability == SourceApplicabilityStatuses.Unsupported) return "unsupported";
        if (HasNewerDirectProducerEvidence(manifest.SourceId)) return "observed";
        if (sshInventory.SupportsQuietJournalObservation && lastSuccessfulReadAt.HasValue) return "supported_quiet";
        return sshInventory.State switch
        {
            LinuxSshInventoryStates.SupportedInactive => "producer_inactive",
            LinuxSshInventoryStates.PermissionDenied => "permission_denied",
            LinuxSshInventoryStates.Timeout => "stale",
            LinuxSshInventoryStates.Malformed => "degraded",
            _ => "unverified"
        };
    }

    private decimal? EventRatePerMinute(DateTimeOffset now)
    {
        if (collectedCount == 0 || firstCollectedAt is null)
        {
            return 0;
        }

        var minutes = Math.Max(1m, (decimal)(now - firstCollectedAt.Value).TotalMinutes);
        return Math.Round(collectedCount / minutes, 3, MidpointRounding.AwayFromZero);
    }

    private string DetermineStatus(SourceManifestEntry manifest, bool enabled)
    {
        if (manifest.Applicability == SourceApplicabilityStatuses.Unsupported)
        {
            return SourceHealthStatuses.Unsupported;
        }
        if (manifest.Applicability == SourceApplicabilityStatuses.NotApplicable)
        {
            return SourceHealthStatuses.NotApplicable;
        }
        if (!enabled)
        {
            return SourceHealthStatuses.Disabled;
        }
        if (gap && status is (SourceHealthStatuses.Healthy or SourceHealthStatuses.Stale or SourceHealthStatuses.Degraded))
        {
            return SourceHealthStatuses.Error;
        }
        if (options.Journal.IncludeAccessibleUserJournals)
        {
            var visibilityStatus = systemJournalVisibility switch
            {
                SystemJournalVisibility.Verified => SourceHealthStatuses.Healthy,
                SystemJournalVisibility.PermissionDenied => SourceHealthStatuses.PermissionDenied,
                SystemJournalVisibility.Unavailable => SourceHealthStatuses.Missing,
                SystemJournalVisibility.Error => SourceHealthStatuses.Error,
                _ => SourceHealthStatuses.Missing
            };
            if (visibilityStatus != SourceHealthStatuses.Healthy) return visibilityStatus;
        }
        if (status == SourceHealthStatuses.Healthy
            && manifest.SourceId == LinuxTelemetrySourceIds.Firewall
            && !HasNewerDirectProducerEvidence(manifest.SourceId))
        {
            var firewallStatus = firewallInventory.State switch
            {
                LinuxFirewallInventoryStates.LoggingDisabled => SourceHealthStatuses.Disabled,
                LinuxFirewallInventoryStates.PermissionDenied => SourceHealthStatuses.PermissionDenied,
                LinuxFirewallInventoryStates.Timeout => SourceHealthStatuses.Stale,
                LinuxFirewallInventoryStates.Malformed or LinuxFirewallInventoryStates.Unknown => SourceHealthStatuses.Degraded,
                _ => SourceHealthStatuses.Healthy
            };
            if (firewallStatus != SourceHealthStatuses.Healthy) return firewallStatus;
        }
        if (status == SourceHealthStatuses.Healthy
            && manifest.SourceId == LinuxTelemetrySourceIds.Ssh
            && !HasNewerDirectProducerEvidence(manifest.SourceId))
        {
            var sshStatus = sshInventory.State switch
            {
                LinuxSshInventoryStates.Unsupported => SourceHealthStatuses.Unsupported,
                LinuxSshInventoryStates.PermissionDenied => SourceHealthStatuses.PermissionDenied,
                LinuxSshInventoryStates.Timeout => SourceHealthStatuses.Stale,
                LinuxSshInventoryStates.SupportedInactive or LinuxSshInventoryStates.Malformed or LinuxSshInventoryStates.Unknown => SourceHealthStatuses.Degraded,
                _ => SourceHealthStatuses.Healthy
            };
            if (sshStatus != SourceHealthStatuses.Healthy) return sshStatus;
        }
        if (manifest.Applicability == SourceApplicabilityStatuses.Unknown)
        {
            return SourceHealthStatuses.Degraded;
        }
        if (status == SourceHealthStatuses.Healthy
            && manifest.CoverageLevel == WindowsCoverageLevel.L2
            && manifest.SourceKind == TelemetrySourceKinds.LinuxJournal
            && (!LinuxTelemetrySourceCatalog.SuccessfulJournalObservationSourceIds.Contains(manifest.SourceId)
                || LinuxTelemetrySourceCatalog.JournalObservationRequiresProducerEvidenceSourceIds.Contains(manifest.SourceId))
            && !HasProducerEvidence(manifest.SourceId))
        {
            return SourceHealthStatuses.Degraded;
        }
        return status;
    }

    private bool HasProducerEvidence(string sourceId)
    {
        return sourceId switch
        {
            LinuxTelemetrySourceIds.Firewall => HasNewerDirectProducerEvidence(sourceId)
                || firewallInventory.State == LinuxFirewallInventoryStates.LoggingEnabled,
            LinuxTelemetrySourceIds.Ssh => HasNewerDirectProducerEvidence(sourceId)
                || sshInventory.SupportsQuietJournalObservation,
            _ => observedSources.Contains(sourceId)
        };
    }

    private bool HasNewerDirectProducerEvidence(string sourceId)
    {
        if (!currentProducerObservations.TryGetValue(sourceId, out var direct)) return false;
        if (!inventoryObservations.TryGetValue(sourceId, out var inventory)) return true;
        var timeOrder = direct.ObservedAt.CompareTo(inventory.ObservedAt);
        return timeOrder > 0 || timeOrder == 0 && direct.Sequence > inventory.Sequence;
    }

    private void RecordCurrentProducerObservation(string sourceId, DateTimeOffset observedAt)
    {
        if (sourceId is not LinuxTelemetrySourceIds.Firewall and not LinuxTelemetrySourceIds.Ssh) return;
        var candidate = new EvidenceObservation(observedAt, ++evidenceObservationSequence);
        if (!currentProducerObservations.TryGetValue(sourceId, out var current)
            || candidate.ObservedAt > current.ObservedAt
            || candidate.ObservedAt == current.ObservedAt && candidate.Sequence > current.Sequence)
        {
            currentProducerObservations[sourceId] = candidate;
        }
    }

    private void RecordInventoryObservation(string sourceId, DateTimeOffset observedAt) =>
        inventoryObservations[sourceId] = new(observedAt, ++evidenceObservationSequence);

    private static DateTimeOffset SnapshotObservationTime(
        IEnumerable<AssetInventorySnapshot> snapshots,
        DateTimeOffset fallback) => snapshots
        .Select(snapshot => snapshot.CollectedAt)
        .Where(collectedAt => collectedAt != default)
        .DefaultIfEmpty(fallback)
        .Max();

    private string? ErrorFor(SourceManifestEntry manifest, string effectiveStatus)
    {
        if (effectiveStatus == SourceHealthStatuses.Unsupported)
        {
            return manifest.ApplicabilityReason ?? "source_unsupported";
        }
        if (effectiveStatus == SourceHealthStatuses.NotApplicable)
        {
            return null;
        }
        if (effectiveStatus == SourceHealthStatuses.Degraded)
        {
            if (manifest.SourceId == LinuxTelemetrySourceIds.PackageManagement
                && packageManagementInventory.State == LinuxPackageManagementInventoryStates.Supported
                && !observedSources.Contains(manifest.SourceId))
            {
                return "package_manager_journal_visibility_unverified";
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.Firewall
                && !HasNewerDirectProducerEvidence(manifest.SourceId))
            {
                return firewallInventory.Reason;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.Ssh
                && !HasNewerDirectProducerEvidence(manifest.SourceId)
                && manifest.Applicability == SourceApplicabilityStatuses.Applicable)
            {
                return sshInventory.Reason;
            }
            return manifest.Applicability == SourceApplicabilityStatuses.Unknown
                ? manifest.ApplicabilityReason ?? "source_applicability_unknown"
                : "source_event_family_not_observed";
        }
        if (manifest.SourceId == LinuxTelemetrySourceIds.Firewall
            && !HasNewerDirectProducerEvidence(manifest.SourceId)
            && manifest.CoverageLevel <= options.Journal.TargetCoverageLevel
            && (effectiveStatus == SourceHealthStatuses.Disabled
                && firewallInventory.State == LinuxFirewallInventoryStates.LoggingDisabled
                || effectiveStatus == SourceHealthStatuses.PermissionDenied
                && firewallInventory.State == LinuxFirewallInventoryStates.PermissionDenied
                || effectiveStatus == SourceHealthStatuses.Stale
                && firewallInventory.State == LinuxFirewallInventoryStates.Timeout))
        {
            return firewallInventory.Reason;
        }
        if (manifest.SourceId == LinuxTelemetrySourceIds.Ssh
            && !HasNewerDirectProducerEvidence(manifest.SourceId)
            && (effectiveStatus == SourceHealthStatuses.PermissionDenied
                && sshInventory.State == LinuxSshInventoryStates.PermissionDenied
                || effectiveStatus == SourceHealthStatuses.Stale
                && sshInventory.State == LinuxSshInventoryStates.Timeout))
        {
            return sshInventory.Reason;
        }
        if (effectiveStatus == SourceHealthStatuses.Disabled && manifest.CoverageLevel > options.Journal.TargetCoverageLevel)
        {
            return "source_above_configured_level";
        }
        if (effectiveStatus == SourceHealthStatuses.Disabled
            && manifest.CoverageLevel == WindowsCoverageLevel.L4
            && manifest.Requirement == SourceRequirementKinds.RoleSpecific)
        {
            return "l4_approval_hash_missing_or_mismatch";
        }
        if (options.Journal.IncludeAccessibleUserJournals
            && systemJournalVisibility != SystemJournalVisibility.Verified)
        {
            return systemJournalVisibility switch
            {
                SystemJournalVisibility.PermissionDenied => "system_journal_permission_denied",
                SystemJournalVisibility.Unavailable => "system_journal_unavailable",
                SystemJournalVisibility.Error => "system_journal_visibility_check_failed",
                _ => "system_journal_visibility_unknown"
            };
        }
        if (effectiveStatus == SourceHealthStatuses.Error && errorCode is null && gapState != "none")
        {
            return $"journal_{gapState}_gap";
        }
        return errorCode;
    }

    private IReadOnlyDictionary<string, string> BuildPrerequisiteStatuses(
        SourceManifestEntry manifest,
        bool enabled,
        string effectiveStatus)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var prerequisite in manifest.Prerequisites)
        {
            if (prerequisite is "systemd_journal_available" or "systemd_journal_readable")
            {
                values[prerequisite] = SystemVisibilityEvidence(enabled, effectiveStatus);
                continue;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.PackageManagement
                && prerequisite == "package_manager_journal_visibility")
            {
                values[prerequisite] = PackageManagementPrerequisiteEvidence(enabled, effectiveStatus);
                continue;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.Firewall
                && prerequisite == "firewall_logging_already_enabled")
            {
                values[prerequisite] = FirewallPrerequisiteEvidence(enabled, effectiveStatus);
                continue;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.Ssh
                && prerequisite == "sshd_journal_visibility")
            {
                values[prerequisite] = SshPrerequisiteEvidence(enabled, effectiveStatus);
                continue;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.AgentLogTamper
                && prerequisite == "journald_and_agent_unit_visibility")
            {
                values[prerequisite] = SuccessfulJournalObservationPrerequisiteEvidence(enabled, effectiveStatus);
                continue;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.KernelSecurity
                && prerequisite == "kernel_journal_visibility")
            {
                values[prerequisite] = SuccessfulJournalObservationPrerequisiteEvidence(enabled, effectiveStatus);
                continue;
            }
            if (manifest.SourceId == LinuxTelemetrySourceIds.LoginSession
                && prerequisite == "pam_or_logind_journal_visibility")
            {
                values[prerequisite] = SuccessfulJournalObservationPrerequisiteEvidence(enabled, effectiveStatus);
                continue;
            }
            values[prerequisite] = effectiveStatus switch
            {
                SourceHealthStatuses.Unsupported => SourceEvidenceStatuses.Unsupported,
                SourceHealthStatuses.NotApplicable => SourceEvidenceStatuses.NotApplicable,
                SourceHealthStatuses.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
                SourceHealthStatuses.Stale => SourceEvidenceStatuses.Stale,
                SourceHealthStatuses.Error => SourceEvidenceStatuses.Degraded,
                SourceHealthStatuses.Missing => SourceEvidenceStatuses.Missing,
                _ when !enabled => SourceEvidenceStatuses.Disabled,
                _ when prerequisite is "systemd_journal_available" or "systemd_journal_readable" => SourceEvidenceStatuses.Satisfied,
                _ when prerequisite.StartsWith("declared_role_", StringComparison.Ordinal)
                    && manifest.Applicability == SourceApplicabilityStatuses.Applicable => SourceEvidenceStatuses.Satisfied,
                _ when observedSources.Contains(manifest.SourceId) => SourceEvidenceStatuses.Satisfied,
                _ => SourceEvidenceStatuses.Unknown
            };
        }
        return values;
    }

    private string SuccessfulJournalObservationPrerequisiteEvidence(bool enabled, string effectiveStatus) =>
        effectiveStatus switch
        {
            SourceHealthStatuses.Unsupported => SourceEvidenceStatuses.Unsupported,
            SourceHealthStatuses.NotApplicable => SourceEvidenceStatuses.NotApplicable,
            SourceHealthStatuses.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
            SourceHealthStatuses.Stale => SourceEvidenceStatuses.Stale,
            SourceHealthStatuses.Error => SourceEvidenceStatuses.Degraded,
            SourceHealthStatuses.Missing => SourceEvidenceStatuses.Missing,
            _ when !enabled => SourceEvidenceStatuses.Disabled,
            _ when lastSuccessfulReadAt.HasValue => SourceEvidenceStatuses.Satisfied,
            _ => SourceEvidenceStatuses.Unknown
        };

    private string PackageManagementPrerequisiteEvidence(bool enabled, string effectiveStatus)
    {
        if (effectiveStatus == SourceHealthStatuses.Unsupported) return SourceEvidenceStatuses.Unsupported;
        if (effectiveStatus == SourceHealthStatuses.NotApplicable) return SourceEvidenceStatuses.NotApplicable;
        if (!enabled || effectiveStatus == SourceHealthStatuses.Disabled) return SourceEvidenceStatuses.Disabled;
        if (effectiveStatus == SourceHealthStatuses.PermissionDenied) return SourceEvidenceStatuses.PermissionDenied;
        if (effectiveStatus == SourceHealthStatuses.Stale) return SourceEvidenceStatuses.Stale;
        if (effectiveStatus == SourceHealthStatuses.Missing) return SourceEvidenceStatuses.Missing;
        if (gap || throttled || status == SourceHealthStatuses.Error) return SourceEvidenceStatuses.Degraded;
        if (observedSources.Contains(LinuxTelemetrySourceIds.PackageManagement)) return SourceEvidenceStatuses.Satisfied;
        return packageManagementInventory.PrerequisiteStatus;
    }

    private string SshPrerequisiteEvidence(bool enabled, string effectiveStatus)
    {
        if (effectiveStatus == SourceHealthStatuses.Unsupported) return SourceEvidenceStatuses.Unsupported;
        if (effectiveStatus == SourceHealthStatuses.NotApplicable) return SourceEvidenceStatuses.NotApplicable;
        if (!enabled || effectiveStatus == SourceHealthStatuses.Disabled) return SourceEvidenceStatuses.Disabled;
        if (effectiveStatus == SourceHealthStatuses.PermissionDenied) return SourceEvidenceStatuses.PermissionDenied;
        if (effectiveStatus == SourceHealthStatuses.Stale) return SourceEvidenceStatuses.Stale;
        if (effectiveStatus == SourceHealthStatuses.Missing) return SourceEvidenceStatuses.Missing;
        if (gap || throttled || status == SourceHealthStatuses.Error) return SourceEvidenceStatuses.Degraded;
        if (HasNewerDirectProducerEvidence(LinuxTelemetrySourceIds.Ssh)) return SourceEvidenceStatuses.Satisfied;
        if (!lastSuccessfulReadAt.HasValue) return SourceEvidenceStatuses.Unknown;
        return sshInventory.PrerequisiteStatus;
    }

    private string FirewallPrerequisiteEvidence(bool enabled, string effectiveStatus)
    {
        if (effectiveStatus == SourceHealthStatuses.Unsupported) return SourceEvidenceStatuses.Unsupported;
        if (effectiveStatus == SourceHealthStatuses.NotApplicable) return SourceEvidenceStatuses.NotApplicable;
        if (!enabled) return SourceEvidenceStatuses.Disabled;
        if (effectiveStatus == SourceHealthStatuses.PermissionDenied) return SourceEvidenceStatuses.PermissionDenied;
        if (effectiveStatus == SourceHealthStatuses.Stale) return SourceEvidenceStatuses.Stale;
        if (effectiveStatus == SourceHealthStatuses.Missing) return SourceEvidenceStatuses.Missing;
        if (gap || throttled || status == SourceHealthStatuses.Error) return SourceEvidenceStatuses.Degraded;
        if (HasNewerDirectProducerEvidence(LinuxTelemetrySourceIds.Firewall)) return SourceEvidenceStatuses.Satisfied;
        if (!lastSuccessfulReadAt.HasValue) return SourceEvidenceStatuses.Unknown;
        return firewallInventory.PrerequisiteStatus;
    }

    private string SystemVisibilityEvidence(bool enabled, string effectiveStatus)
    {
        if (effectiveStatus == SourceHealthStatuses.Unsupported) return SourceEvidenceStatuses.Unsupported;
        if (effectiveStatus == SourceHealthStatuses.NotApplicable) return SourceEvidenceStatuses.NotApplicable;
        if (!enabled) return SourceEvidenceStatuses.Disabled;
        if (!options.Journal.IncludeAccessibleUserJournals)
        {
            return effectiveStatus switch
            {
                SourceHealthStatuses.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
                SourceHealthStatuses.Missing => SourceEvidenceStatuses.Missing,
                SourceHealthStatuses.Error => SourceEvidenceStatuses.Degraded,
                _ => SourceEvidenceStatuses.Satisfied
            };
        }
        return systemJournalVisibility switch
        {
            SystemJournalVisibility.Verified => SourceEvidenceStatuses.Satisfied,
            SystemJournalVisibility.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
            SystemJournalVisibility.Unavailable => SourceEvidenceStatuses.Missing,
            SystemJournalVisibility.Error => SourceEvidenceStatuses.Degraded,
            _ => SourceEvidenceStatuses.Unknown
        };
    }

    private static string VisibilityDetail(SystemJournalVisibility value) => value switch
    {
        SystemJournalVisibility.Verified => "verified",
        SystemJournalVisibility.PermissionDenied => "permission_denied",
        SystemJournalVisibility.Unavailable => "unavailable",
        SystemJournalVisibility.Error => "error",
        _ => "unknown"
    };

    private void ClearObservedEvidence()
    {
        observedSources.Clear();
        observedFamilies.Clear();
        latestBySource.Clear();
        currentProducerObservations.Clear();
        if (latestEvent.HasValue) latestBySource[LinuxTelemetrySourceIds.JournalL1] = latestEvent.Value;
    }

    private IReadOnlyDictionary<string, string> BuildEventFamilyStatuses(
        SourceManifestEntry manifest,
        bool enabled,
        string effectiveStatus)
    {
        observedFamilies.TryGetValue(manifest.SourceId, out var observed);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var family in manifest.EventFamilies)
        {
            values[family] = effectiveStatus switch
            {
                SourceHealthStatuses.Unsupported => SourceEvidenceStatuses.Unsupported,
                SourceHealthStatuses.NotApplicable => SourceEvidenceStatuses.NotApplicable,
                SourceHealthStatuses.PermissionDenied => SourceEvidenceStatuses.PermissionDenied,
                SourceHealthStatuses.Stale => SourceEvidenceStatuses.Stale,
                SourceHealthStatuses.Error => SourceEvidenceStatuses.Degraded,
                _ when !enabled => SourceEvidenceStatuses.Disabled,
                _ when observed?.Contains(family) == true => SourceEvidenceStatuses.Observed,
                _ => SourceEvidenceStatuses.NotObserved
            };
        }
        return values;
    }

    private static SourceCheckpoint Checkpoint(string? cursor, DateTimeOffset? time) => new()
    {
        Cursor = cursor ?? "uncollected",
        EventTime = time,
        RecordedAt = time
    };

    private static string ToGapState(JournalGapKind kind) => kind switch
    {
        JournalGapKind.Rotation => "rotation",
        JournalGapKind.Vacuum => "vacuum",
        JournalGapKind.InvalidCursor => "invalid_cursor",
        _ => "none"
    };

    private sealed record EvidenceObservation(DateTimeOffset ObservedAt, long Sequence);
}
