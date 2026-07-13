using System.Globalization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed class LinuxJournalRuntime(IOptions<LinuxAgentOptions> configured, LinuxStateStore state, TimeProvider timeProvider)
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly object sync = new();
    private readonly Dictionary<string, DateTimeOffset> latestBySource = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> observedFamilies = new(StringComparer.Ordinal);
    private readonly HashSet<string> observedSources = new(StringComparer.Ordinal);
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
    private long duplicateCount;
    private long reorderedCount;
    private long malformedCount;
    private long binaryOrInvalidTextCount;
    private long collectedCount;
    private DateTimeOffset? firstCollectedAt;
    private DateTimeOffset? latestEvent;
    private string version = "0.0.0";
    private string configHash = string.Empty;

    public async Task InitializeAsync(string sourceVersion, string sourceConfigHash, CancellationToken cancellationToken)
    {
        var loaded = await state.ReadJournalAsync(cancellationToken);
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
        }
    }

    public string? CollectedCursor { get { lock (sync) return checkpoint.CollectedCursor; } }
    public DateTimeOffset? CollectedEventTime { get { lock (sync) return checkpoint.CollectedEventTime; } }

    public async Task RecordCollectedAsync(NormalizedJournalRecord record, CancellationToken cancellationToken)
    {
        await state.WriteCollectedJournalAsync(record.Cursor, record.Envelope.EventTime, cancellationToken);
        lock (sync)
        {
            checkpoint = checkpoint with { CollectedCursor = record.Cursor, CollectedEventTime = record.Envelope.EventTime };
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
            if (!observedFamilies.TryGetValue(record.Envelope.SourceId!, out var families))
            {
                families = new HashSet<string>(StringComparer.Ordinal);
                observedFamilies[record.Envelope.SourceId!] = families;
            }
            families.Add(record.EventFamily);
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
            permissionDenied = false;
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

    public void RecordReadResult(JournalReadResult result)
    {
        lock (sync)
        {
            throttled = false;
            permissionDenied = result.Status == JournalReadStatus.PermissionDenied;
            if (permissionDenied && permissionDeniedSince is null)
            {
                permissionDeniedSince = DateTimeOffset.UtcNow;
                transitionedAt = permissionDeniedSince;
                transitionState = HealthTransitionStates.Degraded;
            }
            gap |= result.GapKind != JournalGapKind.None || result.Status == JournalReadStatus.InvalidCursor;
            if (result.GapKind != JournalGapKind.None)
            {
                gapState = ToGapState(result.GapKind);
                status = SourceHealthStatuses.Stale;
                errorCode = $"journal_{gapState}_gap";
            }
            if (result.Status == JournalReadStatus.Success)
            {
                if (result.Records.Count == 0)
                {
                    sourceState = checkpoint.CollectedCursor is null ? "empty" : "idle";
                    if (!gap && permissionDeniedSince.HasValue)
                    {
                        recoveredAt = DateTimeOffset.UtcNow;
                        transitionedAt = recoveredAt;
                        transitionState = HealthTransitionStates.Recovered;
                        permissionDeniedSince = null;
                    }
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

    public void RecordMalformed(string code)
    {
        lock (sync)
        {
            malformedCount++;
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
            var manifest = LinuxTelemetrySourceCatalog.BuildHeartbeatManifest(
                targetLevel,
                options.Journal.DeclaredRoles,
                observedSources);
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
        var effectiveStatus = DetermineStatus(manifest, enabled);
        var sourceLatest = manifest.SourceId == LinuxTelemetrySourceIds.JournalL1
            ? latestEvent
            : latestBySource.GetValueOrDefault(manifest.SourceId);
        var isJournalSource = manifest.SourceKind == TelemetrySourceKinds.LinuxJournal;
        var collected = isJournalSource ? Checkpoint(checkpoint.CollectedCursor, checkpoint.CollectedEventTime) : null;
        var acknowledged = isJournalSource ? Checkpoint(checkpoint.AcknowledgedCursor, checkpoint.AcknowledgedEventTime) : null;

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
            ObservedAt = now,
            CollectedCheckpoint = collected,
            AcknowledgedCheckpoint = acknowledged,
            LagSeconds = sourceLatest.HasValue ? Math.Max(0, (long)(now - sourceLatest.Value).TotalSeconds) : null,
            SilenceSeconds = sourceLatest.HasValue ? Math.Max(0, (long)(now - sourceLatest.Value).TotalSeconds) : null,
            EventRatePerMinute = EventRatePerMinute(now),
            ErrorCode = ErrorFor(manifest, effectiveStatus),
            ErrorMessage = ErrorFor(manifest, effectiveStatus),
            GapDetected = isJournalSource && gap,
            BookmarkGapDetected = isJournalSource && gap,
            GapCount = gap ? Math.Max(1, malformedCount + reorderedCount) : 0,
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
            Details = new Dictionary<string, string>(StringComparer.Ordinal)
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
                ["collector_version"] = version
            }
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
        if (manifest.Applicability == SourceApplicabilityStatuses.Unknown)
        {
            return SourceHealthStatuses.Degraded;
        }
        if (status == SourceHealthStatuses.Healthy
            && manifest.CoverageLevel == WindowsCoverageLevel.L2
            && manifest.SourceKind == TelemetrySourceKinds.LinuxJournal
            && !observedSources.Contains(manifest.SourceId))
        {
            return SourceHealthStatuses.Degraded;
        }
        return status;
    }

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
            return manifest.Applicability == SourceApplicabilityStatuses.Unknown
                ? manifest.ApplicabilityReason ?? "source_applicability_unknown"
                : "source_event_family_not_observed";
        }
        if (effectiveStatus == SourceHealthStatuses.Disabled && manifest.CoverageLevel > options.Journal.TargetCoverageLevel)
        {
            return "source_above_configured_level";
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
                _ when observedSources.Contains(manifest.SourceId) => SourceEvidenceStatuses.Satisfied,
                _ => SourceEvidenceStatuses.Unknown
            };
        }
        return values;
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
}
