using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.State;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed class LinuxJournalRuntime(IOptions<LinuxAgentOptions> configured, LinuxStateStore state, TimeProvider timeProvider)
{
    private readonly LinuxAgentOptions options = configured.Value;
    private readonly object sync = new();
    private JournalCheckpointState checkpoint = new();
    private string status = SourceHealthStatuses.Missing;
    private string? errorCode;
    private bool gap;
    private bool permissionDenied;
    private bool throttled;
    private string sourceState = "starting";
    private string gapState = "none";
    private long duplicateCount;
    private long reorderedCount;
    private long malformedCount;
    private long binaryOrInvalidTextCount;
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
            latestEvent = record.Envelope.EventTime;
            status = SourceHealthStatuses.Healthy;
            errorCode = null;
            sourceState = "collecting";
            permissionDenied = false;
        }
    }

    public async Task RecordAcknowledgedAsync(IReadOnlyCollection<EventEnvelope> events, CancellationToken cancellationToken)
    {
        var latest = events
            .Where(item => item.Source == EventSources.LinuxJournal && !string.IsNullOrEmpty(item.Checkpoint?.Cursor))
            .OrderBy(item => item.EventTime)
            .LastOrDefault();
        if (latest?.Checkpoint?.Cursor is not { } cursor) return;
        lock (sync)
        {
            if (checkpoint.AcknowledgedEventTime is { } acknowledgedAt && latest.EventTime < acknowledgedAt) return;
        }
        await state.WriteAcknowledgedJournalAsync(cursor, latest.EventTime, cancellationToken);
        lock (sync) checkpoint = checkpoint with { AcknowledgedCursor = cursor, AcknowledgedEventTime = latest.EventTime };
    }

    public void RecordReadResult(JournalReadResult result)
    {
        lock (sync)
        {
            throttled = false;
            permissionDenied = result.Status == JournalReadStatus.PermissionDenied;
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
                    if (!gap)
                    {
                        status = checkpoint.CollectedCursor is null ? SourceHealthStatuses.Missing : SourceHealthStatuses.Healthy;
                        errorCode = checkpoint.CollectedCursor is null ? "journal_empty" : null;
                    }
                }
                else if (!gap) { status = SourceHealthStatuses.Healthy; errorCode = null; }
            }
            else
            {
                status = result.Status == JournalReadStatus.Unavailable ? SourceHealthStatuses.Missing : SourceHealthStatuses.Error;
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

    public void RecordMalformed(string code) { lock (sync) { malformedCount++; gap = true; gapState = "malformed_record"; status = SourceHealthStatuses.Error; errorCode = code; } }
    public void RecordBinaryOrInvalidText() { lock (sync) binaryOrInvalidTextCount++; }
    public void RecordDuplicate() { lock (sync) duplicateCount++; }
    public void RecordReordered() { lock (sync) { reorderedCount++; gap = true; gapState = "reordered_input"; } }
    public void RecordGap(string state) { lock (sync) { gap = true; gapState = state; status = SourceHealthStatuses.Stale; errorCode = $"journal_{state}_gap"; } }
    public void RecordThrottle(string reason) { lock (sync) { throttled = true; sourceState = "throttled"; status = SourceHealthStatuses.Stale; errorCode = reason; } }

    public JournalRuntimeSnapshot Snapshot()
    {
        lock (sync)
        {
            var now = timeProvider.GetUtcNow();
            var collected = Checkpoint(checkpoint.CollectedCursor, checkpoint.CollectedEventTime);
            var acknowledged = Checkpoint(checkpoint.AcknowledgedCursor, checkpoint.AcknowledgedEventTime);
            var manifest = new SourceManifestEntry
            {
                SourceId = LinuxJournalNormalizer.SourceId,
                Platform = TelemetryPlatforms.Linux,
                SourceKind = TelemetrySourceKinds.LinuxJournal,
                SourceNamespace = "systemd",
                Applicability = SourceApplicabilityStatuses.Applicable,
                CheckpointKind = SourceCheckpointKinds.Cursor,
                DisplayName = "Linux L1 system journal",
                CoverageLevel = WindowsCoverageLevel.L1,
                Required = true,
                EnabledByDefault = options.Journal.Enabled,
                SourcePack = "linux-l1-journal",
                ParserId = "journald-json-v1",
                Prerequisites = ["systemd_journal_readable"],
                EventFamilies = ["kernel", "boot", "service", "authentication", "system"],
                ValidationScenarios = ["cursor_restart", "rotation_vacuum", "outage_replay", "pressure"],
                Privacy = "high_sensitivity",
                InstallerManaged = false
            };
            var health = new SourceHealthReport
            {
                SourceId = manifest.SourceId,
                Platform = manifest.Platform,
                SourceKind = manifest.SourceKind,
                DisplayName = manifest.DisplayName,
                SourceNamespace = manifest.SourceNamespace,
                Applicability = manifest.Applicability,
                CoverageLevel = WindowsCoverageLevel.L1,
                Status = options.Journal.Enabled ? status : SourceHealthStatuses.Disabled,
                Required = true,
                Enabled = options.Journal.Enabled,
                LastEventTime = latestEvent,
                CollectedCheckpoint = collected,
                AcknowledgedCheckpoint = acknowledged,
                LagSeconds = latestEvent.HasValue ? Math.Max(0, (long)(now - latestEvent.Value).TotalSeconds) : null,
                ErrorCode = errorCode,
                ErrorMessage = errorCode,
                GapDetected = gap,
                BookmarkGapDetected = gap,
                ConfigHash = configHash,
                SourceVersion = version,
                Details = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["collector_state"] = sourceState,
                    ["gap_state"] = gapState,
                    ["rotation_state"] = gapState == "rotation" ? "gap" : "cursor_continuity_or_unknown",
                    ["vacuum_state"] = gapState == "vacuum" ? "gap" : gapState == "invalid_cursor" ? "possible_gap" : "no_gap_observed",
                    ["permission_state"] = permissionDenied ? "denied" : "allowed_or_unknown",
                    ["throttle_state"] = throttled ? "active" : "inactive",
                    ["duplicate_records"] = duplicateCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["reordered_records"] = reorderedCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["malformed_records"] = malformedCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["binary_or_invalid_text_records"] = binaryOrInvalidTextCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["configuration_state"] = options.Journal.Enabled ? "enabled" : "disabled",
                    ["collector_version"] = version
                }
            };
            return new(manifest, health, throttled, checkpoint.CollectedCursor, checkpoint.AcknowledgedCursor);
        }
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
