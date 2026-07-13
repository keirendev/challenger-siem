using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Challenger.Siem.Agent.Core.Serialization;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.SelfIntegrity;

public sealed class LinuxSelfIntegrityCollector(
    IOptions<LinuxAgentOptions> configured,
    ILinuxSelfIntegritySource source,
    TimeProvider timeProvider)
{
    public const string CollectorVersion = "linux-agent-self-integrity-snapshot-v1";
    public static readonly IReadOnlyList<SelfIntegrityAllowlistEntry> Allowlist =
    [
        new("agent_binary", "/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent", SelfIntegrityEntryKind.HashedFile, 64 * 1024 * 1024, "agent_executable_digest", false),
        new("systemd_unit", "/etc/systemd/system/challenger-siem-agent.service", SelfIntegrityEntryKind.HashedFile, 256 * 1024, "agent_service_digest", false),
        new("agent_config", "/etc/challenger-siem-agent/agentsettings.json", SelfIntegrityEntryKind.MetadataFile, 256 * 1024, "credential_bearing_metadata_only", true),
        new("config_directory", "/etc/challenger-siem-agent/", SelfIntegrityEntryKind.Directory, 0, "directory_metadata_only", false),
        new("state_directory", "/var/lib/challenger-siem-agent/", SelfIntegrityEntryKind.Directory, 0, "directory_metadata_only", false)
    ];

    private readonly LinuxAgentOptions options = configured.Value;

    public string PlanHash => ComputePlanHash(options.SelfIntegrity);

    public bool IsEnabledAndApproved => options.SelfIntegrity.Enabled
        && string.Equals(options.SelfIntegrity.ApprovedPlanHash, PlanHash, StringComparison.Ordinal);

    public static string ComputePlanHash(SelfIntegrityOptions options)
    {
        var canonical = string.Join('\n', new[]
        {
            CollectorVersion,
            $"interval={options.IntervalSeconds}",
            $"timeout={options.ScanTimeoutSeconds}",
            $"queue_pause={options.QueuePauseDepth}",
            $"max_events={options.MaxEventsPerScan}",
            string.Join(';', Allowlist.Select(entry => string.Join(',', entry.PathId, entry.AbsolutePath, entry.Kind, entry.MaxBytes, entry.SecretBearing)))
        });
        return "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public async Task<SelfIntegrityPlan> PreflightAsync(CancellationToken cancellationToken)
    {
        var entries = new List<SelfIntegrityPlanEntry>();
        foreach (var entry in Allowlist)
        {
            var observation = await source.ObserveAsync(entry, cancellationToken);
            var state = observation.State switch
            {
                LinuxSelfIntegrityStates.Unchanged => "present",
                LinuxSelfIntegrityStates.Deleted => "missing",
                LinuxSelfIntegrityStates.Unreadable => "unreadable",
                _ => observation.State
            };
            entries.Add(new(entry.PathId, entry.AbsolutePath, Handling(entry), state, observation.ErrorCode, entry.MaxBytes, entry.Privacy));
        }

        var platform = OperatingSystem.IsLinux()
            ? $"linux/{System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant()}"
            : "unsupported_non_linux";
        return new SelfIntegrityPlan(
            PlanHash,
            platform,
            "POSIX stat/open on ordinary local filesystems; no audit, eBPF, fanotify, inotify, IMA, kernel modules, packages, or policy changes required.",
            "Existing agent service identity only; denied reads are reported as permission_denied and never fixed by adding groups, ACLs, capabilities, or helpers.",
            "Metadata and bounded SHA-256 digests only. The credential-bearing configuration file is never content-read or hashed; no secret values or file contents are emitted.",
            $"At most {Allowlist.Count} literal allowlist entries, two bounded content hashes, non-overlapping scans, {options.SelfIntegrity.IntervalSeconds}s cadence, {options.SelfIntegrity.ScanTimeoutSeconds}s deadline, {options.SelfIntegrity.MaxEventsPerScan} events per scan.",
            "Queue-before-collected-sequence and accepted/duplicate-before-acknowledged-sequence. Pressure pauses L3 before journal L1/L2 and emits bounded gap/drop/sample states when capacity permits.",
            $"Disable Agent:SelfIntegrity:Enabled and remove only collector state {options.SelfIntegrity.StatePath}; monitored files and host policy are untouched.",
            entries);
    }

    public async Task<SelfIntegrityCollectionResult> CollectAsync(LinuxSelfIntegrityState previous, string agentId, string hostname, CancellationToken cancellationToken)
    {
        var observations = new List<SelfIntegrityObservation>();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.SelfIntegrity.ScanTimeoutSeconds));
        try
        {
            foreach (var entry in Allowlist.Take(20))
            {
                observations.Add(await source.ObserveAsync(entry, timeout.Token));
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return BuildGap(previous, agentId, hostname, "scan_deadline_exceeded", LinuxSelfIntegrityStates.Gap);
        }

        var now = timeProvider.GetUtcNow();
        var signatures = observations.ToDictionary(item => item.Entry.PathId, item => item.Signature, StringComparer.Ordinal);
        var events = new List<SelfIntegrityCollectedEvent>();
        var sequence = Math.Max(1, previous.NextSequence);
        long sampled = 0;
        long dropped = 0;

        foreach (var observation in observations)
        {
            var state = DetermineState(previous.Signatures.GetValueOrDefault(observation.Entry.PathId), observation);
            if (state == LinuxSelfIntegrityStates.Unchanged) continue;
            if (events.Count >= options.SelfIntegrity.MaxEventsPerScan)
            {
                dropped++;
                continue;
            }
            events.Add(CreateEvent(agentId, hostname, observation, state, sequence++, now));
        }

        if (events.Count < options.SelfIntegrity.MaxEventsPerScan)
        {
            sampled = observations.Count;
            events.Add(CreateSampleEvent(agentId, hostname, observations, sequence++, now));
        }
        else
        {
            dropped++;
        }
        if (dropped > 0 && events.Count < options.SelfIntegrity.MaxEventsPerScan)
        {
            events.Add(CreateGapOrDropEvent(agentId, hostname, LinuxSelfIntegrityStates.Drop, "event_limit_exceeded", dropped, sequence++, now));
        }

        var health = observations.Any(item => item.State == LinuxSelfIntegrityStates.Unreadable)
            ? SourceHealthStatuses.PermissionDenied
            : SourceHealthStatuses.Healthy;
        return new(events, signatures, sequence, true, health, health == SourceHealthStatuses.Healthy ? "none" : "allowlist_unreadable", 0, dropped, sampled);
    }

    public SelfIntegrityCollectionResult BuildPressureGap(LinuxSelfIntegrityState previous, string agentId, string hostname, int queueDepth) =>
        BuildGap(previous, agentId, hostname, $"queue_pressure_depth_{queueDepth.ToString(CultureInfo.InvariantCulture)}", LinuxSelfIntegrityStates.Gap);

    private SelfIntegrityCollectionResult BuildGap(LinuxSelfIntegrityState previous, string agentId, string hostname, string reason, string state)
    {
        var sequence = Math.Max(1, previous.NextSequence);
        var evt = CreateGapOrDropEvent(agentId, hostname, state, reason, 1, sequence++, timeProvider.GetUtcNow());
        return new[] { evt }.ToList() is var events
            ? new SelfIntegrityCollectionResult(events, previous.Signatures, sequence, false, SourceHealthStatuses.Degraded, reason, 1, 0, 0)
            : throw new InvalidOperationException();
    }

    private SelfIntegrityCollectedEvent CreateEvent(string agentId, string hostname, SelfIntegrityObservation observation, string state, long sequence, DateTimeOffset now)
    {
        var raw = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = CollectorVersion,
            ["state"] = state,
            ["path_id"] = observation.Entry.PathId,
            ["path"] = observation.Entry.AbsolutePath,
            ["path_kind"] = observation.Entry.Kind.ToString(),
            ["path_type"] = observation.PathType,
            ["error_code"] = observation.ErrorCode,
            ["mode"] = observation.Mode.HasValue ? Convert.ToString((int)observation.Mode.Value, 8) : null,
            ["owner_id"] = observation.OwnerId,
            ["group_id"] = observation.GroupId,
            ["size_bucket"] = BucketSize(observation.SizeBytes),
            ["mtime_bucket_utc"] = BucketTime(observation.MtimeUtc),
            ["sha256"] = observation.Entry.HashContent ? observation.Sha256 : null,
            ["secret_bearing"] = observation.Entry.SecretBearing,
            ["content_collected"] = false
        };
        return BuildEvent(agentId, hostname, state, sequence, now, raw, observation.Entry.AbsolutePath);
    }

    private SelfIntegrityCollectedEvent CreateSampleEvent(string agentId, string hostname, IReadOnlyList<SelfIntegrityObservation> observations, long sequence, DateTimeOffset now)
    {
        var raw = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = CollectorVersion,
            ["state"] = LinuxSelfIntegrityStates.Sample,
            ["path_count"] = observations.Count,
            ["changed_path_count"] = observations.Count(item => item.State != LinuxSelfIntegrityStates.Unchanged),
            ["unreadable_path_count"] = observations.Count(item => item.State == LinuxSelfIntegrityStates.Unreadable),
            ["allowlist_version"] = PlanHash,
            ["content_collected"] = false
        };
        return BuildEvent(agentId, hostname, LinuxSelfIntegrityStates.Sample, sequence, now, raw, null);
    }

    private SelfIntegrityCollectedEvent CreateGapOrDropEvent(string agentId, string hostname, string state, string reason, long count, long sequence, DateTimeOffset now)
    {
        var raw = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = CollectorVersion,
            ["state"] = state,
            ["reason"] = reason,
            ["count"] = count,
            ["allowlist_version"] = PlanHash,
            ["content_collected"] = false
        };
        return BuildEvent(agentId, hostname, state, sequence, now, raw, null);
    }

    private SelfIntegrityCollectedEvent BuildEvent(string agentId, string hostname, string state, long sequence, DateTimeOffset now, SortedDictionary<string, object?> raw, string? path)
    {
        var rawElement = ToJsonElement(raw);
        var rawSha = DeterministicEventIdentity.ComputeRawSha256(rawElement);
        var envelope = new EventEnvelope
        {
            AgentId = agentId,
            Hostname = hostname,
            Platform = TelemetryPlatforms.Linux,
            Source = EventSources.AgentHealth,
            SourceId = LinuxTelemetrySourceIds.AgentSelfIntegrity,
            EventCode = $"self_integrity_snapshot_{state}",
            Checkpoint = new SourceCheckpoint { Sequence = sequence, EventTime = now, RecordedAt = now },
            EventTime = now,
            Severity = state is LinuxSelfIntegrityStates.Gap or LinuxSelfIntegrityStates.Drop or LinuxSelfIntegrityStates.Unreadable ? "warning" : "information",
            Message = $"Linux agent self-integrity snapshot {state}.",
            Normalized = path is null ? null : new NormalizedEventFields { Category = "agent_integrity", Action = state, File = new FileTelemetryConcept { Path = path, Operation = state } },
            Raw = rawElement,
            Deduplication = new EventDeduplicationMetadata
            {
                Algorithm = DeduplicationAlgorithms.Sha256Uuid,
                Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointSequence, DeduplicationInputs.EventCode, DeduplicationInputs.RawSha256],
                RawSha256 = rawSha
            },
            DataHandling = new DataHandlingMetadata
            {
                RawSizeBytes = JsonSerializer.SerializeToUtf8Bytes(rawElement, JsonDefaults.Options).Length,
                RedactionApplied = false,
                RedactedFields = [],
                TruncationApplied = false,
                TruncatedFields = []
            }
        };
        envelope = envelope with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelope) };
        return new(envelope, sequence, state);
    }

    private static string DetermineState(string? previousSignature, SelfIntegrityObservation observation)
    {
        if (observation.State == LinuxSelfIntegrityStates.Deleted) return LinuxSelfIntegrityStates.Deleted;
        if (observation.State == LinuxSelfIntegrityStates.Unreadable) return LinuxSelfIntegrityStates.Unreadable;
        if (previousSignature is null) return LinuxSelfIntegrityStates.Added;
        return string.Equals(previousSignature, observation.Signature, StringComparison.Ordinal)
            ? LinuxSelfIntegrityStates.Unchanged
            : LinuxSelfIntegrityStates.Changed;
    }

    private static string Handling(SelfIntegrityAllowlistEntry entry) => entry.Kind switch
    {
        SelfIntegrityEntryKind.HashedFile => $"regular-file metadata plus SHA-256, max {entry.MaxBytes} bytes, no symlinks/hardlinks/special files",
        SelfIntegrityEntryKind.MetadataFile => "regular-file metadata only, no content read/hash because credential-bearing",
        _ => "directory owner/group/mode/type metadata only, no recursion"
    };

    private static JsonElement ToJsonElement<T>(T value) => JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(value, JsonDefaults.Options), JsonDefaults.Options);
    private static string? BucketTime(DateTimeOffset? value) => value?.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:00'Z'", CultureInfo.InvariantCulture);
    private static string BucketSize(long? size) => size switch
    {
        null => "unknown",
        0 => "0",
        <= 1024 => "1-1024",
        <= 256 * 1024 => "1KiB-256KiB",
        <= 64 * 1024 * 1024 => "256KiB-64MiB",
        _ => "over-64MiB"
    };
}
