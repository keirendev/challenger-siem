using System.Globalization;
using System.Net;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Detections;

public sealed record DetectionEvaluationResult(
    DetectionRuleMetadata Rule,
    bool PrerequisitesMet,
    bool Matched,
    string Reason)
{
    public string EffectiveConfidence { get; init; } = Rule.Confidence;
    public string SuppressionKey { get; init; } = string.Empty;
    public IReadOnlyList<string> MatchedFields { get; init; } = Array.Empty<string>();
}

public sealed class DetectionEngine
{
    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> CanonicalLinuxL2SourceFamilies =
        LinuxTelemetrySourceCatalog.L2Security.ToDictionary(
            entry => entry.SourceId,
            entry => (IReadOnlySet<string>)new HashSet<string>(entry.EventFamilies, StringComparer.Ordinal),
            StringComparer.Ordinal);

    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> CanonicalLinuxL4RoleSourceFamilies =
        LinuxTelemetrySourceCatalog.L4
            .Where(entry => string.Equals(entry.Requirement, SourceRequirementKinds.RoleSpecific, StringComparison.Ordinal)
                && string.Equals(entry.SourceKind, TelemetrySourceKinds.LinuxJournal, StringComparison.Ordinal)
                && string.Equals(entry.SourcePack, LinuxTelemetrySourceCatalog.L4RolePackId, StringComparison.Ordinal))
            .ToDictionary(
                entry => entry.SourceId,
                entry => (IReadOnlySet<string>)new HashSet<string>(entry.EventFamilies, StringComparer.Ordinal),
                StringComparer.Ordinal);

    private static readonly IReadOnlySet<string> DegradingSourceStates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        SourceHealthStatuses.Stale,
        SourceHealthStatuses.Degraded
    };

    private static readonly IReadOnlySet<string> SuppressingSourceStates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        SourceHealthStatuses.Missing,
        SourceHealthStatuses.Disabled,
        SourceHealthStatuses.PermissionDenied,
        SourceHealthStatuses.Unsupported,
        SourceHealthStatuses.Error,
        SourceHealthStatuses.NotApplicable
    };

    private static readonly IReadOnlySet<string> DegradingEvidenceStates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        SourceEvidenceStatuses.Stale,
        SourceEvidenceStatuses.Degraded,
        SourceEvidenceStatuses.NotObserved,
        SourceEvidenceStatuses.Unknown
    };

    private static readonly IReadOnlySet<string> DegradingEventFamilyStates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        SourceEvidenceStatuses.Stale,
        SourceEvidenceStatuses.Degraded,
        SourceEvidenceStatuses.Unknown
    };

    private static readonly IReadOnlySet<string> SuppressingEvidenceStates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        SourceEvidenceStatuses.Missing,
        SourceEvidenceStatuses.Disabled,
        SourceEvidenceStatuses.PermissionDenied,
        SourceEvidenceStatuses.Unsupported,
        SourceEvidenceStatuses.NotApplicable
    };

    public IReadOnlyList<DetectionEvaluationResult> Evaluate(EventEnvelope envelope, IReadOnlySet<string> healthySources)
    {
        return DetectionRuleCatalog.BuiltInRules
            .Where(rule => rule.Enabled)
            .Select(rule => EvaluateRule(rule, envelope, healthySources))
            .ToArray();
    }

    public IReadOnlyList<DetectionEvaluationResult> EvaluateLinux(
        EventEnvelope envelope,
        IReadOnlyDictionary<string, SourceHealthReport> sourceHealth)
    {
        if (!IsLinuxEvent(envelope))
        {
            return Array.Empty<DetectionEvaluationResult>();
        }

        return DetectionRuleCatalog.BuiltInRules
            .Where(rule => rule.Enabled && DetectionRuleCatalog.IsLinuxRule(rule.RuleId))
            .Select(rule => EvaluateLinuxRule(rule, envelope, sourceHealth))
            .ToArray();
    }

    private static DetectionEvaluationResult EvaluateRule(
        DetectionRuleMetadata rule,
        EventEnvelope envelope,
        IReadOnlySet<string> healthySources)
    {
        var prerequisitesMet = rule.RequiredSources.Count == 0
            || rule.RequiredSources.Any(source => healthySources.Contains(source));
        if (!prerequisitesMet)
        {
            return new DetectionEvaluationResult(rule, false, false, "required source missing or stale");
        }

        var categoryMatches = string.Equals(rule.Category, envelope.Normalized?.Category, StringComparison.OrdinalIgnoreCase);
        var actionMatches = rule.RuleId switch
        {
            "tamper.event-log-cleared" => envelope.WindowsEventId == 1102,
            "malware.defender-detection" => envelope.WindowsEventId is 1116 or 1117,
            _ => categoryMatches
        };

        return new DetectionEvaluationResult(
            rule,
            true,
            actionMatches,
            actionMatches ? "event matched rule category or event-id predicate" : "event did not match rule predicate")
        {
            SuppressionKey = BuildSuppressionKey(rule, envelope),
            MatchedFields = actionMatches ? PresentFields(rule, envelope) : Array.Empty<string>()
        };
    }

    private static DetectionEvaluationResult EvaluateLinuxRule(
        DetectionRuleMetadata rule,
        EventEnvelope envelope,
        IReadOnlyDictionary<string, SourceHealthReport> sourceHealth)
    {
        var sourceMatch = MatchingRequiredSource(rule, envelope);
        if (sourceMatch is null)
        {
            return new DetectionEvaluationResult(rule, false, false, "event source does not satisfy rule source prerequisites");
        }

        var (prerequisitesMet, confidence, prerequisiteReason) = EvaluatePrerequisites(sourceMatch, envelope, sourceHealth);
        if (!prerequisitesMet)
        {
            return new DetectionEvaluationResult(rule, false, false, prerequisiteReason)
            {
                EffectiveConfidence = confidence,
                SuppressionKey = BuildSuppressionKey(rule, envelope)
            };
        }

        if (HasEventLocalCompletenessGap(envelope))
        {
            confidence = "low";
            prerequisiteReason = $"{prerequisiteReason}; event reports partial host-metrics evidence; confidence lowered";
        }

        var matched = LinuxRulePredicate(rule.RuleId, envelope);
        return new DetectionEvaluationResult(
            rule,
            true,
            matched,
            matched
                ? (confidence == rule.Confidence ? "structured Linux event matched rule predicate" : prerequisiteReason)
                : "structured Linux fields did not match rule predicate")
        {
            EffectiveConfidence = confidence,
            SuppressionKey = BuildSuppressionKey(rule, envelope),
            MatchedFields = matched ? PresentFields(rule, envelope) : Array.Empty<string>()
        };
    }

    private static (bool Met, string Confidence, string Reason) EvaluatePrerequisites(
        string requiredSource,
        EventEnvelope envelope,
        IReadOnlyDictionary<string, SourceHealthReport> sourceHealth)
    {
        if (!sourceHealth.TryGetValue(requiredSource, out var report))
        {
            if (EventSourceMatches(requiredSource, envelope))
            {
                return (true, "low", "matching event exists but prerequisite source-health row is missing; confidence lowered");
            }

            return (false, "low", $"required source {requiredSource} missing from source health; evaluation suppressed");
        }

        if (SuppressingSourceStates.Contains(report.Status))
        {
            // The accepted event is direct evidence from this source. An unhealthy
            // current source-health row describes incomplete visibility around that
            // evidence; it must not erase or suppress the event that already arrived.
            return (true, "low", $"matching event retained while required source {requiredSource} is {report.Status}; confidence lowered");
        }

        if (HasSuppressingEvidence(report))
        {
            return (true, "low", $"matching event retained while required source {requiredSource} prerequisite evidence is unavailable; confidence lowered");
        }

        if (DegradingSourceStates.Contains(report.Status)
            || HasDegradingEvidence(report)
            || report.GapDetected
            || report.BookmarkGapDetected
            || report.ClearedDetected
            // Passive source drop counters are cumulative history. Their active
            // gap/status/transition fields carry current confidence impact.
            || ((report.DroppedEvents ?? 0) > 0 && !SourceHealthRules.IsSuccessfulPollingSource(report.SourceId))
            || string.Equals(report.TransitionState, "throttled", StringComparison.OrdinalIgnoreCase)
            || string.Equals(report.Details.GetValueOrDefault("pressure_state"), "paused", StringComparison.OrdinalIgnoreCase)
            || string.Equals(report.Details.GetValueOrDefault("pressure_state"), QueuePressureStates.Throttled, StringComparison.OrdinalIgnoreCase))
        {
            return (true, "low", $"required source {requiredSource} is degraded, stale, throttled, or gapped; confidence lowered");
        }

        return (true, "medium", "prerequisite source healthy");
    }

    private static bool HasSuppressingEvidence(SourceHealthReport report) =>
        report.PrerequisiteStatuses?.Values.Any(SuppressingEvidenceStates.Contains) == true;

    private static bool HasDegradingEvidence(SourceHealthReport report) =>
        report.PrerequisiteStatuses?.Values.Any(DegradingEvidenceStates.Contains) == true
        // A healthy source is not degraded merely because a rare sibling lifecycle
        // family has not occurred. The event being evaluated is itself evidence for
        // its family; only an explicitly unhealthy family state lowers confidence.
        || report.EventFamilyStatuses?.Values.Any(DegradingEventFamilyStates.Contains) == true;

    private static bool LinuxRulePredicate(string ruleId, EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        if (normalized is null)
        {
            return false;
        }

        return ruleId switch
        {
            "auth.bruteforce.linux" => IsAuthenticationFailure(envelope),
            "auth.success-after-failures.linux" => IsAuthenticationSuccess(envelope),
            "privilege.sudo-su-root.linux" => IsPrivilegeSuccess(envelope),
            "ssh.root-login.linux" => IsSshPrivilegedSuccess(envelope),
            "process.suspicious-privileged-command.linux" => IsSuspiciousPrivilegedCommand(envelope),
            "process.suspicious-snapshot-command.linux" => IsSuspiciousSnapshotCommand(envelope),
            "persistence.service-start.linux" => IsServiceStart(envelope),
            "persistence.scheduler-activity.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.Scheduler)
                && CategoryEquals(normalized, "scheduler")
                && ActionIn(normalized, "job_execute", "timer_trigger"),
            "package.change.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.PackageManagement)
                && CategoryEquals(normalized, "package")
                && ActionIn(normalized, "install", "update", "remove")
                && HasValue(normalized.PackageName),
            "kernel.security-control-change.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.KernelSecurity)
                && CategoryEquals(normalized, "kernel_security")
                && ActionIn(normalized, "security_denial", "security_event", "module_load"),
            "policy.security-posture-drift.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.PolicyPostureDrift)
                && CategoryEquals(normalized, "policy_posture")
                && ActionEquals(normalized, "drift")
                && string.Equals(envelope.EventCode, "policy_drift", StringComparison.Ordinal),
            "firewall.change.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.Firewall)
                && CategoryEquals(normalized, "firewall")
                && ActionIn(normalized, "policy_change", "allow", "deny"),
            "network.listener-observed.linux" => IsListenerObserved(envelope),
            "behavior.host-resource-pressure.linux" => IsHostResourcePressure(envelope),
            "tamper.agent-log-source-silence.linux" => IsAgentLogOrSourceSilence(envelope),
            "tamper.agent-self-integrity.linux" => IsAgentSelfIntegrity(envelope),
            _ => false
        };
    }

    private static bool IsAuthenticationFailure(EventEnvelope envelope) =>
        ((SourceIdEquals(envelope, LinuxTelemetrySourceIds.LoginSession) || SourceIdEquals(envelope, LinuxTelemetrySourceIds.Ssh))
            && CategoryEquals(envelope.Normalized, "authentication")
            || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.LoginSession, "login")
            || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.Ssh, "ssh_authentication"))
        && ActionEquals(envelope.Normalized, "authenticate")
        && OutcomeEquals(envelope.Normalized, "failure")
        && (HasValue(envelope.Normalized?.TargetUserName) || HasValue(envelope.Normalized?.SourceIp));

    private static bool IsAuthenticationSuccess(EventEnvelope envelope) =>
        ((SourceIdEquals(envelope, LinuxTelemetrySourceIds.LoginSession) || SourceIdEquals(envelope, LinuxTelemetrySourceIds.Ssh))
            && CategoryEquals(envelope.Normalized, "authentication")
            || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.LoginSession, "login")
            || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.Ssh, "ssh_authentication"))
        && ActionEquals(envelope.Normalized, "authenticate")
        && OutcomeEquals(envelope.Normalized, "success")
        && (HasValue(envelope.Normalized?.TargetUserName) || HasValue(envelope.Normalized?.SourceIp));

    private static bool IsPrivilegeSuccess(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        return ((SourceIdEquals(envelope, LinuxTelemetrySourceIds.Privilege)
                && CategoryEquals(normalized, "authorization"))
            || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.Privilege, "sudo", "su"))
            && OutcomeEquals(normalized, "success")
            && ActionIn(normalized, "command_execute", "session_start")
            && IsPrivilegedUser(TargetUser(normalized));
    }

    private static bool IsSshPrivilegedSuccess(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        var directSource = SourceIdEquals(envelope, LinuxTelemetrySourceIds.Ssh)
            && (CategoryEquals(normalized, "authentication") || CategoryEquals(normalized, "session"));
        var roleSecondarySource = RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.Ssh, "ssh_authentication")
                && ActionEquals(normalized, "authenticate")
            || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.Ssh, "ssh_session")
                && ActionEquals(normalized, "session_start");
        return (directSource || roleSecondarySource)
            && OutcomeEquals(normalized, "success")
            && IsPrivilegedUser(TargetUser(normalized));
    }

    private static bool IsSuspiciousPrivilegedCommand(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        if (!(SourceIdEquals(envelope, LinuxTelemetrySourceIds.Privilege)
                || RoleSecondarySourceFamilyIn(envelope, LinuxTelemetrySourceIds.Privilege, "sudo", "su"))
            || !HasValue(CommandLine(normalized)))
        {
            return false;
        }

        var command = CommandLine(normalized)!.ToLowerInvariant();
        return ContainsAny(command, "curl ", "wget ", "nc ", "ncat ", "socat ", "bash -c", "sh -c", "python -c", "perl -e", "chmod +x", "base64 -d");
    }

    private static bool IsServiceStart(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        var directSource = SourceIdEquals(envelope, LinuxTelemetrySourceIds.ServiceChange)
            && CategoryEquals(normalized, "service");
        var roleSecondarySource = TryGetCanonicalRoleSecondary(envelope, out var secondarySource, out var secondaryFamily)
            && string.Equals(secondarySource, LinuxTelemetrySourceIds.ServiceChange, StringComparison.Ordinal)
            && string.Equals(secondaryFamily, normalized?.Action, StringComparison.Ordinal);
        return (directSource || roleSecondarySource)
            && ActionIn(normalized, "service_start", "service_reload", "service_failure")
            && HasValue(normalized?.ServiceName);
    }

    private static bool IsSuspiciousSnapshotCommand(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        if (!SourceIdEquals(envelope, LinuxTelemetrySourceIds.ProcessSnapshotDiff)
            || !CategoryEquals(normalized, "process")
            || !ActionIn(normalized, "observed", "changed")
            || !HasValue(CommandLine(normalized)))
        {
            return false;
        }

        var command = NormalizeCommand(CommandLine(normalized)!);
        return IsDownloadToShell(command)
            || IsReverseShell(command)
            || IsEncodedExecution(command)
            || IsChainedDownloadAndExecute(command);
    }

    private static bool IsDownloadToShell(string command) =>
        (ContainsExecutable(command, "curl") || ContainsExecutable(command, "wget"))
        && PipeFeedsShell(command);

    private static bool IsReverseShell(string command)
    {
        var shellDevice = ContainsAny(command, "/dev/tcp/", "/dev/udp/")
            && ContainsExecutable(command, "bash")
            && ContainsAny(command, " -i", " -c");
        var netcatExec = (ContainsExecutable(command, "nc") || ContainsExecutable(command, "ncat"))
            && ContainsAny(command, " -e ", " --exec ", " -c ");
        var socatExec = ContainsExecutable(command, "socat")
            && command.Contains("exec:", StringComparison.Ordinal)
            && command.Contains("tcp", StringComparison.Ordinal);
        var interpreterSocket = (ContainsExecutable(command, "python") || ContainsExecutable(command, "python3"))
            && command.Contains("socket", StringComparison.Ordinal)
            && command.Contains(".connect(", StringComparison.Ordinal)
            && ContainsAny(command, "pty.spawn", "subprocess");
        return shellDevice || netcatExec || socatExec || interpreterSocket;
    }

    private static bool IsEncodedExecution(string command)
    {
        var base64Decode = ContainsExecutable(command, "base64")
            && ContainsAny(command, " --decode", " -d")
            && PipeFeedsShell(command);
        var opensslDecode = ContainsExecutable(command, "openssl")
            && command.Contains(" enc ", StringComparison.Ordinal)
            && ContainsAny(command, " -d", " -decrypt")
            && PipeFeedsShell(command);
        var interpreterDecode = (ContainsExecutable(command, "python") || ContainsExecutable(command, "python3"))
            && command.Contains("base64.b64decode", StringComparison.Ordinal)
            && ContainsAny(command, "exec(", "eval(");
        return base64Decode || opensslDecode || interpreterDecode;
    }

    private static bool IsChainedDownloadAndExecute(string command)
    {
        var segments = command
            .Replace("||", "&&", StringComparison.Ordinal)
            .Split(["&&", ";"], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 3
            || !segments.Any(segment => ContainsExecutable(segment, "curl") || ContainsExecutable(segment, "wget"))
            || !segments.Any(segment => segment.Contains("chmod +x", StringComparison.Ordinal)))
        {
            return false;
        }

        return segments.Any(segment =>
        {
            var firstToken = FirstCommandToken(segment);
            return firstToken.StartsWith("./", StringComparison.Ordinal)
                || firstToken.StartsWith("/tmp/", StringComparison.Ordinal)
                || firstToken.StartsWith("/var/tmp/", StringComparison.Ordinal);
        });
    }

    private static bool PipeFeedsShell(string command)
    {
        for (var index = command.IndexOf('|'); index >= 0; index = command.IndexOf('|', index + 1))
        {
            if ((index > 0 && command[index - 1] == '|') || (index + 1 < command.Length && command[index + 1] == '|'))
            {
                continue;
            }

            var token = FirstCommandToken(command[(index + 1)..]);
            if (IsShellToken(token))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsListenerObserved(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        var address = normalized?.SourceIp ?? normalized?.Network?.SourceIp;
        var protocol = normalized?.Protocol ?? normalized?.Network?.Protocol;
        return SourceIdEquals(envelope, LinuxTelemetrySourceIds.NetworkSocketSnapshotDiff)
            && CategoryEquals(normalized, "network_listener")
            && ActionIn(normalized, "observed", "changed")
            && string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase)
            && IsNonLoopbackOrWildcardAddress(address)
            && TryReadSourcePort(normalized, out _);
    }

    private static bool IsHostResourcePressure(EventEnvelope envelope)
    {
        if (!SourceIdEquals(envelope, LinuxTelemetrySourceIds.HostBehaviourMetrics)
            || !CategoryEquals(envelope.Normalized, "host_behavior")
            || !ActionEquals(envelope.Normalized, "sampled"))
        {
            return false;
        }

        var cpuPressure = TryReadBoundedRawInt64(envelope, "cpu_busy_permille", 0, 1_000, out var cpuBusy)
            && cpuBusy >= 950;
        var memoryPressure = TryReadBoundedRawInt64(envelope, "memory_total_bytes", 1, 1L << 60, out var memoryTotal)
            && TryReadBoundedRawInt64(envelope, "memory_available_bytes", 0, 1L << 60, out var memoryAvailable)
            && memoryAvailable <= memoryTotal
            && (decimal)memoryAvailable / memoryTotal <= 0.05m;
        var blockedPressure = TryReadBoundedRawInt64(envelope, "processes_blocked", 0, 1_000_000, out var blocked)
            && blocked >= 8;
        var severePsi = RawMetricAtLeast(envelope, "cpu_pressure_some_avg10_milli", 50_000, 100_000)
            || RawMetricAtLeast(envelope, "memory_pressure_some_avg10_milli", 50_000, 100_000)
            || RawMetricAtLeast(envelope, "io_pressure_some_avg10_milli", 50_000, 100_000);
        return cpuPressure || memoryPressure || blockedPressure || severePsi;
    }

    private static bool HasEventLocalCompletenessGap(EventEnvelope envelope) =>
        SourceIdEquals(envelope, LinuxTelemetrySourceIds.HostBehaviourMetrics)
        && (string.Equals(envelope.Normalized?.Outcome, "unknown", StringComparison.OrdinalIgnoreCase)
            || string.Equals(envelope.Normalized?.Labels.GetValueOrDefault("metrics.completeness"), "partial", StringComparison.OrdinalIgnoreCase));

    private static bool RawMetricAtLeast(EventEnvelope envelope, string field, long threshold, long maximum) =>
        TryReadBoundedRawInt64(envelope, field, 0, maximum, out var value) && value >= threshold;

    private static bool TryReadBoundedRawInt64(EventEnvelope envelope, string field, long minimum, long maximum, out long value)
    {
        value = 0;
        return envelope.Raw.ValueKind == System.Text.Json.JsonValueKind.Object
            && envelope.Raw.TryGetProperty(field, out var property)
            && property.ValueKind == System.Text.Json.JsonValueKind.Number
            && property.TryGetInt64(out value)
            && value >= minimum
            && value <= maximum;
    }

    private static bool TryReadSourcePort(NormalizedEventFields? normalized, out int port)
    {
        port = 0;
        if (HasValue(normalized?.SourcePort))
        {
            return int.TryParse(normalized!.SourcePort, NumberStyles.None, CultureInfo.InvariantCulture, out port)
                && port is >= 1 and <= 65_535;
        }

        port = normalized?.Network?.SourcePort ?? 0;
        return port is >= 1 and <= 65_535;
    }

    private static bool IsNonLoopbackOrWildcardAddress(string? value)
    {
        if (!HasValue(value))
        {
            return false;
        }

        var candidate = value!.Trim();
        if (candidate == "*")
        {
            return true;
        }
        if (candidate.Length > 2 && candidate[0] == '[' && candidate[^1] == ']')
        {
            candidate = candidate[1..^1];
        }
        if (!IPAddress.TryParse(candidate, out var address))
        {
            return false;
        }

        return address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || !IPAddress.IsLoopback(address);
    }

    private static string NormalizeCommand(string command) =>
        string.Join(' ', command.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToLowerInvariant();

    private static bool ContainsExecutable(string command, string executable)
    {
        for (var index = command.IndexOf(executable, StringComparison.Ordinal); index >= 0; index = command.IndexOf(executable, index + 1, StringComparison.Ordinal))
        {
            var before = index == 0 ? '\0' : command[index - 1];
            var afterIndex = index + executable.Length;
            var after = afterIndex == command.Length ? '\0' : command[afterIndex];
            var validBefore = before == '\0' || char.IsWhiteSpace(before) || before is '/' or '|' or ';' or '&' or '(' or '\'' or '"';
            var validAfter = after == '\0' || char.IsWhiteSpace(after) || after is '|' or ';' or '&' or ')' or '\'' or '"';
            if (validBefore && validAfter)
            {
                return true;
            }
        }

        return false;
    }

    private static string FirstCommandToken(string segment)
    {
        var trimmed = segment.TrimStart();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }
        var end = trimmed.IndexOfAny([' ', '\t', '\r', '\n']);
        return (end < 0 ? trimmed : trimmed[..end]).Trim('\'', '"');
    }

    private static bool IsShellToken(string token) =>
        token is "sh" or "bash" or "dash" or "zsh" or "ksh"
        || token.EndsWith("/sh", StringComparison.Ordinal)
        || token.EndsWith("/bash", StringComparison.Ordinal)
        || token.EndsWith("/dash", StringComparison.Ordinal)
        || token.EndsWith("/zsh", StringComparison.Ordinal)
        || token.EndsWith("/ksh", StringComparison.Ordinal);

    private static bool IsAgentLogOrSourceSilence(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        if (SourceIdEquals(envelope, LinuxTelemetrySourceIds.AgentLogTamper)
            && CategoryEquals(normalized, "tamper")
            && ActionIn(normalized, "agent_config_change", "agent_unit_change", "log_corruption", "source_gap", "source_silence"))
        {
            return true;
        }

        if (!string.Equals(envelope.Source, EventSources.AgentHealth, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var code = envelope.EventCode ?? string.Empty;
        return ContainsAny(code.ToLowerInvariant(), "source_silence", "source_gap", "permission_denied", "throttle", "pressure", "journal_gap", "log_tamper", "agent_tamper")
            || (CategoryEquals(normalized, "tamper") && ActionIn(normalized, "source_silence", "source_gap", "permission_denied", "throttle"));
    }

    private static bool IsAgentSelfIntegrity(EventEnvelope envelope)
    {
        var sourceId = envelope.SourceId ?? string.Empty;
        var code = (envelope.EventCode ?? string.Empty).ToLowerInvariant();
        var collectorMaterialChange = sourceId.Equals(LinuxTelemetrySourceIds.AgentSelfIntegrity, StringComparison.OrdinalIgnoreCase)
            && (code is "self_integrity_snapshot_changed" or "self_integrity_snapshot_deleted" or "self_integrity_snapshot_unreadable"
                || (CategoryEquals(envelope.Normalized, "agent_integrity") && ActionIn(envelope.Normalized, "changed", "deleted", "unreadable")));
        var legacyChangeCode = ContainsAny(code, "agent_self_integrity_change", "agent_integrity_change", "agent_binary_changed", "agent_unit_changed", "agent_config_metadata_changed");
        var legacyChangeAction = CategoryEquals(envelope.Normalized, "tamper") && ActionIn(envelope.Normalized, "agent_integrity_change", "agent_config_change");
        return collectorMaterialChange || legacyChangeCode || legacyChangeAction;
    }

    private static string? MatchingRequiredSource(DetectionRuleMetadata rule, EventEnvelope envelope) =>
        rule.RequiredSources.FirstOrDefault(source => EventSourceMatches(source, envelope));

    private static bool EventSourceMatches(string requiredSource, EventEnvelope envelope)
    {
        if (SourceIdEquals(envelope, requiredSource))
        {
            return true;
        }
        if (RoleSecondarySourceEquals(envelope, requiredSource)) return true;

        var normalizedRequired = NormalizeSourceName(requiredSource);
        return normalizedRequired == NormalizeSourceName(envelope.Source)
            || normalizedRequired == NormalizeSourceName(envelope.SourceId)
            || (normalizedRequired == "agent-health" && string.Equals(envelope.Source, EventSources.AgentHealth, StringComparison.OrdinalIgnoreCase))
            || (normalizedRequired == "inventory-diff" && string.Equals(envelope.Source, EventSources.InventoryDiff, StringComparison.OrdinalIgnoreCase));
    }

    private static string BuildSuppressionKey(DetectionRuleMetadata rule, EventEnvelope envelope)
    {
        var values = rule.SuppressionKeys.Count == 0 ? rule.RequiredFields : rule.SuppressionKeys;
        return string.Join('|', values.Select(key => $"{key}={FieldValue(envelope, key) ?? "<missing>"}"));
    }

    private static IReadOnlyList<string> PresentFields(DetectionRuleMetadata rule, EventEnvelope envelope) =>
        rule.RequiredFields.Where(field => HasValue(FieldValue(envelope, field))).ToArray();

    public static string? FieldValue(EventEnvelope envelope, string fieldName)
    {
        var n = envelope.Normalized;
        return fieldName switch
        {
            "agent_id" => envelope.AgentId,
            "source_id" => envelope.SourceId,
            "source" => envelope.Source,
            "event_code" => envelope.EventCode,
            "action" => n?.Action,
            "outcome" => n?.Outcome,
            "user_name" => n?.UserName ?? n?.User?.Name,
            "target_user_name" => n?.TargetUserName,
            "source_ip" => n?.SourceIp ?? n?.Network?.SourceIp,
            "source_port" => n?.SourcePort ?? n?.Network?.SourcePort?.ToString(CultureInfo.InvariantCulture),
            "destination_ip" => n?.DestinationIp ?? n?.Network?.DestinationIp,
            "destination_port" => n?.DestinationPort ?? n?.Network?.DestinationPort?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "protocol" => n?.Protocol ?? n?.Network?.Protocol,
            "process_image" => n?.ProcessImage ?? n?.Process?.Executable,
            "process_command_line" => n?.ProcessCommandLine ?? n?.Process?.CommandLine,
            "service_name" => n?.ServiceName,
            "task_name" => n?.TaskName,
            "package_name" => n?.PackageName,
            "file_path" => n?.FilePath ?? n?.File?.Path,
            "hash" => n?.Hash ?? n?.File?.Sha256,
            "cpu_busy_permille" or "memory_total_bytes" or "memory_available_bytes" or "processes_blocked"
                or "cpu_pressure_some_avg10_milli" or "memory_pressure_some_avg10_milli" or "io_pressure_some_avg10_milli"
                => RawNumberField(envelope, fieldName),
            _ => n?.Labels.GetValueOrDefault(fieldName)
        };
    }

    private static string? RawNumberField(EventEnvelope envelope, string fieldName) =>
        envelope.Raw.ValueKind == System.Text.Json.JsonValueKind.Object
        && envelope.Raw.TryGetProperty(fieldName, out var property)
        && property.ValueKind == System.Text.Json.JsonValueKind.Number
        && property.TryGetInt64(out var value)
            ? value.ToString(CultureInfo.InvariantCulture)
            : null;

    private static bool IsLinuxEvent(EventEnvelope envelope) =>
        string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase)
        || string.Equals(envelope.Source, EventSources.LinuxJournal, StringComparison.OrdinalIgnoreCase)
        || string.Equals(envelope.Source, EventSources.LinuxAudit, StringComparison.OrdinalIgnoreCase)
        || (string.Equals(envelope.Source, EventSources.AgentHealth, StringComparison.OrdinalIgnoreCase) && string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase))
        || (string.Equals(envelope.Source, EventSources.InventoryDiff, StringComparison.OrdinalIgnoreCase) && string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase));

    private static bool SourceIdEquals(EventEnvelope envelope, string sourceId) =>
        string.Equals(envelope.SourceId, sourceId, StringComparison.OrdinalIgnoreCase);

    private static bool RoleSecondarySourceEquals(EventEnvelope envelope, string sourceId) =>
        TryGetCanonicalRoleSecondary(envelope, out var secondarySource, out _)
        && string.Equals(secondarySource, sourceId, StringComparison.Ordinal);

    private static bool RoleSecondarySourceFamilyIn(EventEnvelope envelope, string sourceId, params string[] families) =>
        TryGetCanonicalRoleSecondary(envelope, out var secondarySource, out var secondaryFamily)
        && string.Equals(secondarySource, sourceId, StringComparison.Ordinal)
        && families.Contains(secondaryFamily, StringComparer.Ordinal);

    private static bool TryGetCanonicalRoleSecondary(
        EventEnvelope envelope,
        out string secondarySource,
        out string secondaryFamily)
    {
        secondarySource = string.Empty;
        secondaryFamily = string.Empty;
        if (!string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.Ordinal)
            || !string.Equals(envelope.Source, EventSources.LinuxJournal, StringComparison.Ordinal)
            || envelope.SourceId is null
            || !CanonicalLinuxL4RoleSourceFamilies.TryGetValue(envelope.SourceId, out var primaryFamilies)
            || envelope.Normalized?.Labels is not { } labels
            || !labels.TryGetValue("linux.event_family", out var primaryFamily)
            || !primaryFamilies.Contains(primaryFamily))
        {
            return false;
        }

        if (!labels.TryGetValue("linux.secondary_source_id", out var candidateSecondarySource)
            || !labels.TryGetValue("linux.secondary_event_family", out var candidateSecondaryFamily)
            || !CanonicalLinuxL2SourceFamilies.TryGetValue(candidateSecondarySource, out var canonicalSecondaryFamilies)
            || !canonicalSecondaryFamilies.Contains(candidateSecondaryFamily))
        {
            return false;
        }

        secondarySource = candidateSecondarySource;
        secondaryFamily = candidateSecondaryFamily;

        return true;
    }

    private static bool CategoryEquals(NormalizedEventFields? normalized, string value) =>
        string.Equals(normalized?.Category, value, StringComparison.OrdinalIgnoreCase);

    private static bool ActionEquals(NormalizedEventFields? normalized, string value) =>
        string.Equals(normalized?.Action, value, StringComparison.OrdinalIgnoreCase);

    private static bool ActionIn(NormalizedEventFields? normalized, params string[] values) =>
        normalized?.Action is not null && values.Any(value => string.Equals(normalized.Action, value, StringComparison.OrdinalIgnoreCase));

    private static bool OutcomeEquals(NormalizedEventFields? normalized, string value) =>
        string.Equals(normalized?.Outcome, value, StringComparison.OrdinalIgnoreCase);

    private static string? TargetUser(NormalizedEventFields? normalized) =>
        normalized?.TargetUserName ?? normalized?.User?.Name ?? normalized?.UserName;

    private static string? CommandLine(NormalizedEventFields? normalized) =>
        normalized?.ProcessCommandLine ?? normalized?.Process?.CommandLine;

    private static bool IsPrivilegedUser(string? value) =>
        value is not null && (value.Equals("root", StringComparison.OrdinalIgnoreCase) || value == "0");

    private static bool HasValue(string? value) => !string.IsNullOrWhiteSpace(value);

    private static bool ContainsAny(string value, params string[] needles) => needles.Any(value.Contains);

    private static string NormalizeSourceName(string? value) => (value ?? string.Empty).Replace('_', '-').ToLowerInvariant();
}
