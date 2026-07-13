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
            return (false, "low", $"required source {requiredSource} is {report.Status}; evaluation suppressed");
        }

        if (HasSuppressingEvidence(report))
        {
            return (false, "low", $"required source {requiredSource} prerequisite evidence is unavailable; evaluation suppressed");
        }

        if (DegradingSourceStates.Contains(report.Status)
            || HasDegradingEvidence(report)
            || report.GapDetected
            || report.BookmarkGapDetected
            || report.ClearedDetected
            || (report.DroppedEvents ?? 0) > 0
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
        || report.EventFamilyStatuses?.Values.Any(DegradingEvidenceStates.Contains) == true;

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
            "persistence.service-start.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.ServiceChange)
                && CategoryEquals(normalized, "service")
                && ActionIn(normalized, "service_start", "service_reload", "service_failure")
                && HasValue(normalized.ServiceName),
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
            "firewall.change.linux" => SourceIdEquals(envelope, LinuxTelemetrySourceIds.Firewall)
                && CategoryEquals(normalized, "firewall")
                && ActionIn(normalized, "policy_change", "allow", "deny"),
            "tamper.agent-log-source-silence.linux" => IsAgentLogOrSourceSilence(envelope),
            "tamper.agent-self-integrity.linux" => IsAgentSelfIntegrity(envelope),
            _ => false
        };
    }

    private static bool IsAuthenticationFailure(EventEnvelope envelope) =>
        (SourceIdEquals(envelope, LinuxTelemetrySourceIds.LoginSession) || SourceIdEquals(envelope, LinuxTelemetrySourceIds.Ssh))
        && CategoryEquals(envelope.Normalized, "authentication")
        && ActionEquals(envelope.Normalized, "authenticate")
        && OutcomeEquals(envelope.Normalized, "failure")
        && (HasValue(envelope.Normalized?.TargetUserName) || HasValue(envelope.Normalized?.SourceIp));

    private static bool IsAuthenticationSuccess(EventEnvelope envelope) =>
        (SourceIdEquals(envelope, LinuxTelemetrySourceIds.LoginSession) || SourceIdEquals(envelope, LinuxTelemetrySourceIds.Ssh))
        && CategoryEquals(envelope.Normalized, "authentication")
        && ActionEquals(envelope.Normalized, "authenticate")
        && OutcomeEquals(envelope.Normalized, "success")
        && (HasValue(envelope.Normalized?.TargetUserName) || HasValue(envelope.Normalized?.SourceIp));

    private static bool IsPrivilegeSuccess(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        return SourceIdEquals(envelope, LinuxTelemetrySourceIds.Privilege)
            && CategoryEquals(normalized, "authorization")
            && OutcomeEquals(normalized, "success")
            && ActionIn(normalized, "command_execute", "session_start")
            && IsPrivilegedUser(TargetUser(normalized));
    }

    private static bool IsSshPrivilegedSuccess(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        return SourceIdEquals(envelope, LinuxTelemetrySourceIds.Ssh)
            && (CategoryEquals(normalized, "authentication") || CategoryEquals(normalized, "session"))
            && OutcomeEquals(normalized, "success")
            && IsPrivilegedUser(TargetUser(normalized));
    }

    private static bool IsSuspiciousPrivilegedCommand(EventEnvelope envelope)
    {
        var normalized = envelope.Normalized;
        if (!SourceIdEquals(envelope, LinuxTelemetrySourceIds.Privilege) || !HasValue(CommandLine(normalized)))
        {
            return false;
        }

        var command = CommandLine(normalized)!.ToLowerInvariant();
        return ContainsAny(command, "curl ", "wget ", "nc ", "ncat ", "socat ", "bash -c", "sh -c", "python -c", "perl -e", "chmod +x", "base64 -d");
    }

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
            _ => n?.Labels.GetValueOrDefault(fieldName)
        };
    }

    private static bool IsLinuxEvent(EventEnvelope envelope) =>
        string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase)
        || string.Equals(envelope.Source, EventSources.LinuxJournal, StringComparison.OrdinalIgnoreCase)
        || string.Equals(envelope.Source, EventSources.LinuxAudit, StringComparison.OrdinalIgnoreCase)
        || (string.Equals(envelope.Source, EventSources.AgentHealth, StringComparison.OrdinalIgnoreCase) && string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase))
        || (string.Equals(envelope.Source, EventSources.InventoryDiff, StringComparison.OrdinalIgnoreCase) && string.Equals(envelope.Platform, TelemetryPlatforms.Linux, StringComparison.OrdinalIgnoreCase));

    private static bool SourceIdEquals(EventEnvelope envelope, string sourceId) =>
        string.Equals(envelope.SourceId, sourceId, StringComparison.OrdinalIgnoreCase);

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
