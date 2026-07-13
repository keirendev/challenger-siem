using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed partial class LinuxJournalNormalizer
{
    public const string SourceId = LinuxTelemetrySourceIds.JournalL1;
    private const int MaxFieldChars = 2048;
    private const int MaxCommandLineChars = 4096;
    private const int MaxMessageChars = 20000;
    private const int MaxMessageEvidenceChars = 4096;
    private const int MaxRawFields = 32;
    private static readonly string[] RawFieldNames =
    [
        "_BOOT_ID", "_TRANSPORT", "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT", "SYSLOG_IDENTIFIER",
        "SYSLOG_FACILITY", "PRIORITY", "MESSAGE_ID", "_PID", "_UID", "_COMM", "_EXE",
        "_CMDLINE", "USER", "LOGNAME", "PAM_USER", "PAM_TYPE", "PAM_RHOST", "PAM_SERVICE",
        "REMOTE_ADDR", "REMOTE_PORT", "DESTINATION_ADDR", "DESTINATION_PORT", "PROTOCOL", "RESULT", "ACTION", "UNIT", "OBJECT_SYSTEMD_UNIT",
        "PACKAGE_NAME", "PACKAGE", "MODULE", "MESSAGE"
    ];

    public bool TryNormalize(
        string record,
        LinuxAgentOptions options,
        DateTimeOffset observedAt,
        out NormalizedJournalRecord? normalized,
        out string errorCode)
    {
        normalized = null;
        errorCode = "journal_record_malformed";
        if (Encoding.UTF8.GetByteCount(record) > options.Journal.MaxInputRecordBytes)
        {
            errorCode = "journal_record_oversized";
            return false;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(record, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            return false;
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            var root = document.RootElement;
            if (!TryText(root, "__CURSOR", out var cursor) || string.IsNullOrWhiteSpace(cursor)
                || !TryText(root, "_BOOT_ID", out var bootId) || string.IsNullOrWhiteSpace(bootId)
                || !TryMicroseconds(root, out var microseconds))
            {
                errorCode = "journal_identity_missing";
                return false;
            }

            if (!TryEventTime(microseconds, out var eventTime))
            {
                errorCode = "journal_timestamp_malformed";
                return false;
            }

            var raw = new Dictionary<string, object?>(StringComparer.Ordinal);
            var redacted = new SortedSet<string>(StringComparer.Ordinal);
            var truncated = new SortedSet<string>(StringComparer.Ordinal);
            var binaryOrInvalidText = false;
            var originalBytes = Encoding.UTF8.GetByteCount(record);
            foreach (var field in RawFieldNames.Take(MaxRawFields))
            {
                if (!root.TryGetProperty(field, out var value))
                {
                    continue;
                }

                if (value.ValueKind != JsonValueKind.String)
                {
                    raw[field] = "<binary-or-nontext>";
                    binaryOrInvalidText = true;
                    redacted.Add($"raw.{field}");
                    continue;
                }

                var maxChars = field switch
                {
                    "MESSAGE" => MaxMessageChars,
                    "_CMDLINE" => MaxCommandLineChars,
                    _ => MaxFieldChars
                };
                var text = Sanitize(value.GetString() ?? string.Empty, maxChars, out var wasTruncated, out var invalidText);
                if (!TryRedactSecrets(text, out var replaced))
                {
                    errorCode = "journal_pattern_timeout";
                    return false;
                }
                if (!string.Equals(replaced, text, StringComparison.Ordinal))
                {
                    text = replaced;
                    redacted.Add($"raw.{field}");
                }

                if (wasTruncated)
                {
                    truncated.Add($"raw.{field}");
                }
                if (invalidText)
                {
                    binaryOrInvalidText = true;
                    redacted.Add($"raw.{field}");
                }
                raw[field] = text;
            }

            raw["__CURSOR"] = Sanitize(cursor!, 1024, out var cursorTruncated, out var cursorInvalid);
            if (cursorTruncated || cursorInvalid)
            {
                errorCode = "journal_cursor_invalid";
                return false;
            }
            raw["__REALTIME_TIMESTAMP"] = microseconds.ToString(CultureInfo.InvariantCulture);

            var rawElement = JsonSerializer.SerializeToElement(raw);
            var rawSize = JsonSerializer.SerializeToUtf8Bytes(rawElement).Length;
            if (rawSize > ContractLimits.RawPayloadMaxUtf8Bytes)
            {
                errorCode = "journal_normalized_raw_oversized";
                return false;
            }

            var message = GetRaw(raw, "MESSAGE");
            bootId = GetRaw(raw, "_BOOT_ID");
            var transport = GetRaw(raw, "_TRANSPORT");
            var unit = FirstBounded(raw, 255, "UNIT", "OBJECT_SYSTEMD_UNIT", "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT");
            var identifier = FirstBounded(raw, 255, "SYSLOG_IDENTIFIER", "_COMM");
            var facility = FirstBounded(raw, 128, "SYSLOG_FACILITY");
            var messageId = FirstBounded(raw, 128, "MESSAGE_ID");
            LinuxJournalClassification? classification = null;
            if (options.Journal.TargetCoverageLevel >= WindowsCoverageLevel.L2)
            {
                try
                {
                    classification = ClassifyL2(raw, message, transport, unit, identifier, facility, messageId);
                }
                catch (RegexMatchTimeoutException)
                {
                    errorCode = "journal_pattern_timeout";
                    return false;
                }
            }
            classification ??= ClassifyL1(transport, unit, identifier, facility, messageId);

            var processId = FirstBounded(raw, 64, "_PID");
            var processImage = FirstBounded(raw, 2048, "_EXE", "_COMM");
            var processCommandLine = FirstBounded(raw, MaxCommandLineChars, "_CMDLINE");
            var userId = FirstBounded(raw, 512, "_UID");
            var actorUser = classification.ActorUser ?? FirstBounded(raw, 512, "USER", "LOGNAME");
            var targetUser = classification.TargetUser ?? FirstBounded(raw, 512, "PAM_USER");
            var userName = actorUser ?? targetUser;
            var sourceIp = classification.SourceIp ?? ValidIp(FirstBounded(raw, 128, "REMOTE_ADDR", "PAM_RHOST"));
            var sourcePort = classification.SourcePort ?? ValidPort(FirstBounded(raw, 16, "REMOTE_PORT"));
            var destinationIp = classification.DestinationIp ?? ValidIp(FirstBounded(raw, 128, "DESTINATION_ADDR"));
            var destinationPort = classification.DestinationPort ?? ValidPort(FirstBounded(raw, 16, "DESTINATION_PORT"));
            var serviceName = classification.ServiceName ?? unit ?? identifier;
            var packageName = classification.PackageName ?? FirstBounded(raw, 512, "PACKAGE_NAME", "PACKAGE");
            var commandLine = classification.CommandLine ?? processCommandLine;
            var moduleName = classification.ModuleName ?? FirstBounded(raw, 512, "MODULE");
            var taskName = classification.TaskName;
            if (taskName is null && classification.SourceId == LinuxTelemetrySourceIds.Scheduler)
            {
                taskName = unit;
            }

            var labels = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["journal.boot_id"] = bootId!,
                ["journal.transport"] = transport,
                ["linux.event_family"] = classification.EventFamily,
                ["linux.evidence"] = classification.UsedMessageEvidence ? "structured_and_bounded_message" : "structured",
                ["linux.source_pack"] = classification.SourceId == LinuxTelemetrySourceIds.JournalL1
                    ? LinuxTelemetrySourceCatalog.L1PackId
                    : LinuxTelemetrySourceCatalog.L2PackId
            };
            var normalizedFields = new NormalizedEventFields
            {
                Category = classification.Category,
                Action = classification.Action,
                Outcome = classification.Outcome,
                UserName = userName,
                UserSid = userId,
                TargetUserName = targetUser,
                ProcessId = processId,
                ProcessImage = processImage,
                ProcessCommandLine = commandLine,
                SourceIp = sourceIp,
                SourcePort = sourcePort?.ToString(CultureInfo.InvariantCulture),
                DestinationIp = destinationIp,
                DestinationPort = destinationPort?.ToString(CultureInfo.InvariantCulture),
                Protocol = classification.Protocol,
                ServiceName = BoundOrNull(serviceName, 512),
                DriverName = BoundOrNull(moduleName, 512),
                TaskName = BoundOrNull(taskName, 512),
                PackageName = BoundOrNull(packageName, 512),
                Process = Any(processId, processImage, commandLine)
                    ? new ProcessTelemetryConcept { Pid = processId, Executable = processImage, CommandLine = commandLine }
                    : null,
                User = Any(userName, userId)
                    ? new UserTelemetryConcept { Name = userName, Id = userId }
                    : null,
                Network = Any(sourceIp, destinationIp, classification.Protocol) || sourcePort.HasValue || destinationPort.HasValue
                    ? new NetworkTelemetryConcept
                    {
                        SourceIp = sourceIp,
                        SourcePort = sourcePort,
                        DestinationIp = destinationIp,
                        DestinationPort = destinationPort,
                        Protocol = classification.Protocol
                    }
                    : null,
                Entities = Array.Empty<EventEntity>(),
                Labels = labels
            };

            var eventCode = messageId ?? $"{classification.EventFamily}.{classification.Action ?? "event"}";
            var envelopeWithoutId = new EventEnvelope
            {
                AgentId = options.AgentId,
                Hostname = Sanitize(Environment.MachineName, 255, out _, out _),
                Platform = TelemetryPlatforms.Linux,
                Source = EventSources.LinuxJournal,
                SourceId = classification.SourceId,
                Facility = facility,
                Unit = unit,
                EventCode = Sanitize(eventCode, 128, out _, out _),
                EventTime = eventTime,
                Severity = EventSeverity(GetRaw(raw, "PRIORITY"), classification),
                Message = message,
                Normalized = normalizedFields,
                Raw = rawElement,
                Checkpoint = new SourceCheckpoint { Cursor = cursor, EventTime = eventTime, RecordedAt = observedAt },
                Deduplication = new EventDeduplicationMetadata
                {
                    Inputs = [DeduplicationInputs.AgentId, DeduplicationInputs.SourceId, DeduplicationInputs.CheckpointCursor]
                },
                DataHandling = new DataHandlingMetadata
                {
                    RawSizeBytes = rawSize,
                    RedactionApplied = redacted.Count > 0,
                    RedactedFields = redacted.ToArray(),
                    TruncationApplied = truncated.Count > 0,
                    TruncatedFields = truncated.ToArray(),
                    OriginalSizeBytes = truncated.Count > 0 ? Math.Max(originalBytes, rawSize + 1) : null
                }
            };
            normalized = new NormalizedJournalRecord(
                envelopeWithoutId with { EventId = DeterministicEventIdentity.ComputeSha256Uuid(envelopeWithoutId) },
                cursor!,
                bootId!,
                microseconds,
                binaryOrInvalidText,
                classification.EventFamily);
            errorCode = string.Empty;
            return true;
        }
    }

    private static LinuxJournalClassification? ClassifyL2(
        IReadOnlyDictionary<string, object?> raw,
        string message,
        string transport,
        string? unit,
        string? identifier,
        string? facility,
        string? messageId)
    {
        var source = (identifier ?? string.Empty).ToLowerInvariant();
        var unitLower = (unit ?? string.Empty).ToLowerInvariant();
        var pamService = GetRaw(raw, "PAM_SERVICE").ToLowerInvariant();
        var action = NormalizeAction(GetRaw(raw, "ACTION"));
        var outcome = NormalizeOutcome(GetRaw(raw, "RESULT"));
        var pamType = GetRaw(raw, "PAM_TYPE").ToLowerInvariant();
        var actor = FirstBounded(raw, 512, "USER", "LOGNAME");
        var target = FirstBounded(raw, 512, "PAM_USER");
        var sourceIp = ValidIp(FirstBounded(raw, 128, "REMOTE_ADDR", "PAM_RHOST"));
        var sourcePort = ValidPort(FirstBounded(raw, 16, "REMOTE_PORT"));
        var service = FirstBounded(raw, 512, "UNIT", "OBJECT_SYSTEMD_UNIT", "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT");
        var package = FirstBounded(raw, 512, "PACKAGE_NAME", "PACKAGE");
        var module = FirstBounded(raw, 512, "MODULE");
        var boundedMessage = message.Length <= MaxMessageEvidenceChars ? message : message[..MaxMessageEvidenceChars];

        if (TryClassifyTamper(source, unitLower, action, outcome, boundedMessage, out var tamper))
        {
            return tamper;
        }

        var sshSource = source is "sshd" or "ssh" || unitLower is "sshd.service" or "ssh.service" || pamService == "sshd";
        if (sshSource)
        {
            var structuredAction = PamAction(pamType) ?? action;
            var family = structuredAction is "session_start" or "session_end" ? "ssh_session" : "ssh_authentication";
            var ssh = new LinuxJournalClassification(
                LinuxTelemetrySourceIds.Ssh,
                family,
                structuredAction is "session_start" or "session_end" ? "session" : "authentication",
                structuredAction,
                outcome,
                ActorUser: actor,
                TargetUser: target,
                SourceIp: sourceIp,
                SourcePort: sourcePort,
                ServiceName: service);
            if (structuredAction is not null || outcome is not null)
            {
                return FillSshMessageEvidence(ssh, boundedMessage);
            }

            var parsed = FillSshMessageEvidence(ssh, boundedMessage);
            if (parsed.Action is not null || parsed.Outcome is not null)
            {
                return parsed;
            }
        }

        var privilegeSource = source is "sudo" or "su" || pamService is "sudo" or "su";
        if (privilegeSource)
        {
            var privilegeAction = PamAction(pamType) ?? action;
            if (source == "sudo" && privilegeAction is null && !string.IsNullOrWhiteSpace(GetRaw(raw, "_CMDLINE")))
            {
                privilegeAction = "command_execute";
            }
            var family = source == "su" || pamService == "su" ? "su" : "sudo";
            var privilege = new LinuxJournalClassification(
                LinuxTelemetrySourceIds.Privilege,
                family,
                "authorization",
                privilegeAction,
                outcome,
                ActorUser: actor,
                TargetUser: target,
                ServiceName: service);
            privilege = FillPrivilegeMessageEvidence(privilege, boundedMessage, family);
            if (privilege.Action is not null || privilege.Outcome is not null)
            {
                return privilege;
            }
        }

        var loginSource = source is "login" or "systemd-logind" or "pam_unix" or "gdm-password" or "lightdm"
            || unitLower == "systemd-logind.service" || (!string.IsNullOrEmpty(pamService) && pamService != "sshd");
        if (loginSource)
        {
            var loginAction = PamAction(pamType) ?? SessionActionFromMessageId(messageId) ?? action;
            var login = new LinuxJournalClassification(
                LinuxTelemetrySourceIds.LoginSession,
                loginAction is "session_start" or "session_end" ? "session" : "login",
                loginAction is "session_start" or "session_end" ? "session" : "authentication",
                loginAction,
                outcome,
                ActorUser: actor,
                TargetUser: target,
                SourceIp: sourceIp,
                SourcePort: sourcePort,
                ServiceName: service);
            login = FillSessionMessageEvidence(login, boundedMessage);
            if (login.Action is not null || login.Outcome is not null)
            {
                return login;
            }
        }

        var timerUnit = unitLower.EndsWith(".timer", StringComparison.Ordinal);
        var schedulerSource = timerUnit || source is "cron" or "crond" or "atd";
        if (schedulerSource)
        {
            var schedulerAction = timerUnit
                ? (SystemdAction(messageId) is not null ? "timer_trigger" : action)
                : action;
            var family = timerUnit ? "systemd_timer" : "cron";
            var scheduler = new LinuxJournalClassification(
                LinuxTelemetrySourceIds.Scheduler,
                family,
                "scheduler",
                schedulerAction,
                outcome,
                ActorUser: actor,
                TargetUser: target,
                ServiceName: service,
                TaskName: timerUnit ? service : null);
            scheduler = FillSchedulerMessageEvidence(scheduler, boundedMessage, timerUnit);
            if (scheduler.Action is not null || scheduler.Outcome is not null)
            {
                return scheduler;
            }
        }

        var packageSource = source is "apt" or "apt-get" or "dpkg" or "dnf" or "yum" or "rpm" or "packagekit" or "packagekitd";
        if (packageSource)
        {
            var packageAction = PackageAction(action);
            var packageEvent = new LinuxJournalClassification(
                LinuxTelemetrySourceIds.PackageManagement,
                PackageFamily(packageAction),
                "package",
                packageAction,
                outcome,
                ActorUser: actor,
                PackageName: package);
            packageEvent = FillPackageMessageEvidence(packageEvent, boundedMessage);
            if (packageEvent.Action is not null && packageEvent.PackageName is not null)
            {
                return packageEvent;
            }
        }

        var firewallSource = source is "ufw" or "firewalld" or "nft" or "nftables"
            || boundedMessage.StartsWith("[UFW ", StringComparison.OrdinalIgnoreCase)
            || boundedMessage.StartsWith("nftables ", StringComparison.OrdinalIgnoreCase);
        if (firewallSource)
        {
            var firewall = new LinuxJournalClassification(
                LinuxTelemetrySourceIds.Firewall,
                FirewallFamily(action),
                "firewall",
                FirewallAction(action),
                outcome,
                ActorUser: actor,
                SourceIp: sourceIp,
                SourcePort: sourcePort,
                Protocol: FirstBounded(raw, 64, "PROTOCOL"));
            firewall = FillFirewallMessageEvidence(firewall, boundedMessage);
            if (firewall.Action is not null)
            {
                return firewall;
            }
        }

        var securityKernel = transport == "kernel" && IsKernelSecurityMessage(action, boundedMessage, module);
        if (securityKernel)
        {
            var kernelAction = KernelAction(action, boundedMessage, module);
            var securityModuleMessage = boundedMessage.Contains("apparmor", StringComparison.OrdinalIgnoreCase)
                || boundedMessage.Contains("selinux", StringComparison.OrdinalIgnoreCase)
                || boundedMessage.Contains("avc:", StringComparison.OrdinalIgnoreCase);
            var kernelModuleMessage = boundedMessage.Contains("module", StringComparison.OrdinalIgnoreCase);
            var kernelFamily = action is "module_load" or "module_unload"
                ? "kernel_module"
                : securityModuleMessage
                    ? "security_module"
                    : module is not null || kernelModuleMessage
                        ? "kernel_module"
                        : "kernel_security";
            var messageOutcome = KernelOutcome(boundedMessage);
            return new LinuxJournalClassification(
                LinuxTelemetrySourceIds.KernelSecurity,
                kernelFamily,
                "kernel_security",
                kernelAction,
                outcome ?? messageOutcome,
                ActorUser: actor,
                ModuleName: module,
                SeverityOverride: "warning",
                UsedMessageEvidence: action is null
                    || (kernelFamily == "security_module" && securityModuleMessage)
                    || (kernelFamily == "kernel_module" && module is null && kernelModuleMessage)
                    || (outcome is null && messageOutcome is not null));
        }

        var serviceAction = SystemdAction(messageId) ?? ServiceAction(action);
        var serviceSource = unitLower.EndsWith(".service", StringComparison.Ordinal) && serviceAction is not null;
        if (serviceSource)
        {
            return new LinuxJournalClassification(
                LinuxTelemetrySourceIds.ServiceChange,
                ServiceFamily(serviceAction!),
                "service",
                serviceAction,
                outcome ?? (serviceAction == "service_failure" ? "failure" : "success"),
                ActorUser: actor,
                ServiceName: service);
        }

        return null;
    }

    private static LinuxJournalClassification ClassifyL1(
        string transport,
        string? unit,
        string? identifier,
        string? facility,
        string? messageId)
    {
        if (transport == "kernel")
        {
            return new(LinuxTelemetrySourceIds.JournalL1, "system", "kernel", null, null);
        }
        if (IsAuthentication(identifier, facility, unit))
        {
            return new(LinuxTelemetrySourceIds.JournalL1, "system", "authentication", null, null);
        }
        if (!string.IsNullOrEmpty(messageId) && unit is "systemd" or "systemd-journald.service")
        {
            return new(LinuxTelemetrySourceIds.JournalL1, "boot", "boot", null, null);
        }
        if (!string.IsNullOrEmpty(unit))
        {
            return new(LinuxTelemetrySourceIds.JournalL1, "application_service", "service", null, null);
        }
        return new(LinuxTelemetrySourceIds.JournalL1, "system", "system", null, null);
    }

    private static bool TryClassifyTamper(
        string source,
        string unit,
        string? action,
        string? outcome,
        string message,
        out LinuxJournalClassification? classification)
    {
        classification = null;
        var journald = source is "systemd-journald" or "journalctl" || unit == "systemd-journald.service";
        var agent = source.Contains("challenger", StringComparison.Ordinal) || unit == "challenger-siem-agent.service";
        if (!journald && !agent)
        {
            return false;
        }

        string? tamperAction = action switch
        {
            "clear" or "log_clear" => "log_clear",
            "rotate" or "log_rotate" => "log_rotate",
            "vacuum" or "log_vacuum" => "log_vacuum",
            "corrupt" or "log_corruption" => "log_corruption",
            "disable" or "agent_disable" when agent => "agent_disable",
            "stop" or "service_stop" when agent => "agent_stop",
            "config_change" or "agent_config_change" when agent => "agent_config_change",
            _ => null
        };
        var messageEvidence = false;
        if (tamperAction is null)
        {
            tamperAction = TamperActionFromMessage(message, journald, agent);
            messageEvidence = tamperAction is not null;
        }
        if (tamperAction is null)
        {
            return false;
        }

        classification = new LinuxJournalClassification(
            LinuxTelemetrySourceIds.AgentLogTamper,
            agent ? "agent_tamper" : "log_tamper",
            "tamper",
            tamperAction,
            outcome,
            ServiceName: unit,
            SeverityOverride: tamperAction == "log_corruption" ? "error" : "warning",
            UsedMessageEvidence: messageEvidence);
        return true;
    }

    private static LinuxJournalClassification FillSshMessageEvidence(LinuxJournalClassification source, string message)
    {
        if (source.Action is "session_start" or "session_end")
        {
            return FillSessionMessageEvidence(source, message);
        }

        var match = SshAuthenticationPattern().Match(message);
        if (match.Success)
        {
            var parsedOutcome = match.Groups["result"].Value.Equals("Accepted", StringComparison.OrdinalIgnoreCase) ? "success" : "failure";
            var parsedTarget = BoundOrNull(match.Groups["user"].Value, 512);
            var parsedIp = ValidIp(match.Groups["ip"].Value);
            var parsedPort = ValidPort(match.Groups["port"].Value);
            var usedMessage = source.Action is null
                || source.Outcome is null
                || (source.TargetUser is null && parsedTarget is not null)
                || (source.SourceIp is null && parsedIp is not null)
                || (source.SourcePort is null && parsedPort is not null);
            return source with
            {
                EventFamily = "ssh_authentication",
                Category = "authentication",
                Action = source.Action ?? "authenticate",
                Outcome = source.Outcome ?? parsedOutcome,
                TargetUser = source.TargetUser ?? parsedTarget,
                SourceIp = source.SourceIp ?? parsedIp,
                SourcePort = source.SourcePort ?? parsedPort,
                UsedMessageEvidence = source.UsedMessageEvidence || usedMessage
            };
        }

        return source.Action is null ? FillSessionMessageEvidence(source, message) : source;
    }

    private static LinuxJournalClassification FillPrivilegeMessageEvidence(
        LinuxJournalClassification source,
        string message,
        string family)
    {
        if (family == "sudo")
        {
            var match = SudoPattern().Match(message);
            if (match.Success)
            {
                var parsedActor = BoundOrNull(match.Groups["actor"].Value, 512);
                var parsedTarget = BoundOrNull(match.Groups["target"].Value, 512);
                var parsedCommand = BoundOrNull(match.Groups["command"].Value, MaxCommandLineChars);
                var usedMessage = source.Action is null
                    || source.Outcome is null
                    || (source.ActorUser is null && parsedActor is not null)
                    || (source.TargetUser is null && parsedTarget is not null)
                    || (source.CommandLine is null && parsedCommand is not null);
                return source with
                {
                    Action = source.Action ?? "command_execute",
                    Outcome = source.Outcome ?? "success",
                    ActorUser = source.ActorUser ?? parsedActor,
                    TargetUser = source.TargetUser ?? parsedTarget,
                    CommandLine = source.CommandLine ?? parsedCommand,
                    UsedMessageEvidence = source.UsedMessageEvidence || usedMessage
                };
            }
        }
        return source.Action is null or "session_start" or "session_end"
            ? FillSessionMessageEvidence(source, message)
            : source;
    }

    private static LinuxJournalClassification FillSessionMessageEvidence(LinuxJournalClassification source, string message)
    {
        var match = SessionPattern().Match(message);
        if (!match.Success)
        {
            return source;
        }

        var opened = match.Groups["state"].Value.Equals("opened", StringComparison.OrdinalIgnoreCase);
        var parsedAction = opened ? "session_start" : "session_end";
        var parsedTarget = BoundOrNull(match.Groups["target"].Value, 512);
        var parsedActor = BoundOrNull(match.Groups["actor"].Value, 512);
        var sessionClassification = source.Action is null or "session_start" or "session_end";
        var usedMessage = source.Action is null
            || source.Outcome is null
            || (source.TargetUser is null && parsedTarget is not null)
            || (source.ActorUser is null && parsedActor is not null);
        return source with
        {
            EventFamily = sessionClassification && source.SourceId == LinuxTelemetrySourceIds.Ssh ? "ssh_session" : source.EventFamily,
            Category = sessionClassification ? "session" : source.Category,
            Action = source.Action ?? parsedAction,
            Outcome = source.Outcome ?? "success",
            TargetUser = source.TargetUser ?? parsedTarget,
            ActorUser = source.ActorUser ?? parsedActor,
            UsedMessageEvidence = source.UsedMessageEvidence || usedMessage
        };
    }

    private static LinuxJournalClassification FillSchedulerMessageEvidence(
        LinuxJournalClassification source,
        string message,
        bool timerUnit)
    {
        if (timerUnit)
        {
            var action = ServiceActionFromMessage(message);
            if (action is null)
            {
                return source;
            }
            var usedTimerMessage = source.Action is null || source.Outcome is null;
            return source with
            {
                Action = source.Action ?? "timer_trigger",
                Outcome = source.Outcome ?? "success",
                UsedMessageEvidence = source.UsedMessageEvidence || usedTimerMessage
            };
        }

        var match = CronPattern().Match(message);
        if (!match.Success)
        {
            return source;
        }
        var parsedAction = match.Groups["verb"].Value.Equals("CMD", StringComparison.Ordinal) ? "job_execute" : "configuration_reload";
        var parsedTarget = BoundOrNull(match.Groups["user"].Value, 512);
        var parsedCommand = BoundOrNull(match.Groups["command"].Value, MaxCommandLineChars);
        var usedMessage = source.Action is null
            || source.Outcome is null
            || (source.TargetUser is null && parsedTarget is not null)
            || (source.CommandLine is null && parsedCommand is not null);
        return source with
        {
            Action = source.Action ?? parsedAction,
            Outcome = source.Outcome ?? "success",
            TargetUser = source.TargetUser ?? parsedTarget,
            CommandLine = source.CommandLine ?? parsedCommand,
            UsedMessageEvidence = source.UsedMessageEvidence || usedMessage
        };
    }

    private static LinuxJournalClassification FillPackageMessageEvidence(LinuxJournalClassification source, string message)
    {
        var match = PackagePattern().Match(message);
        if (!match.Success)
        {
            return source;
        }
        var parsedAction = PackageAction(NormalizeAction(match.Groups["verb"].Value));
        var effectiveAction = source.Action ?? parsedAction;
        var parsedPackage = BoundOrNull(match.Groups["package"].Value, 512);
        var usedMessage = source.Action is null
            || source.Outcome is null
            || (source.PackageName is null && parsedPackage is not null);
        return source with
        {
            EventFamily = PackageFamily(effectiveAction),
            Action = effectiveAction,
            Outcome = source.Outcome ?? "success",
            PackageName = source.PackageName ?? parsedPackage,
            UsedMessageEvidence = source.UsedMessageEvidence || usedMessage
        };
    }

    private static LinuxJournalClassification FillFirewallMessageEvidence(LinuxJournalClassification source, string message)
    {
        var action = source.Action;
        if (message.StartsWith("[UFW ", StringComparison.OrdinalIgnoreCase))
        {
            var close = message.IndexOf(']');
            if (close > 5)
            {
                action ??= FirewallAction(message[5..close]);
            }
        }
        var values = ParseKeyValues(message);
        var sourceIp = source.SourceIp;
        var sourcePort = source.SourcePort;
        var destinationIp = source.DestinationIp;
        var destinationPort = source.DestinationPort;
        var protocol = source.Protocol;
        if (values.TryGetValue("SRC", out var parsedIp))
        {
            sourceIp ??= ValidIp(parsedIp);
        }
        if (values.TryGetValue("SPT", out var parsedPort))
        {
            sourcePort ??= ValidPort(parsedPort);
        }
        if (values.TryGetValue("DST", out var parsedDestinationIp))
        {
            destinationIp ??= ValidIp(parsedDestinationIp);
        }
        if (values.TryGetValue("DPT", out var parsedDestinationPort))
        {
            destinationPort ??= ValidPort(parsedDestinationPort);
        }
        if (values.TryGetValue("PROTO", out var parsedProtocol))
        {
            protocol ??= BoundOrNull(parsedProtocol.ToLowerInvariant(), 64);
        }
        return source with
        {
            EventFamily = FirewallFamily(action),
            Action = action,
            Outcome = source.Outcome ?? (action is "deny" or "drop" or "reject" ? "failure" : action is "allow" or "accept" ? "success" : null),
            SourceIp = sourceIp,
            SourcePort = sourcePort,
            DestinationIp = destinationIp,
            DestinationPort = destinationPort,
            Protocol = protocol,
            UsedMessageEvidence = action != source.Action
                || sourceIp != source.SourceIp
                || sourcePort != source.SourcePort
                || destinationIp != source.DestinationIp
                || destinationPort != source.DestinationPort
                || protocol != source.Protocol
        };
    }

    private static IReadOnlyDictionary<string, string> ParseKeyValues(string message)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var token in message.Split(' ', 64, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = token.IndexOf('=');
            if (separator is <= 0 or >= 16 || separator == token.Length - 1)
            {
                continue;
            }
            var key = token[..separator];
            if (key.All(character => character is >= 'A' and <= 'Z'))
            {
                values.TryAdd(key, token[(separator + 1)..]);
            }
        }
        return values;
    }

    private static string? NormalizeAction(string value) => value.Trim().ToLowerInvariant() switch
    {
        "start" or "started" => "start",
        "stop" or "stopped" => "stop",
        "reload" or "reloaded" => "reload",
        "fail" or "failed" => "failure",
        "allow" or "allowed" or "accept" or "accepted" => "allow",
        "deny" or "denied" or "block" or "blocked" or "drop" or "dropped" or "reject" or "rejected" => "deny",
        "change" or "changed" or "policy_change" => "policy_change",
        "install" or "installed" => "install",
        "upgrade" or "upgraded" or "update" or "updated" => "update",
        "remove" or "removed" or "erase" or "erased" or "uninstall" or "uninstalled" => "remove",
        "open_session" => "session_start",
        "close_session" => "session_end",
        "authenticate" or "authentication" => "authenticate",
        "execute" or "command" => "command_execute",
        "trigger" => "timer_trigger",
        "clear" or "log_clear" => "log_clear",
        "rotate" or "log_rotate" => "log_rotate",
        "vacuum" or "log_vacuum" => "log_vacuum",
        "corrupt" or "log_corruption" => "log_corruption",
        "disable" or "agent_disable" => "agent_disable",
        "config_change" or "agent_config_change" => "agent_config_change",
        "module_load" or "load_module" => "module_load",
        "module_unload" or "unload_module" => "module_unload",
        "security_denial" => "security_denial",
        "security_event" => "security_event",
        _ => null
    };

    private static string? NormalizeOutcome(string value) => value.Trim().ToLowerInvariant() switch
    {
        "success" or "succeeded" or "ok" or "accepted" or "allowed" => "success",
        "failure" or "failed" or "error" or "denied" or "rejected" or "blocked" => "failure",
        _ => null
    };

    private static string? PamAction(string value) => value switch
    {
        "open_session" => "session_start",
        "close_session" => "session_end",
        "auth" or "authenticate" or "authentication" => "authenticate",
        _ => null
    };

    private static string? PackageAction(string? value) => value switch
    {
        "install" => "install",
        "update" or "upgrade" => "update",
        "remove" or "erase" or "uninstall" => "remove",
        _ => null
    };

    private static string PackageFamily(string? action) => action switch
    {
        "install" => "package_install",
        "update" => "package_update",
        "remove" => "package_remove",
        _ => "package_update"
    };

    private static string? FirewallAction(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "allow" or "accept" => "allow",
        "deny" or "block" => "deny",
        "drop" => "drop",
        "reject" => "reject",
        "change" or "policy_change" => "policy_change",
        _ => null
    };

    private static string FirewallFamily(string? action) => action == "policy_change" ? "firewall_change"
        : action is "allow" or "accept" ? "firewall_allow" : "firewall_deny";

    private static string? ServiceAction(string? value) => value switch
    {
        "start" => "service_start",
        "stop" => "service_stop",
        "reload" => "service_reload",
        "failure" => "service_failure",
        _ => null
    };

    private static string ServiceFamily(string action) => action switch
    {
        "service_start" => "service_start",
        "service_stop" => "service_stop",
        "service_reload" => "service_reload",
        _ => "service_failure"
    };

    private static string? SystemdAction(string? messageId) => messageId?.ToLowerInvariant() switch
    {
        "39f53479d3a045ac8e11786248231fbf" => "service_start",
        "de5b426a63be47a7b6ac3eaac82e2f6f" => "service_stop",
        "be02cf6855d2428ba40df7e9d022f03d" => "service_failure",
        "7d4958e842da4a758f6c1cdc7b36dcc5" => "service_start",
        "d9b373ed55a64feb8242e02dbe79a49c" => "service_stop",
        _ => null
    };

    private static string? SessionActionFromMessageId(string? messageId) => messageId?.ToLowerInvariant() switch
    {
        "8d45620c1a4348dbb17410da57c60c66" => "session_start",
        "3354939424b4456d9802ca8333ed424a" => "session_end",
        _ => null
    };

    private static string? ServiceActionFromMessage(string message)
    {
        var match = ServicePattern().Match(message);
        return !match.Success ? null : match.Groups["verb"].Value.ToLowerInvariant() switch
        {
            "started" or "starting" => "service_start",
            "stopped" or "stopping" => "service_stop",
            "reloaded" => "service_reload",
            "failed" => "service_failure",
            _ => null
        };
    }

    private static string? TamperActionFromMessage(string message, bool journald, bool agent)
    {
        if (journald && message.Contains("corrupt", StringComparison.OrdinalIgnoreCase)) return "log_corruption";
        if (journald && message.Contains("vacuum", StringComparison.OrdinalIgnoreCase)) return "log_vacuum";
        if (journald && message.Contains("rotat", StringComparison.OrdinalIgnoreCase)) return "log_rotate";
        if (journald && message.Contains("cleared", StringComparison.OrdinalIgnoreCase)) return "log_clear";
        if (agent && message.StartsWith("Stopped ", StringComparison.OrdinalIgnoreCase)) return "agent_stop";
        if (agent && message.Contains("disabled", StringComparison.OrdinalIgnoreCase)) return "agent_disable";
        if (agent && message.Contains("configuration changed", StringComparison.OrdinalIgnoreCase)) return "agent_config_change";
        return null;
    }

    private static bool IsKernelSecurityMessage(string? action, string message, string? module) =>
        action is "module_load" or "module_unload" or "security_denial" or "security_event"
        || module is not null
        || message.Contains("apparmor", StringComparison.OrdinalIgnoreCase)
        || message.Contains("selinux", StringComparison.OrdinalIgnoreCase)
        || message.Contains("avc:", StringComparison.OrdinalIgnoreCase)
        || message.Contains("module verification", StringComparison.OrdinalIgnoreCase)
        || message.Contains("kernel module", StringComparison.OrdinalIgnoreCase);

    private static string KernelAction(string? action, string message, string? module)
    {
        if (action is "module_load" or "module_unload" or "security_denial" or "security_event") return action;
        if (message.Contains("denied", StringComparison.OrdinalIgnoreCase) || message.Contains("avc:", StringComparison.OrdinalIgnoreCase)) return "security_denial";
        if (message.Contains("unload", StringComparison.OrdinalIgnoreCase)) return "module_unload";
        if (module is not null || message.Contains("module", StringComparison.OrdinalIgnoreCase)) return "module_load";
        return "security_event";
    }

    private static string? KernelOutcome(string message) =>
        message.Contains("denied", StringComparison.OrdinalIgnoreCase) || message.Contains("failed", StringComparison.OrdinalIgnoreCase)
            ? "failure"
            : null;

    private static string EventSeverity(string priority, LinuxJournalClassification classification)
    {
        if (classification.SeverityOverride is not null)
        {
            return classification.SeverityOverride;
        }
        if (classification.Category is "authentication" or "authorization")
        {
            if (classification.Outcome == "success") return "audit_success";
            if (classification.Outcome == "failure") return "audit_failure";
        }
        return priority switch
        {
            "0" or "1" or "2" => "critical",
            "3" => "error",
            "4" => "warning",
            "7" => "verbose",
            _ => "information"
        };
    }

    private static bool IsAuthentication(string? identifier, string? facility, string? unit) =>
        facility is "4" or "10"
        || identifier is "sshd" or "sudo" or "su" or "login" or "pam_unix"
        || unit is "sshd.service" or "systemd-logind.service";

    private static string GetRaw(IReadOnlyDictionary<string, object?> raw, string key) =>
        raw.TryGetValue(key, out var value) ? value?.ToString() ?? string.Empty : string.Empty;

    private static string? FirstBounded(IReadOnlyDictionary<string, object?> raw, int maxChars, params string[] keys)
    {
        foreach (var key in keys)
        {
            var bounded = BoundOrNull(GetRaw(raw, key), maxChars);
            if (bounded is not null && bounded != "<binary-or-nontext>")
            {
                return bounded;
            }
        }
        return null;
    }

    private static string? BoundOrNull(string? value, int maxChars)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return Sanitize(value, maxChars, out _, out _);
    }

    private static bool Any(params string?[] values) => values.Any(value => !string.IsNullOrWhiteSpace(value));

    private static string? ValidIp(string? value) => value is not null && IPAddress.TryParse(value, out _)
        ? BoundOrNull(value, 128)
        : null;

    private static int? ValidPort(string? value) => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
        && port is >= 0 and <= 65535 ? port : null;

    private static bool TryMicroseconds(JsonElement root, out long value)
    {
        value = 0;
        return TryText(root, "__REALTIME_TIMESTAMP", out var text)
               && long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value)
               && value >= 0;
    }

    private static bool TryEventTime(long microseconds, out DateTimeOffset eventTime)
    {
        eventTime = default;
        var milliseconds = microseconds / 1000;
        if (milliseconds < DateTimeOffset.MinValue.ToUnixTimeMilliseconds()
            || milliseconds > DateTimeOffset.MaxValue.ToUnixTimeMilliseconds())
        {
            return false;
        }

        try
        {
            eventTime = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TryText(JsonElement root, string name, out string? text)
    {
        text = null;
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        text = value.GetString();
        return true;
    }

    private static bool TryRedactSecrets(string value, out string redacted)
    {
        try
        {
            redacted = SecretPattern().Replace(value, "$1=<redacted>");
            return true;
        }
        catch (RegexMatchTimeoutException)
        {
            redacted = string.Empty;
            return false;
        }
    }

    private static string Sanitize(string value, int maxChars, out bool truncated, out bool invalidText)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maxChars));
        invalidText = false;
        foreach (var rune in value.EnumerateRunes())
        {
            if (builder.Length + rune.Utf16SequenceLength > maxChars) break;
            if (Rune.IsControl(rune) && rune.Value is not 9 and not 10 and not 13)
            {
                builder.Append('\uFFFD');
                invalidText = true;
            }
            else
            {
                builder.Append(rune.ToString());
            }
        }
        truncated = builder.Length < value.Length;
        return builder.ToString();
    }

    [GeneratedRegex("^(?<result>Accepted|Failed|Invalid)(?: [A-Za-z0-9_-]+)?(?: for (?:invalid user )?(?<user>[A-Za-z0-9._@-]{1,512}))? from (?<ip>[0-9A-Fa-f:.]{2,128})(?: port (?<port>[0-9]{1,5}))?", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 50)]
    private static partial Regex SshAuthenticationPattern();

    [GeneratedRegex("^\\s*(?<actor>[A-Za-z0-9._@-]{1,512})\\s*:\\s*.*?\\bUSER=(?<target>[A-Za-z0-9._@-]{1,512})\\s*;\\s*COMMAND=(?<command>.{1,4096})$", RegexOptions.CultureInvariant, 50)]
    private static partial Regex SudoPattern();

    [GeneratedRegex("session (?<state>opened|closed) for user (?<target>[A-Za-z0-9._@-]{1,512})(?: by (?<actor>[A-Za-z0-9._@-]{1,512}))?", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 50)]
    private static partial Regex SessionPattern();

    [GeneratedRegex("^\\((?<user>[A-Za-z0-9._@-]{1,512})\\)\\s+(?<verb>CMD|RELOAD)(?:\\s+\\((?<command>.{1,4096})\\))?$", RegexOptions.CultureInvariant, 50)]
    private static partial Regex CronPattern();

    [GeneratedRegex("^(?<verb>install|installed|upgrade|upgraded|update|updated|remove|removed|erase|erased|uninstall|uninstalled)\\s+(?<package>[A-Za-z0-9.+:_-]{1,512})(?:\\s|$)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 50)]
    private static partial Regex PackagePattern();

    [GeneratedRegex("^(?<verb>Started|Starting|Stopped|Stopping|Reloaded|Failed)(?: to start)?\\s+", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 50)]
    private static partial Regex ServicePattern();

    [GeneratedRegex("(?i)\\b(password|passwd|token|authorization|cookie|connection_string)\\s*[:=]\\s*[^\\s;,]+", RegexOptions.CultureInvariant, 100)]
    private static partial Regex SecretPattern();

    private sealed record LinuxJournalClassification(
        string SourceId,
        string EventFamily,
        string Category,
        string? Action,
        string? Outcome,
        string? ActorUser = null,
        string? TargetUser = null,
        string? SourceIp = null,
        int? SourcePort = null,
        string? DestinationIp = null,
        int? DestinationPort = null,
        string? Protocol = null,
        string? ServiceName = null,
        string? PackageName = null,
        string? CommandLine = null,
        string? ModuleName = null,
        string? TaskName = null,
        string? SeverityOverride = null,
        bool UsedMessageEvidence = false);
}
