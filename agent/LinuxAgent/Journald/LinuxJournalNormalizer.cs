using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Challenger.Siem.Contracts.V1;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Journal;

public sealed partial class LinuxJournalNormalizer
{
    public const string SourceId = "linux-journal-l1";
    private const int MaxFieldChars = 2048;
    private const int MaxMessageChars = 20000;
    private const int MaxRawFields = 16;
    private static readonly string[] RawFieldNames =
    [
        "_BOOT_ID", "_TRANSPORT", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "SYSLOG_FACILITY",
        "PRIORITY", "MESSAGE_ID", "_PID", "_UID", "MESSAGE"
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
        try { document = JsonDocument.Parse(record, new JsonDocumentOptions { MaxDepth = 8 }); }
        catch (JsonException) { return false; }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var root = document.RootElement;
            if (!TryText(root, "__CURSOR", out var cursor, out _) || string.IsNullOrWhiteSpace(cursor)
                || !TryText(root, "_BOOT_ID", out var bootId, out _)
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
            var binaryOrInvalidText = false;
            var truncated = new SortedSet<string>(StringComparer.Ordinal);
            var originalBytes = Encoding.UTF8.GetByteCount(record);
            foreach (var field in RawFieldNames.Take(MaxRawFields))
            {
                if (!root.TryGetProperty(field, out var value)) continue;
                if (value.ValueKind != JsonValueKind.String)
                {
                    raw[field] = "<binary-or-nontext>";
                    binaryOrInvalidText = true;
                    redacted.Add($"raw.{field}");
                    continue;
                }
                var text = Sanitize(value.GetString() ?? string.Empty, MaxFieldChars, out var wasTruncated, out var invalidText);
                if (field == "MESSAGE")
                {
                    text = Sanitize(value.GetString() ?? string.Empty, MaxMessageChars, out wasTruncated, out invalidText);
                    var replaced = SecretPattern().Replace(text, "$1=<redacted>");
                    if (!string.Equals(replaced, text, StringComparison.Ordinal))
                    {
                        text = replaced;
                        redacted.Add("raw.MESSAGE");
                    }
                }
                if (wasTruncated) truncated.Add($"raw.{field}");
                if (invalidText) { binaryOrInvalidText = true; redacted.Add($"raw.{field}"); }
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

            var message = raw.TryGetValue("MESSAGE", out var rawMessage) ? rawMessage?.ToString() ?? string.Empty : string.Empty;
            bootId = GetRaw(raw, "_BOOT_ID");
            var transport = GetRaw(raw, "_TRANSPORT");
            var unit = BoundOrNull(GetRaw(raw, "_SYSTEMD_UNIT"), 255);
            var identifier = BoundOrNull(GetRaw(raw, "SYSLOG_IDENTIFIER"), 255);
            var facility = BoundOrNull(GetRaw(raw, "SYSLOG_FACILITY"), 128);
            var messageId = BoundOrNull(GetRaw(raw, "MESSAGE_ID"), 128);
            var category = Classify(transport, unit, identifier, facility, messageId);
            var eventCode = messageId ?? $"journal_{category}";
            var envelopeWithoutId = new EventEnvelope
            {
                AgentId = options.AgentId,
                Hostname = Sanitize(Environment.MachineName, 255, out _, out _),
                Platform = TelemetryPlatforms.Linux,
                Source = EventSources.LinuxJournal,
                SourceId = SourceId,
                Facility = facility,
                Unit = unit,
                EventCode = Sanitize(eventCode, 128, out _, out _),
                EventTime = eventTime,
                Severity = Severity(GetRaw(raw, "PRIORITY")),
                Message = message,
                Normalized = new NormalizedEventFields
                {
                    Category = category,
                    ServiceName = BoundOrNull(unit ?? identifier ?? string.Empty, 512),
                    ProcessId = BoundOrNull(GetRaw(raw, "_PID"), 64),
                    UserSid = BoundOrNull(GetRaw(raw, "_UID"), 512),
                    Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["journal.boot_id"] = bootId!,
                        ["journal.transport"] = transport
                    }
                },
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
                cursor!, bootId!, microseconds, binaryOrInvalidText);
            errorCode = string.Empty;
            return true;
        }
    }

    private static string Classify(string transport, string? unit, string? identifier, string? facility, string? messageId)
    {
        if (transport == "kernel") return "kernel";
        if (IsAuthentication(identifier, facility, unit)) return "authentication";
        if (!string.IsNullOrEmpty(messageId) && unit is "systemd" or "systemd-journald.service") return "boot";
        if (!string.IsNullOrEmpty(unit)) return "service";
        return "system";
    }

    private static bool IsAuthentication(string? identifier, string? facility, string? unit) =>
        facility is "4" or "10"
        || identifier is "sshd" or "sudo" or "su" or "login" or "pam_unix"
        || unit is "sshd.service" or "systemd-logind.service";

    private static string Severity(string priority) => priority switch
    {
        "0" or "1" or "2" => "critical",
        "3" => "error",
        "4" => "warning",
        "7" => "verbose",
        _ => "information"
    };

    private static string GetRaw(IReadOnlyDictionary<string, object?> raw, string key) =>
        raw.TryGetValue(key, out var value) ? value?.ToString() ?? string.Empty : string.Empty;
    private static string? BoundOrNull(string value, int maxChars)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return Sanitize(value, maxChars, out _, out _);
    }

    private static bool TryMicroseconds(JsonElement root, out long value)
    {
        value = 0;
        return TryText(root, "__REALTIME_TIMESTAMP", out var text, out _) &&
               long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= 0;
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

    private static bool TryText(JsonElement root, string name, out string? text, out bool binary)
    {
        text = null; binary = false;
        if (!root.TryGetProperty(name, out var value)) return false;
        if (value.ValueKind != JsonValueKind.String) { binary = true; return false; }
        text = value.GetString();
        return true;
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
            else builder.Append(rune.ToString());
        }
        truncated = builder.Length < value.Length;
        return builder.ToString();
    }

    [GeneratedRegex("(?i)\\b(password|passwd|token|authorization|cookie|connection_string)\\s*[:=]\\s*[^\\s;,]+", RegexOptions.CultureInvariant, 100)]
    private static partial Regex SecretPattern();
}
