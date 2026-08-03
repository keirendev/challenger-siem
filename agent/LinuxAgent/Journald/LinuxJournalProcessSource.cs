using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.Journal;

internal static class LinuxJournalScopes
{
    public const string SystemOnly = "system_only";
    public const string AllAccessibleLocal = "all_accessible_local";

    public static string Configured(JournalOptions options) =>
        options.IncludeAccessibleUserJournals ? AllAccessibleLocal : SystemOnly;
}

/// <summary>Reads one fixed local-journal scope through systemd's machine-readable interface.</summary>
public sealed class LinuxJournalProcessSource(
    IOptions<LinuxAgentOptions> configured,
    TimeProvider timeProvider) : ILinuxJournalSource
{
    private const int MaxDiagnosticBytes = 4096;
    private static readonly TimeSpan SystemVisibilityProbeInterval = TimeSpan.FromMinutes(1);
    private static readonly string[] ApprovedPaths = ["/usr/bin/journalctl", "/bin/journalctl"];
    private readonly bool includeAccessibleUserJournals = configured.Value.Journal.IncludeAccessibleUserJournals;
    private readonly object probeSync = new();
    private SystemJournalVisibility cachedSystemVisibility = SystemJournalVisibility.Unknown;
    private DateTimeOffset nextSystemVisibilityProbeAt = DateTimeOffset.MinValue;

    public async Task<JournalReadResult> ReadAsync(string? afterCursor, int maxRecords, int maxRecordBytes, CancellationToken cancellationToken)
    {
        var executable = ApprovedPaths.FirstOrDefault(File.Exists);
        if (executable is null)
            return new(JournalReadStatus.Unavailable, Array.Empty<string>(), ErrorCode: "journalctl_unavailable",
                SystemJournalVisibility: SystemJournalVisibility.Unavailable);

        var boundedRecords = Math.Clamp(maxRecords, 1, 5000);
        var boundedRecordBytes = Math.Clamp(maxRecordBytes, 4096, 262144);
        var systemVisibility = includeAccessibleUserJournals
            ? await GetSystemJournalVisibilityAsync(executable, cancellationToken)
            : SystemJournalVisibility.Unknown;
        var start = BuildReadStartInfo(executable, includeAccessibleUserJournals, afterCursor, boundedRecords);

        using var process = new Process { StartInfo = start };
        try
        {
            process.Start();
            var outputTask = ReadBoundedRecordsAsync(process.StandardOutput.BaseStream, boundedRecords, boundedRecordBytes, cancellationToken);
            var errorTask = ReadDiagnosticAsync(process.StandardError, MaxDiagnosticBytes, cancellationToken);
            var (records, limitReached) = await outputTask;
            if (limitReached) TryKill(process);
            await process.WaitForExitAsync(cancellationToken);
            var diagnostic = await errorTask;
            if (process.ExitCode == 0 || limitReached)
                return new(JournalReadStatus.Success, records,
                    SystemJournalVisibility: includeAccessibleUserJournals
                        ? systemVisibility
                        : SystemJournalVisibility.Verified);

            var normalized = diagnostic.ToLowerInvariant();
            if (normalized.Contains("cursor", StringComparison.Ordinal) || normalized.Contains("seek", StringComparison.Ordinal))
                return new(JournalReadStatus.InvalidCursor, records, JournalGapKind.InvalidCursor, "journal_cursor_invalid",
                    includeAccessibleUserJournals ? systemVisibility : SystemJournalVisibility.Verified);
            if (DiagnosticIndicatesDefinitePermissionDenial(normalized))
                return new(JournalReadStatus.PermissionDenied, records, ErrorCode: "journal_permission_denied",
                    SystemJournalVisibility: includeAccessibleUserJournals
                        ? systemVisibility
                        : SystemJournalVisibility.PermissionDenied);
            return new(JournalReadStatus.Error, records, ErrorCode: "journal_read_failed",
                SystemJournalVisibility: includeAccessibleUserJournals
                    ? systemVisibility
                    : SystemJournalVisibility.Error);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException)
        {
            TryKill(process);
            return new(JournalReadStatus.Unavailable, Array.Empty<string>(), ErrorCode: "journal_reader_unavailable",
                SystemJournalVisibility: includeAccessibleUserJournals
                    ? systemVisibility
                    : SystemJournalVisibility.Unavailable);
        }
    }

    internal static ProcessStartInfo BuildReadStartInfo(
        string executable,
        bool includeAccessibleUserJournals,
        string? afterCursor,
        int boundedRecords)
    {
        var start = CreateStartInfo(executable);
        if (!includeAccessibleUserJournals) start.ArgumentList.Add("--system");
        start.ArgumentList.Add("--no-pager");
        start.ArgumentList.Add("--quiet");
        start.ArgumentList.Add("--output=json");
        start.ArgumentList.Add("--all");
        start.ArgumentList.Add("--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_TRANSPORT,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,SYSLOG_IDENTIFIER,SYSLOG_FACILITY,PRIORITY,MESSAGE,MESSAGE_ID,_PID,_UID,_COMM,_EXE,_CMDLINE,USER,LOGNAME,PAM_USER,PAM_TYPE,PAM_RHOST,PAM_SERVICE,REMOTE_ADDR,REMOTE_PORT,DESTINATION_ADDR,DESTINATION_PORT,PROTOCOL,RESULT,ACTION,UNIT,OBJECT_SYSTEMD_UNIT,PACKAGE_NAME,PACKAGE,MODULE,_AUDIT_ID,_AUDIT_TYPE_NAME");
        if (string.IsNullOrEmpty(afterCursor))
            start.ArgumentList.Add($"--lines={boundedRecords}");
        else
            start.ArgumentList.Add($"--after-cursor={afterCursor}");
        return start;
    }

    internal static ProcessStartInfo BuildSystemVisibilityProbeStartInfo(string executable)
    {
        var start = CreateStartInfo(executable);
        start.ArgumentList.Add("--system");
        start.ArgumentList.Add("--no-pager");
        start.ArgumentList.Add("--output=json");
        start.ArgumentList.Add("--output-fields=__CURSOR");
        start.ArgumentList.Add("--lines=1");
        return start;
    }

    private static ProcessStartInfo CreateStartInfo(string executable)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.Environment.Clear();
        start.Environment["LANG"] = "C.UTF-8";
        start.Environment["LC_ALL"] = "C.UTF-8";
        return start;
    }

    private async Task<SystemJournalVisibility> GetSystemJournalVisibilityAsync(
        string executable,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        lock (probeSync)
        {
            if (now < nextSystemVisibilityProbeAt) return cachedSystemVisibility;
        }

        var observed = await ProbeSystemJournalVisibilityAsync(executable, cancellationToken);
        lock (probeSync)
        {
            cachedSystemVisibility = observed;
            nextSystemVisibilityProbeAt = now + SystemVisibilityProbeInterval;
            return cachedSystemVisibility;
        }
    }

    private static async Task<SystemJournalVisibility> ProbeSystemJournalVisibilityAsync(
        string executable,
        CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = BuildSystemVisibilityProbeStartInfo(executable) };
        try
        {
            process.Start();
            var outputTask = ReadDiagnosticAsync(process.StandardOutput, MaxDiagnosticBytes, cancellationToken);
            var errorTask = ReadDiagnosticAsync(process.StandardError, MaxDiagnosticBytes, cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            var output = await outputTask;
            var diagnostic = await errorTask;
            return ClassifySystemVisibilityProbe(process.ExitCode, output, diagnostic);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException)
        {
            TryKill(process);
            return SystemJournalVisibility.Unavailable;
        }
    }

    internal static SystemJournalVisibility ClassifySystemVisibilityProbe(
        int exitCode,
        string output,
        string diagnostic)
    {
        var normalized = diagnostic.ToLowerInvariant();
        if (DiagnosticIndicatesDefinitePermissionDenial(normalized)
            || normalized.Contains("not seeing messages from other users", StringComparison.Ordinal))
        {
            return SystemJournalVisibility.PermissionDenied;
        }
        if (exitCode != 0)
        {
            return normalized.Contains("no journal files were found", StringComparison.Ordinal)
                ? SystemJournalVisibility.Unavailable
                : SystemJournalVisibility.Error;
        }

        try
        {
            using var document = JsonDocument.Parse(output);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("__CURSOR", out var cursor)
                && cursor.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(cursor.GetString())
                    ? SystemJournalVisibility.Verified
                    : SystemJournalVisibility.Unknown;
        }
        catch (JsonException)
        {
            return SystemJournalVisibility.Unknown;
        }
    }

    internal static bool DiagnosticIndicatesDefinitePermissionDenial(string diagnostic)
    {
        var normalized = diagnostic.ToLowerInvariant();
        return normalized.Contains("permission denied", StringComparison.Ordinal)
            || normalized.Contains("insufficient permission", StringComparison.Ordinal)
            || normalized.Contains("no journal files were opened due to", StringComparison.Ordinal);
    }

    internal static async Task<(IReadOnlyList<JournalInputRecord> Records, bool LimitReached)> ReadBoundedRecordsAsync(
        Stream stream,
        int maxRecords,
        int maxRecordBytes,
        CancellationToken cancellationToken)
    {
        var records = new List<JournalInputRecord>(maxRecords);
        var readBuffer = new byte[8192];
        var recordBuffer = new MemoryStream(Math.Min(maxRecordBytes, 8192));
        var metadata = new JournalMetadataExtractor();
        var oversized = false;
        long recordBytes = 0;
        while (records.Count < maxRecords)
        {
            var read = await stream.ReadAsync(readBuffer, cancellationToken);
            if (read == 0) break;
            for (var index = 0; index < read; index++)
            {
                var value = readBuffer[index];
                if (value == (byte)'\n')
                {
                    records.Add(CompleteRecord());
                    recordBuffer.SetLength(0);
                    metadata = new JournalMetadataExtractor();
                    oversized = false;
                    recordBytes = 0;
                    if (records.Count == maxRecords) return (records, true);
                }
                else
                {
                    if (recordBytes < long.MaxValue) recordBytes++;
                    metadata.Observe(value);
                    if (!oversized)
                    {
                        if (recordBuffer.Length >= maxRecordBytes) oversized = true;
                        else recordBuffer.WriteByte(value);
                    }
                }
            }
        }
        if (recordBytes > 0 && records.Count < maxRecords)
            records.Add(CompleteRecord());
        return (records, false);

        JournalInputRecord CompleteRecord()
        {
            if (!oversized)
            {
                return JournalInputRecord.FromRaw(
                    Encoding.UTF8.GetString(recordBuffer.GetBuffer(), 0, (int)recordBuffer.Length));
            }

            var completed = metadata.TryCreateOversizedRecord(recordBytes, out var omitted) && omitted is not null
                ? JournalInputRecord.OmitOversized(omitted)
                : JournalInputRecord.UnrecoverableOversized(recordBytes);
            recordBuffer.GetBuffer().AsSpan(0, (int)recordBuffer.Length).Clear();
            return completed;
        }
    }

    private sealed class JournalMetadataExtractor
    {
        private const int MaxKeyBytes = 64;
        private const int MaxCursorBytes = 4096;
        private const int MaxBootIdBytes = 512;
        private const int MaxTimestampBytes = 64;
        private readonly List<byte> token = new(MaxKeyBytes);
        private ParseState state = ParseState.Start;
        private string? pendingKey;
        private string? cursor;
        private string? bootId;
        private string? realtimeTimestamp;
        private bool inString;
        private bool stringEscape;
        private bool readingKey;
        private bool captureString;
        private bool tokenOverflow;
        private int tokenLimit;
        private int compositeDepth;
        private bool compositeInString;
        private bool compositeEscape;

        public void Observe(byte value)
        {
            if (state == ParseState.Invalid) return;
            if (inString)
            {
                ObserveString(value);
                return;
            }
            if (state == ParseState.Composite)
            {
                ObserveComposite(value);
                return;
            }

            switch (state)
            {
                case ParseState.Start:
                    if (IsWhitespace(value)) return;
                    state = value == (byte)'{' ? ParseState.KeyOrEnd : ParseState.Invalid;
                    return;
                case ParseState.KeyOrEnd:
                    if (IsWhitespace(value)) return;
                    if (value == (byte)'}')
                    {
                        state = ParseState.Done;
                        return;
                    }
                    if (value == (byte)'"')
                    {
                        BeginString(isKey: true);
                        return;
                    }
                    state = ParseState.Invalid;
                    return;
                case ParseState.Colon:
                    if (IsWhitespace(value)) return;
                    state = value == (byte)':' ? ParseState.Value : ParseState.Invalid;
                    return;
                case ParseState.Value:
                    if (IsWhitespace(value)) return;
                    if (value == (byte)'"')
                    {
                        BeginString(isKey: false);
                        return;
                    }
                    if (value is (byte)'{' or (byte)'[')
                    {
                        compositeDepth = 1;
                        compositeInString = false;
                        compositeEscape = false;
                        state = ParseState.Composite;
                        return;
                    }
                    BeginBareValue(value);
                    return;
                case ParseState.BareValue:
                    ObserveBareValue(value);
                    return;
                case ParseState.AfterValue:
                    if (IsWhitespace(value)) return;
                    if (value == (byte)',')
                    {
                        pendingKey = null;
                        state = ParseState.KeyOrEnd;
                        return;
                    }
                    if (value == (byte)'}')
                    {
                        pendingKey = null;
                        state = ParseState.Done;
                        return;
                    }
                    state = ParseState.Invalid;
                    return;
                case ParseState.Done:
                    if (!IsWhitespace(value)) state = ParseState.Invalid;
                    return;
            }
        }

        public bool TryCreateOversizedRecord(long recordBytes, out OversizedJournalRecord? record)
        {
            record = null;
            return state == ParseState.Done
                && long.TryParse(realtimeTimestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var microseconds)
                && OversizedJournalRecord.TryCreate(cursor, bootId, microseconds, recordBytes, out record);
        }

        private void BeginString(bool isKey)
        {
            inString = true;
            stringEscape = false;
            readingKey = isKey;
            captureString = isKey || IsMetadataKey(pendingKey);
            tokenOverflow = false;
            token.Clear();
            tokenLimit = isKey ? MaxKeyBytes : pendingKey switch
            {
                "__CURSOR" => MaxCursorBytes,
                "_BOOT_ID" => MaxBootIdBytes,
                "__REALTIME_TIMESTAMP" => MaxTimestampBytes,
                _ => 0
            };
        }

        private void ObserveString(byte value)
        {
            if (stringEscape)
            {
                AppendToken(value);
                stringEscape = false;
                return;
            }
            if (value == (byte)'\\')
            {
                AppendToken(value);
                stringEscape = true;
                return;
            }
            if (value != (byte)'"')
            {
                AppendToken(value);
                return;
            }

            inString = false;
            var decoded = captureString && !tokenOverflow ? DecodeJsonString(token) : null;
            if (readingKey)
            {
                pendingKey = decoded;
                state = decoded is null ? ParseState.Invalid : ParseState.Colon;
                return;
            }

            StoreMetadata(decoded);
            pendingKey = null;
            state = ParseState.AfterValue;
        }

        private void BeginBareValue(byte value)
        {
            token.Clear();
            tokenOverflow = false;
            tokenLimit = MaxTimestampBytes;
            captureString = string.Equals(pendingKey, "__REALTIME_TIMESTAMP", StringComparison.Ordinal);
            state = ParseState.BareValue;
            ObserveBareValue(value);
        }

        private void ObserveBareValue(byte value)
        {
            if (value is (byte)',' or (byte)'}')
            {
                var decoded = captureString && !tokenOverflow
                    ? Encoding.ASCII.GetString(token.ToArray()).Trim()
                    : null;
                StoreMetadata(decoded);
                pendingKey = null;
                state = value == (byte)',' ? ParseState.KeyOrEnd : ParseState.Done;
                return;
            }
            AppendToken(value);
        }

        private void ObserveComposite(byte value)
        {
            if (compositeInString)
            {
                if (compositeEscape)
                {
                    compositeEscape = false;
                    return;
                }
                if (value == (byte)'\\')
                {
                    compositeEscape = true;
                    return;
                }
                if (value == (byte)'"') compositeInString = false;
                return;
            }

            if (value == (byte)'"')
            {
                compositeInString = true;
                return;
            }
            if (value is (byte)'{' or (byte)'[') compositeDepth++;
            else if (value is (byte)'}' or (byte)']') compositeDepth--;
            if (compositeDepth != 0) return;
            pendingKey = null;
            state = ParseState.AfterValue;
        }

        private void AppendToken(byte value)
        {
            if (!captureString || tokenOverflow) return;
            if (token.Count >= tokenLimit)
            {
                tokenOverflow = true;
                token.Clear();
                return;
            }
            token.Add(value);
        }

        private void StoreMetadata(string? value)
        {
            if (value is null) return;
            switch (pendingKey)
            {
                case "__CURSOR": cursor = value; break;
                case "_BOOT_ID": bootId = value; break;
                case "__REALTIME_TIMESTAMP": realtimeTimestamp = value; break;
            }
        }

        private static string? DecodeJsonString(List<byte> raw)
        {
            var encoded = new byte[raw.Count + 2];
            encoded[0] = (byte)'"';
            raw.CopyTo(encoded, 1);
            encoded[^1] = (byte)'"';
            try { return JsonSerializer.Deserialize<string>(encoded); }
            catch (JsonException) { return null; }
        }

        private static bool IsMetadataKey(string? key) => key is "__CURSOR" or "_BOOT_ID" or "__REALTIME_TIMESTAMP";
        private static bool IsWhitespace(byte value) => value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';

        private enum ParseState
        {
            Start,
            KeyOrEnd,
            Colon,
            Value,
            BareValue,
            Composite,
            AfterValue,
            Done,
            Invalid
        }
    }

    private static async Task<string> ReadDiagnosticAsync(StreamReader reader, int maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new char[1024];
        var result = new StringBuilder(maxBytes);
        while (await reader.ReadAsync(buffer, cancellationToken) is var read && read > 0)
        {
            if (result.Length < maxBytes)
                result.Append(buffer, 0, Math.Min(read, maxBytes - result.Length));
        }
        return result.ToString();
    }

    private static void TryKill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
    }
}
