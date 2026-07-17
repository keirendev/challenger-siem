using System.Diagnostics;
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
        start.ArgumentList.Add("--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_TRANSPORT,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,SYSLOG_IDENTIFIER,SYSLOG_FACILITY,PRIORITY,MESSAGE,MESSAGE_ID,_PID,_UID,_COMM,_EXE,_CMDLINE,USER,LOGNAME,PAM_USER,PAM_TYPE,PAM_RHOST,PAM_SERVICE,REMOTE_ADDR,REMOTE_PORT,DESTINATION_ADDR,DESTINATION_PORT,PROTOCOL,RESULT,ACTION,UNIT,OBJECT_SYSTEMD_UNIT,PACKAGE_NAME,PACKAGE,MODULE");
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

    private static async Task<(IReadOnlyList<string> Records, bool LimitReached)> ReadBoundedRecordsAsync(
        Stream stream,
        int maxRecords,
        int maxRecordBytes,
        CancellationToken cancellationToken)
    {
        var records = new List<string>(maxRecords);
        var readBuffer = new byte[8192];
        var recordBuffer = new MemoryStream(Math.Min(maxRecordBytes, 8192));
        var oversized = false;
        while (records.Count < maxRecords)
        {
            var read = await stream.ReadAsync(readBuffer, cancellationToken);
            if (read == 0) break;
            for (var index = 0; index < read; index++)
            {
                var value = readBuffer[index];
                if (value == (byte)'\n')
                {
                    records.Add(oversized ? "{}" : Encoding.UTF8.GetString(recordBuffer.GetBuffer(), 0, (int)recordBuffer.Length));
                    recordBuffer.SetLength(0);
                    oversized = false;
                    if (records.Count == maxRecords) return (records, true);
                }
                else if (!oversized)
                {
                    if (recordBuffer.Length >= maxRecordBytes) oversized = true;
                    else recordBuffer.WriteByte(value);
                }
            }
        }
        if ((recordBuffer.Length > 0 || oversized) && records.Count < maxRecords)
            records.Add(oversized ? "{}" : Encoding.UTF8.GetString(recordBuffer.GetBuffer(), 0, (int)recordBuffer.Length));
        return (records, false);
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
