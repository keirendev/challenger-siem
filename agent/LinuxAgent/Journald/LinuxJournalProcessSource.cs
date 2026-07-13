using System.Diagnostics;
using System.Text;

namespace Challenger.Siem.LinuxAgent.Journal;

/// <summary>Reads the system journal through systemd's fixed machine-readable interface.</summary>
public sealed class LinuxJournalProcessSource : ILinuxJournalSource
{
    private const int MaxDiagnosticBytes = 4096;
    private static readonly string[] ApprovedPaths = ["/usr/bin/journalctl", "/bin/journalctl"];

    public async Task<JournalReadResult> ReadAsync(string? afterCursor, int maxRecords, int maxRecordBytes, CancellationToken cancellationToken)
    {
        var executable = ApprovedPaths.FirstOrDefault(File.Exists);
        if (executable is null)
            return new(JournalReadStatus.Unavailable, Array.Empty<string>(), ErrorCode: "journalctl_unavailable");

        var boundedRecords = Math.Clamp(maxRecords, 1, 5000);
        var boundedRecordBytes = Math.Clamp(maxRecordBytes, 4096, 262144);
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
        start.ArgumentList.Add("--system");
        start.ArgumentList.Add("--no-pager");
        start.ArgumentList.Add("--quiet");
        start.ArgumentList.Add("--output=json");
        start.ArgumentList.Add("--all");
        start.ArgumentList.Add("--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_TRANSPORT,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,SYSLOG_FACILITY,PRIORITY,MESSAGE,MESSAGE_ID,_PID,_UID");
        if (string.IsNullOrEmpty(afterCursor))
            start.ArgumentList.Add($"--lines={boundedRecords}");
        else
            start.ArgumentList.Add($"--after-cursor={afterCursor}");

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
                return new(JournalReadStatus.Success, records);

            var normalized = diagnostic.ToLowerInvariant();
            if (normalized.Contains("permission denied", StringComparison.Ordinal))
                return new(JournalReadStatus.PermissionDenied, records, ErrorCode: "journal_permission_denied");
            if (normalized.Contains("cursor", StringComparison.Ordinal) || normalized.Contains("seek", StringComparison.Ordinal))
                return new(JournalReadStatus.InvalidCursor, records, JournalGapKind.InvalidCursor, "journal_cursor_invalid");
            return new(JournalReadStatus.Error, records, ErrorCode: "journal_read_failed");
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException)
        {
            TryKill(process);
            return new(JournalReadStatus.Unavailable, Array.Empty<string>(), ErrorCode: "journal_reader_unavailable");
        }
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
