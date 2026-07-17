using System.Diagnostics;
using System.Globalization;

namespace Challenger.Siem.LinuxAgent.L4;

public interface ILinuxAgentSloSource
{
    Task<LinuxAgentSloObservation> ObserveAsync(CancellationToken cancellationToken);
}

public sealed class LinuxAgentSloSource(TimeProvider timeProvider) : ILinuxAgentSloSource
{
    private const int MaximumIoBytes = 4096;

    public async Task<LinuxAgentSloObservation> ObserveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var process = Process.GetCurrentProcess();
        return new(
            timeProvider.GetUtcNow(),
            process.TotalProcessorTime,
            Math.Max(1, Environment.ProcessorCount),
            process.WorkingSet64 >= 0 ? process.WorkingSet64 : null,
            GC.GetTotalMemory(forceFullCollection: false),
            await ReadWriteBytesAsync(cancellationToken),
            process.StartTime.ToUniversalTime().Ticks);
    }

    private static async Task<long?> ReadWriteBytesAsync(CancellationToken cancellationToken)
    {
        const string path = "/proc/self/io";
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var buffer = new byte[MaximumIoBytes + 1];
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read > MaximumIoBytes) return null;
            var text = System.Text.Encoding.ASCII.GetString(buffer, 0, read);
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!line.StartsWith("write_bytes:", StringComparison.Ordinal)) continue;
                return long.TryParse(line.AsSpan("write_bytes:".Length).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                    && value >= 0 ? value : null;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException) { }
        return null;
    }
}
