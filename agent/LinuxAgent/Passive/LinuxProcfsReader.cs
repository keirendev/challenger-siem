using System.Text;

namespace Challenger.Siem.LinuxAgent.Passive;

internal sealed class ProcfsReadBudget(int maximumBytes)
{
    private int remaining = maximumBytes;

    public long BytesRead { get; private set; }
    public bool Exhausted => remaining <= 0;

    public int Allow(int requested) => Math.Max(0, Math.Min(requested, remaining));

    public void Record(int bytes)
    {
        var bounded = Math.Max(0, Math.Min(bytes, remaining));
        remaining -= bounded;
        BytesRead += bounded;
    }
}

internal sealed record ProcfsTextResult(string? Text, string ErrorCode, bool Truncated)
{
    public bool Success => Text is not null;
}

internal static class LinuxProcfsReader
{
    public static async Task<ProcfsTextResult> ReadTextAsync(
        string path,
        int maximumBytes,
        ProcfsReadBudget budget,
        CancellationToken cancellationToken)
    {
        var allowed = budget.Allow(maximumBytes + 1);
        if (allowed <= 0) return new(null, "read_budget_exhausted", true);

        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);
            using var memory = new MemoryStream(Math.Min(allowed, 4096));
            var buffer = new byte[Math.Min(4096, allowed)];
            while (memory.Length < allowed)
            {
                var remaining = allowed - (int)memory.Length;
                var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken);
                if (read == 0) break;
                memory.Write(buffer, 0, read);
            }

            var bytes = memory.ToArray();
            budget.Record(bytes.Length);
            var budgetLimited = allowed <= maximumBytes;
            var truncated = bytes.Length > maximumBytes || (budgetLimited && bytes.Length == allowed);
            var retained = bytes.Length > maximumBytes ? bytes[..maximumBytes] : bytes;
            try
            {
                return new(new UTF8Encoding(false, true).GetString(retained), truncated ? "field_truncated" : "none", truncated);
            }
            catch (DecoderFallbackException)
            {
                return new(null, "invalid_utf8", truncated);
            }
        }
        catch (UnauthorizedAccessException)
        {
            return new(null, "permission_denied", false);
        }
        catch (FileNotFoundException)
        {
            return new(null, "missing", false);
        }
        catch (DirectoryNotFoundException)
        {
            return new(null, "missing", false);
        }
        catch (IOException)
        {
            return new(null, "io_error", false);
        }
    }
}
