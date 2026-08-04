using System.Text;
using Challenger.Siem.LinuxAgent.Config;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public interface ILinuxKernelProcessEnricher
{
    Task<LinuxKernelProcessMetadata> EnrichAsync(
        LinuxKernelNetworkFrame frame,
        CancellationToken cancellationToken);
}

internal sealed class LinuxKernelProcessEnricher(IOptions<LinuxAgentOptions> configured) : ILinuxKernelProcessEnricher
{
    private readonly LinuxAgentOptions options = configured.Value;

    public async Task<LinuxKernelProcessMetadata> EnrichAsync(
        LinuxKernelNetworkFrame frame,
        CancellationToken cancellationToken)
    {
        if (frame.ProcessId == 0 || frame.ProcessId > int.MaxValue)
            return new(null, null, frame.UserId == uint.MaxValue ? null : frame.UserId.ToString(), false, false, "unattributed");

        var root = $"/proc/{frame.ProcessId}";
        string? executable = null;
        string? commandLine = null;
        string? userId = frame.UserId == uint.MaxValue ? null : frame.UserId.ToString();
        var truncated = false;
        try
        {
            executable = File.ResolveLinkTarget(Path.Combine(root, "exe"), returnFinalTarget: false)?.FullName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException) { }
        try
        {
            var maximum = options.KernelNetworkTelemetry.MaxCommandLineBytes;
            await using var stream = new FileStream(
                Path.Combine(root, "cmdline"),
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                4096,
                FileOptions.Asynchronous);
            var bytes = new byte[maximum + 1];
            var read = await stream.ReadAsync(bytes, cancellationToken);
            truncated = read > maximum;
            if (!truncated && read > 0)
                commandLine = new UTF8Encoding(false, true).GetString(bytes, 0, read).Replace('\0', ' ').Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException or FileNotFoundException) { }
        if (userId is null)
        {
            try
            {
                await using var stream = new FileStream(
                    Path.Combine(root, "status"),
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete,
                    4096,
                    FileOptions.Asynchronous);
                var bytes = new byte[16 * 1024 + 1];
                var read = await stream.ReadAsync(bytes, cancellationToken);
                if (read <= 16 * 1024)
                {
                    var status = new UTF8Encoding(false, true).GetString(bytes, 0, read);
                    var uidLine = status.Split('\n').FirstOrDefault(line => line.StartsWith("Uid:\t", StringComparison.Ordinal));
                    var effective = uidLine?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Skip(2).FirstOrDefault();
                    if (uint.TryParse(effective, out var parsed)) userId = parsed.ToString();
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException or FileNotFoundException) { }
        }

        return LinuxKernelNetworkService.SanitizeProcessMetadata(
            frame,
            executable,
            commandLine,
            userId,
            truncated,
            4096,
            options.KernelNetworkTelemetry.MaxCommandLineBytes);
    }
}
