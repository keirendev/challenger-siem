using System.Text;
using Challenger.Siem.Contracts.V2;
using Challenger.Siem.LinuxAgent.Config;
using Challenger.Siem.LinuxAgent.Passive;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.LinuxAgent.KernelNetwork;

public interface ILinuxKernelProcessEnricher
{
    Task<LinuxKernelProcessMetadata> EnrichAsync(
        LinuxKernelNetworkFrame frame,
        CancellationToken cancellationToken);
}

internal sealed class LinuxKernelProcessEnricher(
    IOptions<LinuxAgentOptions> configured,
    TimeProvider timeProvider) : ILinuxKernelProcessEnricher
{
    private readonly LinuxAgentOptions options = configured.Value;

    public async Task<LinuxKernelProcessMetadata> EnrichAsync(
        LinuxKernelNetworkFrame frame,
        CancellationToken cancellationToken)
    {
        if (frame.ProcessId == 0 || frame.ProcessId > int.MaxValue)
            return new(
                null,
                null,
                frame.UserId == uint.MaxValue ? null : frame.UserId.ToString(),
                false,
                false,
                "unattributed",
                ProcessInstanceId: null,
                IdentityStatus: "unattributed");

        var root = $"/proc/{frame.ProcessId}";
        var observedAt = timeProvider.GetUtcNow();
        LinuxProcfsProcessSource.ParsedProcessStat? firstIdentity = null;
        string identityStatus;
        string? processInstanceId = null;
        try
        {
            firstIdentity = await ReadStatAsync(root, cancellationToken);
            identityStatus = firstIdentity is null ? "process_exited_before_enrichment" : "pending_verification";
        }
        catch (UnauthorizedAccessException)
        {
            identityStatus = "process_identity_permission_denied";
        }
        catch (IOException)
        {
            identityStatus = "process_exited_before_enrichment";
        }
        catch (DecoderFallbackException)
        {
            identityStatus = "process_identity_invalid_text";
        }
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

        if (firstIdentity is not null)
        {
            LinuxProcfsProcessSource.ParsedProcessStat? secondIdentity = null;
            try
            {
                secondIdentity = await ReadStatAsync(root, cancellationToken);
                (_, identityStatus) = ResolveIdentity(null, firstIdentity, secondIdentity);
            }
            catch (UnauthorizedAccessException)
            {
                identityStatus = "process_identity_permission_denied";
            }
            catch (IOException)
            {
                identityStatus = "process_exited_during_enrichment";
            }
            catch (DecoderFallbackException)
            {
                identityStatus = "process_identity_invalid_text";
            }

            if (secondIdentity is not null && LinuxProcfsProcessSource.SameIdentity(firstIdentity.Value, secondIdentity.Value))
            {
                try
                {
                    var boot = await ReadBoundedTextAsync("/proc/sys/kernel/random/boot_id", 128, cancellationToken);
                    var bootHash = LinuxBootIdentity.TryHash(new ProcfsTextResult(boot, "none", false), out var bootIdentitySha256)
                        ? bootIdentitySha256
                        : null;
                    (processInstanceId, identityStatus) = ResolveIdentity(bootHash, firstIdentity, secondIdentity);
                }
                catch (UnauthorizedAccessException)
                {
                    identityStatus = "boot_identity_permission_denied";
                }
                catch (IOException)
                {
                    identityStatus = "boot_identity_unavailable";
                }
                catch (DecoderFallbackException)
                {
                    identityStatus = "boot_identity_invalid_text";
                }
            }
        }

        return LinuxKernelNetworkService.SanitizeProcessMetadata(
            frame,
            executable,
            commandLine,
            userId,
            truncated,
            4096,
            options.KernelNetworkTelemetry.MaxCommandLineBytes,
            processInstanceId,
            identityStatus,
            observedAt);
    }

    private static async Task<LinuxProcfsProcessSource.ParsedProcessStat?> ReadStatAsync(
        string root,
        CancellationToken cancellationToken)
    {
        var content = await ReadBoundedTextAsync(Path.Combine(root, "stat"), 4096, cancellationToken);
        return LinuxProcfsProcessSource.TryParseStat(content, out var parsed) ? parsed : null;
    }

    internal static (string? ProcessInstanceId, string Status) ResolveIdentity(
        string? bootIdentitySha256,
        LinuxProcfsProcessSource.ParsedProcessStat? first,
        LinuxProcfsProcessSource.ParsedProcessStat? second)
    {
        if (first is null) return (null, "process_exited_before_enrichment");
        if (second is null) return (null, "process_exited_during_enrichment");
        if (!LinuxProcfsProcessSource.SameIdentity(first.Value, second.Value)) return (null, "process_identity_race");
        if (!ProcessInstanceIdentity.IsValid(bootIdentitySha256)) return (null, "boot_identity_unavailable");
        return (
            ProcessInstanceIdentity.DeriveSha256(bootIdentitySha256!, first.Value.ProcessId, first.Value.StartTicks),
            "observed_stable_procfs_identity");
    }

    private static async Task<string> ReadBoundedTextAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.Asynchronous);
        var bytes = new byte[maximumBytes + 1];
        var read = await stream.ReadAsync(bytes, cancellationToken);
        if (read > maximumBytes) throw new IOException("procfs_identity_field_oversized");
        return new UTF8Encoding(false, true).GetString(bytes, 0, read);
    }
}
