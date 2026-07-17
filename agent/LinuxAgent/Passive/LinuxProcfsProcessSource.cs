using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxProcfsProcessSource(string procRoot = "/proc") : ILinuxProcessSnapshotSource
{
    public async Task<PassiveReadResult<LinuxProcessObservation>> ReadAsync(
        PassiveTelemetryOptions options,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(procRoot))
            return new(Array.Empty<LinuxProcessObservation>(), PassiveReadStatuses.Missing, "procfs_missing", false, 0);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.ScanTimeoutSeconds));
        var token = deadline.Token;
        var budget = new ProcfsReadBudget(options.MaxProcessReadBytesPerScan);
        var observations = new List<LinuxProcessObservation>(Math.Min(options.MaxProcessesPerScan, 1024));
        long skipped = 0;
        long visibilityGaps = 0;
        long denied = 0;
        var partial = false;
        var truncated = false;
        var visibilityState = "full";
        var details = new Dictionary<string, string>(StringComparer.Ordinal);

        try
        {
            var mountInfo = await LinuxProcfsReader.ReadTextAsync(
                Path.Combine(procRoot, "self/mountinfo"),
                256 * 1024,
                budget,
                token);
            visibilityState = mountInfo.Success
                ? DetermineProcVisibility(mountInfo.Text!)
                : "unknown";
            if (!mountInfo.Success || mountInfo.Truncated || visibilityState != "full")
            {
                partial = true;
                visibilityGaps++;
                if (mountInfo.ErrorCode == "permission_denied") denied++;
            }

            var boot = await LinuxProcfsReader.ReadTextAsync(
                Path.Combine(procRoot, "sys/kernel/random/boot_id"),
                128,
                budget,
                token);
            if (!LinuxBootIdentity.TryHash(boot, out var bootIdentitySha256))
            {
                visibilityGaps++;
                details["boot_identity"] = boot.Success ? "invalid" : boot.ErrorCode;
                var status = boot.ErrorCode switch
                {
                    "permission_denied" => PassiveReadStatuses.PermissionDenied,
                    "missing" => PassiveReadStatuses.Missing,
                    _ => PassiveReadStatuses.Error
                };
                return new(
                    Array.Empty<LinuxProcessObservation>(),
                    status,
                    boot.Success ? "boot_identity_invalid" : $"boot_identity_{boot.ErrorCode}",
                    boot.Truncated,
                    budget.BytesRead,
                    skipped,
                    visibilityGaps,
                    details);
            }
            details[LinuxBootIdentity.DetailKey] = bootIdentitySha256;
            details["boot_identity"] = "observed_hashed";

            var processIds = new List<int>(options.MaxProcessesPerScan + 1);
            foreach (var directory in Directory.EnumerateDirectories(procRoot))
            {
                token.ThrowIfCancellationRequested();
                var value = Path.GetFileName(directory);
                if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var processId)
                    || processId <= 0)
                {
                    continue;
                }
                processIds.Add(processId);
                if (processIds.Count > options.MaxProcessesPerScan) break;
            }
            if (processIds.Count > options.MaxProcessesPerScan)
            {
                processIds.RemoveAt(processIds.Count - 1);
                truncated = true;
                skipped++;
                visibilityGaps++;
            }
            processIds.Sort();

            for (var index = 0; index < processIds.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                if (budget.Exhausted)
                {
                    truncated = true;
                    var omitted = processIds.Count - index;
                    skipped += omitted;
                    visibilityGaps += omitted;
                    break;
                }

                var processId = processIds[index];
                var directory = Path.Combine(procRoot, processId.ToString(CultureInfo.InvariantCulture));
                var statResult = await LinuxProcfsReader.ReadTextAsync(Path.Combine(directory, "stat"), 4096, budget, token);
                if (!statResult.Success || !TryParseStat(statResult.Text!, out var stat))
                {
                    skipped++;
                    if (IsVisibilityFailure(statResult) || statResult.Success)
                    {
                        partial = true;
                        visibilityGaps++;
                        if (statResult.ErrorCode == "permission_denied") denied++;
                    }
                    continue;
                }

                var statusResult = await LinuxProcfsReader.ReadTextAsync(Path.Combine(directory, "status"), 16 * 1024, budget, token);
                var status = statusResult.Success ? ParseStatus(statusResult.Text!) : new Dictionary<string, string>(StringComparer.Ordinal);
                var loginResult = await LinuxProcfsReader.ReadTextAsync(Path.Combine(directory, "loginuid"), 64, budget, token);
                var cgroupResult = await LinuxProcfsReader.ReadTextAsync(Path.Combine(directory, "cgroup"), 4096, budget, token);
                var commandLineResult = await LinuxProcfsReader.ReadTextAsync(
                    Path.Combine(directory, "cmdline"),
                    options.MaxCommandLineBytes,
                    budget,
                    token);

                var executable = ReadExecutableLink(Path.Combine(directory, "exe"));
                var executableSanitized = TelemetryTextSanitizer.SanitizeAndRedact(executable.Value, 2048);
                var executableText = executableSanitized.Truncated || executable.ErrorCode == "field_truncated"
                    ? new SanitizedTelemetryText(string.Empty, true, executableSanitized.InvalidText, true, true)
                    : executableSanitized;
                var commandLineValue = commandLineResult.Text?.Replace('\0', ' ').Trim();
                var commandLine = commandLineResult.Truncated || commandLineResult.ErrorCode == "invalid_utf8"
                    ? new SanitizedTelemetryText(
                        string.Empty,
                        commandLineResult.Truncated,
                        commandLineResult.ErrorCode == "invalid_utf8",
                        true,
                        true)
                    : TelemetryTextSanitizer.SanitizeAndRedact(commandLineValue, options.MaxCommandLineBytes);
                var cgroupHash = cgroupResult.Text is null
                    ? null
                    : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(cgroupResult.Text))).ToLowerInvariant();
                var userId = FirstNumeric(status.GetValueOrDefault("Uid"));
                var groupId = FirstNumeric(status.GetValueOrDefault("Gid"));
                var loginUserId = SafeUnsigned(loginResult.Text?.Trim());
                var capEff = SafeHex(status.GetValueOrDefault("CapEff"), 32);
                var noNewPrivileges = ParseBooleanNumber(status.GetValueOrDefault("NoNewPrivs"));
                var seccomp = ParseInt(status.GetValueOrDefault("Seccomp"));
                var tracerPid = ParseInt(status.GetValueOrDefault("TracerPid"));
                var verification = await LinuxProcfsReader.ReadTextAsync(Path.Combine(directory, "stat"), 4096, budget, token);
                if (!verification.Success
                    || !TryParseStat(verification.Text!, out var verified)
                    || !SameIdentity(stat, verified))
                {
                    skipped++;
                    if (IsVisibilityFailure(verification))
                    {
                        partial = true;
                        visibilityGaps++;
                        if (verification.ErrorCode == "permission_denied") denied++;
                    }
                    continue;
                }

                var command = TelemetryTextSanitizer.SanitizeAndRedact(verified.Command, 256);
                var key = HashSignature(
                    bootIdentitySha256,
                    verified.ProcessId.ToString(CultureInfo.InvariantCulture),
                    verified.StartTicks.ToString(CultureInfo.InvariantCulture));
                var signature = HashSignature(
                    verified.ParentProcessId.ToString(CultureInfo.InvariantCulture),
                    command.Value,
                    executableText.Dropped ? string.Empty : executableText.Value,
                    commandLine.Dropped ? string.Empty : commandLine.Value,
                    userId,
                    groupId,
                    capEff,
                    noNewPrivileges?.ToString(),
                    seccomp?.ToString(CultureInfo.InvariantCulture),
                    tracerPid?.ToString(CultureInfo.InvariantCulture),
                    loginUserId,
                    cgroupHash);
                var enrichmentPartial = IsVisibilityFailure(statusResult)
                    || IsVisibilityFailure(loginResult)
                    || IsVisibilityFailure(cgroupResult)
                    || IsVisibilityFailure(commandLineResult)
                    || executable.ErrorCode is "permission_denied" or "io_error" or "field_truncated"
                    || executableText.Truncated
                    || executableText.Dropped;
                if (enrichmentPartial)
                {
                    partial = true;
                    visibilityGaps++;
                    if (statusResult.ErrorCode == "permission_denied"
                        || loginResult.ErrorCode == "permission_denied"
                        || cgroupResult.ErrorCode == "permission_denied"
                        || commandLineResult.ErrorCode == "permission_denied"
                        || executable.ErrorCode == "permission_denied")
                    {
                        denied++;
                    }
                }

                observations.Add(new(
                    key,
                    signature,
                    verified.ProcessId,
                    verified.ParentProcessId,
                    verified.StartTicks,
                    verified.State,
                    command.Value,
                    executableText.Dropped ? null : EmptyToNull(executableText.Value),
                    commandLine.Dropped ? null : EmptyToNull(commandLine.Value),
                    userId,
                    groupId,
                    capEff,
                    noNewPrivileges,
                    seccomp,
                    tracerPid,
                    loginUserId,
                    cgroupHash,
                    commandLine.Redacted || commandLine.Dropped,
                    commandLine.Truncated || commandLineResult.Truncated,
                    command.InvalidText
                    || executableText.InvalidText
                    || commandLine.InvalidText
                    || statusResult.ErrorCode == "invalid_utf8"
                    || loginResult.ErrorCode == "invalid_utf8"
                    || cgroupResult.ErrorCode == "invalid_utf8",
                    enrichmentPartial,
                    command.Redacted || command.Dropped,
                    executableText.Redacted || executableText.Dropped,
                    executableText.Truncated || executable.ErrorCode == "field_truncated"));
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(observations, PassiveReadStatuses.Partial, "process_scan_deadline", true, budget.BytesRead,
                skipped + 1, visibilityGaps + 1, details);
        }
        catch (UnauthorizedAccessException)
        {
            return new(observations, observations.Count == 0 ? PassiveReadStatuses.PermissionDenied : PassiveReadStatuses.Partial,
                "procfs_process_permission_denied", truncated, budget.BytesRead, skipped + 1, visibilityGaps + 1, details);
        }
        catch (IOException)
        {
            return new(observations, observations.Count == 0 ? PassiveReadStatuses.Error : PassiveReadStatuses.Partial,
                "procfs_process_io_error", truncated, budget.BytesRead, skipped + 1, visibilityGaps + 1, details);
        }

        var statusName = observations.Count == 0
            ? denied > 0 ? PassiveReadStatuses.PermissionDenied : visibilityGaps > 0 ? PassiveReadStatuses.Error : PassiveReadStatuses.Missing
            : partial || truncated ? PassiveReadStatuses.Partial : PassiveReadStatuses.Success;
        var code = statusName switch
        {
            PassiveReadStatuses.Success => "none",
            PassiveReadStatuses.Missing => "no_readable_processes",
            PassiveReadStatuses.PermissionDenied => "procfs_process_permission_denied",
            _ when visibilityState == "restricted" => "process_visibility_restricted",
            _ when visibilityState == "unknown" => "process_visibility_unknown",
            _ when truncated => "process_scan_truncated",
            _ => "process_enrichment_partial"
        };
        details["process_visibility"] = visibilityState;
        details["polling_skips"] = skipped.ToString(CultureInfo.InvariantCulture);
        return new(observations, statusName, code, truncated, budget.BytesRead, skipped, visibilityGaps, details);
    }

    internal static bool TryParseStat(string value, out ParsedProcessStat parsed)
    {
        parsed = default;
        var open = value.IndexOf('(');
        var close = value.LastIndexOf(')');
        if (open <= 0 || close <= open || close + 2 >= value.Length) return false;
        if (!int.TryParse(value[..open].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0) return false;
        var command = value[(open + 1)..close];
        var fields = value[(close + 1)..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 20
            || fields[0].Length != 1
            || !int.TryParse(fields[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var parentPid)
            || !long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var startTicks))
        {
            return false;
        }
        parsed = new(pid, parentPid, startTicks, fields[0], command);
        return true;
    }

    internal static IReadOnlyDictionary<string, string> ParseStatus(string content)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp", "TracerPid"
        };
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in content.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var name = line[..separator];
            if (!allowed.Contains(name)) continue;
            var value = line[(separator + 1)..].Trim();
            if (value.Length <= 128) result[name] = value;
        }
        return result;
    }

    internal static bool SameIdentity(ParsedProcessStat first, ParsedProcessStat second) =>
        first.ProcessId == second.ProcessId && first.StartTicks == second.StartTicks;

    internal static string DetermineProcVisibility(string mountInfo)
    {
        foreach (var line in mountInfo.Replace("\r", string.Empty, StringComparison.Ordinal)
                     .Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(" - ", StringComparison.Ordinal);
            if (separator < 0) continue;
            var left = line[..separator].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var right = line[(separator + 3)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (left.Length < 6 || right.Length < 3 || left[4] != "/proc" || right[0] != "proc") continue;
            var options = string.Join(',', left[5], right[2]);
            foreach (var option in options.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (option.StartsWith("hidepid=", StringComparison.Ordinal)
                    && option is not "hidepid=0" and not "hidepid=off")
                {
                    return "restricted";
                }
            }
            return "full";
        }
        return "unknown";
    }

    private static ProcfsLinkResult ReadExecutableLink(string path)
    {
        try
        {
            var target = new FileInfo(path).LinkTarget;
            return target switch
            {
                { Length: <= 4096 } => new(target, "none"),
                { Length: > 4096 } => new(null, "field_truncated"),
                _ => new(null, "missing")
            };
        }
        catch (UnauthorizedAccessException)
        {
            return new(null, "permission_denied");
        }
        catch (IOException)
        {
            return new(null, "io_error");
        }
        catch (ArgumentException)
        {
            return new(null, "missing");
        }
    }

    private static bool IsVisibilityFailure(ProcfsTextResult result) =>
        result.Truncated || result.ErrorCode is "permission_denied" or "io_error" or "read_budget_exhausted" or "invalid_utf8";

    private static string? FirstNumeric(string? value) => value?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() is { } token
        ? SafeUnsigned(token)
        : null;

    private static string? SafeUnsigned(string? value) =>
        uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            ? number.ToString(CultureInfo.InvariantCulture)
            : null;

    private static string? SafeHex(string? value, int maxLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maxLength && value.All(char.IsAsciiHexDigit)
            ? value.ToLowerInvariant()
            : null;

    private static bool? ParseBooleanNumber(string? value) => value?.Trim() switch
    {
        "0" => false,
        "1" => true,
        _ => null
    };

    private static int? ParseInt(string? value) =>
        int.TryParse(value?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number >= 0
            ? number
            : null;

    private static string? SafeToken(string? value, int maxLength) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maxLength
            && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')
                ? value
                : null;

    private static string HashSignature(params string?[] values) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', values.Select(value => value ?? string.Empty))))).ToLowerInvariant();

    private static string? EmptyToNull(string value) => value.Length == 0 ? null : value;

    internal readonly record struct ParsedProcessStat(int ProcessId, int ParentProcessId, long StartTicks, string State, string Command);
    private readonly record struct ProcfsLinkResult(string? Value, string ErrorCode);
}
