using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Challenger.Siem.Agent.Core.Security;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxProcfsProcessSource : ILinuxProcessSnapshotSource
{
    private readonly string procRoot;
    private readonly ILinuxProcessProcfs procfs;
    private readonly LinuxSocketOwnershipCache? ownershipCache;

    internal LinuxProcfsProcessSource(string procRoot = "/proc")
        : this(procRoot, new SystemLinuxProcessProcfs(), null)
    {
    }

    public LinuxProcfsProcessSource(LinuxSocketOwnershipCache ownershipCache)
        : this("/proc", new SystemLinuxProcessProcfs(), ownershipCache)
    {
    }

    internal LinuxProcfsProcessSource(string procRoot, ILinuxProcessProcfs procfs)
        : this(procRoot, procfs, null)
    {
    }

    internal LinuxProcfsProcessSource(string procRoot, ILinuxProcessProcfs procfs, LinuxSocketOwnershipCache? ownershipCache)
    {
        this.procRoot = procRoot;
        this.procfs = procfs;
        this.ownershipCache = ownershipCache;
    }

    public async Task<PassiveReadResult<LinuxProcessObservation>> ReadAsync(
        PassiveTelemetryOptions options,
        CancellationToken cancellationToken)
    {
        if (!procfs.DirectoryExists(procRoot))
            return new(Array.Empty<LinuxProcessObservation>(), PassiveReadStatuses.Missing, "procfs_missing", false, 0);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.ScanTimeoutSeconds));
        var token = deadline.Token;
        var budget = new ProcfsReadBudget(options.MaxProcessReadBytesPerScan);
        var observations = new List<LinuxProcessObservation>(Math.Min(options.MaxProcessesPerScan, 1024));
        long skipped = 0;
        long expectedRaceSkips = 0;
        long coverageGapReadSkips = 0;
        long visibilityGaps = 0;
        long denied = 0;
        long malformed = 0;
        var partial = false;
        var truncated = false;
        var enumeratedProcessCount = 0;
        long eligibleProcessCount = 0;
        long readableCommandLineCount = 0;
        long readableExecutableCount = 0;
        long descriptorLinksInspected = 0;
        var descriptorCapReached = false;
        var descriptorPermissionDenied = false;
        var socketOwners = new Dictionary<long, List<LinuxSocketOwner>>();
        var visibilityState = "full";
        var details = new Dictionary<string, string>(StringComparer.Ordinal);

        try
        {
            var mountInfo = await procfs.ReadTextAsync(
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

            var boot = await procfs.ReadTextAsync(
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
                SetCounterDetails(
                    details,
                    visibilityState,
                    skipped,
                    expectedRaceSkips,
                    coverageGapReadSkips,
                    denied + (boot.ErrorCode == "permission_denied" ? 1 : 0),
                    malformed + (boot.Success ? 1 : 0));
                SetVisibilityRatioDetails(details, eligibleProcessCount, readableCommandLineCount, readableExecutableCount);
                PublishOwnership(options, socketOwners, false, descriptorCapReached, descriptorPermissionDenied, descriptorLinksInspected);
                return new(
                    Array.Empty<LinuxProcessObservation>(),
                    status,
                    boot.Success ? "boot_identity_invalid" : $"boot_identity_{boot.ErrorCode}",
                    boot.Truncated,
                    budget.BytesRead,
                    skipped,
                    visibilityGaps,
                    details,
                    expectedRaceSkips,
                    coverageGapReadSkips);
            }
            details[LinuxBootIdentity.DetailKey] = bootIdentitySha256;
            details["boot_identity"] = "observed_hashed";

            var processIds = new List<int>(options.MaxProcessesPerScan + 1);
            foreach (var directory in procfs.EnumerateDirectories(procRoot))
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
                coverageGapReadSkips++;
                visibilityGaps++;
            }
            processIds.Sort();
            enumeratedProcessCount = processIds.Count;

            for (var index = 0; index < processIds.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                if (budget.Exhausted)
                {
                    truncated = true;
                    var omitted = processIds.Count - index;
                    skipped += omitted;
                    coverageGapReadSkips += omitted;
                    visibilityGaps += omitted;
                    break;
                }

                var processId = processIds[index];
                var directory = Path.Combine(procRoot, processId.ToString(CultureInfo.InvariantCulture));
                var statResult = await procfs.ReadTextAsync(Path.Combine(directory, "stat"), 4096, budget, token);
                if (!statResult.Success
                    || !TryParseStat(statResult.Text!, out var stat)
                    || stat.ProcessId != processId)
                {
                    skipped++;
                    if (!statResult.Success && statResult.ErrorCode == "missing")
                    {
                        expectedRaceSkips++;
                    }
                    else
                    {
                        partial = true;
                        coverageGapReadSkips++;
                        visibilityGaps++;
                        if (statResult.ErrorCode == "permission_denied") denied++;
                        if (statResult.Success || statResult.ErrorCode == "invalid_utf8") malformed++;
                    }
                    continue;
                }

                var statusResult = await procfs.ReadTextAsync(Path.Combine(directory, "status"), 16 * 1024, budget, token);
                var status = statusResult.Success ? ParseStatus(statusResult.Text!) : new Dictionary<string, string>(StringComparer.Ordinal);
                var loginResult = await procfs.ReadTextAsync(Path.Combine(directory, "loginuid"), 64, budget, token);
                var cgroupResult = await procfs.ReadTextAsync(Path.Combine(directory, "cgroup"), 4096, budget, token);
                var commandLineResult = await procfs.ReadTextAsync(
                    Path.Combine(directory, "cmdline"),
                    options.MaxCommandLineBytes,
                    budget,
                    token);

                var executable = procfs.ReadLink(Path.Combine(directory, "exe"));
                var executableDeleted = executable.Value?.EndsWith(" (deleted)", StringComparison.Ordinal) == true;
                var executableMemfd = executable.Value?.StartsWith("/memfd:", StringComparison.Ordinal) == true
                    || executable.Value?.StartsWith("memfd:", StringComparison.Ordinal) == true;
                var executableTemporary = IsTemporaryExecutable(executable.Value);
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
                var malformedMetadata = HasMalformedStatusMetadata(
                    status,
                    userId,
                    groupId,
                    capEff,
                    noNewPrivileges,
                    seccomp,
                    tracerPid)
                    || (loginResult.Success
                        && !string.IsNullOrWhiteSpace(loginResult.Text)
                        && loginUserId is null)
                    || statusResult.ErrorCode == "invalid_utf8"
                    || loginResult.ErrorCode == "invalid_utf8"
                    || cgroupResult.ErrorCode == "invalid_utf8";
                var verification = await procfs.ReadTextAsync(Path.Combine(directory, "stat"), 4096, budget, token);
                if (!verification.Success || !TryParseStat(verification.Text!, out var verified))
                {
                    skipped++;
                    if (!verification.Success && verification.ErrorCode == "missing")
                    {
                        expectedRaceSkips++;
                    }
                    else
                    {
                        partial = true;
                        coverageGapReadSkips++;
                        visibilityGaps++;
                        if (verification.ErrorCode == "permission_denied") denied++;
                        if (verification.Success || verification.ErrorCode == "invalid_utf8") malformed++;
                    }
                    continue;
                }
                if (!SameIdentity(stat, verified))
                {
                    skipped++;
                    expectedRaceSkips++;
                    continue;
                }

                var command = TelemetryTextSanitizer.SanitizeAndRedact(verified.Command, 256);
                var isKernelThread = (verified.Flags & 0x00200000UL) != 0;
                var isZombie = string.Equals(verified.State, "Z", StringComparison.Ordinal);
                var eligible = !isKernelThread && !isZombie;
                if (eligible)
                {
                    eligibleProcessCount++;
                    if (commandLineResult.Success && !commandLineResult.Truncated && commandLineResult.ErrorCode == "none")
                        readableCommandLineCount++;
                    if (executable.ErrorCode == "none" && !string.IsNullOrWhiteSpace(executable.Value))
                        readableExecutableCount++;
                }
                var dangerousCapabilities = DecodeDangerousCapabilities(capEff);
                malformedMetadata = malformedMetadata
                    || command.InvalidText
                    || command.Truncated
                    || command.Dropped
                    || executableText.InvalidText
                    || commandLine.InvalidText
                    || commandLine.Dropped;
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
                var materialEnrichmentFailure = IsVisibilityFailure(statusResult)
                    || IsVisibilityFailure(loginResult)
                    || IsVisibilityFailure(cgroupResult)
                    || IsVisibilityFailure(commandLineResult)
                    || executable.ErrorCode is "permission_denied" or "io_error" or "field_truncated"
                    || executableText.Truncated
                    || executableText.Dropped
                    || malformedMetadata;
                // Missing optional enrichment contributes to the aggregate visibility ratios.
                // It is not by itself a per-process collection failure unless the underlying
                // read was denied, malformed, truncated, or otherwise materially failed.
                var enrichmentPartial = materialEnrichmentFailure;
                if (materialEnrichmentFailure)
                {
                    partial = true;
                    visibilityGaps++;
                    if (malformedMetadata) malformed++;
                    denied += CountPermissionDenials(
                        statusResult.ErrorCode,
                        loginResult.ErrorCode,
                        cgroupResult.ErrorCode,
                        commandLineResult.ErrorCode,
                        executable.ErrorCode);
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
                    executableText.Truncated || executable.ErrorCode == "field_truncated",
                    isKernelThread,
                    isZombie,
                    executableDeleted,
                    executableMemfd,
                    executableTemporary,
                    dangerousCapabilities));

                if (options.CollectSocketOwnership && ownershipCache is not null)
                {
                    CollectSocketOwners(
                        directory,
                        new LinuxSocketOwner(
                            verified.ProcessId,
                            executableText.Dropped ? null : EmptyToNull(executableText.Value),
                            command.Value,
                            userId,
                            "exact_inode_current_scan"),
                        socketOwners,
                        ref descriptorLinksInspected,
                        ref descriptorCapReached,
                        ref descriptorPermissionDenied);
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            SetCounterDetails(details, visibilityState, skipped + 1, expectedRaceSkips, coverageGapReadSkips + 1, denied, malformed);
            SetVisibilityRatioDetails(details, eligibleProcessCount, readableCommandLineCount, readableExecutableCount);
            PublishOwnership(options, socketOwners, false, descriptorCapReached, descriptorPermissionDenied, descriptorLinksInspected);
            return new(observations, PassiveReadStatuses.Partial, "process_scan_deadline", true, budget.BytesRead,
                skipped + 1, visibilityGaps + 1, details, expectedRaceSkips, coverageGapReadSkips + 1);
        }
        catch (UnauthorizedAccessException)
        {
            SetCounterDetails(details, visibilityState, skipped + 1, expectedRaceSkips, coverageGapReadSkips + 1, denied + 1, malformed);
            SetVisibilityRatioDetails(details, eligibleProcessCount, readableCommandLineCount, readableExecutableCount);
            PublishOwnership(options, socketOwners, false, descriptorCapReached, true, descriptorLinksInspected);
            return new(observations, observations.Count == 0 ? PassiveReadStatuses.PermissionDenied : PassiveReadStatuses.Partial,
                "procfs_process_permission_denied", truncated, budget.BytesRead, skipped + 1, visibilityGaps + 1, details,
                expectedRaceSkips, coverageGapReadSkips + 1);
        }
        catch (IOException)
        {
            SetCounterDetails(details, visibilityState, skipped + 1, expectedRaceSkips, coverageGapReadSkips + 1, denied, malformed);
            SetVisibilityRatioDetails(details, eligibleProcessCount, readableCommandLineCount, readableExecutableCount);
            PublishOwnership(options, socketOwners, false, descriptorCapReached, descriptorPermissionDenied, descriptorLinksInspected);
            return new(observations, observations.Count == 0 ? PassiveReadStatuses.Error : PassiveReadStatuses.Partial,
                "procfs_process_io_error", truncated, budget.BytesRead, skipped + 1, visibilityGaps + 1, details,
                expectedRaceSkips, coverageGapReadSkips + 1);
        }

        var commandLinePermille = VisibilityPermille(readableCommandLineCount, eligibleProcessCount);
        var executablePermille = VisibilityPermille(readableExecutableCount, eligibleProcessCount);
        var belowVisibilityThreshold = eligibleProcessCount >= 10
            && (commandLinePermille < 800 || executablePermille < 800);
        if (belowVisibilityThreshold)
        {
            partial = true;
            visibilityGaps++;
        }
        SetVisibilityRatioDetails(details, eligibleProcessCount, readableCommandLineCount, readableExecutableCount);
        PublishOwnership(
            options,
            socketOwners,
            !partial && !truncated && !descriptorCapReached && !descriptorPermissionDenied,
            descriptorCapReached,
            descriptorPermissionDenied,
            descriptorLinksInspected);

        var expectedRacesOnly = observations.Count == 0
            && enumeratedProcessCount > 0
            && expectedRaceSkips > 0
            && skipped == expectedRaceSkips
            && coverageGapReadSkips == 0
            && visibilityGaps == 0
            && !partial
            && !truncated;
        var statusName = observations.Count == 0
            ? expectedRacesOnly
                ? PassiveReadStatuses.Success
                : denied > 0 ? PassiveReadStatuses.PermissionDenied : visibilityGaps > 0 ? PassiveReadStatuses.Error : PassiveReadStatuses.Missing
            : partial || truncated ? PassiveReadStatuses.Partial : PassiveReadStatuses.Success;
        var code = statusName switch
        {
            PassiveReadStatuses.Success => "none",
            PassiveReadStatuses.Missing => "no_readable_processes",
            PassiveReadStatuses.PermissionDenied => "procfs_process_permission_denied",
            _ when visibilityState == "restricted" => "process_visibility_restricted",
            _ when visibilityState == "unknown" => "process_visibility_unknown",
            _ when truncated => "process_scan_truncated",
            _ when denied > 0 => "process_metadata_permission_denied",
            _ when malformed > 0 => "process_metadata_malformed",
            _ when belowVisibilityThreshold => "process_visibility_below_threshold",
            _ => "process_enrichment_partial"
        };
        SetCounterDetails(details, visibilityState, skipped, expectedRaceSkips, coverageGapReadSkips, denied, malformed);
        return new(observations, statusName, code, truncated, budget.BytesRead, skipped, visibilityGaps, details,
            expectedRaceSkips, coverageGapReadSkips);
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
            || parentPid < 0
            || !ulong.TryParse(fields[6], NumberStyles.None, CultureInfo.InvariantCulture, out var flags)
            || !long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var startTicks))
        {
            return false;
        }
        parsed = new(pid, parentPid, startTicks, fields[0], command, flags);
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

    private static bool HasMalformedStatusMetadata(
        IReadOnlyDictionary<string, string> status,
        string? userId,
        string? groupId,
        string? effectiveCapabilities,
        bool? noNewPrivileges,
        int? seccomp,
        int? tracerPid) =>
        (status.TryGetValue("Uid", out var uid) && (userId is null || !AllUnsignedTokens(uid)))
        || (status.TryGetValue("Gid", out var gid) && (groupId is null || !AllUnsignedTokens(gid)))
        || (status.ContainsKey("CapEff") && effectiveCapabilities is null)
        || (status.ContainsKey("NoNewPrivs") && noNewPrivileges is null)
        || (status.ContainsKey("Seccomp") && seccomp is null)
        || (status.ContainsKey("TracerPid") && tracerPid is null);

    private static bool AllUnsignedTokens(string value)
    {
        var tokens = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return tokens.Length > 0
            && tokens.All(token => uint.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out _));
    }

    private static void SetCounterDetails(
        IDictionary<string, string> details,
        string visibilityState,
        long skipped,
        long expectedRaceSkips,
        long coverageGapReadSkips,
        long denied,
        long malformed)
    {
        details["process_visibility"] = visibilityState;
        details["polling_skips"] = skipped.ToString(CultureInfo.InvariantCulture);
        details["expected_race_skips"] = expectedRaceSkips.ToString(CultureInfo.InvariantCulture);
        details["coverage_gap_read_skips"] = coverageGapReadSkips.ToString(CultureInfo.InvariantCulture);
        details["permission_denied_reads"] = denied.ToString(CultureInfo.InvariantCulture);
        details["malformed_metadata_records"] = malformed.ToString(CultureInfo.InvariantCulture);
    }

    private static void SetVisibilityRatioDetails(
        IDictionary<string, string> details,
        long eligible,
        long readableCommandLines,
        long readableExecutables)
    {
        details["eligible_processes"] = eligible.ToString(CultureInfo.InvariantCulture);
        details["command_line_readable_count"] = readableCommandLines.ToString(CultureInfo.InvariantCulture);
        details["executable_readable_count"] = readableExecutables.ToString(CultureInfo.InvariantCulture);
        details["command_line_readability_permille"] = VisibilityPermille(readableCommandLines, eligible).ToString(CultureInfo.InvariantCulture);
        details["executable_readability_permille"] = VisibilityPermille(readableExecutables, eligible).ToString(CultureInfo.InvariantCulture);
    }

    private static int VisibilityPermille(long visible, long eligible) => eligible <= 0
        ? 1000
        : (int)Math.Clamp(visible * 1000 / eligible, 0, 1000);

    internal static string? DecodeDangerousCapabilities(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !ulong.TryParse(value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var mask))
            return null;
        var dangerous = new (int Bit, string Name)[]
        {
            (1, "dac_override"), (2, "dac_read_search"), (6, "setgid"), (7, "setuid"),
            (12, "net_admin"), (13, "net_raw"), (16, "sys_module"), (17, "sys_rawio"),
            (19, "sys_ptrace"), (21, "sys_admin"), (22, "sys_boot"), (33, "mac_admin"),
            (38, "perfmon"), (39, "bpf"), (40, "checkpoint_restore")
        };
        var names = dangerous.Where(capability => (mask & (1UL << capability.Bit)) != 0).Select(capability => capability.Name).ToArray();
        return names.Length == 0 ? null : string.Join(',', names);
    }

    internal static bool IsTemporaryExecutable(string? executable)
    {
        if (string.IsNullOrWhiteSpace(executable)) return false;
        var value = executable.EndsWith(" (deleted)", StringComparison.Ordinal)
            ? executable[..^10]
            : executable;
        return value.StartsWith("/tmp/", StringComparison.Ordinal)
            || value.StartsWith("/var/tmp/", StringComparison.Ordinal)
            || value.StartsWith("/dev/shm/", StringComparison.Ordinal)
            || value.StartsWith("/run/user/", StringComparison.Ordinal);
    }

    private void CollectSocketOwners(
        string processDirectory,
        LinuxSocketOwner owner,
        IDictionary<long, List<LinuxSocketOwner>> owners,
        ref long inspected,
        ref bool capReached,
        ref bool permissionDenied)
    {
        if (inspected >= LinuxSocketOwnershipCache.MaxDescriptorLinksPerScan)
        {
            capReached = true;
            return;
        }
        try
        {
            var count = 0;
            foreach (var descriptor in Directory.EnumerateFileSystemEntries(Path.Combine(processDirectory, "fd")))
            {
                if (count++ >= LinuxSocketOwnershipCache.MaxDescriptorsPerProcess
                    || inspected >= LinuxSocketOwnershipCache.MaxDescriptorLinksPerScan)
                {
                    capReached = true;
                    break;
                }
                inspected++;
                string? target;
                try { target = new FileInfo(descriptor).LinkTarget; }
                catch (UnauthorizedAccessException) { permissionDenied = true; continue; }
                catch (IOException) { continue; }
                if (!LinuxSocketOwnershipCache.TryParseSocketTarget(target, out var inode)) continue;
                if (!owners.TryGetValue(inode, out var list)) owners[inode] = list = new();
                if (list.Count < LinuxSocketOwnershipCache.MaxOwnersPerSocket
                    && list.All(existing => existing.ProcessId != owner.ProcessId))
                    list.Add(owner);
                else if (list.Count >= LinuxSocketOwnershipCache.MaxOwnersPerSocket)
                    capReached = true;
            }
        }
        catch (UnauthorizedAccessException) { permissionDenied = true; }
        catch (DirectoryNotFoundException) { }
        catch (IOException) { }
    }

    private void PublishOwnership(
        PassiveTelemetryOptions options,
        IReadOnlyDictionary<long, List<LinuxSocketOwner>> owners,
        bool complete,
        bool capReached,
        bool permissionDenied,
        long inspected)
    {
        if (!options.CollectSocketOwnership || ownershipCache is null) return;
        ownershipCache.Publish(
            owners.ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlyList<LinuxSocketOwner>)pair.Value.OrderBy(owner => owner.ProcessId).ToArray()),
            complete,
            capReached,
            permissionDenied,
            inspected);
    }

    private static int CountPermissionDenials(params string[] errorCodes) =>
        errorCodes.Count(errorCode => errorCode == "permission_denied");

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

    internal readonly record struct ParsedProcessStat(int ProcessId, int ParentProcessId, long StartTicks, string State, string Command, ulong Flags);
}

internal interface ILinuxProcessProcfs
{
    bool DirectoryExists(string path);
    IEnumerable<string> EnumerateDirectories(string path);
    Task<ProcfsTextResult> ReadTextAsync(
        string path,
        int maximumBytes,
        ProcfsReadBudget budget,
        CancellationToken cancellationToken);
    ProcfsLinkResult ReadLink(string path);
}

internal sealed class SystemLinuxProcessProcfs : ILinuxProcessProcfs
{
    public bool DirectoryExists(string path) => Directory.Exists(path);

    public IEnumerable<string> EnumerateDirectories(string path) => Directory.EnumerateDirectories(path);

    public Task<ProcfsTextResult> ReadTextAsync(
        string path,
        int maximumBytes,
        ProcfsReadBudget budget,
        CancellationToken cancellationToken) =>
        LinuxProcfsReader.ReadTextAsync(path, maximumBytes, budget, cancellationToken);

    public ProcfsLinkResult ReadLink(string path)
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
}

internal readonly record struct ProcfsLinkResult(string? Value, string ErrorCode);
