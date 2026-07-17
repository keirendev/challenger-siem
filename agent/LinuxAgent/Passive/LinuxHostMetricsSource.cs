using System.Globalization;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxHostMetricsSource(string procRoot = "/proc", TimeProvider? timeProvider = null) : ILinuxHostMetricsSource
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<PassiveReadResult<LinuxHostMetricsObservation>> ReadAsync(
        PassiveTelemetryOptions options,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(procRoot))
            return new(Array.Empty<LinuxHostMetricsObservation>(), PassiveReadStatuses.Missing, "procfs_metrics_missing", false, 0);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.ScanTimeoutSeconds));
        var budget = new ProcfsReadBudget(Math.Min(options.MaxNetworkReadBytesPerScan, 1024 * 1024));
        var paths = new (string Key, string Path, bool Required)[]
        {
            ("stat", "stat", true),
            ("meminfo", "meminfo", true),
            ("loadavg", "loadavg", true),
            ("uptime", "uptime", true),
            ("diskstats", "diskstats", true),
            ("netdev", "net/dev", true),
            ("pressure_cpu", "pressure/cpu", false),
            ("pressure_memory", "pressure/memory", false),
            ("pressure_io", "pressure/io", false)
        };
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var requiredMissing = 0;
        var denied = 0;
        long skipped = 0;
        long visibilityGaps = 0;
        var truncated = false;
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            var boot = await LinuxProcfsReader.ReadTextAsync(
                Path.Combine(procRoot, "sys", "kernel", "random", "boot_id"),
                128,
                budget,
                deadline.Token);
            if (!LinuxBootIdentity.TryHash(boot, out var bootIdentitySha256))
            {
                details["boot_identity"] = boot.Success ? "invalid" : boot.ErrorCode;
                var bootStatus = boot.ErrorCode switch
                {
                    "permission_denied" => PassiveReadStatuses.PermissionDenied,
                    "missing" => PassiveReadStatuses.Missing,
                    _ => PassiveReadStatuses.Error
                };
                return new(
                    Array.Empty<LinuxHostMetricsObservation>(),
                    bootStatus,
                    boot.Success ? "boot_identity_invalid" : $"boot_identity_{boot.ErrorCode}",
                    boot.Truncated,
                    budget.BytesRead,
                    0,
                    1,
                    details);
            }
            details[LinuxBootIdentity.DetailKey] = bootIdentitySha256;
            details["boot_identity"] = "observed_hashed";

            foreach (var path in paths)
            {
                var result = await LinuxProcfsReader.ReadTextAsync(Path.Combine(procRoot, path.Path), 256 * 1024, budget, deadline.Token);
                if (result.Success)
                {
                    values[path.Key] = result.Text!;
                    details[$"input_{path.Key}"] = result.Truncated ? "truncated" : "observed";
                }
                else if (!path.Required && result.ErrorCode == "missing")
                {
                    details[$"input_{path.Key}"] = "not_available";
                    continue;
                }
                else
                {
                    if (result.ErrorCode == "permission_denied") denied++;
                    if (path.Required) requiredMissing++;
                    skipped++;
                    visibilityGaps++;
                    details[$"input_{path.Key}"] = result.ErrorCode;
                }
                if (result.Truncated)
                {
                    truncated = true;
                    visibilityGaps++;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(Array.Empty<LinuxHostMetricsObservation>(), PassiveReadStatuses.Partial, "metrics_scan_deadline", true,
                budget.BytesRead, skipped + 1, visibilityGaps + 1, details);
        }

        if (values.Count == 0)
        {
            return new(Array.Empty<LinuxHostMetricsObservation>(), denied > 0 ? PassiveReadStatuses.PermissionDenied : PassiveReadStatuses.Missing,
                denied > 0 ? "procfs_metrics_permission_denied" : "procfs_metrics_files_missing", truncated, budget.BytesRead,
                Math.Max(1, skipped), Math.Max(1, visibilityGaps), details);
        }

        var observation = Parse(values, clock.GetUtcNow());
        var coreComplete = HasCoreMetrics(observation);
        if (!coreComplete)
        {
            visibilityGaps++;
            details["core_parse"] = "incomplete";
        }
        else
        {
            details["core_parse"] = "complete";
        }
        details["disk_aggregate_scope"] = "sum_all_visible_diskstats_rows_including_stacked_devices_and_partitions";
        details["network_aggregate_scope"] = "sum_all_visible_netdev_interfaces_including_loopback_and_virtual";
        var status = requiredMissing > 0 || denied > 0 || truncated || !coreComplete || visibilityGaps > 0
            ? PassiveReadStatuses.Partial
            : PassiveReadStatuses.Success;
        return new([observation], status, status == PassiveReadStatuses.Success ? "none" : "metrics_visibility_partial",
            truncated, budget.BytesRead, skipped, visibilityGaps, details);
    }

    internal static LinuxHostMetricsObservation Parse(IReadOnlyDictionary<string, string> values, DateTimeOffset observedAt)
    {
        ParseCpu(values.GetValueOrDefault("stat"), out var totalTicks, out var idleTicks, out var running, out var blocked);
        ParseMemory(values.GetValueOrDefault("meminfo"), out var memoryTotal, out var memoryAvailable, out var swapFree);
        ParseLoad(values.GetValueOrDefault("loadavg"), out var load1, out var load5, out var load15);
        ParseDisk(values.GetValueOrDefault("diskstats"), out var readSectors, out var writtenSectors);
        ParseNetwork(values.GetValueOrDefault("netdev"), out var receiveBytes, out var transmitBytes);
        return new()
        {
            ObservedAt = observedAt,
            UptimeSeconds = ParseFirstDecimalAsLong(values.GetValueOrDefault("uptime")),
            Load1Milli = load1,
            Load5Milli = load5,
            Load15Milli = load15,
            MemoryTotalBytes = memoryTotal,
            MemoryAvailableBytes = memoryAvailable,
            SwapFreeBytes = swapFree,
            ProcessesRunning = running,
            ProcessesBlocked = blocked,
            CpuTotalTicks = totalTicks,
            CpuIdleTicks = idleTicks,
            DiskReadSectors = readSectors,
            DiskWrittenSectors = writtenSectors,
            NetworkReceiveBytes = receiveBytes,
            NetworkTransmitBytes = transmitBytes,
            CpuPressureSomeAvg10Milli = ParsePressure(values.GetValueOrDefault("pressure_cpu")),
            MemoryPressureSomeAvg10Milli = ParsePressure(values.GetValueOrDefault("pressure_memory")),
            IoPressureSomeAvg10Milli = ParsePressure(values.GetValueOrDefault("pressure_io"))
        };
    }

    private static void ParseCpu(string? content, out long? total, out long? idle, out long? running, out long? blocked)
    {
        total = idle = running = blocked = null;
        foreach (var line in Lines(content))
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 9 && fields[0] == "cpu")
            {
                // guest and guest_nice are already included in user/nice by the kernel;
                // summing beyond steal would double count them.
                var numbers = fields.Skip(1).Take(8).Select(ParseLong).ToArray();
                if (numbers.Length == 8 && numbers.All(item => item.HasValue))
                {
                    total = numbers.Aggregate(0L, (current, item) => SaturatingAdd(current, item!.Value));
                    idle = SaturatingAdd(numbers.ElementAtOrDefault(3) ?? 0, numbers.ElementAtOrDefault(4) ?? 0);
                }
            }
            else if (fields.Length == 2 && fields[0] == "procs_running") running = ParseLong(fields[1]);
            else if (fields.Length == 2 && fields[0] == "procs_blocked") blocked = ParseLong(fields[1]);
        }
    }

    private static void ParseMemory(string? content, out long? total, out long? available, out long? swapFree)
    {
        total = available = swapFree = null;
        foreach (var line in Lines(content))
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2) continue;
            long? bytes = ParseLong(fields[1]) is { } kib && kib <= long.MaxValue / 1024 ? kib * 1024 : null;
            if (fields[0] == "MemTotal:") total = bytes;
            else if (fields[0] == "MemAvailable:") available = bytes;
            else if (fields[0] == "SwapFree:") swapFree = bytes;
        }
    }

    private static void ParseLoad(string? content, out long? one, out long? five, out long? fifteen)
    {
        one = five = fifteen = null;
        var fields = content?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields is not { Length: >= 3 }) return;
        one = ParseMilli(fields[0]);
        five = ParseMilli(fields[1]);
        fifteen = ParseMilli(fields[2]);
    }

    private static void ParseDisk(string? content, out long? reads, out long? writes)
    {
        long readTotal = 0;
        long writeTotal = 0;
        var observed = false;
        foreach (var line in Lines(content))
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 10) continue;
            if (ParseLong(fields[5]) is not { } read || ParseLong(fields[9]) is not { } write) continue;
            readTotal = SaturatingAdd(readTotal, read);
            writeTotal = SaturatingAdd(writeTotal, write);
            observed = true;
        }
        reads = observed ? readTotal : null;
        writes = observed ? writeTotal : null;
    }

    private static void ParseNetwork(string? content, out long? receive, out long? transmit)
    {
        long receiveTotal = 0;
        long transmitTotal = 0;
        var observed = false;
        foreach (var line in Lines(content).Skip(2))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var fields = line[(separator + 1)..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 9 || ParseLong(fields[0]) is not { } rx || ParseLong(fields[8]) is not { } tx) continue;
            receiveTotal = SaturatingAdd(receiveTotal, rx);
            transmitTotal = SaturatingAdd(transmitTotal, tx);
            observed = true;
        }
        receive = observed ? receiveTotal : null;
        transmit = observed ? transmitTotal : null;
    }

    private static long? ParsePressure(string? content)
    {
        var line = Lines(content).FirstOrDefault(item => item.StartsWith("some ", StringComparison.Ordinal));
        if (line is null) return null;
        var token = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(item => item.StartsWith("avg10=", StringComparison.Ordinal));
        return token is null ? null : ParseMilli(token[6..]);
    }

    private static long? ParseFirstDecimalAsLong(string? content)
    {
        var value = content?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return decimal.TryParse(value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var number)
            && number is >= 0 and <= long.MaxValue
            ? (long)decimal.Truncate(number)
            : null;
    }

    private static long? ParseMilli(string? value)
    {
        if (!decimal.TryParse(value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var number)
            || number < 0
            || number > long.MaxValue / 1000m)
        {
            return null;
        }
        var scaled = decimal.Round(number * 1000m, 0, MidpointRounding.AwayFromZero);
        return scaled <= long.MaxValue ? (long)scaled : null;
    }

    private static long? ParseLong(string? value) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number >= 0 ? number : null;

    private static bool HasCoreMetrics(LinuxHostMetricsObservation value) =>
        value.UptimeSeconds.HasValue
        && value.Load1Milli.HasValue
        && value.Load5Milli.HasValue
        && value.Load15Milli.HasValue
        && value.MemoryTotalBytes.HasValue
        && value.MemoryAvailableBytes.HasValue
        && value.SwapFreeBytes.HasValue
        && value.ProcessesRunning.HasValue
        && value.ProcessesBlocked.HasValue
        && value.CpuTotalTicks.HasValue
        && value.CpuIdleTicks.HasValue
        && value.DiskReadSectors.HasValue
        && value.DiskWrittenSectors.HasValue
        && value.NetworkReceiveBytes.HasValue
        && value.NetworkTransmitBytes.HasValue;

    private static long SaturatingAdd(long left, long right) => left > long.MaxValue - right ? long.MaxValue : left + right;

    private static IEnumerable<string> Lines(string? content) =>
        content?.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n', StringSplitOptions.RemoveEmptyEntries)
        ?? Array.Empty<string>();
}
