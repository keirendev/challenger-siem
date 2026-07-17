using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Challenger.Siem.LinuxAgent.Config;

namespace Challenger.Siem.LinuxAgent.Passive;

public sealed class LinuxProcfsNetworkSource(string procNetRoot = "/proc/net") : ILinuxNetworkSnapshotSource
{
    private static readonly (string FileName, string Protocol, bool Ipv6, bool Required)[] Sources =
    [
        ("tcp", "tcp", false, true),
        ("tcp6", "tcp", true, false),
        ("udp", "udp", false, true),
        ("udp6", "udp", true, false)
    ];

    public async Task<PassiveReadResult<LinuxSocketObservation>> ReadAsync(
        PassiveTelemetryOptions options,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(procNetRoot))
            return new(Array.Empty<LinuxSocketObservation>(), PassiveReadStatuses.Missing, "procfs_network_missing", false, 0);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.ScanTimeoutSeconds));
        var budget = new ProcfsReadBudget(options.MaxNetworkReadBytesPerScan);
        var records = new List<LinuxSocketObservation>();
        long skipped = 0;
        var denied = 0;
        var malformed = 0;
        var requiredObserved = 0;
        var requiredUnavailable = 0;
        long visibilityGaps = 0;
        var truncated = false;
        var deadlineExceeded = false;
        var ioFailure = false;
        var details = new Dictionary<string, string>(StringComparer.Ordinal);

        try
        {
            var boot = await LinuxProcfsReader.ReadTextAsync(
                Path.GetFullPath(Path.Combine(procNetRoot, "..", "sys", "kernel", "random", "boot_id")),
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
                    Array.Empty<LinuxSocketObservation>(),
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

            foreach (var source in Sources)
            {
                var result = await LinuxProcfsReader.ReadTextAsync(
                    Path.Combine(procNetRoot, source.FileName),
                    options.MaxNetworkReadBytesPerScan,
                    budget,
                    deadline.Token);
                if (!result.Success)
                {
                    if (result.ErrorCode == "missing" && !source.Required)
                    {
                        details[$"table_{source.FileName}"] = "not_available";
                        continue;
                    }
                    if (result.ErrorCode == "permission_denied") denied++;
                    if (source.Required) requiredUnavailable++;
                    visibilityGaps++;
                    truncated |= result.Truncated || result.ErrorCode == "read_budget_exhausted";
                    details[$"table_{source.FileName}"] = result.ErrorCode;
                    continue;
                }
                if (source.Required) requiredObserved++;
                details[$"table_{source.FileName}"] = result.Truncated ? "truncated" : "observed";
                if (result.Truncated)
                {
                    truncated = true;
                    visibilityGaps++;
                }
                var lines = result.Text!.Replace("\r", string.Empty, StringComparison.Ordinal)
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries);
                for (var index = 1; index < lines.Length; index++)
                {
                    if (records.Count >= options.MaxSocketsPerScan + 1)
                    {
                        var omitted = lines.Length - index;
                        skipped += omitted;
                        visibilityGaps += Math.Max(1, omitted);
                        truncated = true;
                        break;
                    }
                    if (!TryParseSocketLine(lines[index], source.Protocol, source.Ipv6, out var observation))
                    {
                        malformed++;
                        visibilityGaps++;
                        continue;
                    }
                    records.Add(observation);
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            deadlineExceeded = true;
            truncated = true;
            skipped++;
            visibilityGaps++;
        }
        catch (IOException)
        {
            ioFailure = true;
            skipped++;
            visibilityGaps++;
        }

        var grouped = records
            .GroupBy(item => item.Key, StringComparer.Ordinal)
            .Select(group =>
            {
                var first = group.First();
                var count = group.Aggregate(0, (current, item) => SaturatingAdd(current, item.Count));
                return first with
                {
                    Count = count,
                    Signature = HashSignature(first.Key, first.State, first.UserId, count.ToString(CultureInfo.InvariantCulture))
                };
            })
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .ToArray();
        if (grouped.Length > options.MaxSocketsPerScan)
        {
            var omitted = grouped.Length - options.MaxSocketsPerScan;
            skipped += omitted;
            visibilityGaps += omitted;
            grouped = grouped.Take(options.MaxSocketsPerScan).ToArray();
            truncated = true;
        }
        skipped += malformed;

        var status = grouped.Length == 0 && requiredObserved == 0 && denied > 0
            ? PassiveReadStatuses.PermissionDenied
            : grouped.Length == 0 && requiredObserved == 0 && requiredUnavailable == Sources.Count(source => source.Required)
                ? PassiveReadStatuses.Missing
                : deadlineExceeded || ioFailure || truncated || requiredUnavailable > 0 || denied > 0 || malformed > 0 || visibilityGaps > 0
                    ? PassiveReadStatuses.Partial
                    : PassiveReadStatuses.Success;
        var error = status switch
        {
            PassiveReadStatuses.Success => "none",
            PassiveReadStatuses.PermissionDenied => "procfs_network_permission_denied",
            PassiveReadStatuses.Missing => "procfs_network_files_missing",
            _ when deadlineExceeded => "network_scan_deadline",
            _ when ioFailure => "procfs_network_io_error",
            _ when truncated => "network_scan_truncated",
            _ => "network_visibility_partial"
        };
        details["aggregate_scope"] = "all_visible_proc_net_inet_tables";
        details["malformed_rows"] = malformed.ToString(CultureInfo.InvariantCulture);
        return new(grouped, status, error, truncated, budget.BytesRead, skipped, visibilityGaps, details);
    }

    internal static bool TryParseSocketLine(
        string line,
        string protocol,
        bool ipv6,
        out LinuxSocketObservation observation)
    {
        observation = null!;
        var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 10
            || !TryParseEndpoint(fields[1], ipv6, out var localAddress, out var localPort)
            || !TryParseEndpoint(fields[2], ipv6, out var remoteAddressValue, out var remotePortValue))
        {
            return false;
        }
        var state = MapState(protocol, fields[3]);
        if (state is null) return false;
        var remoteAddress = IsUnspecified(remoteAddressValue) ? null : remoteAddressValue;
        int? remotePort = remotePortValue == 0 ? null : remotePortValue;
        var userId = uint.TryParse(fields[7], NumberStyles.None, CultureInfo.InvariantCulture, out var uid)
            ? uid.ToString(CultureInfo.InvariantCulture)
            : null;
        long? inode = long.TryParse(fields[9], NumberStyles.None, CultureInfo.InvariantCulture, out var inodeValue) && inodeValue > 0
            ? inodeValue
            : null;
        var tupleIdentity = string.Join('|', protocol, localAddress, localPort.ToString(CultureInfo.InvariantCulture),
            remoteAddress ?? string.Empty, remotePort?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            inode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty);
        var key = HashSignature(tupleIdentity);
        var signature = HashSignature(key, state, userId);
        observation = new(key, signature, protocol, state, localAddress, localPort, remoteAddress, remotePort, inode, userId, 1);
        return true;
    }

    internal static bool TryParseEndpoint(string value, bool ipv6, out string address, out int port)
    {
        address = string.Empty;
        port = 0;
        var separator = value.LastIndexOf(':');
        if (separator <= 0
            || !int.TryParse(value[(separator + 1)..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out port)
            || port is < 0 or > 65_535)
        {
            return false;
        }
        var encoded = value[..separator];
        try
        {
            var bytes = Convert.FromHexString(encoded);
            if ((!ipv6 && bytes.Length != 4) || (ipv6 && bytes.Length != 16)) return false;
            if (ipv6)
            {
                for (var offset = 0; offset < bytes.Length; offset += 4) Array.Reverse(bytes, offset, 4);
            }
            else
            {
                Array.Reverse(bytes);
            }
            address = new IPAddress(bytes).ToString();
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string? MapState(string protocol, string value)
    {
        if (protocol == "udp")
        {
            return value.ToUpperInvariant() switch
            {
                "07" => "unconnected",
                "01" => "established",
                _ when value.Length == 2 && value.All(char.IsAsciiHexDigit) => "unknown",
                _ => null
            };
        }
        return value.ToUpperInvariant() switch
        {
            "01" => "established",
            "02" => "syn_sent",
            "03" => "syn_received",
            "04" => "fin_wait_1",
            "05" => "fin_wait_2",
            "06" => "time_wait",
            "07" => "closed",
            "08" => "close_wait",
            "09" => "last_ack",
            "0A" => "listen",
            "0B" => "closing",
            "0C" => "new_syn_received",
            _ => null
        };
    }

    private static bool IsUnspecified(string value) =>
        IPAddress.TryParse(value, out var address) && address.Equals(address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? IPAddress.Any
            : IPAddress.IPv6Any);

    private static string HashSignature(params string?[] values) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\u001f', values.Select(item => item ?? string.Empty))))).ToLowerInvariant();

    private static int SaturatingAdd(int left, int right) =>
        left > int.MaxValue - right ? int.MaxValue : left + right;
}
