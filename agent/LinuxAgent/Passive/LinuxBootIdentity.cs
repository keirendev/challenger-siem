using System.Security.Cryptography;
using System.Text;

namespace Challenger.Siem.LinuxAgent.Passive;

internal static class LinuxBootIdentity
{
    public const string DetailKey = "boot_identity_sha256";

    public static bool TryHash(ProcfsTextResult result, out string hash)
    {
        hash = string.Empty;
        var value = result.Text?.Trim();
        if (!result.Success
            || result.Truncated
            || value is null
            || !Guid.TryParseExact(value, "D", out var parsed))
        {
            return false;
        }

        var canonical = parsed.ToString("D");
        hash = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(canonical))).ToLowerInvariant();
        return true;
    }

    public static bool IsHash(string? value) =>
        value is { Length: 64 } && value.All(char.IsAsciiHexDigit);

    public static LinuxPassiveTelemetryState ApplyEpoch(
        LinuxPassiveTelemetryState state,
        string bootIdentitySha256)
    {
        if (!IsHash(bootIdentitySha256))
            throw new InvalidOperationException("Linux boot identity hash is invalid.");
        if (string.Equals(state.BootIdentitySha256, bootIdentitySha256, StringComparison.Ordinal))
            return state;

        return state with
        {
            BootIdentitySha256 = bootIdentitySha256,
            Process = new LinuxPassiveProcessState
            {
                Progress = state.Process.Progress
            },
            Network = new LinuxPassiveNetworkState
            {
                Progress = state.Network.Progress
            },
            Metrics = new LinuxPassiveMetricsState
            {
                Progress = state.Metrics.Progress
            }
        };
    }
}
