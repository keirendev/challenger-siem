using System.Globalization;
using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Review;

public static class TimeDisplay
{
    private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    public static string FormatUtc(DateTimeOffset? value, string format = "yyyy-MM-dd HH:mm:ss") =>
        value.HasValue ? $"{value.Value.ToUniversalTime().ToString(format, Invariant)} UTC" : "—";

    public static string FormatUtcInput(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm", Invariant) ?? string.Empty;

    public static string FormatHostTime(DateTimeOffset? value, HostTimezoneMetadata? timezone, string format = "yyyy-MM-dd HH:mm:ss")
    {
        if (!value.HasValue)
        {
            return "—";
        }

        if (TryGetOffset(timezone, out var offset))
        {
            return $"{value.Value.ToUniversalTime().ToOffset(offset).ToString(format, Invariant)} UTC{FormatOffset(offset)}";
        }

        return FormatUtc(value, format);
    }

    public static string HostTimezoneLabel(HostTimezoneMetadata? timezone)
    {
        if (!TryGetOffset(timezone, out var offset))
        {
            return "UTC (host timezone unknown)";
        }

        var name = !string.IsNullOrWhiteSpace(timezone?.Id)
            ? timezone.Id
            : !string.IsNullOrWhiteSpace(timezone?.DisplayName)
                ? timezone.DisplayName
                : "host timezone";
        var dst = timezone?.IsDaylightSavingTime is true ? ", DST" : string.Empty;
        return $"Host time ({name}, UTC{FormatOffset(offset)}{dst})";
    }

    public static string HostTimezoneShortLabel(HostTimezoneMetadata? timezone)
    {
        if (!TryGetOffset(timezone, out var offset))
        {
            return "timezone unknown";
        }

        var name = !string.IsNullOrWhiteSpace(timezone?.Id) ? timezone.Id : "host timezone";
        return $"{name} UTC{FormatOffset(offset)}";
    }

    public static string FormatOffset(int offsetMinutes) => FormatOffset(TimeSpan.FromMinutes(offsetMinutes));

    private static bool TryGetOffset(HostTimezoneMetadata? timezone, out TimeSpan offset)
    {
        if (timezone?.UtcOffsetMinutes is >= -14 * 60 and <= 14 * 60)
        {
            offset = TimeSpan.FromMinutes(timezone.UtcOffsetMinutes.Value);
            return true;
        }

        offset = TimeSpan.Zero;
        return false;
    }

    private static string FormatOffset(TimeSpan offset)
    {
        var sign = offset < TimeSpan.Zero ? "-" : "+";
        var absolute = offset.Duration();
        return string.Format(Invariant, "{0}{1:00}:{2:00}", sign, (int)absolute.TotalHours, absolute.Minutes);
    }
}
