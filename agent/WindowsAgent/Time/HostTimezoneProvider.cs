using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.WindowsAgent.Time;

public static class HostTimezoneProvider
{
    public static HostTimezoneMetadata Current() => ForInstant(DateTimeOffset.UtcNow, TimeZoneInfo.Local);

    public static HostTimezoneMetadata ForInstant(DateTimeOffset instant) => ForInstant(instant, TimeZoneInfo.Local);

    public static HostTimezoneMetadata ForInstant(DateTimeOffset instant, TimeZoneInfo timeZone)
    {
        var utcInstant = instant.ToUniversalTime();
        var offset = timeZone.GetUtcOffset(utcInstant);
        var hostLocalTime = TimeZoneInfo.ConvertTime(utcInstant, timeZone).DateTime;

        return new HostTimezoneMetadata
        {
            Id = Truncate(timeZone.Id, 128),
            DisplayName = Truncate(timeZone.DisplayName, 255),
            StandardName = Truncate(timeZone.StandardName, 255),
            DaylightName = Truncate(timeZone.DaylightName, 255),
            BaseUtcOffsetMinutes = ToWholeMinutes(timeZone.BaseUtcOffset),
            UtcOffsetMinutes = ToWholeMinutes(offset),
            IsDaylightSavingTime = timeZone.IsDaylightSavingTime(hostLocalTime)
        };
    }

    public static DateTimeOffset ToUtc(DateTime? value) => ToUtc(value, TimeZoneInfo.Local);

    public static DateTimeOffset ToUtc(DateTime? value, TimeZoneInfo timeZone)
    {
        if (!value.HasValue)
        {
            return DateTimeOffset.UtcNow;
        }

        return value.Value.Kind switch
        {
            DateTimeKind.Utc => new DateTimeOffset(DateTime.SpecifyKind(value.Value, DateTimeKind.Utc)),
            DateTimeKind.Local => new DateTimeOffset(value.Value).ToUniversalTime(),
            _ => UnspecifiedHostTimeToUtc(value.Value, timeZone)
        };
    }

    private static DateTimeOffset UnspecifiedHostTimeToUtc(DateTime value, TimeZoneInfo timeZone)
    {
        var hostLocal = DateTime.SpecifyKind(value, DateTimeKind.Unspecified);
        var offset = timeZone.GetUtcOffset(hostLocal);
        return new DateTimeOffset(hostLocal, offset).ToUniversalTime();
    }

    private static int ToWholeMinutes(TimeSpan offset) => Convert.ToInt32(Math.Round(offset.TotalMinutes, MidpointRounding.AwayFromZero));

    private static string Truncate(string value, int maxLength) =>
        string.IsNullOrEmpty(value) || value.Length <= maxLength ? value : value[..maxLength];
}
