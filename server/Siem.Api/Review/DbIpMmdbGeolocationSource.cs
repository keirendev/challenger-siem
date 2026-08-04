using System.Globalization;
using System.Net;
using MaxMind.Db;

namespace Challenger.Siem.Api.Review;

internal interface ILocalIpGeolocationSource : IDisposable
{
    string ProviderId { get; }
    IpGeolocationRecord Lookup(string ip, DateTimeOffset now, TimeSpan successTtl, TimeSpan negativeTtl);
}

internal sealed class DbIpMmdbGeolocationSource : ILocalIpGeolocationSource
{
    private const long MaximumDatabaseBytes = 1024L * 1024 * 1024;
    private readonly Reader country;
    private readonly Reader? city;
    private readonly Reader? asn;

    public DbIpMmdbGeolocationSource(string countryPath, string? cityPath, string? asnPath)
    {
        country = Open(countryPath);
        try
        {
            city = OpenOptional(cityPath);
            asn = OpenOptional(asnPath);
        }
        catch
        {
            city?.Dispose();
            country.Dispose();
            throw;
        }

        ProviderId = string.Join(':',
            TrafficMapLocalDatabaseMetadata.ProviderName,
            Stamp(country),
            city is null ? "no-city" : Stamp(city),
            asn is null ? "no-asn" : Stamp(asn));
    }

    public string ProviderId { get; }

    public IpGeolocationRecord Lookup(string ip, DateTimeOffset now, TimeSpan successTtl, TimeSpan negativeTtl)
    {
        var address = IPAddress.Parse(ip);
        return DbIpMmdbRecordMapper.Map(
            ip,
            country.Find<Dictionary<string, object>>(address),
            city?.Find<Dictionary<string, object>>(address),
            asn?.Find<Dictionary<string, object>>(address),
            ProviderId,
            now,
            successTtl,
            negativeTtl);
    }

    public void Dispose()
    {
        asn?.Dispose();
        city?.Dispose();
        country.Dispose();
    }

    private static Reader? OpenOptional(string? path) => string.IsNullOrWhiteSpace(path) ? null : Open(path);

    private static Reader Open(string path)
    {
        RejectLink(path);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is <= 0 or > MaximumDatabaseBytes)
            throw new InvalidOperationException("A configured local geolocation database is missing or outside the supported size bound.");
        return new Reader(path, FileAccessMode.MemoryMapped);
    }

    private static void RejectLink(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("A configured local geolocation database directory is unavailable.");
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0
            || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Local geolocation database paths must not be symbolic links.");
        }
    }

    private static string Stamp(Reader reader) => string.Create(
        CultureInfo.InvariantCulture,
        $"{reader.Metadata.DatabaseType}-{new DateTimeOffset(DateTime.SpecifyKind(reader.Metadata.BuildDate, DateTimeKind.Utc)).ToUnixTimeSeconds()}");
}

internal static class TrafficMapLocalDatabaseMetadata
{
    public const string ProviderName = "dbip_mmdb";
    public const string AttributionText = "IP geolocation by DB-IP";
    public const string AttributionUrl = "https://db-ip.com";
}

internal static class DbIpMmdbRecordMapper
{
    public static IpGeolocationRecord Map(
        string ip,
        IReadOnlyDictionary<string, object>? countryRecord,
        IReadOnlyDictionary<string, object>? cityRecord,
        IReadOnlyDictionary<string, object>? asnRecord,
        string providerId,
        DateTimeOffset now,
        TimeSpan successTtl,
        TimeSpan negativeTtl)
    {
        var country = Nested(cityRecord, "country") ?? Nested(countryRecord, "country") ?? Nested(asnRecord, "country");
        var continent = Nested(cityRecord, "continent") ?? Nested(countryRecord, "continent") ?? Nested(asnRecord, "continent");
        var city = Nested(cityRecord, "city");
        var location = Nested(cityRecord, "location");
        var traits = Nested(asnRecord, "traits");
        var subdivision = FirstMap(Value(cityRecord, "subdivisions"));
        var countryName = Name(country);
        var countryCode = Bound(Text(country, "iso_code"), 8)?.ToUpperInvariant();
        var latitude = Number(location, "latitude", -90, 90);
        var longitude = Number(location, "longitude", -180, 180);
        var asn = Integer(traits, "autonomous_system_number")
                  ?? Integer(asnRecord, "autonomous_system_number")
                  ?? Integer(asnRecord, "asn");
        var organization = Bound(
            Text(traits, "autonomous_system_organization")
            ?? Text(asnRecord, "autonomous_system_organization")
            ?? Text(asnRecord, "organization"),
            200);
        var isp = Bound(Text(traits, "isp"), 200);
        var hasGeography = countryCode is not null || countryName is not null || latitude.HasValue && longitude.HasValue;

        return new(
            ip,
            hasGeography ? "ready" : "unmapped",
            latitude,
            longitude,
            Bound(Name(city), 160),
            Bound(Name(subdivision), 160),
            Bound(countryName, 160),
            countryCode,
            Bound(Name(continent) ?? Text(continent, "code"), 80),
            asn is > 0 ? asn : null,
            organization,
            isp,
            providerId,
            now,
            now.Add(hasGeography ? successTtl : negativeTtl));
    }

    private static IReadOnlyDictionary<string, object>? Nested(IReadOnlyDictionary<string, object>? value, string key) =>
        AsMap(Value(value, key));

    private static object? Value(IReadOnlyDictionary<string, object>? value, string key) =>
        value is not null && value.TryGetValue(key, out var item) ? item : null;

    private static IReadOnlyDictionary<string, object>? AsMap(object? value) => value switch
    {
        IReadOnlyDictionary<string, object> readOnly => readOnly,
        IDictionary<string, object> dictionary => new Dictionary<string, object>(dictionary, StringComparer.Ordinal),
        _ => null
    };

    private static IReadOnlyDictionary<string, object>? FirstMap(object? value)
    {
        if (value is not System.Collections.IEnumerable items || value is string) return null;
        foreach (var item in items)
        {
            var map = AsMap(item);
            if (map is not null) return map;
        }
        return null;
    }

    private static string? Name(IReadOnlyDictionary<string, object>? value)
    {
        var names = Nested(value, "names");
        if (names is null) return null;
        var english = Text(names, "en");
        return english ?? names.OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(item => Convert.ToString(item.Value, CultureInfo.InvariantCulture))
            .FirstOrDefault(item => !string.IsNullOrWhiteSpace(item));
    }

    private static string? Text(IReadOnlyDictionary<string, object>? value, string key) =>
        Value(value, key) is string text && !string.IsNullOrWhiteSpace(text) ? text.Trim() : null;

    private static double? Number(IReadOnlyDictionary<string, object>? value, string key, double minimum, double maximum)
    {
        var item = Value(value, key);
        if (item is null) return null;
        try
        {
            var number = Convert.ToDouble(item, CultureInfo.InvariantCulture);
            return double.IsFinite(number) && number >= minimum && number <= maximum ? number : null;
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private static long? Integer(IReadOnlyDictionary<string, object>? value, string key)
    {
        var item = Value(value, key);
        if (item is null) return null;
        try
        {
            return Convert.ToInt64(item, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private static string? Bound(string? value, int maximum) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().Length <= maximum ? value.Trim() : value.Trim()[..maximum];
}
