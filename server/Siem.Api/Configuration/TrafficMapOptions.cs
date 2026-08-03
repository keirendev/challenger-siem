using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Configuration;

public sealed class TrafficMapOptions
{
    public const string SectionName = "TrafficMap";

    public bool Enabled { get; set; }
    public bool ReadOnlyDatabase { get; set; }
    public string PublicBaseUrl { get; set; } = string.Empty;
    public TrafficMapOriginOptions Origin { get; set; } = new();
    public TrafficMapTileOptions Map { get; set; } = new();
    public TrafficMapGeolocationOptions Geolocation { get; set; } = new();
}

public sealed class TrafficMapOriginOptions
{
    public string Label { get; set; } = string.Empty;
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
}

public sealed class TrafficMapTileOptions
{
    public string TileUrl { get; set; } = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
    public string Attribution { get; set; } = "© OpenStreetMap contributors";
}

public sealed class TrafficMapGeolocationOptions
{
    public bool Enabled { get; set; } = true;
    public string Provider { get; set; } = "ipwhois";
    public string EndpointTemplate { get; set; } = "https://ipwho.is/{ip}";
    public string? ApiKey { get; set; }
    public string ApiKeyHeader { get; set; } = "X-Api-Key";
    public string CachePath { get; set; } = string.Empty;
    public int DailyRequestLimit { get; set; } = 900;
    public int RequestTimeoutSeconds { get; set; } = 5;
    public int SuccessTtlDays { get; set; } = 30;
    public int NegativeTtlHours { get; set; } = 6;
    public int MaximumQueuedLookups { get; set; } = 2048;
    public int MaximumProviderResponseBytes { get; set; } = 65536;
}

public sealed class TrafficMapOptionsValidator(IHostEnvironment environment) : IValidateOptions<TrafficMapOptions>
{
    public ValidateOptionsResult Validate(string? name, TrafficMapOptions options)
    {
        if (!options.Enabled)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        if (!Uri.TryCreate(options.PublicBaseUrl, UriKind.Absolute, out var publicBase)
            || !(publicBase.Scheme == Uri.UriSchemeHttps
                 || publicBase.Scheme == Uri.UriSchemeHttp && IsLoopbackHost(publicBase.Host))
            || !string.IsNullOrEmpty(publicBase.UserInfo)
            || !string.IsNullOrEmpty(publicBase.Query)
            || !string.IsNullOrEmpty(publicBase.Fragment)
            || publicBase.AbsolutePath != "/")
        {
            failures.Add("TrafficMap:PublicBaseUrl must be a credential-free root HTTPS URL or loopback HTTP URL.");
        }

        if (string.IsNullOrWhiteSpace(options.Origin.Label) || options.Origin.Label.Length > 120
            || options.Origin.Latitude is not >= -90 or not <= 90
            || options.Origin.Longitude is not >= -180 or not <= 180)
        {
            failures.Add("TrafficMap:Origin requires a label, latitude from -90 to 90, and longitude from -180 to 180.");
        }

        if (!Uri.TryCreate(options.Map.TileUrl.Replace("{z}", "0", StringComparison.Ordinal)
                .Replace("{x}", "0", StringComparison.Ordinal)
                .Replace("{y}", "0", StringComparison.Ordinal), UriKind.Absolute, out var tileUri)
            || tileUri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(tileUri.UserInfo)
            || !options.Map.TileUrl.Contains("{z}", StringComparison.Ordinal)
            || !options.Map.TileUrl.Contains("{x}", StringComparison.Ordinal)
            || !options.Map.TileUrl.Contains("{y}", StringComparison.Ordinal))
        {
            failures.Add("TrafficMap:Map:TileUrl must be an HTTPS template containing {z}, {x}, and {y}.");
        }

        if (string.IsNullOrWhiteSpace(options.Map.Attribution) || options.Map.Attribution.Length > 300)
        {
            failures.Add("TrafficMap:Map:Attribution is required and must be 300 characters or fewer.");
        }

        if (options.Geolocation.Enabled)
        {
            if (!string.Equals(options.Geolocation.Provider, "ipwhois", StringComparison.Ordinal))
            {
                failures.Add("TrafficMap:Geolocation:Provider currently supports only ipwhois-compatible responses.");
            }
            if (!Uri.TryCreate(options.Geolocation.EndpointTemplate.Replace("{ip}", "192.0.2.1", StringComparison.Ordinal), UriKind.Absolute, out var endpoint)
                || endpoint.Scheme != Uri.UriSchemeHttps
                || !string.IsNullOrEmpty(endpoint.UserInfo)
                || !options.Geolocation.EndpointTemplate.Contains("{ip}", StringComparison.Ordinal))
            {
                failures.Add("TrafficMap:Geolocation:EndpointTemplate must be an HTTPS URL containing {ip}.");
            }
            if (!string.IsNullOrWhiteSpace(options.Geolocation.ApiKey)
                && !IsHttpToken(options.Geolocation.ApiKeyHeader))
            {
                failures.Add("TrafficMap:Geolocation:ApiKeyHeader must be a valid HTTP header name when an API key is configured.");
            }
            if (string.IsNullOrWhiteSpace(options.Geolocation.CachePath))
            {
                failures.Add("TrafficMap:Geolocation:CachePath is required when geolocation is enabled.");
            }
            else
            {
                var fullPath = Path.GetFullPath(options.Geolocation.CachePath, environment.ContentRootPath);
                if (!fullPath.EndsWith(".sqlite3", StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add("TrafficMap:Geolocation:CachePath must use the .sqlite3 extension.");
                }
            }
            if (options.Geolocation.DailyRequestLimit is < 1 or > 100000
                || options.Geolocation.RequestTimeoutSeconds is < 1 or > 30
                || options.Geolocation.SuccessTtlDays is < 1 or > 365
                || options.Geolocation.NegativeTtlHours is < 1 or > 168
                || options.Geolocation.MaximumQueuedLookups is < 1 or > 10000
                || options.Geolocation.MaximumProviderResponseBytes is < 1024 or > 1048576)
            {
                failures.Add("TrafficMap geolocation limits are outside their supported bounds.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static bool IsLoopbackHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || System.Net.IPAddress.TryParse(host, out var address) && System.Net.IPAddress.IsLoopback(address);

    private static bool IsHttpToken(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 64
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');
}
