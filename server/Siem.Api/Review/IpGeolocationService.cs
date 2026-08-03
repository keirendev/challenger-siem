using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Channels;
using Challenger.Siem.Api.Configuration;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Review;

public sealed record IpGeolocationRecord(
    string Ip,
    string Status,
    double? Latitude,
    double? Longitude,
    string? City,
    string? Region,
    string? Country,
    string? CountryCode,
    string? Continent,
    long? Asn,
    string? Organization,
    string? Isp,
    string Provider,
    DateTimeOffset FetchedAtUtc,
    DateTimeOffset ExpiresAtUtc);

public sealed class IpGeolocationService : BackgroundService
{
    private readonly TrafficMapOptions options;
    private readonly string cachePath;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<IpGeolocationService> logger;
    private readonly Channel<string> queue;
    private readonly ConcurrentDictionary<string, byte> queued = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim initialization = new(1, 1);
    private bool initialized;

    public IpGeolocationService(
        IOptions<TrafficMapOptions> options,
        IHostEnvironment environment,
        IHttpClientFactory httpClientFactory,
        TimeProvider timeProvider,
        ILogger<IpGeolocationService> logger)
    {
        this.options = options.Value;
        this.httpClientFactory = httpClientFactory;
        this.timeProvider = timeProvider;
        this.logger = logger;
        cachePath = string.IsNullOrWhiteSpace(this.options.Geolocation.CachePath)
            ? string.Empty
            : Path.GetFullPath(this.options.Geolocation.CachePath, environment.ContentRootPath);
        queue = Channel.CreateBounded<string>(new BoundedChannelOptions(
            Math.Clamp(this.options.Geolocation.MaximumQueuedLookups, 1, 10000))
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public async Task<IReadOnlyDictionary<string, IpGeolocationRecord>> GetCachedAsync(
        IEnumerable<string> addresses,
        CancellationToken cancellationToken)
    {
        var distinct = addresses.Distinct(StringComparer.Ordinal).Take(10000).ToArray();
        if (!options.Enabled || !options.Geolocation.Enabled || distinct.Length == 0)
        {
            return new Dictionary<string, IpGeolocationRecord>(StringComparer.Ordinal);
        }

        await EnsureInitializedAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        var results = new Dictionary<string, IpGeolocationRecord>(StringComparer.Ordinal);
        await using var connection = await OpenAsync(cancellationToken);
        foreach (var batch in distinct.Chunk(500))
        {
            await using var command = connection.CreateCommand();
            var placeholders = new List<string>(batch.Length);
            for (var index = 0; index < batch.Length; index++)
            {
                var name = $"@ip{index}";
                placeholders.Add(name);
                command.Parameters.AddWithValue(name, batch[index]);
            }
            command.CommandText = $"select ip,status,latitude,longitude,city,region,country,country_code,continent,asn,organization,isp,provider,fetched_at_utc,expires_at_utc from ip_geolocation_cache where ip in ({string.Join(',', placeholders)});";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var record = ReadRecord(reader);
                if (record.ExpiresAtUtc > now)
                {
                    results[record.Ip] = record;
                }
            }
        }

        foreach (var ip in distinct)
        {
            if (results.ContainsKey(ip)) continue;
            if (!IpAddressScopeClassifier.IsPubliclyRoutable(ip))
            {
                results[ip] = Unmapped(ip, now);
                continue;
            }
            Enqueue(ip);
        }
        return results;
    }

    public async Task<IReadOnlyList<string>> SearchCachedIpsAsync(
        string? query,
        string? countryCode,
        long? asn,
        int limit,
        CancellationToken cancellationToken)
    {
        if (!options.Enabled || !options.Geolocation.Enabled
            || string.IsNullOrWhiteSpace(query) && string.IsNullOrWhiteSpace(countryCode) && !asn.HasValue)
        {
            return Array.Empty<string>();
        }

        await EnsureInitializedAsync(cancellationToken);
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var predicates = new List<string> { "status = 'ready'", "expires_at_utc > @now" };
        command.Parameters.AddWithValue("@now", timeProvider.GetUtcNow().ToString("O", CultureInfo.InvariantCulture));
        if (!string.IsNullOrWhiteSpace(query))
        {
            predicates.Add("(ip like @query escape '\\' or coalesce(city,'') like @query escape '\\' or coalesce(region,'') like @query escape '\\' or coalesce(country,'') like @query escape '\\' or coalesce(country_code,'') like @query escape '\\' or coalesce(organization,'') like @query escape '\\' or coalesce(isp,'') like @query escape '\\' or cast(asn as text) like @query escape '\\')");
            command.Parameters.AddWithValue("@query", $"%{EscapeLike(query.Trim())}%");
        }
        if (!string.IsNullOrWhiteSpace(countryCode))
        {
            predicates.Add("country_code = @country_code collate nocase");
            command.Parameters.AddWithValue("@country_code", countryCode.Trim());
        }
        if (asn.HasValue)
        {
            predicates.Add("asn = @asn");
            command.Parameters.AddWithValue("@asn", asn.Value);
        }
        command.Parameters.AddWithValue("@limit", Math.Clamp(limit, 1, 10001));
        command.CommandText = $"select ip from ip_geolocation_cache where {string.Join(" and ", predicates)} order by fetched_at_utc desc limit @limit;";
        var results = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) results.Add(reader.GetString(0));
        return results;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled || !options.Geolocation.Enabled) return;
        await EnsureInitializedAsync(stoppingToken);
        await foreach (var ip in queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                var result = await LookupWithRetryAsync(ip, stoppingToken);
                await StoreAsync(result, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or InvalidOperationException)
            {
                logger.LogWarning("A traffic-map geolocation lookup failed with {ErrorType}; the destination address was not logged.", ex.GetType().Name);
                await StoreFailureAsync(ip, "provider_error", TimeSpan.FromHours(options.Geolocation.NegativeTtlHours), CancellationToken.None);
            }
            finally
            {
                queued.TryRemove(ip, out _);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private void Enqueue(string ip)
    {
        if (!queued.TryAdd(ip, 0)) return;
        if (!queue.Writer.TryWrite(ip)) queued.TryRemove(ip, out _);
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (initialized) return;
        await initialization.WaitAsync(cancellationToken);
        try
        {
            if (initialized) return;
            var directory = Path.GetDirectoryName(cachePath) ?? throw new InvalidOperationException("Geolocation cache directory is unavailable.");
            RejectLink(directory, allowMissing: true);
            Directory.CreateDirectory(directory);
            RejectLink(directory, allowMissing: false);
            RejectLink(cachePath, allowMissing: true);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                if (!File.Exists(cachePath))
                {
                    using var created = new FileStream(cachePath, new FileStreamOptions
                    {
                        Mode = FileMode.CreateNew,
                        Access = FileAccess.ReadWrite,
                        Share = FileShare.None,
                        UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                    });
                }
                File.SetUnixFileMode(cachePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            await using var connection = await OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                pragma journal_mode = wal;
                pragma synchronous = full;
                create table if not exists ip_geolocation_cache (
                    ip text primary key,
                    status text not null,
                    latitude real null,
                    longitude real null,
                    city text null,
                    region text null,
                    country text null,
                    country_code text null,
                    continent text null,
                    asn integer null,
                    organization text null,
                    isp text null,
                    provider text not null,
                    fetched_at_utc text not null,
                    expires_at_utc text not null
                );
                create index if not exists idx_ip_geolocation_country_code on ip_geolocation_cache(country_code);
                create index if not exists idx_ip_geolocation_asn on ip_geolocation_cache(asn);
                create table if not exists ip_geolocation_quota (
                    quota_day_utc text primary key,
                    request_count integer not null
                );
                pragma optimize;
                """;
            await command.ExecuteNonQueryAsync(cancellationToken);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(cachePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            initialized = true;
        }
        finally
        {
            initialization.Release();
        }
    }

    private async Task<IpGeolocationRecord> LookupWithRetryAsync(string ip, CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            if (!await TryReserveDailyRequestAsync(cancellationToken))
                return Failure(ip, "quota_limited", TimeSpan.FromHours(1));

            try
            {
                return await LookupOnceAsync(ip, cancellationToken);
            }
            catch (Exception ex) when (IsTransient(ex, cancellationToken))
            {
                lastError = ex;
                if (attempt == 3) break;
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt * attempt), cancellationToken);
            }
        }

        throw new HttpRequestException("Geolocation provider failed after bounded retries.", lastError);
    }

    private async Task<IpGeolocationRecord> LookupOnceAsync(string ip, CancellationToken cancellationToken)
    {
        var endpoint = options.Geolocation.EndpointTemplate.Replace("{ip}", Uri.EscapeDataString(ip), StringComparison.Ordinal);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.Geolocation.RequestTimeoutSeconds));
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Challenger-SIEM", "2.5"));
        if (!string.IsNullOrWhiteSpace(options.Geolocation.ApiKey))
            request.Headers.TryAddWithoutValidation(options.Geolocation.ApiKeyHeader, options.Geolocation.ApiKey);
        var client = httpClientFactory.CreateClient("traffic-map-geolocation");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if ((int)response.StatusCode == 429)
        {
            return Failure(ip, "quota_limited", TimeSpan.FromHours(1));
        }
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > options.Geolocation.MaximumProviderResponseBytes)
        {
            throw new InvalidOperationException("Geolocation provider response exceeded the configured bound.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var bounded = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, timeout.Token);
            if (read == 0) break;
            if (bounded.Length + read > options.Geolocation.MaximumProviderResponseBytes)
                throw new InvalidOperationException("Geolocation provider response exceeded the configured bound.");
            await bounded.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
        }
        bounded.Position = 0;
        using var document = await JsonDocument.ParseAsync(bounded, cancellationToken: timeout.Token);
        var root = document.RootElement;
        if (!root.TryGetProperty("success", out var success) || !success.GetBoolean())
            return Failure(ip, "unmapped", TimeSpan.FromHours(options.Geolocation.NegativeTtlHours));
        if (!root.TryGetProperty("ip", out var echoed) || !string.Equals(echoed.GetString(), ip, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Geolocation provider returned a mismatched address.");
        if (!TryDouble(root, "latitude", -90, 90, out var latitude)
            || !TryDouble(root, "longitude", -180, 180, out var longitude))
            return Failure(ip, "unmapped", TimeSpan.FromHours(options.Geolocation.NegativeTtlHours));

        root.TryGetProperty("connection", out var connection);
        var now = timeProvider.GetUtcNow();
        return new(
            ip,
            "ready",
            latitude,
            longitude,
            BoundedString(root, "city", 160),
            BoundedString(root, "region", 160),
            BoundedString(root, "country", 160),
            BoundedString(root, "country_code", 8)?.ToUpperInvariant(),
            BoundedString(root, "continent", 80),
            connection.ValueKind == JsonValueKind.Object && connection.TryGetProperty("asn", out var asn) && asn.TryGetInt64(out var asnValue) && asnValue > 0 ? asnValue : null,
            connection.ValueKind == JsonValueKind.Object ? BoundedString(connection, "org", 200) : null,
            connection.ValueKind == JsonValueKind.Object ? BoundedString(connection, "isp", 200) : null,
            options.Geolocation.Provider,
            now,
            now.AddDays(options.Geolocation.SuccessTtlDays));
    }

    private static bool IsTransient(Exception exception, CancellationToken stoppingToken) =>
        exception is HttpRequestException or IOException or JsonException or InvalidOperationException
        || exception is OperationCanceledException && !stoppingToken.IsCancellationRequested;

    private async Task<bool> TryReserveDailyRequestAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        var day = timeProvider.GetUtcNow().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            insert into ip_geolocation_quota(quota_day_utc,request_count) values(@day,1)
            on conflict(quota_day_utc) do update set request_count = request_count + 1
            where request_count < @limit
            returning request_count;
            """;
        command.Parameters.AddWithValue("@day", day);
        command.Parameters.AddWithValue("@limit", options.Geolocation.DailyRequestLimit);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result is not null;
    }

    private Task StoreFailureAsync(string ip, string status, TimeSpan ttl, CancellationToken cancellationToken) =>
        StoreAsync(Failure(ip, status, ttl), cancellationToken);

    private IpGeolocationRecord Failure(string ip, string status, TimeSpan ttl)
    {
        var now = timeProvider.GetUtcNow();
        return new(ip, status, null, null, null, null, null, null, null, null, null, null,
            options.Geolocation.Provider, now, now.Add(ttl));
    }

    private static IpGeolocationRecord Unmapped(string ip, DateTimeOffset now) =>
        new(ip, "unmapped", null, null, null, null, null, null, null, null, null, null, "local_scope", now, now.AddYears(1));

    private async Task StoreAsync(IpGeolocationRecord record, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            insert into ip_geolocation_cache(ip,status,latitude,longitude,city,region,country,country_code,continent,asn,organization,isp,provider,fetched_at_utc,expires_at_utc)
            values(@ip,@status,@latitude,@longitude,@city,@region,@country,@country_code,@continent,@asn,@organization,@isp,@provider,@fetched,@expires)
            on conflict(ip) do update set status=excluded.status,latitude=excluded.latitude,longitude=excluded.longitude,
                city=excluded.city,region=excluded.region,country=excluded.country,country_code=excluded.country_code,
                continent=excluded.continent,asn=excluded.asn,organization=excluded.organization,isp=excluded.isp,
                provider=excluded.provider,fetched_at_utc=excluded.fetched_at_utc,expires_at_utc=excluded.expires_at_utc;
            """;
        command.Parameters.AddWithValue("@ip", record.Ip);
        command.Parameters.AddWithValue("@status", record.Status);
        command.Parameters.AddWithValue("@latitude", DbValue(record.Latitude));
        command.Parameters.AddWithValue("@longitude", DbValue(record.Longitude));
        command.Parameters.AddWithValue("@city", DbValue(record.City));
        command.Parameters.AddWithValue("@region", DbValue(record.Region));
        command.Parameters.AddWithValue("@country", DbValue(record.Country));
        command.Parameters.AddWithValue("@country_code", DbValue(record.CountryCode));
        command.Parameters.AddWithValue("@continent", DbValue(record.Continent));
        command.Parameters.AddWithValue("@asn", DbValue(record.Asn));
        command.Parameters.AddWithValue("@organization", DbValue(record.Organization));
        command.Parameters.AddWithValue("@isp", DbValue(record.Isp));
        command.Parameters.AddWithValue("@provider", record.Provider);
        command.Parameters.AddWithValue("@fetched", record.FetchedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("@expires", record.ExpiresAtUtc.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = cachePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true
        }.ToString());
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static IpGeolocationRecord ReadRecord(SqliteDataReader reader) => new(
        reader.GetString(0), reader.GetString(1), NullableDouble(reader, 2), NullableDouble(reader, 3),
        NullableString(reader, 4), NullableString(reader, 5), NullableString(reader, 6), NullableString(reader, 7),
        NullableString(reader, 8), NullableLong(reader, 9), NullableString(reader, 10), NullableString(reader, 11),
        reader.GetString(12), DateTimeOffset.Parse(reader.GetString(13), CultureInfo.InvariantCulture),
        DateTimeOffset.Parse(reader.GetString(14), CultureInfo.InvariantCulture));

    private static double? NullableDouble(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);
    private static long? NullableLong(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    private static string? NullableString(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static object DbValue(object? value) => value ?? DBNull.Value;
    private static string EscapeLike(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
    private static string? BoundedString(JsonElement value, string property, int maximum) =>
        value.TryGetProperty(property, out var item) && item.ValueKind == JsonValueKind.String
            ? Bound(item.GetString(), maximum)
            : null;
    private static string? Bound(string? value, int maximum) => string.IsNullOrWhiteSpace(value) ? null : value.Trim().Length <= maximum ? value.Trim() : value.Trim()[..maximum];
    private static bool TryDouble(JsonElement root, string property, double minimum, double maximum, out double value)
    {
        value = default;
        return root.TryGetProperty(property, out var element)
            && element.TryGetDouble(out value)
            && double.IsFinite(value)
            && value >= minimum
            && value <= maximum;
    }

    private static void RejectLink(string path, bool allowMissing)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            if (allowMissing) return;
            throw new InvalidOperationException("Required geolocation cache path is missing.");
        }
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Geolocation cache paths must not be symbolic links.");
    }
}

public static class IpAddressScopeClassifier
{
    public static bool IsPubliclyRoutable(string value)
    {
        if (!IPAddress.TryParse(value, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 ? IsPublicIpv4(bytes) : IsPublicIpv6(bytes);
    }

    private static bool IsPublicIpv4(byte[] value) =>
        value[0] != 0
        && value[0] != 10
        && value[0] != 127
        && !(value[0] == 100 && value[1] is >= 64 and <= 127)
        && !(value[0] == 169 && value[1] == 254)
        && !(value[0] == 172 && value[1] is >= 16 and <= 31)
        && !(value[0] == 192 && value[1] == 168)
        && !(value[0] == 192 && value[1] == 0 && value[2] is 0 or 2)
        && !(value[0] == 192 && value[1] == 88 && value[2] == 99)
        && !(value[0] == 198 && value[1] is 18 or 19)
        && !(value[0] == 198 && value[1] == 51 && value[2] == 100)
        && !(value[0] == 203 && value[1] == 0 && value[2] == 113)
        && value[0] < 224;

    private static bool IsPublicIpv6(byte[] value) =>
        !value.All(item => item == 0)
        && !(value[..15].All(item => item == 0) && value[15] == 1)
        && !value[..12].All(item => item == 0)
        && (value[0] & 0xfe) != 0xfc
        && !(value[0] == 0xfe && (value[1] & 0xc0) is 0x80 or 0xc0)
        && value[0] != 0xff
        && !Prefix(value, [0x00, 0x64, 0xff, 0x9b])
        && !Prefix(value, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        && !Prefix(value, [0x20, 0x01, 0x00, 0x00])
        && !Prefix(value, [0x20, 0x01, 0x00, 0x02, 0x00, 0x00])
        && !(Prefix(value, [0x20, 0x01, 0x00]) && (value[3] & 0xf0) is 0x10 or 0x20)
        && !Prefix(value, [0x20, 0x01, 0x0d, 0xb8])
        && !Prefix(value, [0x20, 0x02])
        && !(value[0] == 0x3f && value[1] == 0xff && (value[2] & 0xf0) == 0x00);

    private static bool Prefix(byte[] address, byte[] prefix) => address.AsSpan(0, prefix.Length).SequenceEqual(prefix);
}
