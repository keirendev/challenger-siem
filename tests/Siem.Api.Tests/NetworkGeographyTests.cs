using System.Net;
using System.Text;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Mcp;
using Challenger.Siem.Api.Review;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class NetworkGeographyTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("10" + ".20.30.40", false)]
    [InlineData("192.0.2.10", false)]
    [InlineData("198.51.100.20", false)]
    [InlineData("203.0.113.30", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fec0::1", false)]
    [InlineData("2002:c000:0201::1", false)]
    [InlineData("3fff::1", false)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("not-an-address", false)]
    public void ProviderBoundaryAcceptsOnlyPubliclyRoutableAddresses(string address, bool expected) =>
        Assert.Equal(expected, IpAddressScopeClassifier.IsPubliclyRoutable(address));

    [Fact]
    public void GeographyQueryValidatesBoundsAndNormalizesFilters()
    {
        var query = NetworkGeographyQuery.FromQuery(new QueryCollection(new Dictionary<string, StringValues>
        {
            ["from"] = "2026-08-03T12:00:00Z",
            ["to"] = "2026-08-03T11:00:00Z",
            ["destination_port"] = "70000",
            ["protocol"] = "ICMP",
            ["country_code"] = "aus",
            ["limit"] = "5000"
        }));

        Assert.Contains(query.ValidationErrors, item => item.Field == "time");
        Assert.Contains(query.ValidationErrors, item => item.Field == "destination_port");
        Assert.Contains(query.ValidationErrors, item => item.Field == "protocol");
        Assert.Contains(query.ValidationErrors, item => item.Field == "country_code");
        Assert.Contains(query.ValidationErrors, item => item.Field == "limit");
    }

    [Fact]
    public void McpTrafficMapLinkContainsOnlyBoundedFilters()
    {
        var link = SiemMcpTools.BuildTrafficMapLink(
            "http://127.0.0.1:5081",
            new SiemMcpTrafficMapLinkRequest
            {
                Range = "7d",
                DestinationIp = "203.0.113.10",
                CountryCode = "AU",
                DestinationPort = 443
            });

        Assert.StartsWith("http://127.0.0.1:5081/ui/traffic?", link, StringComparison.Ordinal);
        Assert.Contains("range=7d", link, StringComparison.Ordinal);
        Assert.Contains("destination_port=443", link, StringComparison.Ordinal);
        Assert.DoesNotContain("token", link, StringComparison.OrdinalIgnoreCase);
        Assert.Throws<ArgumentException>(() => SiemMcpTools.BuildTrafficMapLink(
            "http://127.0.0.1:5081",
            new SiemMcpTrafficMapLinkRequest { Range = "custom", FromUtc = "invalid", ToUtc = "invalid" }));
        Assert.Throws<ArgumentException>(() => SiemMcpTools.BuildTrafficMapLink(
            "http://127.0.0.1:5081",
            new SiemMcpTrafficMapLinkRequest { Range = "all", DestinationIp = "not-an-ip" }));
        Assert.Throws<ArgumentException>(() => SiemMcpTools.BuildTrafficMapLink(
            "http://127.0.0.1:5081",
            new SiemMcpTrafficMapLinkRequest { Range = "all", Protocol = "icmp" }));
        Assert.Throws<ArgumentException>(() => SiemMcpTools.BuildTrafficMapLink(
            "http://127.0.0.1:5081",
            new SiemMcpTrafficMapLinkRequest { Range = "all", AgentId = "agent id with spaces" }));
    }

    [Fact]
    public void TrafficMapConfigurationRequiresExplicitSafeLocalSettings()
    {
        var validator = new TrafficMapOptionsValidator(new TestHostEnvironment(Path.GetTempPath()));
        var missing = validator.Validate(null, new TrafficMapOptions { Enabled = true });
        Assert.True(missing.Failed);
        Assert.Contains(missing.Failures!, item => item.Contains("PublicBaseUrl", StringComparison.Ordinal));
        Assert.Contains(missing.Failures!, item => item.Contains("Origin", StringComparison.Ordinal));
        Assert.Contains(missing.Failures!, item => item.Contains("CachePath", StringComparison.Ordinal));

        var credentialUrl = CreateOptions(Path.Combine(Path.GetTempPath(), "synthetic-map.sqlite3"));
        credentialUrl.PublicBaseUrl = "https://user:password@example.invalid/";
        Assert.True(validator.Validate(null, credentialUrl).Failed);

        var valid = validator.Validate(null, CreateOptions(Path.Combine(Path.GetTempPath(), "synthetic-map.sqlite3")));
        Assert.True(valid.Succeeded);
    }

    [Fact]
    public async Task McpCacheOnlyGeolocationMethodsNeverInitializeWriteOrCallProvider()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-readonly-{Guid.NewGuid():N}");
        using var http = new StubHttpClientFactory(new SequenceHandler((_, _) =>
            throw new InvalidOperationException("The cache-only path must not call the provider.")));
        var service = CreateService(CreateOptions(Path.Combine(root, "cache.sqlite3")), root, http, TimeProvider.System);

        var records = await service.GetCachedReadOnlyAsync(["8.8.8.8"], CancellationToken.None);
        var matches = await service.SearchCachedIpsReadOnlyAsync(null, "CN", null, 100, CancellationToken.None);

        Assert.Empty(records);
        Assert.Empty(matches);
        Assert.False(Directory.Exists(root));
        Assert.Equal(0, http.Handler.CallCount);
    }

    [Fact]
    public async Task GeolocationCachePersistsOnlyNormalizedFieldsWithPrivateModesAndExpiry()
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-{Guid.NewGuid():N}");
        var cachePath = Path.Combine(root, "cache.sqlite3");
        var clock = new MutableTimeProvider(DateTimeOffset.Parse("2026-08-03T12:00:00Z"));
        var handler = new SequenceHandler((_, _) => JsonResponse("""
            {"success":true,"ip":"8.8.8.8","city":"Synthetic City","region":"Synthetic Region","country":"Synthetic Country","country_code":"EX","continent":"Synthetic","latitude":-10.5,"longitude":120.25,"connection":{"asn":64500,"org":"Synthetic Org","isp":"Synthetic ISP"}}
            """));
        using var http = new StubHttpClientFactory(handler);
        var service = CreateService(CreateOptions(cachePath, "synthetic-provider-key"), root, http, clock);

        try
        {
            await service.StartAsync(CancellationToken.None);
            await service.GetCachedAsync(["8.8.8.8"], CancellationToken.None);
            var ready = await WaitForStatusAsync(service, "8.8.8.8", "ready", TimeSpan.FromSeconds(5));
            Assert.Equal("Synthetic City", ready.City);
            Assert.Equal(64500, ready.Asn);
            Assert.Equal(1, handler.CallCount);
            Assert.DoesNotContain("synthetic-provider-key", handler.LastRequestUri, StringComparison.Ordinal);
            Assert.Equal("synthetic-provider-key", handler.LastApiKey);
            await service.StopAsync(CancellationToken.None);

            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(root));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(cachePath));
            }

            await using (var connection = new SqliteConnection($"Data Source={cachePath}"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "pragma table_info(ip_geolocation_cache);";
                var columns = new List<string>();
                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync()) columns.Add(reader.GetString(1));
                Assert.DoesNotContain(columns, item => item.Contains("raw", StringComparison.OrdinalIgnoreCase));
                Assert.Contains("organization", columns);
                Assert.Contains("expires_at_utc", columns);
            }

            using var noNetwork = new StubHttpClientFactory(new SequenceHandler((_, _) => throw new InvalidOperationException("Cache hit must not call the provider.")));
            var restored = CreateService(CreateOptions(cachePath), root, noNetwork, clock);
            var cached = await restored.GetCachedAsync(["8.8.8.8"], CancellationToken.None);
            Assert.Equal("ready", Assert.Single(cached).Value.Status);
            Assert.Equal(0, noNetwork.Handler.CallCount);

            clock.Advance(TimeSpan.FromDays(2));
            var expired = await restored.GetCachedAsync(["8.8.8.8"], CancellationToken.None);
            Assert.Empty(expired);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task GeolocationProviderUsesBoundedRetriesAndHandlesRateLimits()
    {
        var retryRoot = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-retry-{Guid.NewGuid():N}");
        var retryHandler = new SequenceHandler((request, call) => call < 3
            ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            : JsonResponse($"{{\"success\":true,\"ip\":\"{request.RequestUri!.Segments[^1]}\",\"latitude\":1,\"longitude\":2}}"));
        using var retryHttp = new StubHttpClientFactory(retryHandler);
        var retryService = CreateService(CreateOptions(Path.Combine(retryRoot, "cache.sqlite3")), retryRoot, retryHttp, TimeProvider.System);
        try
        {
            await retryService.StartAsync(CancellationToken.None);
            await retryService.GetCachedAsync(["8.8.4.4"], CancellationToken.None);
            await WaitForStatusAsync(retryService, "8.8.4.4", "ready", TimeSpan.FromSeconds(10));
            Assert.Equal(3, retryHandler.CallCount);
        }
        finally
        {
            await retryService.StopAsync(CancellationToken.None);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(retryRoot)) Directory.Delete(retryRoot, recursive: true);
        }

        var rateRoot = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-rate-{Guid.NewGuid():N}");
        using var rateHttp = new StubHttpClientFactory(new SequenceHandler((_, _) => new HttpResponseMessage(HttpStatusCode.TooManyRequests)));
        var rateService = CreateService(CreateOptions(Path.Combine(rateRoot, "cache.sqlite3")), rateRoot, rateHttp, TimeProvider.System);
        try
        {
            await rateService.StartAsync(CancellationToken.None);
            await rateService.GetCachedAsync(["1.1.1.1"], CancellationToken.None);
            await WaitForStatusAsync(rateService, "1.1.1.1", "quota_limited", TimeSpan.FromSeconds(5));
            Assert.Equal(1, rateHttp.Handler.CallCount);
        }
        finally
        {
            await rateService.StopAsync(CancellationToken.None);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(rateRoot)) Directory.Delete(rateRoot, recursive: true);
        }

        var quotaRoot = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-quota-{Guid.NewGuid():N}");
        var quotaHandler = new SequenceHandler((request, _) => JsonResponse($"{{\"success\":true,\"ip\":\"{request.RequestUri!.Segments[^1]}\",\"latitude\":1,\"longitude\":2}}"));
        using var quotaHttp = new StubHttpClientFactory(quotaHandler);
        var quotaOptions = CreateOptions(Path.Combine(quotaRoot, "cache.sqlite3"));
        quotaOptions.Geolocation.DailyRequestLimit = 1;
        var quotaService = CreateService(quotaOptions, quotaRoot, quotaHttp, TimeProvider.System);
        try
        {
            await quotaService.StartAsync(CancellationToken.None);
            await quotaService.GetCachedAsync(["9.9.9.9", "8.8.8.8"], CancellationToken.None);
            await WaitForStatusAsync(quotaService, "9.9.9.9", "ready", TimeSpan.FromSeconds(5));
            await WaitForStatusAsync(quotaService, "8.8.8.8", "quota_limited", TimeSpan.FromSeconds(5));
            Assert.Equal(1, quotaHandler.CallCount);
        }
        finally
        {
            await quotaService.StopAsync(CancellationToken.None);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(quotaRoot)) Directory.Delete(quotaRoot, recursive: true);
        }
    }

    [Fact]
    public async Task GeolocationProviderRejectsMalformedOversizedAndTimedOutResponsesWithoutSecretLogs()
    {
        var malformedLogger = new CapturingLogger<IpGeolocationService>();
        await AssertProviderFailureAsync(
            new SequenceHandler((_, _) => JsonResponse("{\"secret\":\"synthetic-provider-key\"")),
            malformedLogger,
            "8.8.8.8");

        var oversizedLogger = new CapturingLogger<IpGeolocationService>();
        await AssertProviderFailureAsync(
            new SequenceHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(new string('x', 5000), Encoding.UTF8, "application/json")
            }),
            oversizedLogger,
            "8.8.4.4");

        var timeoutLogger = new CapturingLogger<IpGeolocationService>();
        await AssertProviderFailureAsync(new TimeoutHandler(), timeoutLogger, "1.0.0.1", requestTimeoutSeconds: 1, timeout: TimeSpan.FromSeconds(8));
    }

    [Fact]
    public async Task GeolocationCacheRejectsSymbolicLinkDirectories()
    {
        if (OperatingSystem.IsWindows()) return;
        var root = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-link-{Guid.NewGuid():N}");
        var real = Path.Combine(root, "real");
        var link = Path.Combine(root, "link");
        Directory.CreateDirectory(real);
        Directory.CreateSymbolicLink(link, real);
        using var http = new StubHttpClientFactory(new SequenceHandler((_, _) => throw new InvalidOperationException("Provider must not be called.")));
        var service = CreateService(CreateOptions(Path.Combine(link, "cache.sqlite3")), root, http, TimeProvider.System);
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => service.GetCachedAsync(["8.8.8.8"], CancellationToken.None));
            Assert.Equal(0, http.Handler.CallCount);
        }
        finally
        {
            if (Directory.Exists(link)) Directory.Delete(link);
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static TrafficMapOptions CreateOptions(string cachePath, string? apiKey = null) => new()
    {
        Enabled = true,
        PublicBaseUrl = "http://127.0.0.1:5081",
        Origin = new() { Label = "Synthetic origin", Latitude = 0, Longitude = 0 },
        Geolocation = new()
        {
            Enabled = true,
            CachePath = cachePath,
            ApiKey = apiKey,
            DailyRequestLimit = 20,
            RequestTimeoutSeconds = 2,
            SuccessTtlDays = 1,
            NegativeTtlHours = 1,
            MaximumQueuedLookups = 16,
            MaximumProviderResponseBytes = 4096
        }
    };

    private static IpGeolocationService CreateService(TrafficMapOptions options, string contentRoot, IHttpClientFactory http, TimeProvider clock) =>
        CreateService(options, contentRoot, http, clock, NullLogger<IpGeolocationService>.Instance);

    private static IpGeolocationService CreateService(
        TrafficMapOptions options,
        string contentRoot,
        IHttpClientFactory http,
        TimeProvider clock,
        ILogger<IpGeolocationService> logger) =>
        new(Options.Create(options), new TestHostEnvironment(contentRoot), http, clock, logger);

    private static async Task AssertProviderFailureAsync(
        CountingHandler handler,
        CapturingLogger<IpGeolocationService> logger,
        string ip,
        int requestTimeoutSeconds = 2,
        TimeSpan? timeout = null)
    {
        var root = Path.Combine(Path.GetTempPath(), $"challenger-siem-geo-failure-{Guid.NewGuid():N}");
        using var http = new StubHttpClientFactory(handler);
        var options = CreateOptions(Path.Combine(root, "cache.sqlite3"), "synthetic-provider-key");
        options.Geolocation.RequestTimeoutSeconds = requestTimeoutSeconds;
        var service = CreateService(options, root, http, TimeProvider.System, logger);
        try
        {
            await service.StartAsync(CancellationToken.None);
            await service.GetCachedAsync([ip], CancellationToken.None);
            await WaitForStatusAsync(service, ip, "provider_error", timeout ?? TimeSpan.FromSeconds(6));
            Assert.Equal(3, handler.CallCount);
            Assert.All(logger.Messages, message =>
            {
                Assert.DoesNotContain("synthetic-provider-key", message, StringComparison.Ordinal);
                Assert.DoesNotContain(ip, message, StringComparison.Ordinal);
            });
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<IpGeolocationRecord> WaitForStatusAsync(IpGeolocationService service, string ip, string status, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (true)
        {
            var values = await service.GetCachedAsync([ip], cancellation.Token);
            if (values.TryGetValue(ip, out var value) && value.Status == status) return value;
            await Task.Delay(50, cancellation.Token);
        }
    }

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    private abstract class CountingHandler : HttpMessageHandler
    {
        public int CallCount { get; protected set; }
        public string LastRequestUri { get; private set; } = string.Empty;
        public string? LastApiKey { get; private set; }

        protected int Capture(HttpRequestMessage request)
        {
            CallCount++;
            LastRequestUri = request.RequestUri?.AbsoluteUri ?? string.Empty;
            LastApiKey = request.Headers.TryGetValues("X-Api-Key", out var values) ? values.Single() : null;
            return CallCount;
        }
    }

    private sealed class SequenceHandler(Func<HttpRequestMessage, int, HttpResponseMessage> response) : CountingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response(request, Capture(request)));
    }

    private sealed class TimeoutHandler : CountingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Capture(request);
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return JsonResponse("{}");
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory, IDisposable
    {
        private readonly HttpClient client;
        public CountingHandler Handler { get; }

        public StubHttpClientFactory(CountingHandler handler)
        {
            Handler = handler;
            client = new HttpClient(handler, disposeHandler: false);
        }

        public HttpClient CreateClient(string name) => client;
        public void Dispose() => client.Dispose();
    }

    private sealed class TestHostEnvironment(string contentRoot) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Synthetic";
        public string ContentRootPath { get; set; } = contentRoot;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan duration) => current = current.Add(duration);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NoopScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));

        private sealed class NoopScope : IDisposable
        {
            public static NoopScope Instance { get; } = new();
            public void Dispose() { }
        }
    }
}
