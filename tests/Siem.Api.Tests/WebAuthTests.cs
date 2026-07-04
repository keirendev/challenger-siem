using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class WebAuthTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string ReviewToken = "test-review-token";
    private readonly WebApplicationFactory<Program> factory;

    public WebAuthTests(WebApplicationFactory<Program> factory)
    {
        this.factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SiemDatabase"] = "Host=localhost;Port=5432;Database=challenger_siem_tests;Username=siem;Password=test",
                    ["Auth:EnrollmentToken"] = "test-enrollment-token",
                    ["Auth:ReviewToken"] = ReviewToken
                });
            });
        });
    }

    [Fact]
    public async Task DashboardRequiresOperatorLogin()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await client.GetAsync("/");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/login", response.Headers.Location?.OriginalString, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoginRejectsInvalidReviewTokenWithoutSettingReviewCookie()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var antiForgeryToken = await GetAntiForgeryTokenAsync(client);

        using var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgeryToken,
            ["ReviewToken"] = "wrong-token"
        }));

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Invalid review token.", body, StringComparison.Ordinal);
        Assert.DoesNotContain(response.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : Array.Empty<string>(),
            cookie => cookie.Contains(".ChallengerSiem.Review", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LoginAcceptsValidReviewTokenAndSetsHttpOnlyReviewCookie()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var antiForgeryToken = await GetAntiForgeryTokenAsync(client);

        using var response = await client.PostAsync("/login?returnUrl=%2Fagents", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = antiForgeryToken,
            ["ReviewToken"] = ReviewToken,
            ["ReturnUrl"] = "/agents"
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/agents", response.Headers.Location?.OriginalString);
        var setCookieHeaders = response.Headers.GetValues("Set-Cookie").ToArray();
        Assert.Contains(setCookieHeaders, cookie => cookie.Contains(".ChallengerSiem.Review", StringComparison.Ordinal));
        Assert.Contains(setCookieHeaders, cookie =>
            cookie.Contains(".ChallengerSiem.Review", StringComparison.Ordinal)
            && cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<string> GetAntiForgeryTokenAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/login");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        var match = Regex.Match(
            html,
            "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"",
            RegexOptions.CultureInvariant);

        Assert.True(match.Success, "Login page should contain an antiforgery token.");
        return WebUtility.HtmlDecode(match.Groups["token"].Value);
    }
}
