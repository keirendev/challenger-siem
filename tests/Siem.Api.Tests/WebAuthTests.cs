using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class WebAuthTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> factory;
    public WebAuthTests(WebApplicationFactory<Program> factory) => this.factory=factory.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string,string?>
    {
        ["ConnectionStrings:SiemDatabase"]="Host=localhost;Port=5432;Database=synthetic_missing;Username=siem;Password=synthetic",
        ["Auth:EnrollmentToken"]="synthetic-enrollment"
    })));

    [Theory]
    [InlineData("/")]
    [InlineData("/soc-agent")]
    [InlineData("/graphs")]
    public async Task OperatorPagesRequireLogin(string path)
    {
        using var client=factory.CreateClient(new WebApplicationFactoryClientOptions{AllowAutoRedirect=false});
        using var response=await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect,response.StatusCode); Assert.Contains("/login",response.Headers.Location?.OriginalString,StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoginUsesUsernamePasswordAndAntiforgery()
    {
        using var client=factory.CreateClient(); var html=await client.GetStringAsync("/login");
        Assert.Contains("name=\"Username\"",html,StringComparison.Ordinal); Assert.Contains("name=\"Password\"",html,StringComparison.Ordinal);
        Assert.Contains("__RequestVerificationToken",html,StringComparison.Ordinal); Assert.DoesNotContain("ReviewToken",html,StringComparison.Ordinal);
    }

    [Fact]
    public async Task StaticAssetsRequireHttpsOutsideDevelopment()
    {
        using var productionFactory=factory.WithWebHostBuilder(builder=>builder.UseEnvironment("Production"));using var client=productionFactory.CreateClient(new WebApplicationFactoryClientOptions{AllowAutoRedirect=false});
        using var response=await client.GetAsync("/css/site.css"); Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);
    }
}
