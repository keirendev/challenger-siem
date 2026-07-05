using Challenger.Siem.Api.Platform;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class PlatformCapabilityCatalogTests
{
    [Fact]
    public void CatalogCoversAllSpecificationGapIssues()
    {
        var ids = PlatformCapabilityCatalog.All.Select(item => item.CapabilityId).ToArray();
        Assert.Equal(19, ids.Length);
        for (var i = 1; i <= 19; i++)
        {
            Assert.Contains($"SPEC-GAP-{i:000}", ids);
        }
        Assert.All(PlatformCapabilityCatalog.All, item =>
        {
            Assert.Equal("foundation_ready", item.Status);
            Assert.NotEmpty(item.Controls);
            Assert.StartsWith("/docs/spec-gap-foundations.md", item.DocumentationUrl, StringComparison.Ordinal);
        });
    }
}
