using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class NetworkActivityQueryTests
{
    [Fact]
    public void ProcessIdSelectorRequiresExactAgentAndExplicitBoundedUtcWindow()
    {
        var missingScope = NetworkActivityQuery.FromQuery(Query(("process_id", "4242")));
        Assert.Contains(missingScope.ValidationErrors, item => item.Field == "agent_id");
        Assert.Contains(missingScope.ValidationErrors, item => item.Field == "time");

        var tooWide = NetworkActivityQuery.FromQuery(Query(
            ("agent_id", "synthetic-agent"),
            ("process_id", "4242"),
            ("from", "2026-08-01T00:00:00Z"),
            ("to", "2026-08-13T00:00:00Z")));
        Assert.Contains(tooWide.ValidationErrors, item => item.Field == "time");

        var valid = NetworkActivityQuery.FromQuery(Query(
            ("agent_id", "synthetic-agent"),
            ("process_id", "4242"),
            ("process_instance_id", new string('a', 64)),
            ("from", "2026-08-13T00:00:00Z"),
            ("to", "2026-08-13T01:00:00Z")));
        Assert.Empty(valid.ValidationErrors);
        Assert.Equal(4242, valid.ProcessId);
        Assert.Equal(new string('a', 64), valid.ProcessInstanceId);
    }

    private static IQueryCollection Query(params (string Name, string Value)[] values) =>
        new QueryCollection(values.ToDictionary(item => item.Name, item => new StringValues(item.Value), StringComparer.Ordinal));
}
