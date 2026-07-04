using Xunit;

namespace Challenger.Siem.Api.Tests;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class PostgresFactAttribute : FactAttribute
{
    public PostgresFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CHALLENGER_SIEM_TEST_DATABASE"))
            && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ConnectionStrings__SiemTestDatabase")))
        {
            Skip = "PostgreSQL integration test skipped; set CHALLENGER_SIEM_TEST_DATABASE or ConnectionStrings__SiemTestDatabase to an ignored local test database connection string.";
        }
    }
}
