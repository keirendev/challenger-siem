using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class OperatorSchemaTests
{
    [Fact]
    public void OperatorMigrationProvidesRolesSessionsLockoutAndImmutableSecretSafeAudit()
    {
        var sql=File.ReadAllText(RepositoryPath("server","Siem.Api","Database","003_operator_rbac.sql"));
        foreach(var role in new[]{"viewer","analyst","detection-engineer","admin"})Assert.Contains($"'{role}'",sql,StringComparison.Ordinal);
        Assert.Contains("password_hash",sql,StringComparison.Ordinal);Assert.Contains("api_token_hash",sql,StringComparison.Ordinal);Assert.Contains("token_hash",sql,StringComparison.Ordinal);
        Assert.Contains("locked_until",sql,StringComparison.Ordinal);Assert.Contains("expires_at",sql,StringComparison.Ordinal);Assert.Contains("revoked_at",sql,StringComparison.Ordinal);
        Assert.Contains("before update or delete",sql,StringComparison.OrdinalIgnoreCase);Assert.Contains("append-only",sql,StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password text",sql,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("token text",sql,StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RuntimeConfigHasNoSharedOperatorFallbackAndCookiesAndCsrfAreHardened()
    {
        var settings=File.ReadAllText(RepositoryPath("server","Siem.Api","appsettings.json"));var program=File.ReadAllText(RepositoryPath("server","Siem.Api","Program.cs"));
        Assert.DoesNotContain("ReviewToken",settings,StringComparison.Ordinal);Assert.Contains("HttpOnly = true",program,StringComparison.Ordinal);Assert.Contains("SameSiteMode.Strict",program,StringComparison.Ordinal);Assert.Contains("CookieSecurePolicy.Always",program,StringComparison.Ordinal);Assert.Contains("SlidingExpiration = false",program,StringComparison.Ordinal);Assert.Contains("csrf_safe_bearer_required",program,StringComparison.Ordinal);
    }

    [Fact]
    public void LocalBootstrapIsFailClosedAndRecoveryRevokesSessions()
    {
        var repository=File.ReadAllText(RepositoryPath("server","Siem.Api","Database","OperatorRepository.cs"));var command=File.ReadAllText(RepositoryPath("server","Siem.Api","Auth","OperatorAccountCommand.cs"));
        Assert.Contains("where not exists(select 1 from operators)",repository,StringComparison.OrdinalIgnoreCase);Assert.Contains("credentials_changed",repository,StringComparison.Ordinal);Assert.Contains("failed_login_count+1",repository,StringComparison.Ordinal);Assert.Contains("SIEM_OPERATOR_PASSWORD",command,StringComparison.Ordinal);Assert.DoesNotContain("GetBearerToken",command,StringComparison.Ordinal);
    }

    private static string RepositoryPath(params string[] parts)
    {
        var current=new DirectoryInfo(AppContext.BaseDirectory);while(current is not null&&!File.Exists(Path.Combine(current.FullName,"Challenger.Siem.sln")))current=current.Parent;
        return Path.Combine(new[]{current?.FullName??throw new InvalidOperationException("Repository root not found.")}.Concat(parts).ToArray());
    }
}
