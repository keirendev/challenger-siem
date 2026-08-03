using System.Security.Claims;
using System.Text.Encodings.Web;
using Challenger.Siem.Api.Configuration;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Auth;

public static class ServiceAuthentication
{
    public const string Scheme = "ServiceBearer";
    public const string PrincipalName = "service";
    public static readonly Guid ServiceId = Guid.Empty;

    internal static bool UsesAgentCredential(PathString path) =>
        path.StartsWithSegments("/api/v2/agents", StringComparison.OrdinalIgnoreCase)
        || path.StartsWithSegments("/api/v2/ingest", StringComparison.OrdinalIgnoreCase);

    public static ClaimsPrincipal Principal()
    {
        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.Name, PrincipalName),
                new Claim(ClaimTypes.Role, ServiceRoles.Service),
                new Claim("service_id", ServiceId.ToString())
            },
            Scheme);
        return new ClaimsPrincipal(identity);
    }
}

public sealed class ServiceBearerHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    TokenService tokens,
    SecurityAuditRepository audit,
    IOptions<TrafficMapOptions> trafficMap)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Agent routes validate their per-agent bearer (or enrollment header) inside the
        // endpoint-specific authenticator. Treating that bearer as a failed service token
        // would create false security-audit failures for every healthy agent request.
        if (ServiceAuthentication.UsesAgentCredential(Context.Request.Path))
        {
            return AuthenticateResult.NoResult();
        }

        var token = tokens.GetBearerToken(Context);
        if (token is null)
        {
            return AuthenticateResult.NoResult();
        }

        if (!tokens.IsServiceToken(token))
        {
            if (!trafficMap.Value.ReadOnlyDatabase)
            {
                await audit.RecordAsync(
                    ServiceAuthentication.ServiceId,
                    null,
                    "service.api_auth",
                    "failure",
                    null,
                    null,
                    Context,
                    null,
                    Context.RequestAborted);
            }
            return AuthenticateResult.Fail("Invalid service credential.");
        }

        return AuthenticateResult.Success(
            new AuthenticationTicket(ServiceAuthentication.Principal(), Scheme.Name));
    }
}
