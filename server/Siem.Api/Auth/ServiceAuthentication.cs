using System.Security.Claims;
using System.Text.Encodings.Web;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Auth;

public static class ServiceAuthentication
{
    public const string Scheme = "ServiceBearer";
    public const string PrincipalName = "service";
    public static readonly Guid ServiceId = Guid.Empty;

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
    SecurityAuditRepository audit)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = tokens.GetBearerToken(Context);
        if (token is null)
        {
            return AuthenticateResult.NoResult();
        }

        if (!tokens.IsServiceToken(token))
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
            return AuthenticateResult.Fail("Invalid service credential.");
        }

        return AuthenticateResult.Success(
            new AuthenticationTicket(ServiceAuthentication.Principal(), Scheme.Name));
    }
}
