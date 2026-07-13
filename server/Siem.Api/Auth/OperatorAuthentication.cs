using System.Security.Claims;
using System.Text.Encodings.Web;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.Auth;

public static class OperatorAuthentication
{
    public const string SmartScheme = "Operator";
    public const string BearerScheme = "OperatorBearer";
    public const string SessionTokenClaim = "operator_session_token";
    public const string OperatorIdClaim = "operator_id";

    public static ClaimsPrincipal Principal(OperatorIdentity op, string authenticationType, string? sessionToken = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, op.Username), new(ClaimTypes.Role, op.Role), new(OperatorIdClaim, op.OperatorId.ToString()) };
        if (sessionToken is not null) claims.Add(new(SessionTokenClaim, sessionToken));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType));
    }

    public static Guid? OperatorId(ClaimsPrincipal principal) => Guid.TryParse(principal.FindFirstValue(OperatorIdClaim), out var id) ? id : null;
}

public sealed class OperatorBearerHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, OperatorRepository operators, SecurityAuditRepository audit)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return AuthenticateResult.NoResult();
        var token = header[7..].Trim();
        if (token.Length == 0) return AuthenticateResult.Fail("Missing operator credential.");
        var op = await operators.AuthenticateApiTokenAsync(token, Context.RequestAborted);
        if (op is null)
        {
            await audit.RecordAsync(null, null, "operator.api_auth", "failure", null, null, Context, null, Context.RequestAborted);
            return AuthenticateResult.Fail("Invalid operator credential.");
        }
        return AuthenticateResult.Success(new AuthenticationTicket(OperatorAuthentication.Principal(op, Scheme.Name), Scheme.Name));
    }
}

public sealed class OperatorCookieEvents(OperatorRepository operators, SecurityAuditRepository audit) : CookieAuthenticationEvents
{
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var token = context.Principal?.FindFirstValue(OperatorAuthentication.SessionTokenClaim);
        var session = string.IsNullOrWhiteSpace(token) ? null : await operators.ValidateSessionAsync(token, context.HttpContext.RequestAborted);
        if (session is null)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await audit.RecordAsync(null, context.Principal?.Identity?.Name, "operator.session_validation", "failure", "session", null, context.HttpContext, null, context.HttpContext.RequestAborted);
            return;
        }
        context.ReplacePrincipal(OperatorAuthentication.Principal(session.Operator, CookieAuthenticationDefaults.AuthenticationScheme, token));
    }
}
