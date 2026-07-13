using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

[AllowAnonymous]
public sealed class LoginModel(OperatorRepository operators, SecurityAuditRepository audit) : PageModel
{
    [BindProperty] public string Username { get; set; } = string.Empty;
    [BindProperty] public string Password { get; set; } = string.Empty;
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    public string? ErrorMessage { get; private set; }

    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true ? LocalRedirect(GetSafeReturnUrl()) : Page();

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        LoginResult result;
        try { result = await operators.AuthenticatePasswordAsync(Username, Password, cancellationToken); }
        catch (ArgumentException) { result = new("invalid", null, null); }
        Password = string.Empty; ModelState.Remove(nameof(Password));
        if (result.Session is null || result.SessionToken is null)
        {
            ErrorMessage = result.Status == "locked" ? "Account is temporarily locked. Try again later or use the documented local recovery procedure." : "Invalid username or password.";
            // Bound/hash invalid identifiers centrally; never store raw oversized or credential-shaped login input.
            await audit.RecordAsync(null, Username, "operator.login", "failure", "operator", null, HttpContext, new Dictionary<string,object?>{{"reason",result.Status}}, cancellationToken);
            return Page();
        }
        var op=result.Session.Operator;
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            OperatorAuthentication.Principal(op, CookieAuthenticationDefaults.AuthenticationScheme, result.SessionToken),
            new AuthenticationProperties { IsPersistent=false, IssuedUtc=DateTimeOffset.UtcNow, ExpiresUtc=result.Session.ExpiresAt, AllowRefresh=false });
        await audit.RecordAsync(op.OperatorId,op.Username,"operator.login","success","session",result.Session.SessionId.ToString(),HttpContext,new Dictionary<string,object?>{{"role",op.Role}},cancellationToken);
        return LocalRedirect(GetSafeReturnUrl());
    }
    private string GetSafeReturnUrl()=>Url.IsLocalUrl(ReturnUrl)?ReturnUrl!:"/";
}
