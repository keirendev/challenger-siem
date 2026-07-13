using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

public sealed class LogoutModel(OperatorRepository operators, SecurityAuditRepository audit) : PageModel
{
    public void OnGet() { }
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var token=User.FindFirst(OperatorAuthentication.SessionTokenClaim)?.Value;
        if(!string.IsNullOrWhiteSpace(token)) await operators.RevokeSessionAsync(token,"logout",cancellationToken);
        await audit.RecordAsync(OperatorAuthentication.OperatorId(User),User.Identity?.Name,"operator.logout","success","session",null,HttpContext,null,cancellationToken);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToPage("/Login");
    }
}
