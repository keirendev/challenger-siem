using System.Security.Claims;
using Challenger.Siem.Api.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

[AllowAnonymous]
public sealed class LoginModel(TokenService tokens, IConfiguration configuration) : PageModel
{
    [BindProperty]
    public string ReviewToken { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; private set; }

    public IActionResult OnGet()
    {
        return User.Identity?.IsAuthenticated == true
            ? LocalRedirect(GetSafeReturnUrl())
            : Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var expectedToken = configuration["Auth:ReviewToken"];
        if (string.IsNullOrWhiteSpace(expectedToken))
        {
            ErrorMessage = "Review access is not configured.";
            ClearSubmittedToken();
            return Page();
        }

        if (!tokens.FixedTimeEquals(expectedToken, ReviewToken))
        {
            ErrorMessage = "Invalid review token.";
            ClearSubmittedToken();
            return Page();
        }

        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.Name, "operator"),
                new Claim(ClaimTypes.Role, "review")
            },
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties
            {
                IsPersistent = false,
                IssuedUtc = DateTimeOffset.UtcNow,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
            });

        return LocalRedirect(GetSafeReturnUrl());
    }

    private string GetSafeReturnUrl()
    {
        return Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "/";
    }

    private void ClearSubmittedToken()
    {
        ReviewToken = string.Empty;
        ModelState.Remove(nameof(ReviewToken));
    }
}
