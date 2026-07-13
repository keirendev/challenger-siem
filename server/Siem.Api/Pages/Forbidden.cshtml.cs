using Challenger.Siem.Api.Auth;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

public sealed class ForbiddenModel : PageModel
{
    public string OperatorRole => OperatorAuthorization.Role(User) ?? "unknown";
}
