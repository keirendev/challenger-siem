using System.Reflection;
using Challenger.Siem.Api.Review;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

public sealed class AboutModel(ReviewRepository reviewRepository, IWebHostEnvironment environment) : PageModel
{
    public string ApplicationVersion { get; private set; } = "unknown";

    public string EnvironmentName { get; private set; } = environment.EnvironmentName;

    public DatabaseStatus Database { get; private set; } = new(false, "not checked");

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        ApplicationVersion = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
            ?? "unknown";

        Database = await reviewRepository.CheckDatabaseAsync(cancellationToken);
    }
}
