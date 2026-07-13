using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authorization;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Graphs;

[Authorize(Policy = "investigations")]
public sealed class IndexModel(InvestigationGraphRepository graphs, ILogger<IndexModel> logger) : PageModel
{
    public const int PageSize = 25;

    [BindProperty(SupportsGet = true, Name = "status")]
    public string? Status { get; set; }

    [BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    [BindProperty]
    public string Title { get; set; } = string.Empty;

    [BindProperty]
    public string? Description { get; set; }

    [BindProperty]
    public string? Tags { get; set; }

    [TempData]
    public string? Message { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public IReadOnlyList<InvestigationGraphSummary> Graphs { get; private set; } = Array.Empty<InvestigationGraphSummary>();

    public bool HasPreviousPage => PageNumber > 1;

    public bool HasNextPage { get; private set; }

    public int FirstResultNumber => Graphs.Count == 0 ? 0 : ((PageNumber - 1) * PageSize) + 1;

    public int LastResultNumber => ((PageNumber - 1) * PageSize) + Graphs.Count;

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);
        var loadedGraphs = await graphs.ListAsync(Status, cancellationToken, PageSize + 1, (PageNumber - 1) * PageSize);
        HasNextPage = loadedGraphs.Count > PageSize;
        Graphs = loadedGraphs.Take(PageSize).ToArray();
    }

    public async Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken)
    {
        try
        {
            var created = await graphs.CreateAsync(new InvestigationGraphCreateRequest
            {
                Title = Title,
                Description = Description,
                Owner = User.Identity?.Name ?? "operator",
                Tags = ParseTags(Tags)
            }, User.Identity?.Name ?? "operator", cancellationToken);
            Message = "Investigation graph created.";
            return RedirectToPage("/Graphs/Detail", new { graph_id = created.GraphId });
        }
        catch (Exception ex) when (ex is ArgumentException or OperationCanceledException)
        {
            if (ex is OperationCanceledException) throw;
            ErrorMessage = ex.Message;
            return RedirectToPage("/Graphs/Index", new { status = Status });
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Graph could not be created.");
            ErrorMessage = "Graph could not be created.";
            return RedirectToPage("/Graphs/Index", new { status = Status });
        }
    }

    private static IReadOnlyList<string> ParseTags(string? tags)
    {
        return string.IsNullOrWhiteSpace(tags)
            ? Array.Empty<string>()
            : tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
