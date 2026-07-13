using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Cases;

[Authorize(Policy = "investigations")]
public sealed class IndexModel(CaseRepository cases) : PageModel
{
    public const int PageSize = 50;

    [BindProperty(SupportsGet = true, Name = "status")]
    public string? Status { get; set; }

    [BindProperty(SupportsGet = true, Name = "owner")]
    public string? Owner { get; set; }

    [BindProperty(SupportsGet = true, Name = "page")]
    public int PageNumber { get; set; } = 1;

    [BindProperty]
    public string Title { get; set; } = string.Empty;
    [BindProperty]
    public string? Description { get; set; }
    [BindProperty]
    public string Severity { get; set; } = DetectionSeverities.Medium;
    [BindProperty]
    public string Priority { get; set; } = CasePriorities.Normal;
    [BindProperty]
    public Guid AlertId { get; set; }

    [TempData]
    public string? Message { get; set; }
    [TempData]
    public string? ErrorMessage { get; set; }

    public IReadOnlyList<CaseSummaryRecord> Cases { get; private set; } = Array.Empty<CaseSummaryRecord>();
    public bool HasPreviousPage => PageNumber > 1;
    public bool HasNextPage { get; private set; }
    public int FirstResultNumber => Cases.Count == 0 ? 0 : ((PageNumber - 1) * PageSize) + 1;
    public int LastResultNumber => ((PageNumber - 1) * PageSize) + Cases.Count;

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        await LoadAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken)
    {
        try
        {
            var created = await cases.CreateAsync(new CaseCreateRequest
            {
                Title = Title,
                Description = Description,
                Owner = User.Identity?.Name,
                Severity = Severity,
                Priority = Priority,
                AlertIds = AlertId == Guid.Empty ? Array.Empty<Guid>() : new[] { AlertId },
                IdempotencyKey = $"web-create-{Guid.NewGuid():N}"
            }, User.Identity?.Name ?? "operator", cancellationToken);
            Message = $"Case {created.CaseKey} created.";
            return RedirectToPage("/Cases/Detail", new { case_id = created.CaseId });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
            await LoadAsync(cancellationToken);
            return Page();
        }
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        PageNumber = Math.Max(1, PageNumber);
        var loaded = await cases.ListAsync(Status, Owner, cancellationToken, PageSize + 1, (PageNumber - 1) * PageSize);
        HasNextPage = loaded.Count > PageSize;
        Cases = loaded.Take(PageSize).ToArray();
    }
}
