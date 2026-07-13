using Challenger.Siem.Api.Database;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Cases;

[Authorize(Policy = "investigations")]
public sealed class DetailModel(CaseRepository cases) : PageModel
{
    [BindProperty(SupportsGet = true, Name = "case_id")]
    public Guid CaseId { get; set; }

    [BindProperty]
    public int ExpectedVersion { get; set; }
    [BindProperty]
    public string? Owner { get; set; }
    [BindProperty]
    public string? Status { get; set; }
    [BindProperty]
    public string? Disposition { get; set; }
    [BindProperty]
    public string? ClosureSummary { get; set; }
    [BindProperty]
    public string? ClosureCriteria { get; set; }
    [BindProperty]
    public bool CoverageGapAcknowledged { get; set; }
    [BindProperty]
    public bool ConfirmClose { get; set; }
    [BindProperty]
    public string NoteBody { get; set; } = string.Empty;
    [BindProperty]
    public Guid AlertId { get; set; }
    [BindProperty]
    public string AlertRelationship { get; set; } = "related";
    [BindProperty]
    public string EntityType { get; set; } = string.Empty;
    [BindProperty]
    public string EntityValue { get; set; } = string.Empty;
    [BindProperty]
    public string EntityRelationship { get; set; } = "related";
    [BindProperty]
    public Guid GraphId { get; set; }
    [BindProperty]
    public string GraphRelationship { get; set; } = "investigation";
    [BindProperty]
    public string EvidenceAgentId { get; set; } = string.Empty;
    [BindProperty]
    public Guid EvidenceEventId { get; set; }
    [BindProperty]
    public Guid? EvidenceAlertId { get; set; }
    [BindProperty]
    public string? EvidenceSummary { get; set; }

    [TempData]
    public string? Message { get; set; }
    [TempData]
    public string? ErrorMessage { get; set; }

    public CaseDetailRecord? Case { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) => await LoadPageAsync(cancellationToken);

    public async Task<IActionResult> OnPostAssignAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.AssignAsync(CaseId, new CaseMutationRequest { ExpectedVersion = ExpectedVersion, Owner = Owner, IdempotencyKey = NewKey("assign") }, User.Identity?.Name ?? "operator", cancellationToken), "Case assigned.", cancellationToken);
    public async Task<IActionResult> OnPostStatusAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.SetStatusAsync(CaseId, new CaseMutationRequest { ExpectedVersion = ExpectedVersion, Status = Status, IdempotencyKey = NewKey("status") }, User.Identity?.Name ?? "operator", cancellationToken), "Case status updated.", cancellationToken);
    public async Task<IActionResult> OnPostCloseAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.CloseAsync(CaseId, new CaseMutationRequest { ExpectedVersion = ExpectedVersion, Disposition = Disposition, ClosureSummary = ClosureSummary, ClosureCriteria = ClosureCriteria, CoverageGapAcknowledged = CoverageGapAcknowledged, Confirm = ConfirmClose, IdempotencyKey = NewKey("close") }, User.Identity?.Name ?? "operator", cancellationToken), "Case closed.", cancellationToken);
    public async Task<IActionResult> OnPostReopenAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.ReopenAsync(CaseId, new CaseMutationRequest { ExpectedVersion = ExpectedVersion, IdempotencyKey = NewKey("reopen") }, User.Identity?.Name ?? "operator", cancellationToken), "Case reopened.", cancellationToken);
    public async Task<IActionResult> OnPostNoteAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.AddNoteAsync(CaseId, new CaseNoteRequest { Body = NoteBody, IdempotencyKey = NewKey("note") }, User.Identity?.Name ?? "operator", cancellationToken), "Note added.", cancellationToken);
    public async Task<IActionResult> OnPostLinkAlertAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.LinkAlertAsync(CaseId, new CaseAlertRequest { AlertId = AlertId, Relationship = AlertRelationship, IdempotencyKey = NewKey("alert") }, User.Identity?.Name ?? "operator", cancellationToken), "Alert linked.", cancellationToken);
    public async Task<IActionResult> OnPostLinkEntityAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.LinkEntityAsync(CaseId, new CaseEntityRequest { EntityType = EntityType, EntityValue = EntityValue, Relationship = EntityRelationship, IdempotencyKey = NewKey("entity") }, User.Identity?.Name ?? "operator", cancellationToken), "Entity linked.", cancellationToken);
    public async Task<IActionResult> OnPostLinkGraphAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.LinkGraphAsync(CaseId, new CaseGraphRequest { GraphId = GraphId, Relationship = GraphRelationship, IdempotencyKey = NewKey("graph") }, User.Identity?.Name ?? "operator", cancellationToken), "Graph linked.", cancellationToken);
    public async Task<IActionResult> OnPostLinkEvidenceAsync(CancellationToken cancellationToken) => await MutateAsync(() => cases.LinkEvidenceAsync(CaseId, new CaseEvidenceRequest { AlertId = EvidenceAlertId == Guid.Empty ? null : EvidenceAlertId, AgentId = EvidenceAgentId, EventId = EvidenceEventId, Summary = EvidenceSummary, IdempotencyKey = NewKey("evidence") }, User.Identity?.Name ?? "operator", cancellationToken), "Evidence linked.", cancellationToken);

    private async Task<IActionResult> MutateAsync(Func<Task<CaseDetailRecord?>> action, string success, CancellationToken cancellationToken)
    {
        try
        {
            var result = await action();
            if (result is null) ErrorMessage = "Case changed in another request or was not found; reload and try again.";
            else Message = success;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            ErrorMessage = ex.Message;
        }
        return RedirectToPage(new { case_id = CaseId });
    }

    private async Task<IActionResult> LoadPageAsync(CancellationToken cancellationToken)
    {
        Case = await cases.GetAsync(CaseId, cancellationToken);
        if (Case is null) return NotFound();
        ExpectedVersion = Case.Version;
        Owner = Case.Owner;
        Status = Case.Status;
        Disposition = Case.Disposition;
        ClosureSummary = Case.ClosureSummary;
        ClosureCriteria = Case.ClosureCriteria;
        CoverageGapAcknowledged = Case.CoverageGapAcknowledged;
        return Page();
    }

    private static string NewKey(string prefix) => $"web-{prefix}-{Guid.NewGuid():N}";
}
