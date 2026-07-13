using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Microsoft.AspNetCore.Authorization;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages.Graphs;

[Authorize(Policy = "investigations")]
public sealed class DetailModel(InvestigationGraphRepository graphs, ILogger<DetailModel> logger) : PageModel
{
    [BindProperty(SupportsGet = true, Name = "graph_id")]
    public Guid GraphId { get; set; }

    [BindProperty]
    public string Title { get; set; } = string.Empty;
    [BindProperty]
    public string? Description { get; set; }
    [BindProperty]
    public string? Tags { get; set; }
    [BindProperty]
    public int ExpectedVersion { get; set; }
    [BindProperty]
    public string NodeType { get; set; } = "note";
    [BindProperty]
    public string NodeLabel { get; set; } = string.Empty;
    [BindProperty]
    public string? NodeReferenceKind { get; set; }
    [BindProperty]
    public string? NodeReferenceId { get; set; }
    [BindProperty]
    public string? NodeLinkUrl { get; set; }
    [BindProperty]
    public string? NodeNotes { get; set; }
    [BindProperty]
    public Guid SourceNodeId { get; set; }
    [BindProperty]
    public Guid TargetNodeId { get; set; }
    [BindProperty]
    public string EdgeType { get; set; } = "related_to";
    [BindProperty]
    public string? EdgeLabel { get; set; }
    [BindProperty]
    public string? EdgeNotes { get; set; }
    [BindProperty]
    public string ProposalInstruction { get; set; } = string.Empty;
    [BindProperty]
    public Guid ProposalId { get; set; }
    [BindProperty]
    public bool ConfirmApplyProposal { get; set; }

    [TempData]
    public string? Message { get; set; }
    [TempData]
    public string? ErrorMessage { get; set; }

    public InvestigationGraphDetail? Detail { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        Detail = await graphs.GetDetailAsync(GraphId, cancellationToken);
        if (Detail is null) return NotFound();
        Title = Detail.Graph.Title; Description = Detail.Graph.Description; Tags = string.Join(", ", Detail.Graph.Tags); ExpectedVersion = Detail.Graph.Version;
        return Page();
    }

    public async Task<IActionResult> OnPostUpdateAsync(CancellationToken cancellationToken)
    {
        try
        {
            var updated = await graphs.UpdateAsync(GraphId, new InvestigationGraphUpdateRequest { Title = Title, Description = Description, Tags = ParseTags(Tags), Owner = User.Identity?.Name ?? "operator", ExpectedVersion = ExpectedVersion }, User.Identity?.Name ?? "operator", cancellationToken);
            Message = updated is null ? null : "Graph metadata updated."; ErrorMessage = updated is null ? "Graph was changed by another request or archived; reload and try again." : null;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        return RedirectToPage(new { graph_id = GraphId });
    }

    public async Task<IActionResult> OnPostAddNodeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await graphs.AddNodeAsync(GraphId, new InvestigationGraphNodeRequest { NodeType = NodeType, Label = NodeLabel, ReferenceKind = NodeReferenceKind, ReferenceId = NodeReferenceId, LinkUrl = NodeLinkUrl, Notes = NodeNotes }, User.Identity?.Name ?? "operator", cancellationToken);
            Message = "Node added.";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        catch (Exception ex) { logger.LogWarning(ex, "Node add failed."); ErrorMessage = "Node could not be added."; }
        return RedirectToPage(new { graph_id = GraphId });
    }

    public async Task<IActionResult> OnPostAddEdgeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await graphs.AddEdgeAsync(GraphId, new InvestigationGraphEdgeRequest { SourceNodeId = SourceNodeId, TargetNodeId = TargetNodeId, EdgeType = EdgeType, Label = EdgeLabel, Notes = EdgeNotes }, User.Identity?.Name ?? "operator", cancellationToken);
            Message = "Edge added.";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        catch (Exception ex) { logger.LogWarning(ex, "Edge add failed."); ErrorMessage = "Edge could not be added."; }
        return RedirectToPage(new { graph_id = GraphId });
    }

    public async Task<IActionResult> OnPostArchiveAsync(CancellationToken cancellationToken)
    {
        await graphs.ArchiveAsync(GraphId, User.Identity?.Name ?? "operator", cancellationToken);
        Message = "Graph archived.";
        return RedirectToPage("/Graphs/Index", new { status = "archived" });
    }

    public async Task<IActionResult> OnPostProposeAsync(CancellationToken cancellationToken)
    {
        try { await graphs.CreateSocAgentProposalAsync(GraphId, ProposalInstruction, User.Identity?.Name ?? "operator", cancellationToken); Message = "soc-agent proposal created for review."; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        return RedirectToPage(new { graph_id = GraphId });
    }

    public async Task<IActionResult> OnPostApplyProposalAsync(CancellationToken cancellationToken)
    {
        if (!ConfirmApplyProposal) { ErrorMessage = "Confirm explicit operator approval before applying the proposal."; return RedirectToPage(new { graph_id = GraphId }); }
        await graphs.ApplyProposalAsync(GraphId, ProposalId, User.Identity?.Name ?? "operator", cancellationToken);
        Message = "Proposal applied.";
        return RedirectToPage(new { graph_id = GraphId });
    }

    private static IReadOnlyList<string> ParseTags(string? tags) => string.IsNullOrWhiteSpace(tags) ? Array.Empty<string>() : tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
