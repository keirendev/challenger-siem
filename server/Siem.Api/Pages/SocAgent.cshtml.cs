using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

public sealed class SocAgentModel(SocAgentService socAgent) : PageModel
{
    [BindProperty]
    public string Question { get; set; } = "Summarize current coverage, alerts, and recent events.";

    [BindProperty]
    public string? ContextAgentId { get; set; }

    public SocAgentAskResponse? AgentResponse { get; private set; }
    public string? ErrorMessage { get; private set; }

    public void OnGet([FromQuery(Name = "agent_id")] string? agentId)
    {
        ContextAgentId = agentId;
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(Question) || Question.Length > 4000)
        {
            ErrorMessage = "Enter a question up to 4000 characters.";
            return Page();
        }

        try
        {
            AgentResponse = await socAgent.AskAsync(new SocAgentAskRequest
            {
                Question = Question,
                ContextAgentId = string.IsNullOrWhiteSpace(ContextAgentId) ? null : ContextAgentId.Trim()
            }, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorMessage = "soc-agent could not complete the request. Confirm the database schema is applied and try again.";
        }

        return Page();
    }
}
