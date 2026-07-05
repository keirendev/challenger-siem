using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

public sealed class SocAgentModel(
    SocAgentService socAgent,
    ILogger<SocAgentModel> logger) : PageModel
{
    [BindProperty(SupportsGet = true, Name = "session_id")]
    public Guid? SessionId { get; set; }

    [BindProperty(SupportsGet = true, Name = "agent_id")]
    public string? ContextAgentId { get; set; }

    [BindProperty]
    public string Message { get; set; } = string.Empty;

    [BindProperty]
    public string? ComposerContextAgentId { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public SocAgentProviderStatusResponse ProviderStatus { get; private set; } = new();

    public IReadOnlyList<SocAgentSessionSummary> Sessions { get; private set; } = Array.Empty<SocAgentSessionSummary>();

    public SocAgentSessionSummary? CurrentSession { get; private set; }

    public IReadOnlyList<SocAgentChatMessageDto> Messages { get; private set; } = Array.Empty<SocAgentChatMessageDto>();

    public bool HasCurrentSession => CurrentSession is not null;

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        await LoadPageAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostSendAsync(CancellationToken cancellationToken)
    {
        var contextAgentId = string.IsNullOrWhiteSpace(ComposerContextAgentId)
            ? ContextAgentId
            : ComposerContextAgentId;

        if (string.IsNullOrWhiteSpace(Message) || Message.Length > 4000)
        {
            ErrorMessage = "Enter a message up to 4000 characters.";
            return RedirectToPage(new { session_id = SessionId, agent_id = contextAgentId });
        }

        try
        {
            var response = await socAgent.SendChatMessageAsync(SessionId, new SocAgentChatRequest
            {
                Message = Message,
                ContextAgentId = string.IsNullOrWhiteSpace(contextAgentId) ? null : contextAgentId.Trim()
            }, cancellationToken);

            return RedirectToPage(new { session_id = response.Session.SessionId });
        }
        catch (KeyNotFoundException)
        {
            ErrorMessage = "The selected soc-agent chat session was not found. Start a new chat and try again.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "soc-agent chat message could not be completed.");
            ErrorMessage = "soc-agent could not complete the chat request. Confirm the database schema is applied and try again.";
        }

        return RedirectToPage(new { session_id = SessionId, agent_id = contextAgentId });
    }

    public string StatusBadgeClass()
    {
        return ProviderStatus.Status switch
        {
            "local" => "ok",
            "connected" => "ok",
            "disabled" => "warning",
            "provider_not_configured" => "warning",
            "auth_required" => "warning",
            "expired" => "warning",
            "refresh_failed" => "warning",
            "unsupported_delegated_auth" => "warning",
            "budget_limited" => "warning",
            "rate_limited" => "warning",
            _ => "danger"
        };
    }

    public string RoleLabel(SocAgentChatMessageDto message)
    {
        return string.Equals(message.Role, "operator", StringComparison.OrdinalIgnoreCase)
            ? "Operator"
            : "soc-agent";
    }

    private async Task LoadPageAsync(CancellationToken cancellationToken)
    {
        ProviderStatus = socAgent.GetProviderStatus();
        Sessions = await socAgent.GetRecentSessionsAsync(cancellationToken);
        if (SessionId.HasValue)
        {
            var detail = await socAgent.GetSessionDetailAsync(SessionId.Value, cancellationToken);
            if (detail is null)
            {
                ErrorMessage = "The selected soc-agent chat session was not found.";
                SessionId = null;
            }
            else
            {
                CurrentSession = detail.Session;
                Messages = detail.Messages;
                ProviderStatus = detail.ProviderStatus;
                ContextAgentId = detail.Session.ContextAgentId ?? ContextAgentId;
            }
        }
    }
}
