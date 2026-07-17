using Challenger.Siem.Api.Auth;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.SocAgent;
using Challenger.Siem.Contracts.V1;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Challenger.Siem.Api.Pages;

[Authorize(Policy = "analyst")]
public sealed class SocAgentModel(
    SocAgentService socAgent,
    SocAgentSubscriptionOAuthConnectService subscriptionOAuthConnect,
    ISocAgentCodexAppServerClient codexAppServer,
    SecurityAuditRepository audit,
    ILogger<SocAgentModel> logger) : PageModel
{
    [BindProperty(SupportsGet = true, Name = "session_id")]
    public Guid? SessionId { get; set; }

    [BindProperty(SupportsGet = true, Name = "agent_id")]
    public string? ContextAgentId { get; set; }

    [BindProperty(SupportsGet = true, Name = "oauth_status")]
    public string? OAuthStatus { get; set; }

    [BindProperty(SupportsGet = true, Name = "oauth_error")]
    public string? OAuthError { get; set; }

    [BindProperty]
    public string Message { get; set; } = string.Empty;

    [BindProperty]
    public string? ComposerContextAgentId { get; set; }

    [BindProperty]
    public string? SelectedModel { get; set; }

    [BindProperty]
    public string? ReasoningEffort { get; set; }

    [BindProperty]
    public Guid? DeleteSessionId { get; set; }

    [BindProperty]
    public bool ConfirmDelete { get; set; }

    [BindProperty]
    public bool ConfirmSubscriptionDisconnect { get; set; }

    [BindProperty]
    public bool ConfirmSharedChatGptLogin { get; set; }

    [BindProperty(SupportsGet = true, Name = "manage_login")]
    public bool OpenChatGptLoginSettings { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    [TempData]
    public string? NoticeMessage { get; set; }

    public SocAgentProviderStatusResponse ProviderStatus { get; private set; } = new();

    public SocAgentCodexLoginStatus ChatGptLoginStatus { get; private set; } = null!;

    public IReadOnlyList<SocAgentSessionSummary> Sessions { get; private set; } = Array.Empty<SocAgentSessionSummary>();

    public SocAgentSessionSummary? CurrentSession { get; private set; }

    public IReadOnlyList<SocAgentChatMessageDto> Messages { get; private set; } = Array.Empty<SocAgentChatMessageDto>();

    public bool HasCurrentSession => CurrentSession is not null;

    public bool CanStartSubscriptionOAuthConnect =>
        CanManageProviderAuthentication
        && !UsesCodexManagedLogin
        && subscriptionOAuthConnect.CanStartInteractiveConnect();

    public bool CanDisconnectSubscriptionOAuth =>
        CanManageProviderAuthentication
        && !UsesCodexManagedLogin
        && subscriptionOAuthConnect.CanDisconnectDedicatedCredential();

    public bool CanManageProviderAuthentication => string.Equals(
        OperatorAuthorization.Role(User),
        OperatorRoles.Admin,
        StringComparison.Ordinal);

    public bool CanManageChatGptLogin => CanManageProviderAuthentication;

    public bool UsesCodexManagedLogin => string.Equals(
        ProviderStatus.AuthMode,
        "codex_app_server",
        StringComparison.OrdinalIgnoreCase);

    public string AuthenticationLabel => ProviderStatus.AuthMode.ToLowerInvariant() switch
    {
        "codex_app_server" => "SIEM-managed ChatGPT",
        "subscription_oauth" => "ChatGPT OAuth (advanced)",
        "api_key" => "API key",
        "disabled" => "Disabled",
        _ => ProviderStatus.AuthMode.Replace('_', ' ')
    };

    public bool ShouldShowProviderInlineNotice => ProviderNeedsAttention(ProviderStatus);

    private static bool ProviderNeedsAttention(SocAgentProviderStatusResponse status)
    {
        if (status.RequiresConnection)
        {
            return true;
        }

        return status.Status switch
        {
            "disabled" or
            "provider_not_configured" or
            "auth_required" or
            "expired" or
            "refresh_failed" or
            "unsupported_delegated_auth" or
            "unsupported_subscription_oauth" or
            "scope_missing" or
            "plan_limited" or
            "budget_limited" or
            "rate_limited" or
            "provider_error" => true,
            _ => false
        };
    }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        await LoadPageAsync(cancellationToken);
    }

    public IActionResult OnGetChatGptLoginStatus()
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
        if (!CanManageChatGptLogin)
        {
            return Forbid();
        }

        ProviderStatus = socAgent.GetProviderStatus();
        var status = codexAppServer.GetLoginStatus();
        return new JsonResult(new
        {
            state = status.State,
            is_applicable = UsesCodexManagedLogin,
            can_start = status.IsAvailable && !status.IsActive,
            can_cancel = status.IsActive,
            verification_uri = status.VerificationUrl,
            user_code = status.UserCode,
            message = status.OperatorMessage
        });
    }

    public async Task<IActionResult> OnPostStartChatGptLoginAsync(CancellationToken cancellationToken)
    {
        if (!CanManageChatGptLogin)
        {
            await RecordChatGptLoginAuditAsync("start", "denied", "role_denied", cancellationToken);
            return Forbid();
        }

        ProviderStatus = socAgent.GetProviderStatus();
        if (!UsesCodexManagedLogin)
        {
            ErrorMessage = "The SIEM-managed ChatGPT login is unavailable because CodexAppServer authentication is not configured.";
            await RecordChatGptLoginAuditAsync("start", "denied", "not_applicable", cancellationToken);
            return RedirectToChatGptLoginSettings();
        }

        if (!ConfirmSharedChatGptLogin)
        {
            ErrorMessage = "Confirm that this replaces the shared server ChatGPT login for all soc-agent users.";
            await RecordChatGptLoginAuditAsync("start", "denied", "confirmation_required", cancellationToken);
            return RedirectToChatGptLoginSettings();
        }

        var result = await codexAppServer.StartDeviceLoginAsync(cancellationToken);
        var after = result.Status;
        if (result.Started)
        {
            NoticeMessage = after.OperatorMessage;
        }
        else
        {
            ErrorMessage = after.OperatorMessage;
        }

        await RecordChatGptLoginAuditAsync("start", result.Started ? "success" : "failure", after.State, cancellationToken);
        return RedirectToChatGptLoginSettings();
    }

    public async Task<IActionResult> OnPostCancelChatGptLoginAsync(CancellationToken cancellationToken)
    {
        if (!CanManageChatGptLogin)
        {
            await RecordChatGptLoginAuditAsync("cancel", "denied", "role_denied", cancellationToken);
            return Forbid();
        }

        var result = await codexAppServer.CancelDeviceLoginAsync(cancellationToken);
        var after = result.Status;
        if (result.Cancelled)
        {
            NoticeMessage = after.OperatorMessage;
        }
        else
        {
            ErrorMessage = after.OperatorMessage;
        }

        await RecordChatGptLoginAuditAsync("cancel", result.Cancelled ? "success" : "failure", after.State, cancellationToken);
        return RedirectToChatGptLoginSettings();
    }

    public IActionResult OnPostConnectSubscriptionOAuth()
    {
        if (!CanManageProviderAuthentication)
        {
            return Forbid();
        }

        try
        {
            var authorizationUri = subscriptionOAuthConnect.CreateAuthorizationUri(HttpContext, "/soc-agent");
            return Redirect(authorizationUri.ToString());
        }
        catch (SocAgentSubscriptionOAuthConnectException ex)
        {
            ErrorMessage = ex.OperatorSafeMessage;
            return RedirectToPage();
        }
    }

    public async Task<IActionResult> OnPostDisconnectSubscriptionOAuthAsync(CancellationToken cancellationToken)
    {
        if (!CanManageProviderAuthentication)
        {
            return Forbid();
        }

        var result = await subscriptionOAuthConnect.DisconnectAsync(ConfirmSubscriptionDisconnect, cancellationToken);
        if (result.Succeeded)
        {
            NoticeMessage = result.OperatorSafeMessage;
        }
        else
        {
            ErrorMessage = result.OperatorSafeMessage;
        }

        return RedirectToPage(new { session_id = SessionId });
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
                ContextAgentId = string.IsNullOrWhiteSpace(contextAgentId) ? null : contextAgentId.Trim(),
                Model = SelectedModel,
                ReasoningEffort = ReasoningEffort
            }, OperatorAuthorization.Role(User)!, cancellationToken);

            return RedirectToPage(new { session_id = response.Session.SessionId });
        }
        catch (KeyNotFoundException)
        {
            ErrorMessage = "The selected soc-agent chat session was not found. Start a new chat and try again.";
        }
        catch (ArgumentException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "soc-agent chat message could not be completed.");
            ErrorMessage = "soc-agent could not complete the chat request. Confirm the database schema is applied and try again.";
        }

        return RedirectToPage(new { session_id = SessionId, agent_id = contextAgentId });
    }

    public async Task<IActionResult> OnPostDeleteSessionAsync(CancellationToken cancellationToken)
    {
        var deletedSessionId = DeleteSessionId;
        if (!deletedSessionId.HasValue)
        {
            ErrorMessage = "Choose a soc-agent chat session to delete.";
            return RedirectAfterDeleteAttempt(null, deleted: false);
        }

        if (!ConfirmDelete)
        {
            ErrorMessage = "Confirm chat deletion before removing a soc-agent session.";
            return RedirectAfterDeleteAttempt(deletedSessionId.Value, deleted: false);
        }

        var deleted = false;
        try
        {
            var result = await socAgent.DeleteSessionAsync(deletedSessionId.Value, cancellationToken);
            deleted = result.Deleted;
            if (result.Deleted)
            {
                NoticeMessage = "Deleted soc-agent chat session and associated messages. One-shot audit turns are retained.";
            }
            else if (string.Equals(result.Status, "run_active", StringComparison.OrdinalIgnoreCase))
            {
                ErrorMessage = result.Message;
            }
            else
            {
                ErrorMessage = "The selected soc-agent chat session was not found.";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "soc-agent chat session could not be deleted.");
            ErrorMessage = "soc-agent could not delete the selected chat session. Confirm the database schema is applied and try again.";
        }

        return RedirectAfterDeleteAttempt(deletedSessionId.Value, deleted);
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
            "unsupported_subscription_oauth" => "warning",
            "scope_missing" => "warning",
            "plan_limited" => "warning",
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

    public bool ShouldRenderMarkdown(SocAgentChatMessageDto message)
    {
        return !string.Equals(message.Role, "operator", StringComparison.OrdinalIgnoreCase);
    }

    private IActionResult RedirectAfterDeleteAttempt(Guid? deletedSessionId, bool deleted)
    {
        var keepSession = SessionId.HasValue
            && (!deleted || !deletedSessionId.HasValue || SessionId.Value != deletedSessionId.Value);
        return RedirectToPage(new
        {
            session_id = keepSession ? SessionId : null,
            agent_id = string.IsNullOrWhiteSpace(ContextAgentId) ? null : ContextAgentId.Trim()
        });
    }

    private IActionResult RedirectToChatGptLoginSettings()
    {
        return RedirectToPage(new
        {
            session_id = SessionId,
            manage_login = true
        });
    }

    private Task RecordChatGptLoginAuditAsync(
        string operation,
        string outcome,
        string state,
        CancellationToken cancellationToken)
    {
        return audit.RecordAsync(
            OperatorAuthentication.OperatorId(User),
            User.Identity?.Name,
            $"soc_agent.shared_login.{operation}",
            outcome,
            "soc_agent_provider",
            "shared_chatgpt",
            HttpContext,
            new Dictionary<string, object?> { ["state"] = state },
            cancellationToken);
    }

    private async Task LoadPageAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(OAuthError))
        {
            ErrorMessage = OAuthError.Length <= 500 ? OAuthError : OAuthError[..500];
        }
        else if (!string.IsNullOrWhiteSpace(OAuthStatus))
        {
            NoticeMessage = OAuthStatus.Length <= 500 ? OAuthStatus : OAuthStatus[..500];
        }

        ProviderStatus = socAgent.GetProviderStatus();
        ChatGptLoginStatus = codexAppServer.GetLoginStatus();
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

        var preferredModel = CurrentSession?.Model;
        var selectedOption = ProviderStatus.ModelOptions.FirstOrDefault(option =>
                option.Model.Equals(preferredModel, StringComparison.OrdinalIgnoreCase))
            ?? ProviderStatus.ModelOptions.FirstOrDefault(option =>
                option.Model.Equals(ProviderStatus.Model, StringComparison.OrdinalIgnoreCase))
            ?? ProviderStatus.ModelOptions.FirstOrDefault();
        SelectedModel = selectedOption?.Model ?? ProviderStatus.Model;
        ReasoningEffort = selectedOption?.ReasoningEfforts.Contains(CurrentSession?.ReasoningEffort ?? string.Empty, StringComparer.OrdinalIgnoreCase) == true
            ? CurrentSession?.ReasoningEffort
            : selectedOption?.DefaultReasoningEffort;
    }
}
