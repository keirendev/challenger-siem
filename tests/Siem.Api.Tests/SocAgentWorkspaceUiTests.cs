using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentWorkspaceUiTests
{
    [Fact]
    public void WorkspaceKeepsRecentChatsInANarrowSidebarAndConversationDominant()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var focusedCss = ReadFocusedWorkspaceCss();

        Assert.Contains("ViewData[\"MainClass\"] = \"soc-agent-page\";", page, StringComparison.Ordinal);
        Assert.Contains("<div class=\"soc-agent-workspace\"", page, StringComparison.Ordinal);
        Assert.Contains("<section class=\"soc-agent-conversation\"", page, StringComparison.Ordinal);
        Assert.Contains("<aside class=\"soc-agent-history\"", page, StringComparison.Ordinal);
        Assert.Contains("<h2 id=\"soc-agent-history-title\">Recent chats</h2>", page, StringComparison.Ordinal);
        Assert.True(
            page.IndexOf("<section class=\"soc-agent-conversation\"", StringComparison.Ordinal)
            < page.IndexOf("<aside class=\"soc-agent-history\"", StringComparison.Ordinal),
            "Conversation markup should precede history so chat stays first on narrow screens and for assistive technology.");

        Assert.Contains("grid-template-areas: \"history conversation\";", focusedCss, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(12rem, 14rem) minmax(0, 1fr);", focusedCss, StringComparison.Ordinal);
        Assert.Contains("grid-area: conversation;", focusedCss, StringComparison.Ordinal);
        Assert.Contains("grid-area: history;", focusedCss, StringComparison.Ordinal);
        Assert.Contains("grid-template-areas:\n        \"connection\"\n        \"transcript\"\n        \"composer\";", focusedCss, StringComparison.Ordinal);
        Assert.Contains("grid-template-rows: auto minmax(0, 1fr) auto;", focusedCss, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-connection-banner {\n    grid-area: connection;", focusedCss, StringComparison.Ordinal);
        Assert.Contains(".conversation-scroll {\n    grid-area: transcript;", focusedCss, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-composer {\n    grid-area: composer;", focusedCss, StringComparison.Ordinal);
        Assert.Contains("height: min(64rem, calc(100vh - 7.5rem));", focusedCss, StringComparison.Ordinal);
        Assert.Contains("grid-template-areas:\n            \"conversation\"\n            \"history\";", focusedCss, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"breadcrumbs\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("conversation-header", page, StringComparison.Ordinal);
        Assert.DoesNotContain("New investigation", page, StringComparison.Ordinal);
        Assert.DoesNotContain("soc-agent-activity", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Live tool activity", page, StringComparison.Ordinal);
        Assert.DoesNotContain(".soc-agent-activity", focusedCss, StringComparison.Ordinal);
    }

    [Fact]
    public void SettingsUsesNativeDialogAndServerSideOAuthActionsWithoutCredentialInputs()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");
        var designSystem = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "design-system.js");
        var focusedCss = ReadFocusedWorkspaceCss();

        Assert.Contains("<dialog id=\"soc-agent-settings-dialog\"", page, StringComparison.Ordinal);
        Assert.Contains("<h2 id=\"soc-agent-settings-title\">ChatGPT settings</h2>", page, StringComparison.Ordinal);
        Assert.Contains("data-open-dialog=\"soc-agent-settings-dialog\"", page, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Close settings\" data-close-dialog", page, StringComparison.Ordinal);
        Assert.Contains("dialog.showModal();", designSystem, StringComparison.Ordinal);
        Assert.Contains("dialog.close();", designSystem, StringComparison.Ordinal);
        Assert.Contains("dialog.dataset.returnFocus", designSystem, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-settings-dialog::backdrop", focusedCss, StringComparison.Ordinal);

        Assert.Contains("asp-page-handler=\"ConnectSubscriptionOAuth\"", page, StringComparison.Ordinal);
        Assert.Contains("Reconnect ChatGPT", page, StringComparison.Ordinal);
        Assert.Contains("asp-page-handler=\"DisconnectSubscriptionOAuth\"", page, StringComparison.Ordinal);
        Assert.Contains("@if (Model.CanDisconnectSubscriptionOAuth)", page, StringComparison.Ordinal);
        Assert.Contains("<details class=\"settings-danger-zone\">", page, StringComparison.Ordinal);
        Assert.Contains("name=\"ConfirmSubscriptionDisconnect\" value=\"true\" required", page, StringComparison.Ordinal);
        Assert.Contains("This removes only the dedicated soc-agent subscription credential.", page, StringComparison.Ordinal);
        Assert.Contains("Manage the ChatGPT subscription used by this SIEM instance.", page, StringComparison.Ordinal);
        Assert.Contains("Credentials stay server-side and are never exposed to this page.", page, StringComparison.Ordinal);
        Assert.Contains("subscriptionOAuthConnect.DisconnectAsync(ConfirmSubscriptionDisconnect, cancellationToken)", codeBehind, StringComparison.Ordinal);
        Assert.Contains("CanManageProviderAuthentication\n        && !UsesCodexManagedLogin", codeBehind, StringComparison.Ordinal);
        Assert.Contains("else if (Model.CanManageProviderAuthentication && !string.IsNullOrWhiteSpace(safeConnectUrl))", page, StringComparison.Ordinal);
        Assert.True(
            CountOccurrences(codeBehind, "if (!CanManageProviderAuthentication)") >= 2,
            "Both advanced subscription OAuth mutation handlers must enforce the admin role at the server boundary.");

        Assert.DoesNotContain("type=\"password\"", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("name=\"OpenAiApiKey\"", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("name=\"SubscriptionClientSecret\"", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("name=\"AccessToken\"", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("name=\"RefreshToken\"", page, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AdvancedSubscriptionOAuthStartEndpointRequiresAdmin()
    {
        var program = ReadRepoFile("server", "Siem.Api", "Program.cs");
        var start = program.IndexOf("app.MapGet(\"/soc-agent/oauth/start\"", StringComparison.Ordinal);
        var callback = program.IndexOf("app.MapGet(\"/soc-agent/oauth/callback\"", StringComparison.Ordinal);

        Assert.True(start >= 0 && callback > start);
        var endpoint = program[start..callback];
        Assert.Contains("}).RequireAuthorization(\"admin\");", endpoint, StringComparison.Ordinal);
        Assert.DoesNotContain("RequireAuthorization(\"analyst\")", endpoint, StringComparison.Ordinal);
    }

    [Fact]
    public void SettingsOffersAdminOnlySharedChatGptDeviceLoginWithoutExposingServerControls()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");
        var appServerClient = ReadRepoFile("server", "Siem.Api", "SocAgent", "SocAgentCodexAppServerClient.cs");
        var appSettings = ReadRepoFile("server", "Siem.Api", "appsettings.json");
        var project = ReadRepoFile("server", "Siem.Api", "Siem.Api.csproj");

        Assert.Contains("id=\"soc-agent-chatgpt-login-panel\"", page, StringComparison.Ordinal);
        Assert.Contains("SIEM-managed ChatGPT login", page, StringComparison.Ordinal);
        Assert.Contains("asp-page-handler=\"StartChatGptLogin\"", page, StringComparison.Ordinal);
        Assert.Contains("asp-page-handler=\"CancelChatGptLogin\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"ConfirmSharedChatGptLogin\" value=\"true\" required", page, StringComparison.Ordinal);
        Assert.Contains("I understand this replaces the shared server login for all soc-agent users.", page, StringComparison.Ordinal);
        Assert.Contains("Log in to ChatGPT again", page, StringComparison.Ordinal);
        Assert.Contains("Open ChatGPT sign-in", page, StringComparison.Ordinal);
        Assert.Contains("Model.CanManageChatGptLogin", page, StringComparison.Ordinal);

        Assert.Contains("OperatorRoles.Admin", codeBehind, StringComparison.Ordinal);
        Assert.Contains("OnPostStartChatGptLoginAsync", codeBehind, StringComparison.Ordinal);
        Assert.Contains("OnPostCancelChatGptLoginAsync", codeBehind, StringComparison.Ordinal);
        Assert.Contains("OnGetChatGptLoginStatus", codeBehind, StringComparison.Ordinal);
        Assert.Contains("Response.Headers.CacheControl = \"no-store, max-age=0\";", codeBehind, StringComparison.Ordinal);
        Assert.Contains("soc_agent.shared_login", codeBehind, StringComparison.Ordinal);

        Assert.Contains("parsed.hostname === 'auth.openai.com'", script, StringComparison.Ordinal);
        Assert.Contains("parsed.pathname === '/codex/device'", script, StringComparison.Ordinal);
        Assert.Contains("chatGptLoginCode.textContent = userCode;", script, StringComparison.Ordinal);
        Assert.Contains("cache: 'no-store'", script, StringComparison.Ordinal);
        Assert.Contains("RedirectStandardInput = true", appServerClient, StringComparison.Ordinal);
        Assert.Contains("currentProcess.StandardInput.BaseStream.WriteAsync", appServerClient, StringComparison.Ordinal);
        Assert.Contains("startInfo.ArgumentList.Add(\"app-server\")", appServerClient, StringComparison.Ordinal);
        Assert.Contains("startInfo.ArgumentList.Add(\"stdio://\")", appServerClient, StringComparison.Ordinal);
        Assert.Contains("AddConfigOverride(startInfo, \"cli_auth_credentials_store=\\\"file\\\"\")", appServerClient, StringComparison.Ordinal);
        Assert.Contains("account/login/start", appServerClient, StringComparison.Ordinal);
        Assert.Contains("account/login/cancel", appServerClient, StringComparison.Ordinal);
        Assert.Contains("account/read", appServerClient, StringComparison.Ordinal);
        Assert.DoesNotContain("ArgumentList.Add(authFilePath)", appServerClient, StringComparison.Ordinal);
        Assert.DoesNotContain("PiDevice", page + codeBehind + script + appServerClient, StringComparison.Ordinal);
        Assert.DoesNotContain("SubscriptionPi", page + codeBehind + appSettings, StringComparison.Ordinal);
        Assert.DoesNotContain("pi-device-login-bridge", project + appServerClient, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("innerHTML", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProviderAttentionIsCompactAndRoutesConfigurationToSettings()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");

        Assert.Contains("id=\"soc-agent-provider-pill\"", page, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-provider-inline-notice\"", page, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Provider attention required\"", page, StringComparison.Ordinal);
        Assert.Contains(">Review settings</button>", page, StringComparison.Ordinal);
        Assert.Contains("ShouldShowProviderInlineNotice => ProviderNeedsAttention(ProviderStatus);", codeBehind, StringComparison.Ordinal);
        Assert.Contains("\"provider_error\" => true", codeBehind, StringComparison.Ordinal);
        Assert.DoesNotContain("|| ProviderStatus.DataMayLeaveLocalSiem", codeBehind, StringComparison.Ordinal);
        Assert.DoesNotContain("|| CanStartSubscriptionOAuthConnect", codeBehind, StringComparison.Ordinal);
        Assert.Contains("providerInlineNotice.hidden = !providerNeedsAttention(status);", script, StringComparison.Ordinal);
        Assert.Contains("providerPill.setAttribute('aria-label', `Provider status: ${statusText}`);", script, StringComparison.Ordinal);
        Assert.DoesNotContain("provider-setup-inline", page, StringComparison.Ordinal);
        Assert.DoesNotContain("External provider setup", page, StringComparison.Ordinal);
    }

    [Fact]
    public void ComposerOffersAllowlistedModelAndEffortControlsAndSendsBothSelections()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");

        Assert.Contains("id=\"soc-agent-model-select\" name=\"SelectedModel\"", page, StringComparison.Ordinal);
        Assert.Contains("data-reasoning-efforts=\"@string.Join(',', option.ReasoningEfforts)\"", page, StringComparison.Ordinal);
        Assert.Contains("data-default-reasoning-effort=\"@option.DefaultReasoningEffort\"", page, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-effort-select\" name=\"ReasoningEffort\"", page, StringComparison.Ordinal);
        Assert.Contains("<option value=\"\">Not available</option>", page, StringComparison.Ordinal);
        Assert.Contains("Enter to send · Shift+Enter for a new line · Read-only tools", page, StringComparison.Ordinal);

        Assert.Contains("function syncReasoningEfforts(preferredEffort = effortSelect?.value)", script, StringComparison.Ordinal);
        Assert.Contains("effortSelect.replaceChildren();", script, StringComparison.Ordinal);
        Assert.Contains("modelSelect.disabled = isRunning;", script, StringComparison.Ordinal);
        Assert.Contains("effortSelect.disabled = isRunning || !selectedModelSupportsEffort();", script, StringComparison.Ordinal);
        Assert.Contains("const selectedModel = modelSelect.value || null;", script, StringComparison.Ordinal);
        Assert.Contains("const selectedReasoningEffort = selectedModelSupportsEffort()", script, StringComparison.Ordinal);
        Assert.Contains("model: selectedModel,", script, StringComparison.Ordinal);
        Assert.Contains("reasoning_effort: selectedReasoningEffort", script, StringComparison.Ordinal);
        Assert.Contains("applyExecutionSelection(data.model, data.reasoning_effort);", script, StringComparison.Ordinal);
        Assert.Contains("applyExecutionSelection(data.session.model, data.session.reasoning_effort);", script, StringComparison.Ordinal);
        Assert.Contains("modelSelect.addEventListener('change', () => syncReasoningEfforts());", script, StringComparison.Ordinal);

        Assert.Contains("public string? SelectedModel { get; set; }", codeBehind, StringComparison.Ordinal);
        Assert.Contains("public string? ReasoningEffort { get; set; }", codeBehind, StringComparison.Ordinal);
        Assert.Contains("Model = SelectedModel,", codeBehind, StringComparison.Ordinal);
        Assert.Contains("ReasoningEffort = ReasoningEffort", codeBehind, StringComparison.Ordinal);
    }

    [Fact]
    public void ToolActivityStaysOutOfTheChatWorkspaceWhileSourcesRemainVisible()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");
        var focusedCss = ReadFocusedWorkspaceCss();

        Assert.DoesNotContain("message-activity", page, StringComparison.Ordinal);
        Assert.DoesNotContain("message.ToolRuns", page, StringComparison.Ordinal);
        Assert.DoesNotContain("id=\"soc-agent-activity-list\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("id=\"soc-agent-activity-panel\"", page, StringComparison.Ordinal);

        Assert.Contains("case 'tool_started':", script, StringComparison.Ordinal);
        Assert.Contains("setPendingAssistantPlaceholder('soc-agent is working…');", script, StringComparison.Ordinal);
        Assert.DoesNotContain("data.tool_name", script, StringComparison.Ordinal);
        Assert.Contains("case 'tool_finished':", script, StringComparison.Ordinal);
        Assert.DoesNotContain("hydrateToolActivity", script, StringComparison.Ordinal);
        Assert.DoesNotContain("upsertActivity", script, StringComparison.Ordinal);
        Assert.DoesNotContain("message-activity", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".message-activity", focusedCss, StringComparison.Ordinal);
        Assert.Contains("<div class=\"message-citations\">", page, StringComparison.Ordinal);
        Assert.Contains("<span>Sources</span>", page, StringComparison.Ordinal);
    }

    [Fact]
    public void ThreadAutoFollowUsesOnlyTheInternalConversationScroller()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");
        var focusedCss = ReadFocusedWorkspaceCss();

        Assert.Contains("id=\"soc-agent-thread-scroll\" class=\"conversation-scroll\" tabindex=\"0\"", page, StringComparison.Ordinal);
        Assert.Contains("let autoFollow = false;", script, StringComparison.Ordinal);
        Assert.Contains("function isLatestVisible()", script, StringComparison.Ordinal);
        Assert.Contains("return threadScroll.scrollHeight - threadScroll.scrollTop - threadScroll.clientHeight < 96;", script, StringComparison.Ordinal);
        Assert.Contains("threadScroll.scrollTo({", script, StringComparison.Ordinal);
        Assert.Contains("top: threadScroll.scrollHeight,", script, StringComparison.Ordinal);
        Assert.Contains("programmaticScrollUntil = Date.now() + (force ? 700 : 250);", script, StringComparison.Ordinal);
        Assert.Contains("threadScroll.addEventListener('scroll', () => {", script, StringComparison.Ordinal);
        Assert.Contains("threadScroll.addEventListener('wheel', markUserScrollIntent, { passive: true });", script, StringComparison.Ordinal);
        Assert.Contains("threadScroll.addEventListener('touchmove', markUserScrollIntent, { passive: true });", script, StringComparison.Ordinal);
        Assert.Contains("scrollButton.addEventListener('click', () => scrollToLatest(true));", script, StringComparison.Ordinal);
        Assert.Contains("setAutoFollow(isLatestVisible());", script, StringComparison.Ordinal);
        Assert.DoesNotContain("window.scrollTo", script, StringComparison.Ordinal);
        Assert.DoesNotContain("scrollIntoView", script, StringComparison.Ordinal);

        Assert.Contains("height: min(64rem, calc(100vh - 7.5rem));", focusedCss, StringComparison.Ordinal);
        Assert.Contains("class=\"button tertiary small conversation-latest\"", page, StringComparison.Ordinal);
        Assert.Contains(".conversation-scroll {\n    grid-area: transcript;\n    min-height: 0;\n    overflow-y: auto;", focusedCss, StringComparison.Ordinal);
        Assert.Contains("overscroll-behavior: contain;", focusedCss, StringComparison.Ordinal);
    }

    [Fact]
    public void AssistantMessagesRetainSafeMarkdownWhileOperatorMessagesStayPlainText()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");
        var css = ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "site.css")
            + "\n"
            + ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "soc-agent.css");

        Assert.Contains("Model.ShouldRenderMarkdown(message)", page, StringComparison.Ordinal);
        Assert.Contains("data-message-markdown=\"true\"", page, StringComparison.Ordinal);
        Assert.Contains("function renderMarkdownInto(container, markdown)", script, StringComparison.Ordinal);
        Assert.Contains("function renderInlineInto(parent, text, options = {})", script, StringComparison.Ordinal);
        Assert.Contains("function sanitizeMarkdownLink(url)", script, StringComparison.Ordinal);
        Assert.Contains("function shouldRenderMarkdown(role)", script, StringComparison.Ordinal);
        Assert.Contains("return role !== 'operator';", script, StringComparison.Ordinal);
        Assert.Contains("return createElement('pre', 'message-box', content || '');", script, StringComparison.Ordinal);
        Assert.Contains("value.startsWith('//')", script, StringComparison.Ordinal);
        Assert.Contains("parsed.protocol === 'https:' || parsed.protocol === 'http:'", script, StringComparison.Ordinal);
        Assert.Contains("&& !parsed.username", script, StringComparison.Ordinal);
        Assert.Contains("&& !parsed.password", script, StringComparison.Ordinal);
        Assert.Contains("anchor.rel = 'noreferrer noopener';", script, StringComparison.Ordinal);
        Assert.Contains("parent.appendChild(document.createTextNode(link.label || link.url));", script, StringComparison.Ordinal);
        Assert.Contains("buffer += value.slice(index, image.end);", script, StringComparison.Ordinal);
        Assert.DoesNotContain("innerHTML", script, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("ShouldRenderMarkdown", codeBehind, StringComparison.Ordinal);
        Assert.Contains("!string.Equals(message.Role, \"operator\", StringComparison.OrdinalIgnoreCase)", codeBehind, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-workspace .markdown-content", css, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-workspace .markdown-content .markdown-code-block", css, StringComparison.Ordinal);
        Assert.Contains("white-space: pre;", css, StringComparison.Ordinal);
        Assert.Contains("outline: 2px solid var(--focus);", css, StringComparison.Ordinal);
    }

    [Fact]
    public void LiveSendUsesOptimisticMessagesAndReplaysInitialStreamEvents()
    {
        var script = ReadRepoFile("server", "Siem.Api", "wwwroot", "js", "soc-agent.js");

        Assert.Contains("function appendOptimisticOperatorMessage(content)", script, StringComparison.Ordinal);
        Assert.Contains("setPendingAssistantPlaceholder('Starting soc-agent live run…');", script, StringComparison.Ordinal);
        Assert.Contains("setPendingAssistantPlaceholder('soc-agent is working…');", script, StringComparison.Ordinal);
        Assert.Contains("hydrateOptimisticOperatorMessage(optimisticOperator, result.user_message);", script, StringComparison.Ordinal);
        Assert.Contains("openEventStream(result.run_id, 0);", script, StringComparison.Ordinal);
        Assert.Contains("pendingAssistant.setAttribute('aria-busy', 'true');", script, StringComparison.Ordinal);
        Assert.Contains("case 'tool_started':", script, StringComparison.Ordinal);
        Assert.DoesNotContain("upsertActivity", script, StringComparison.Ordinal);
        Assert.Contains("const explicitSendShortcut = event.ctrlKey || event.metaKey;", script, StringComparison.Ordinal);
        Assert.Contains("if (!running && !sendButton.disabled)", script, StringComparison.Ordinal);
    }

    [Fact]
    public void HistoryDeletionUsesDirectAccessibleControlAndRetainsOneShotAuditTurns()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");

        Assert.Contains("<h2 id=\"soc-agent-history-title\">Recent chats</h2>", page, StringComparison.Ordinal);
        Assert.Contains("<form class=\"history-delete-form\" method=\"post\" asp-page-handler=\"DeleteSession\">", page, StringComparison.Ordinal);
        Assert.Contains("class=\"history-delete-button\"", page, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Delete chat: @session.Title\"", page, StringComparison.Ordinal);
        Assert.Contains("title=\"Delete chat\">×</button>", page, StringComparison.Ordinal);
        Assert.Contains("asp-page-handler=\"DeleteSession\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"DeleteSessionId\"", page, StringComparison.Ordinal);
        Assert.Contains("<input type=\"hidden\" name=\"ConfirmDelete\" value=\"true\" />", page, StringComparison.Ordinal);
        Assert.DoesNotContain("name=\"ConfirmDelete\" value=\"true\" required", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<details class=\"history-actions\">", page, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"history-actions-dialog\"", page, StringComparison.Ordinal);
        var css = ReadFocusedWorkspaceCss();
        Assert.Contains(".history-delete-form {\n    position: absolute;", css, StringComparison.Ordinal);
        Assert.Contains(".history-delete-button:hover,\n.history-delete-button:focus-visible {\n    background: var(--error-surface);", css, StringComparison.Ordinal);
        Assert.Contains("OnPostDeleteSessionAsync", codeBehind, StringComparison.Ordinal);
    }

    private static string ReadFocusedWorkspaceCss()
    {
        const string marker = "/* soc-agent focused workspace */";
        var css = ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "soc-agent.css");
        var markerIndex = css.IndexOf(marker, StringComparison.Ordinal);
        if (markerIndex < 0)
        {
            throw new InvalidOperationException("Could not locate the focused soc-agent workspace CSS block.");
        }

        return css[markerIndex..];
    }

    private static int CountOccurrences(string value, string needle)
    {
        var count = 0;
        var offset = 0;
        while ((offset = value.IndexOf(needle, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += needle.Length;
        }

        return count;
    }

    private static string ReadRepoFile(params string[] pathParts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(pathParts).ToArray());
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not locate repository file {Path.Combine(pathParts)} from {AppContext.BaseDirectory}.");
    }
}
