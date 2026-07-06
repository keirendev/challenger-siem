using Xunit;

namespace Challenger.Siem.Api.Tests;

public sealed class SocAgentWorkspaceUiTests
{
    [Fact]
    public void ComposerHidesManualAgentContextInputButKeepsContextScopingAndShortcutCopy()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");

        Assert.DoesNotContain("Optional agent ID context", page);
        Assert.Contains("type=\"hidden\" id=\"ComposerContextAgentId\" name=\"ComposerContextAgentId\"", page, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-context-chip\"", page, StringComparison.Ordinal);
        Assert.Contains("Clear context", page, StringComparison.Ordinal);
        Assert.Contains("Enter/Ctrl+Enter/Cmd+Enter sends; Shift+Enter adds a newline.", page, StringComparison.Ordinal);
    }

    [Fact]
    public void ScriptUsesThreadAwareAutoFollowStateAndSendShortcuts()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");

        Assert.Contains("let autoFollow = false;", page, StringComparison.Ordinal);
        Assert.Contains("const threadEnd = document.getElementById('soc-agent-thread-end');", page, StringComparison.Ordinal);
        Assert.Contains("function isLatestVisible()", page, StringComparison.Ordinal);
        Assert.Contains("function latestScrollTop(target)", page, StringComparison.Ordinal);
        Assert.Contains("window.scrollTo({", page, StringComparison.Ordinal);
        Assert.Contains("programmaticScrollUntil = Date.now() + (force ? 700 : 250);", page, StringComparison.Ordinal);
        Assert.Contains("function setAutoFollow(shouldFollow)", page, StringComparison.Ordinal);
        Assert.Contains("function markUserScrollIntent()", page, StringComparison.Ordinal);
        Assert.Contains("window.addEventListener('wheel', markUserScrollIntent, { passive: true });", page, StringComparison.Ordinal);
        Assert.Contains("Date.now() < programmaticScrollUntil", page, StringComparison.Ordinal);
        Assert.DoesNotContain("function documentScrollHeight()", page, StringComparison.Ordinal);
        Assert.DoesNotContain("window.scrollTo({ top: documentScrollHeight()", page, StringComparison.Ordinal);
        Assert.DoesNotContain("target.scrollIntoView", page, StringComparison.Ordinal);
        Assert.DoesNotContain("scrollToLatest(true);\n    resumeActiveRun();", page, StringComparison.Ordinal);
        Assert.DoesNotContain("threadScroll.addEventListener('scroll'", page, StringComparison.Ordinal);
        Assert.Contains("scrollButton.addEventListener('click', () => scrollToLatest(true));", page, StringComparison.Ordinal);
        Assert.Contains("const explicitSendShortcut = event.ctrlKey || event.metaKey;", page, StringComparison.Ordinal);
        Assert.Contains("if (!running && !sendButton.disabled)", page, StringComparison.Ordinal);
    }

    [Fact]
    public void WorkspaceCssUsesWiderThreadAwarePageLayoutWithoutNestedVerticalScrollbars()
    {
        var layout = ReadRepoFile("server", "Siem.Api", "Pages", "Shared", "_Layout.cshtml");
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var css = ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "site.css");

        Assert.Contains("ViewData[\"MainClass\"] = \"container soc-agent-container\";", page, StringComparison.Ordinal);
        Assert.Contains("var mainClass = ViewData[\"MainClass\"] as string ?? \"container\";", layout, StringComparison.Ordinal);
        Assert.Contains("class=\"@mainClass\"", layout, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-thread-scroll\"", page, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-thread-end\"", page, StringComparison.Ordinal);
        Assert.Contains(".container.soc-agent-container", css, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(210px, 260px) minmax(0, 1.85fr) minmax(260px, 340px);", css, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-rail,\n.soc-agent-activity {\n    align-self: start;", css, StringComparison.Ordinal);
        Assert.Contains(".live-thread {\n    display: grid;", css, StringComparison.Ordinal);
        Assert.Contains(".thread-scroll {\n    overflow: visible;", css, StringComparison.Ordinal);
        Assert.Contains(".thread-end-sentinel", css, StringComparison.Ordinal);
        Assert.Contains(".soc-agent-workspace .message-box {\n    max-height: none;\n    overflow: visible;", css, StringComparison.Ordinal);
        Assert.DoesNotContain("max-height: calc(100vh - 8rem);", css, StringComparison.Ordinal);
        Assert.DoesNotContain("height: min(74vh, 52rem);", css, StringComparison.Ordinal);
        Assert.DoesNotContain("height: 68vh;", css, StringComparison.Ordinal);
        Assert.DoesNotContain(".thread-scroll {\n    flex: 1;\n    min-height: 0;\n    overflow-y: auto;", css, StringComparison.Ordinal);
    }

    [Fact]
    public void ActivityRailShowsLiveToolActivityWithoutPersistentProviderSetupBoxes()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");
        var css = ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "site.css");

        Assert.Contains("aria-label=\"Provider status: @Model.ProviderStatus.Status\"", page, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-provider-inline-notice\"", page, StringComparison.Ordinal);
        Assert.Contains("ShouldShowProviderInlineNotice => ProviderNeedsAttention(ProviderStatus);", codeBehind, StringComparison.Ordinal);
        Assert.Contains("\"provider_error\" => true", codeBehind, StringComparison.Ordinal);
        Assert.DoesNotContain("|| ProviderStatus.DataMayLeaveLocalSiem", codeBehind, StringComparison.Ordinal);
        Assert.DoesNotContain("|| CanStartSubscriptionOAuthConnect", codeBehind, StringComparison.Ordinal);
        Assert.Contains("providerInlineNotice.hidden = !providerNeedsAttention(status);", page, StringComparison.Ordinal);
        Assert.Contains("<h2 id=\"activity-title\">Live tool activity</h2>", page, StringComparison.Ordinal);
        Assert.Contains("id=\"soc-agent-activity-list\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"compact-provider\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("provider-setup-inline", page, StringComparison.Ordinal);
        Assert.DoesNotContain("External provider setup", page, StringComparison.Ordinal);
        Assert.Contains(".activity-feed", css, StringComparison.Ordinal);
        Assert.Contains("overflow-wrap: anywhere;", css, StringComparison.Ordinal);
        Assert.Contains(".activity-card .tool-card-header strong", css, StringComparison.Ordinal);
    }

    [Fact]
    public void LiveSendShowsOptimisticMessagePendingAssistantAndReplaysInitialStreamEvents()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");

        Assert.Contains("function appendOptimisticOperatorMessage(content)", page, StringComparison.Ordinal);
        Assert.Contains("setPendingAssistantPlaceholder('Starting soc-agent live run…');", page, StringComparison.Ordinal);
        Assert.Contains("setPendingAssistantPlaceholder('soc-agent is running SIEM tools…');", page, StringComparison.Ordinal);
        Assert.Contains("hydrateOptimisticOperatorMessage(optimisticOperator, result.user_message);", page, StringComparison.Ordinal);
        Assert.Contains("openEventStream(result.run_id, 0);", page, StringComparison.Ordinal);
        Assert.Contains("item.classList.remove('pending');", page, StringComparison.Ordinal);
        Assert.Contains("pendingAssistant.setAttribute('aria-busy', 'true');", page, StringComparison.Ordinal);
        Assert.Contains("case 'tool_started':", page, StringComparison.Ordinal);
        Assert.Contains("upsertActivity(type, data, payload.sequence);", page, StringComparison.Ordinal);
    }

    [Fact]
    public void SessionDeletionControlsAreConfirmationGatedAndCollapsedActivityPanelRemainsFocusable()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var codeBehind = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml.cs");
        var css = ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "site.css");

        Assert.Contains("asp-page-handler=\"DeleteSession\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"DeleteSessionId\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"ConfirmDelete\"", page, StringComparison.Ordinal);
        Assert.Contains("One-shot soc-agent audit turns are retained", page, StringComparison.Ordinal);
        Assert.Contains("OnPostDeleteSessionAsync", codeBehind, StringComparison.Ordinal);
        Assert.Contains("Confirm chat deletion before removing a soc-agent session.", codeBehind, StringComparison.Ordinal);
        Assert.Contains("aria-controls=\"soc-agent-activity-panel\"", page, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(210px, 260px) minmax(0, 1.85fr) minmax(8.5rem, 10rem);", css, StringComparison.Ordinal);
        Assert.Contains(".activity-collapsed .activity-panel-header > div", css, StringComparison.Ordinal);
        Assert.Contains(".activity-collapsed #soc-agent-toggle-activity", css, StringComparison.Ordinal);
        Assert.Contains("overflow: visible;", css, StringComparison.Ordinal);
        Assert.Contains("#soc-agent-scroll-bottom[hidden]", css, StringComparison.Ordinal);
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
