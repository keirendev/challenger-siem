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
    public void ScriptUsesExplicitAutoFollowStateAndSendShortcuts()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");

        Assert.Contains("let autoFollow = true;", page, StringComparison.Ordinal);
        Assert.Contains("function setAutoFollow(shouldFollow)", page, StringComparison.Ordinal);
        Assert.Contains("threadScroll.addEventListener('scroll', () => setAutoFollow(isNearBottom()), { passive: true });", page, StringComparison.Ordinal);
        Assert.Contains("scrollButton.addEventListener('click', () => scrollToLatest(true));", page, StringComparison.Ordinal);
        Assert.Contains("const explicitSendShortcut = event.ctrlKey || event.metaKey;", page, StringComparison.Ordinal);
        Assert.Contains("if (!running && !sendButton.disabled)", page, StringComparison.Ordinal);
    }

    [Fact]
    public void CollapsedActivityPanelKeepsExpandControlVisibleAndFocusable()
    {
        var page = ReadRepoFile("server", "Siem.Api", "Pages", "SocAgent.cshtml");
        var css = ReadRepoFile("server", "Siem.Api", "wwwroot", "css", "site.css");

        Assert.Contains("aria-controls=\"soc-agent-activity-panel\"", page, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(220px, 290px) minmax(0, 1fr) minmax(8.5rem, 10rem);", css, StringComparison.Ordinal);
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
