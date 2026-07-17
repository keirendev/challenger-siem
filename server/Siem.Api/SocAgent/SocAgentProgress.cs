using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.SocAgent;

public interface ISocAgentProgressSink
{
    ValueTask ProviderStatusAsync(SocAgentProviderStatusResponse status, CancellationToken cancellationToken);

    ValueTask ToolStartedAsync(string toolName, string summary, CancellationToken cancellationToken);

    ValueTask ToolFinishedAsync(SocAgentToolRunSummary toolRun, CancellationToken cancellationToken);

    ValueTask CitationAddedAsync(SocAgentCitation citation, CancellationToken cancellationToken);
}

public static class SocAgentProgressSinkExtensions
{
    public static async ValueTask AddToolFinishedAsync(
        this ISocAgentProgressSink? progress,
        List<SocAgentToolRunSummary> toolRuns,
        SocAgentToolRunSummary toolRun,
        CancellationToken cancellationToken)
    {
        toolRuns.Add(toolRun);
        if (progress is not null)
        {
            await progress.ToolFinishedAsync(toolRun, cancellationToken);
        }
    }

    public static async ValueTask AddCitationAsync(
        this ISocAgentProgressSink? progress,
        List<SocAgentCitation> citations,
        SocAgentCitation citation,
        CancellationToken cancellationToken)
    {
        citations.Add(citation);
        if (progress is not null)
        {
            await progress.CitationAddedAsync(citation, cancellationToken);
        }
    }
}

public sealed record SocAgentChatTurn(
    SocAgentSessionSummary Session,
    SocAgentChatMessageDto UserMessage,
    SocAgentAskRequest AskRequest,
    SocAgentProviderStatusResponse ProviderStatus,
    SocAgentExecutionSelection Selection,
    string OperatorRole);
