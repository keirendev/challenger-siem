using System.Text;
using Challenger.Siem.Api.Database;
using Challenger.Siem.Api.Review;
using Challenger.Siem.Contracts.V1;
using Microsoft.Extensions.Options;

namespace Challenger.Siem.Api.SocAgent;

public sealed class SocAgentService(
    EventRepository events,
    ReviewRepository review,
    SourceHealthRepository sourceHealth,
    AlertRepository alerts,
    AssetInventoryRepository inventory,
    InvestigationGraphRepository graphs,
    SocAgentRepository audit,
    SocAgentProviderStatusService providerStatus,
    ISocAgentModelProvider modelProvider,
    SocAgentLiveRunRegistry liveRuns,
    IOptions<SocAgentOptions> options)
{
    private readonly SocAgentOptions options = options.Value;

    public SocAgentProviderStatusResponse GetProviderStatus() => providerStatus.GetStatus();

    public Task<IReadOnlyList<SocAgentSessionSummary>> GetRecentSessionsAsync(CancellationToken cancellationToken)
    {
        return audit.GetRecentSessionsAsync(Math.Clamp(options.MaxChatMessages, 1, 50), cancellationToken);
    }

    public async Task<SocAgentSessionSummary> CreateSessionAsync(
        SocAgentSessionCreateRequest request,
        CancellationToken cancellationToken)
    {
        var status = GetProviderStatus();
        var title = string.IsNullOrWhiteSpace(request.Title)
            ? "New investigation"
            : request.Title.Trim();
        return await audit.CreateSessionAsync(
            title,
            EffectiveProvider(status),
            EffectiveModel(status),
            request.ContextAgentId,
            request.ContextEventId,
            cancellationToken);
    }

    public async Task<SocAgentSessionDetailResponse?> GetSessionDetailAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var session = await audit.GetSessionAsync(sessionId, cancellationToken);
        if (session is null)
        {
            return null;
        }

        var messages = await audit.GetMessagesAsync(sessionId, Math.Clamp(options.MaxChatMessages, 1, 200), cancellationToken);
        return new SocAgentSessionDetailResponse
        {
            Session = session,
            Messages = messages,
            ProviderStatus = GetProviderStatus()
        };
    }

    public async Task<SocAgentSessionDeleteResponse> DeleteSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        if (liveRuns.TryGetActiveRunForSession(sessionId, out _))
        {
            return new SocAgentSessionDeleteResponse
            {
                SessionId = sessionId,
                Deleted = false,
                Status = "run_active",
                Message = "Cancel or finish the active soc-agent run before deleting this chat."
            };
        }

        var deleted = await audit.DeleteSessionAsync(sessionId, cancellationToken);
        return new SocAgentSessionDeleteResponse
        {
            SessionId = sessionId,
            Deleted = deleted,
            Status = deleted ? "deleted" : "not_found",
            Message = deleted
                ? "Deleted the soc-agent chat session and its persisted messages. One-shot soc-agent audit turns are retained."
                : "The selected soc-agent chat session was not found."
        };
    }

    public async Task<SocAgentChatResponse> SendChatMessageAsync(
        Guid? sessionId,
        SocAgentChatRequest request,
        string operatorRole,
        CancellationToken cancellationToken)
    {
        var turn = await StartChatTurnAsync(sessionId, request, operatorRole, cancellationToken);
        return await CompleteChatTurnAsync(turn, progress: null, cancellationToken);
    }

    public async Task<SocAgentChatTurn> StartChatTurnAsync(
        Guid? sessionId,
        SocAgentChatRequest request,
        string operatorRole,
        CancellationToken cancellationToken)
    {
        var message = request.Message.Trim();
        var maxPromptCharacters = Math.Clamp(options.MaxPromptCharacters, 1, 20_000);
        if (string.IsNullOrWhiteSpace(message) || message.Length > maxPromptCharacters)
        {
            throw new ArgumentException($"Message is required and must be {maxPromptCharacters} characters or less.", nameof(request));
        }

        var status = GetProviderStatus();
        var session = sessionId.HasValue
            ? await audit.GetSessionAsync(sessionId.Value, cancellationToken)
            : null;
        if (sessionId.HasValue && session is null)
        {
            throw new KeyNotFoundException("soc-agent chat session was not found.");
        }

        session ??= await audit.CreateSessionAsync(
            MakeTitle(message),
            EffectiveProvider(status),
            EffectiveModel(status),
            request.ContextAgentId,
            request.ContextEventId,
            cancellationToken);

        var effectiveContextAgentId = string.IsNullOrWhiteSpace(request.ContextAgentId)
            ? session.ContextAgentId
            : request.ContextAgentId.Trim();
        var effectiveContextEventId = request.ContextEventId ?? session.ContextEventId;

        var userMessage = await audit.AddMessageAsync(
            session.SessionId,
            "operator",
            message,
            provider: null,
            model: null,
            toolRuns: Array.Empty<SocAgentToolRunSummary>(),
            citations: Array.Empty<SocAgentCitation>(),
            errorCode: null,
            cancellationToken);

        return new SocAgentChatTurn(
            session,
            userMessage,
            new SocAgentAskRequest
            {
                Question = message,
                ContextAgentId = effectiveContextAgentId,
                ContextEventId = effectiveContextEventId
            },
            status,
            operatorRole);
    }

    public async Task<SocAgentChatResponse> CompleteChatTurnAsync(
        SocAgentChatTurn turn,
        ISocAgentProgressSink? progress,
        CancellationToken cancellationToken)
    {
        SocAgentAskResponse response;
        string? errorCode = null;
        try
        {
            response = await AskAsync(turn.AskRequest, turn.OperatorRole, progress, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            errorCode = "cancelled";
            response = new SocAgentAskResponse
            {
                Provider = EffectiveProvider(turn.ProviderStatus),
                Model = EffectiveModel(turn.ProviderStatus),
                Answer = "soc-agent turn was cancelled by the operator before completion. No additional SIEM mutations were performed.",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }
        catch (Exception ex)
        {
            errorCode = ex.GetType().Name;
            response = new SocAgentAskResponse
            {
                Provider = EffectiveProvider(turn.ProviderStatus),
                Model = EffectiveModel(turn.ProviderStatus),
                Answer = "soc-agent could not complete the request. Confirm the database schema is applied and try again.",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        var assistantMessage = await audit.AddMessageAsync(
            turn.Session.SessionId,
            "soc_agent",
            response.Answer,
            response.Provider,
            response.Model,
            response.ToolRuns,
            response.Citations,
            errorCode,
            CancellationToken.None);

        var updatedSession = await audit.GetSessionAsync(turn.Session.SessionId, CancellationToken.None) ?? turn.Session;
        return new SocAgentChatResponse
        {
            Session = updatedSession,
            UserMessage = turn.UserMessage,
            AssistantMessage = assistantMessage,
            ProviderStatus = turn.ProviderStatus
        };
    }

    public Task<SocAgentAskResponse> AskAsync(SocAgentAskRequest request, string operatorRole, CancellationToken cancellationToken)
    {
        return AskAsync(request, operatorRole, progress: null, cancellationToken);
    }

    public async Task<SocAgentAskResponse> AskAsync(SocAgentAskRequest request, string operatorRole, ISocAgentProgressSink? progress, CancellationToken cancellationToken)
    {
        var status = GetProviderStatus();
        if (progress is not null)
        {
            await progress.ProviderStatusAsync(status, cancellationToken);
        }
        if (!options.Enabled)
        {
            return new SocAgentAskResponse
            {
                Provider = status.Provider,
                Model = status.Model,
                Answer = status.Message,
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        if (IsExternalProviderUnavailable(status) && !options.FallbackToLocalWhenUnavailable)
        {
            return new SocAgentAskResponse
            {
                Provider = status.Provider,
                Model = status.Model,
                Answer = $"Provider unavailable: {status.Message}",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        var question = string.IsNullOrWhiteSpace(request.Question) ? "Summarize current SIEM posture." : request.Question.Trim();
        var citations = new List<SocAgentCitation>();
        var toolRuns = new List<SocAgentToolRunSummary>();
        var answer = new StringBuilder();
        var usingLocalFallback = IsExternalProviderUnavailable(status) && options.FallbackToLocalWhenUnavailable;

        async ValueTask StartToolAsync(string toolName, string summary)
        {
            if (progress is not null)
            {
                await progress.ToolStartedAsync(toolName, summary, cancellationToken);
            }
        }

        async ValueTask AddToolAsync(SocAgentToolRunSummary toolRun)
        {
            toolRuns.Add(toolRun);
            if (progress is not null)
            {
                await progress.ToolFinishedAsync(toolRun, cancellationToken);
            }
        }

        async ValueTask AddCitationAsync(SocAgentCitation citation)
        {
            citations.Add(citation);
            if (progress is not null)
            {
                await progress.CitationAddedAsync(citation, cancellationToken);
            }
        }

        await StartToolAsync("agent_inventory_search", "Loading recent agent inventory and coverage summary rows.");
        var agents = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, request.ContextAgentId, null, "active"),
            TimeSpan.FromMinutes(15),
            cancellationToken);
        var selectedAgents = agents.Take(Math.Clamp(options.MaxAgents, 1, 50)).ToArray();
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "agent_inventory_search", RowCount = selectedAgents.Length, Summary = "Loaded recent agent inventory and coverage summary rows." });
        await AddCitationAsync(new SocAgentCitation { Kind = "agent_search", Label = "Agent inventory", Url = string.IsNullOrWhiteSpace(request.ContextAgentId) ? "/agents" : $"/agents?agent_id={Uri.EscapeDataString(request.ContextAgentId)}" });

        await StartToolAsync("coverage_summary", "Loading source-health rows and coverage summaries.");
        var sourceHealthResponse = await sourceHealth.SearchAsync(request.ContextAgentId, cancellationToken);
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "coverage_summary", RowCount = sourceHealthResponse.Sources.Count, Summary = "Loaded source-health rows and coverage summaries." });
        if (!string.IsNullOrWhiteSpace(request.ContextAgentId))
        {
            await AddCitationAsync(new SocAgentCitation { Kind = "source_health", Label = "Host coverage", Url = $"/agents/detail?agent_id={Uri.EscapeDataString(request.ContextAgentId)}" });
        }

        var eventQuery = EventSearchQuery.Empty with
        {
            AgentId = request.ContextAgentId,
            From = DateTimeOffset.UtcNow.AddHours(-24),
            Limit = Math.Clamp(options.MaxEvents, 1, 50)
        };
        await StartToolAsync("event_search", "Loading recent normalized events for the current scope.");
        var recentEvents = await events.SearchEventsForOperatorAsync(eventQuery, operatorRole, cancellationToken);
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "event_search", RowCount = recentEvents.Count, Summary = "Loaded recent normalized events for the current scope." });
        await AddCitationAsync(new SocAgentCitation { Kind = "event_search", Label = "Recent events", Url = string.IsNullOrWhiteSpace(request.ContextAgentId) ? "/events" : $"/events?agent_id={Uri.EscapeDataString(request.ContextAgentId)}&limit=25" });
        foreach (var evt in recentEvents.Take(3))
        {
            await AddCitationAsync(new SocAgentCitation
            {
                Kind = "event_detail",
                Label = $"Event {evt.WindowsEventId} on {evt.Hostname}",
                Url = $"/events/detail?agent_id={Uri.EscapeDataString(evt.AgentId)}&event_id={evt.EventId}"
            });
        }

        await StartToolAsync("alert_review", "Loading current alert review rows.");
        var alertRows = await alerts.SearchAlertsAsync(null, cancellationToken);
        var selectedAlerts = alertRows
            .Select(item => Challenger.Siem.Api.Auth.AlertFieldPolicy.Apply(item, operatorRole))
            .Take(Math.Clamp(options.MaxAlerts, 1, 50))
            .ToArray();
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "alert_review", RowCount = selectedAlerts.Length, Summary = "Loaded current alert review rows." });
        await AddCitationAsync(new SocAgentCitation { Kind = "alerts", Label = "Alerts", Url = "/alerts" });

        await StartToolAsync("detection_rule_metadata", "Loading detection rule metadata and prerequisites.");
        var detectionRules = await alerts.GetRulesAsync(cancellationToken);
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "detection_rule_metadata", RowCount = detectionRules.Count, Summary = "Loaded detection rule metadata and prerequisites." });

        await StartToolAsync("inventory_summary", "Loading bounded inventory snapshot summaries.");
        var inventoryRows = await inventory.SearchAsync(request.ContextAgentId, null, cancellationToken);
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "inventory_summary", RowCount = inventoryRows.Count, Summary = "Loaded bounded inventory snapshot summaries." });
        await AddCitationAsync(new SocAgentCitation { Kind = "audit_policy", Label = "Audit policy drift", Url = string.IsNullOrWhiteSpace(request.ContextAgentId) ? "/audit-policy" : $"/audit-policy?agent_id={Uri.EscapeDataString(request.ContextAgentId)}" });

        await StartToolAsync("graph_search", "Loading active investigation graph summaries for operator-managed context.");
        var graphRows = await graphs.ListAsync("active", cancellationToken);
        var selectedGraphs = graphRows.Take(5).ToArray();
        await AddToolAsync(new SocAgentToolRunSummary { ToolName = "graph_search", RowCount = selectedGraphs.Length, Summary = "Loaded active investigation graph summaries for operator-managed context." });
        await AddCitationAsync(new SocAgentCitation { Kind = "graph_search", Label = "Investigation graphs", Url = "/graphs" });
        foreach (var graph in selectedGraphs.Take(3))
        {
            await AddCitationAsync(new SocAgentCitation { Kind = "graph_detail", Label = graph.Title, Url = $"/graphs/detail?graph_id={graph.GraphId}" });
        }

        answer.AppendLine("soc-agent local SIEM assessment");
        answer.AppendLine();
        if (usingLocalFallback)
        {
            answer.AppendLine($"Provider connection status: {status.Message}");
            answer.AppendLine("Using local fallback only; no prompt or telemetry was sent to an external provider.");
            answer.AppendLine();
        }

        answer.AppendLine($"Question: {question}");
        answer.AppendLine();
        answer.AppendLine($"Observed {selectedAgents.Length} active agent(s), {sourceHealthResponse.Sources.Count} source-health row(s), {recentEvents.Count} recent event(s), {selectedAlerts.Length} alert(s), {detectionRules.Count} detection rule(s), {inventoryRows.Count} inventory snapshot(s), and {selectedGraphs.Length} active investigation graph(s) in scope.");

        var unhealthySummaries = sourceHealthResponse.Summaries
            .Where(summary => !string.Equals(summary.OverallStatus, SourceHealthStatuses.Healthy, StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToArray();
        if (unhealthySummaries.Length > 0)
        {
            answer.AppendLine();
            answer.AppendLine("Coverage priorities:");
            foreach (var summary in unhealthySummaries)
            {
                answer.AppendLine($"- {summary.Hostname} ({summary.AgentId}) is {summary.OverallStatus}: {summary.MissingMandatorySources} missing mandatory, {summary.StaleSources} stale, {summary.ErrorSources} error source(s).");
            }
        }

        if (selectedAlerts.Length > 0)
        {
            answer.AppendLine();
            answer.AppendLine("Open alert priorities:");
            foreach (var alert in selectedAlerts.Take(5))
            {
                answer.AppendLine($"- {alert.Severity}/{alert.Confidence}: {alert.Title} ({alert.RuleId} v{alert.RuleVersion}) status={alert.Status} host={alert.Hostname ?? alert.AgentId ?? "n/a"}.");
            }
        }

        if (recentEvents.Count > 0)
        {
            answer.AppendLine();
            answer.AppendLine("Recent event evidence:");
            foreach (var evt in recentEvents.Take(5))
            {
                var hostTime = TimeDisplay.FormatHostTime(evt.EventTime, evt.HostTimezone);
                var timezoneLabel = TimeDisplay.HostTimezoneLabel(evt.HostTimezone);
                answer.AppendLine($"- {hostTime} ({timezoneLabel}; UTC {evt.EventTime:u}) {evt.Hostname} {evt.Channel}/{evt.WindowsEventId} {evt.Normalized?.Category ?? "windows_event"}/{evt.Normalized?.Action ?? "observed"}: {Preview(evt.Message)}");
            }
        }

        if (selectedGraphs.Length > 0)
        {
            answer.AppendLine();
            answer.AppendLine("Investigation graph context:");
            foreach (var graph in selectedGraphs)
            {
                answer.AppendLine($"- {graph.Title} ({graph.NodeCount} node(s), {graph.EdgeCount} edge(s), status={graph.Status}) can preserve explicit operator context. Use the graph page's soc-agent proposal workflow for approval-gated updates.");
            }
        }

        answer.AppendLine();
        answer.AppendLine("Recommended next steps: review cited coverage gaps, inspect linked events/alerts, validate missing mandatory sources on the endpoint, and keep mutating detection changes as proposals requiring explicit operator approval.");

        var maxResultCharacters = Math.Clamp(options.MaxResultCharacters, 1000, 100_000);
        var localAnswer = SocAgentTextSafety.Truncate(answer.ToString().Trim(), maxResultCharacters);
        var response = await CreateResponseAsync(
            request,
            status,
            localAnswer,
            toolRuns,
            citations,
            maxResultCharacters,
            progress,
            cancellationToken);
        await audit.SaveTurnAsync(request, response, cancellationToken);
        return response;
    }

    private async Task<SocAgentAskResponse> CreateResponseAsync(
        SocAgentAskRequest request,
        SocAgentProviderStatusResponse status,
        string localAnswer,
        List<SocAgentToolRunSummary> toolRuns,
        List<SocAgentCitation> citations,
        int maxResultCharacters,
        ISocAgentProgressSink? progress,
        CancellationToken cancellationToken)
    {
        if (CanUseExternalProvider(status))
        {
            try
            {
                if (progress is not null)
                {
                    await progress.ToolStartedAsync("external_model_provider", "Submitting a bounded/redacted prompt to the configured official provider.", cancellationToken);
                }

                var prompt = BuildExternalPrompt(request.Question, localAnswer, toolRuns, citations);
                var providerResult = await modelProvider.CompleteAsync(
                    new SocAgentModelProviderRequest(status, prompt, maxResultCharacters),
                    cancellationToken);
                var providerToolRun = new SocAgentToolRunSummary
                {
                    ToolName = "external_model_provider",
                    RowCount = 0,
                    Summary = "Submitted a bounded/redacted prompt to the configured official provider."
                };
                toolRuns.Add(providerToolRun);
                if (progress is not null)
                {
                    await progress.ToolFinishedAsync(providerToolRun, cancellationToken);
                }

                return new SocAgentAskResponse
                {
                    Provider = providerResult.Provider,
                    Model = providerResult.Model,
                    Answer = providerResult.Answer,
                    ToolRuns = toolRuns,
                    Citations = citations,
                    CreatedAt = DateTimeOffset.UtcNow
                };
            }
            catch (SocAgentModelProviderException ex) when (options.FallbackToLocalWhenUnavailable)
            {
                var providerToolRun = new SocAgentToolRunSummary
                {
                    ToolName = "external_model_provider",
                    RowCount = 0,
                    Summary = $"External provider failed with {ex.ErrorCode}; used local fallback without exposing provider secrets."
                };
                toolRuns.Add(providerToolRun);
                if (progress is not null)
                {
                    await progress.ToolFinishedAsync(providerToolRun, cancellationToken);
                }

                var fallbackAnswer = SocAgentTextSafety.Truncate(
                    $"External provider unavailable ({ex.ErrorCode}): {ex.OperatorSafeMessage}\nUsing local fallback only; no provider secrets were exposed to the browser.\n\n{localAnswer}",
                    maxResultCharacters);
                return new SocAgentAskResponse
                {
                    Provider = options.LocalFallbackProvider,
                    Model = options.LocalFallbackModel,
                    Answer = fallbackAnswer,
                    ToolRuns = toolRuns,
                    Citations = citations,
                    CreatedAt = DateTimeOffset.UtcNow
                };
            }
            catch (SocAgentModelProviderException ex)
            {
                var providerToolRun = new SocAgentToolRunSummary
                {
                    ToolName = "external_model_provider",
                    RowCount = 0,
                    Summary = $"External provider failed with {ex.ErrorCode}; local fallback is disabled."
                };
                toolRuns.Add(providerToolRun);
                if (progress is not null)
                {
                    await progress.ToolFinishedAsync(providerToolRun, cancellationToken);
                }

                return new SocAgentAskResponse
                {
                    Provider = status.Provider,
                    Model = status.Model,
                    Answer = $"External provider unavailable ({ex.ErrorCode}): {ex.OperatorSafeMessage}",
                    ToolRuns = toolRuns,
                    Citations = citations,
                    CreatedAt = DateTimeOffset.UtcNow
                };
            }
        }

        return new SocAgentAskResponse
        {
            Provider = EffectiveProvider(status),
            Model = EffectiveModel(status),
            Answer = localAnswer,
            ToolRuns = toolRuns,
            Citations = citations,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    private string BuildExternalPrompt(
        string question,
        string localAnswer,
        IReadOnlyList<SocAgentToolRunSummary> toolRuns,
        IReadOnlyList<SocAgentCitation> citations)
    {
        var prompt = new StringBuilder();
        prompt.AppendLine("Challenger SIEM soc-agent external-provider request.");
        prompt.AppendLine("Use the bounded/redacted local SIEM context below. Do not request credentials, do not assume uncited data, and do not propose mutations except as operator-approved proposals.");
        prompt.AppendLine();
        prompt.AppendLine("Operator question (redacted):");
        prompt.AppendLine(SocAgentTextSafety.RedactSecrets(question));
        prompt.AppendLine();
        prompt.AppendLine("Local SIEM tool assessment (bounded/redacted):");
        prompt.AppendLine(SocAgentTextSafety.RedactSecrets(localAnswer));
        prompt.AppendLine();
        prompt.AppendLine("Tool summaries:");
        foreach (var tool in toolRuns.Take(Math.Clamp(options.MaxToolCalls, 1, 20)))
        {
            prompt.AppendLine($"- {tool.ToolName}: rows={tool.RowCount}; {SocAgentTextSafety.RedactSecrets(tool.Summary)}");
        }

        prompt.AppendLine();
        prompt.AppendLine("Citations to preserve in the answer:");
        foreach (var citation in citations.Take(20))
        {
            prompt.AppendLine($"- {citation.Label} ({citation.Kind}): {citation.Url}");
        }

        return SocAgentTextSafety.Truncate(
            SocAgentTextSafety.RedactSecrets(prompt.ToString()),
            Math.Clamp(options.MaxPromptCharacters, 1000, 20_000));
    }

    private string EffectiveProvider(SocAgentProviderStatusResponse status)
    {
        return IsExternalProviderUnavailable(status) && options.FallbackToLocalWhenUnavailable
            ? options.LocalFallbackProvider
            : status.Provider;
    }

    private string EffectiveModel(SocAgentProviderStatusResponse status)
    {
        return IsExternalProviderUnavailable(status) && options.FallbackToLocalWhenUnavailable
            ? options.LocalFallbackModel
            : status.Model;
    }

    private static bool CanUseExternalProvider(SocAgentProviderStatusResponse status)
    {
        return string.Equals(status.Status, "connected", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(status.Provider, "Local", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExternalProviderUnavailable(SocAgentProviderStatusResponse status)
    {
        return !string.Equals(status.Provider, "Local", StringComparison.OrdinalIgnoreCase)
            && !CanUseExternalProvider(status);
    }

    private static string MakeTitle(string message)
    {
        var singleLine = message.ReplaceLineEndings(" ").Trim();
        if (singleLine.Length == 0)
        {
            return "New investigation";
        }

        return singleLine.Length <= 80 ? singleLine : singleLine[..80] + "…";
    }

    private static string Preview(string value)
    {
        var singleLine = SocAgentTextSafety.RedactSecrets(value).ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 160 ? singleLine : singleLine[..160] + "…";
    }
}
