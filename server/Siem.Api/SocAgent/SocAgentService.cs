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

    public async Task<SocAgentChatResponse> SendChatMessageAsync(
        Guid? sessionId,
        SocAgentChatRequest request,
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

        SocAgentAskResponse response;
        string? errorCode = null;
        try
        {
            response = await AskAsync(new SocAgentAskRequest
            {
                Question = message,
                ContextAgentId = effectiveContextAgentId,
                ContextEventId = effectiveContextEventId
            }, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            errorCode = ex.GetType().Name;
            response = new SocAgentAskResponse
            {
                Provider = EffectiveProvider(status),
                Model = EffectiveModel(status),
                Answer = "soc-agent could not complete the request. Confirm the database schema is applied and try again.",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        var assistantMessage = await audit.AddMessageAsync(
            session.SessionId,
            "soc_agent",
            response.Answer,
            response.Provider,
            response.Model,
            response.ToolRuns,
            response.Citations,
            errorCode,
            cancellationToken);

        var updatedSession = await audit.GetSessionAsync(session.SessionId, cancellationToken) ?? session;
        return new SocAgentChatResponse
        {
            Session = updatedSession,
            UserMessage = userMessage,
            AssistantMessage = assistantMessage,
            ProviderStatus = status
        };
    }

    public async Task<SocAgentAskResponse> AskAsync(SocAgentAskRequest request, CancellationToken cancellationToken)
    {
        var status = GetProviderStatus();
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

        if (status.RequiresConnection && !options.FallbackToLocalWhenUnavailable)
        {
            return new SocAgentAskResponse
            {
                Provider = status.Provider,
                Model = status.Model,
                Answer = $"Provider connection required: {status.Message}",
                CreatedAt = DateTimeOffset.UtcNow
            };
        }

        var question = string.IsNullOrWhiteSpace(request.Question) ? "Summarize current SIEM posture." : request.Question.Trim();
        var citations = new List<SocAgentCitation>();
        var toolRuns = new List<SocAgentToolRunSummary>();
        var answer = new StringBuilder();
        var usingLocalFallback = status.RequiresConnection && options.FallbackToLocalWhenUnavailable;

        var agents = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, request.ContextAgentId, null, "active"),
            TimeSpan.FromMinutes(15),
            cancellationToken);
        var selectedAgents = agents.Take(Math.Clamp(options.MaxAgents, 1, 50)).ToArray();
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "agent_inventory_search", RowCount = selectedAgents.Length, Summary = "Loaded recent agent inventory and coverage summary rows." });
        citations.Add(new SocAgentCitation { Kind = "agent_search", Label = "Agent inventory", Url = string.IsNullOrWhiteSpace(request.ContextAgentId) ? "/agents" : $"/agents?agent_id={Uri.EscapeDataString(request.ContextAgentId)}" });

        var sourceHealthResponse = await sourceHealth.SearchAsync(request.ContextAgentId, cancellationToken);
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "coverage_summary", RowCount = sourceHealthResponse.Sources.Count, Summary = "Loaded source-health rows and coverage summaries." });
        if (!string.IsNullOrWhiteSpace(request.ContextAgentId))
        {
            citations.Add(new SocAgentCitation { Kind = "source_health", Label = "Host coverage", Url = $"/agents/detail?agent_id={Uri.EscapeDataString(request.ContextAgentId)}" });
        }

        var eventQuery = new EventSearchQuery(
            Hostname: null,
            AgentId: request.ContextAgentId,
            Channel: null,
            WindowsEventId: null,
            From: DateTimeOffset.UtcNow.AddHours(-24),
            To: null,
            Keyword: null,
            Category: null,
            Action: null,
            UserName: null,
            ProcessImage: null,
            SourceIp: null,
            DestinationIp: null,
            ServiceName: null,
            FilePath: null,
            RegistryKey: null,
            Limit: Math.Clamp(options.MaxEvents, 1, 50));
        var recentEvents = await events.SearchEventsAsync(eventQuery, cancellationToken);
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "event_search", RowCount = recentEvents.Count, Summary = "Loaded recent normalized events for the current scope." });
        citations.Add(new SocAgentCitation { Kind = "event_search", Label = "Recent events", Url = string.IsNullOrWhiteSpace(request.ContextAgentId) ? "/events" : $"/events?agent_id={Uri.EscapeDataString(request.ContextAgentId)}&limit=25" });
        foreach (var evt in recentEvents.Take(3))
        {
            citations.Add(new SocAgentCitation
            {
                Kind = "event_detail",
                Label = $"Event {evt.WindowsEventId} on {evt.Hostname}",
                Url = $"/events/detail?agent_id={Uri.EscapeDataString(evt.AgentId)}&event_id={evt.EventId}"
            });
        }

        var alertRows = await alerts.SearchAlertsAsync(null, cancellationToken);
        var selectedAlerts = alertRows.Take(Math.Clamp(options.MaxAlerts, 1, 50)).ToArray();
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "alert_review", RowCount = selectedAlerts.Length, Summary = "Loaded current alert review rows." });
        citations.Add(new SocAgentCitation { Kind = "alerts", Label = "Alerts", Url = "/alerts" });

        var detectionRules = await alerts.GetRulesAsync(cancellationToken);
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "detection_rule_metadata", RowCount = detectionRules.Count, Summary = "Loaded detection rule metadata and prerequisites." });

        var inventoryRows = await inventory.SearchAsync(request.ContextAgentId, null, cancellationToken);
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "inventory_summary", RowCount = inventoryRows.Count, Summary = "Loaded bounded inventory snapshot summaries." });
        citations.Add(new SocAgentCitation { Kind = "audit_policy", Label = "Audit policy drift", Url = string.IsNullOrWhiteSpace(request.ContextAgentId) ? "/audit-policy" : $"/audit-policy?agent_id={Uri.EscapeDataString(request.ContextAgentId)}" });

        var graphRows = await graphs.ListAsync("active", cancellationToken);
        var selectedGraphs = graphRows.Take(5).ToArray();
        toolRuns.Add(new SocAgentToolRunSummary { ToolName = "graph_search", RowCount = selectedGraphs.Length, Summary = "Loaded active investigation graph summaries for operator-managed context." });
        citations.Add(new SocAgentCitation { Kind = "graph_search", Label = "Investigation graphs", Url = "/graphs" });
        foreach (var graph in selectedGraphs.Take(3))
        {
            citations.Add(new SocAgentCitation { Kind = "graph_detail", Label = graph.Title, Url = $"/graphs/detail?graph_id={graph.GraphId}" });
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
                answer.AppendLine($"- {evt.EventTime:u} {evt.Hostname} {evt.Channel}/{evt.WindowsEventId} {evt.Normalized?.Category ?? "windows_event"}/{evt.Normalized?.Action ?? "observed"}: {Preview(evt.Message)}");
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

        var response = new SocAgentAskResponse
        {
            Provider = EffectiveProvider(status),
            Model = EffectiveModel(status),
            Answer = Truncate(answer.ToString().Trim(), Math.Clamp(options.MaxResultCharacters, 1000, 100_000)),
            ToolRuns = toolRuns,
            Citations = citations,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await audit.SaveTurnAsync(request, response, cancellationToken);
        return response;
    }

    private string EffectiveProvider(SocAgentProviderStatusResponse status)
    {
        return status.RequiresConnection && options.FallbackToLocalWhenUnavailable
            ? options.LocalFallbackProvider
            : status.Provider;
    }

    private string EffectiveModel(SocAgentProviderStatusResponse status)
    {
        return status.RequiresConnection && options.FallbackToLocalWhenUnavailable
            ? options.LocalFallbackModel
            : status.Model;
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
        var singleLine = value.ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 160 ? singleLine : singleLine[..160] + "…";
    }

    private static string Truncate(string value, int maxLength) => value.Length <= maxLength ? value : value[..maxLength];
}
