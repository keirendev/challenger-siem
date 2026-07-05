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
    SocAgentRepository audit,
    IOptions<SocAgentOptions> options)
{
    private readonly SocAgentOptions options = options.Value;

    public async Task<SocAgentAskResponse> AskAsync(SocAgentAskRequest request, CancellationToken cancellationToken)
    {
        if (!options.Enabled)
        {
            return new SocAgentAskResponse
            {
                Provider = options.Provider,
                Model = options.Model,
                Answer = "soc-agent is disabled by configuration. Set SocAgent:Enabled=true to enable the local SIEM tool harness."
            };
        }

        var question = string.IsNullOrWhiteSpace(request.Question) ? "Summarize current SIEM posture." : request.Question.Trim();
        var citations = new List<SocAgentCitation>();
        var toolRuns = new List<SocAgentToolRunSummary>();
        var answer = new StringBuilder();

        var agents = await review.SearchAgentsAsync(
            new AgentInventoryQuery(null, request.ContextAgentId, null),
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

        answer.AppendLine("soc-agent local SIEM assessment");
        answer.AppendLine();
        answer.AppendLine($"Question: {question}");
        answer.AppendLine();
        answer.AppendLine($"Observed {selectedAgents.Length} agent(s), {sourceHealthResponse.Sources.Count} source-health row(s), {recentEvents.Count} recent event(s), {selectedAlerts.Length} alert(s), {detectionRules.Count} detection rule(s), and {inventoryRows.Count} inventory snapshot(s) in scope.");

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

        answer.AppendLine();
        answer.AppendLine("Recommended next steps: review cited coverage gaps, inspect linked events/alerts, validate missing mandatory sources on the endpoint, and keep mutating detection changes as proposals requiring explicit operator approval.");

        var response = new SocAgentAskResponse
        {
            Provider = options.Provider,
            Model = options.Model,
            Answer = answer.ToString().Trim(),
            ToolRuns = toolRuns,
            Citations = citations,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await audit.SaveTurnAsync(request, response, cancellationToken);
        return response;
    }

    private static string Preview(string value)
    {
        var singleLine = value.ReplaceLineEndings(" ").Trim();
        return singleLine.Length <= 160 ? singleLine : singleLine[..160] + "…";
    }
}
