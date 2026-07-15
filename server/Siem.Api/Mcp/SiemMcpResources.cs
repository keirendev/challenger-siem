using System.ComponentModel;
using ModelContextProtocol.Server;

namespace Challenger.Siem.Api.Mcp;

[McpServerResourceType]
public sealed class SiemMcpResources(SiemMcpTools tools)
{
    [McpServerResource(
        UriTemplate = "siem://environment/overview",
        Name = "siem_environment_overview",
        Title = "SIEM environment overview",
        MimeType = "application/json")]
    [Description("Bounded aggregate posture for the SIEM environment.")]
    public async Task<string> GetOverviewAsync(CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetOverviewAsync(24, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://events/{agentId}/{eventId}",
        Name = "siem_event",
        Title = "SIEM event",
        MimeType = "application/json")]
    [Description("One role-filtered security event addressed by agent ID and event UUID.")]
    public async Task<string> GetEventAsync(string agentId, string eventId, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetEventAsync(agentId, eventId, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://alerts/{alertId}",
        Name = "siem_alert",
        Title = "SIEM alert",
        MimeType = "application/json")]
    [Description("One role-filtered SIEM alert and its linked evidence metadata.")]
    public async Task<string> GetAlertAsync(string alertId, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetAlertAsync(alertId, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://cases/{caseId}",
        Name = "siem_case",
        Title = "SIEM investigation case",
        MimeType = "application/json")]
    [Description("One investigation case and its existing links, notes, and activity.")]
    public async Task<string> GetCaseAsync(string caseId, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetCaseAsync(caseId, 50, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://detections/{ruleId}/{version}",
        Name = "siem_detection_review",
        Title = "SIEM detection review",
        MimeType = "application/json")]
    [Description("One detection's catalog, prerequisite, alert-outcome, and proposal-only tuning review.")]
    public async Task<string> GetDetectionReviewAsync(string ruleId, int version, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.ReviewDetectionAsync(ruleId, version, 168, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://agents/{agentId}/coverage",
        Name = "siem_agent_coverage",
        Title = "SIEM agent coverage",
        MimeType = "application/json")]
    [Description("One agent's bounded L2 telemetry coverage assessment.")]
    public async Task<string> GetCoverageAsync(string agentId, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetCoverageAsync(agentId, Challenger.Siem.Contracts.V1.WindowsCoverageLevel.L2, 24, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://agents/{agentId}/source-health",
        Name = "siem_agent_source_health",
        Title = "SIEM agent source health",
        MimeType = "application/json")]
    [Description("One agent's source-health and gap metadata.")]
    public async Task<string> GetSourceHealthAsync(string agentId, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetSourceHealthAsync(agentId, Challenger.Siem.Contracts.V1.WindowsCoverageLevel.L2, 50, cancellationToken));

    [McpServerResource(
        UriTemplate = "siem://graphs/{graphId}",
        Name = "siem_investigation_graph",
        Title = "SIEM investigation graph",
        MimeType = "application/json")]
    [Description("One existing investigation graph. Resource reads never accept or apply graph proposals.")]
    public async Task<string> GetGraphAsync(string graphId, CancellationToken cancellationToken = default) =>
        SiemMcpJson.Serialize(await tools.GetGraphAsync(graphId, 50, cancellationToken));
}
