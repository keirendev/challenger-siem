using Challenger.Siem.Contracts.V1;

namespace Challenger.Siem.Api.Platform;

public static class PlatformCapabilityCatalog
{
    public static IReadOnlyList<PlatformCapability> All { get; } = new[]
    {
        Cap("SPEC-GAP-001", "Secure multi-protocol ingestion and back-pressure", "Source registry, transport/security posture, webhook/syslog/MQ adapter design, bounded raw preservation, filtering/sampling, and volume health controls are documented with API/schema extension points.", "ingestion", "back_pressure", "raw_preservation"),
        Cap("SPEC-GAP-002", "Cloud and SaaS audit-log pull collectors", "Connector registry, cursor/checkpoint model, throttling, and cloud/SaaS source runbooks are defined for additive pull collectors.", "connector_registry", "cursor_checkpoints", "cloud_audit"),
        Cap("SPEC-GAP-003", "Common schema and parser lifecycle", "Common event/entity schema, parser versioning, parser validation, and compatibility rules are defined for v1 additions.", "common_schema", "parser_versions", "compatibility"),
        Cap("SPEC-GAP-004", "Non-blocking enrichment", "Asset, identity, geo, DNS, vulnerability enrichment queues and cache semantics are specified as asynchronous non-blocking context layers.", "async_enrichment", "cache_ttl", "privacy"),
        Cap("SPEC-GAP-005", "Threat-intelligence lifecycle", "Indicator source, confidence, expiry, match, and suppression lifecycle controls are specified with bounded storage expectations.", "indicator_lifecycle", "expiry", "matches"),
        Cap("SPEC-GAP-006", "Stateful detection-as-code", "Rule metadata, state windows, suppression, test fixtures, and deterministic evaluation guidance are documented for correlation workflows.", "detection_as_code", "state_windows", "correlation"),
        Cap("SPEC-GAP-007", "Risk-based alerting and UEBA", "Risk scoring, entity baselines, alert scoring, and explainability expectations are documented with additive storage/API plans.", "risk_scoring", "ueba", "explainability"),
        Cap("SPEC-GAP-008", "ATT&CK coverage and detection validation", "ATT&CK mapping, validation scenarios, coverage reporting, and regression evidence expectations are documented.", "attack_coverage", "validation", "detections"),
        Cap("SPEC-GAP-009", "Search, timelines, dashboards, and observability", "Search/query observability, entity timelines, dashboard requirements, and performance telemetry are documented.", "search", "timelines", "query_observability"),
        Cap("SPEC-GAP-010", "Alert context and case management", "Case grouping, alert context, evidence, collaboration, and SOC metrics lifecycle are documented.", "case_management", "grouping", "soc_metrics"),
        Cap("SPEC-GAP-011", "SOAR playbooks and guarded response", "Playbook proposal/approval/execution guardrails, connector boundaries, and audit controls are documented.", "soar", "approval", "response"),
        Cap("SPEC-GAP-012", "RBAC, SSO/MFA, tenancy, and self-audit", "Identity, role, tenancy, MFA, SSO, and SIEM self-audit migration path is documented beyond the review-token MVP.", "rbac", "sso", "audit"),
        Cap("SPEC-GAP-013", "Scale, HA, and latency SLOs", "Scale targets, SLOs, queue/backlog metrics, HA posture, and benchmark plan are documented.", "slo", "ha", "performance"),
        Cap("SPEC-GAP-014", "Storage lifecycle and compliance", "Retention, legal hold, tamper evidence, encryption, residency, and compliance reporting controls are documented.", "retention", "tamper_evidence", "encryption"),
        Cap("SPEC-GAP-015", "Windows EDR-grade telemetry expansion", "WEF, ETW, FIM, registry, AMSI, driver/service/process/network coverage expansion plan and role packs are documented.", "windows_edr", "etw", "fim"),
        Cap("SPEC-GAP-016", "Windows agent hardening and response", "Local detections, guarded response controls, self-protection, update, proxy, mTLS, and OS matrix expectations are documented.", "agent_hardening", "mtls", "updates"),
        Cap("SPEC-GAP-017", "Web application monitoring", "HTTP access/audit/error telemetry, application context, session/user/entity enrichment, and privacy controls are documented.", "web_monitoring", "app_context", "privacy"),
        Cap("SPEC-GAP-018", "OWASP web/API detections", "OWASP-aligned detection catalog, validation scenarios, and web/API evidence requirements are documented.", "owasp", "web_detections", "validation"),
        Cap("SPEC-GAP-019", "Management APIs and downstream export", "Versioned management API and downstream event/alert export contracts, auth, filtering, and audit expectations are documented.", "management_api", "export", "versioning"),
    };

    private static PlatformCapability Cap(string id, string title, string summary, params string[] controls) => new()
    {
        CapabilityId = id,
        Title = title,
        Status = "foundation_ready",
        Summary = summary,
        DocumentationUrl = "/docs/spec-gap-foundations.md#" + id.ToLowerInvariant(),
        Controls = controls
    };
}
