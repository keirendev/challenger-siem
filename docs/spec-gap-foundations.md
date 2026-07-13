# Specification gap foundations

This document captures the implementation foundations and operator guardrails for the SIEM capability gaps tracked in issues #122 through #140. The companion review API `GET /api/v1/platform/capabilities` exposes the same bounded capability catalog to authenticated operators without revealing secrets or telemetry.

Status vocabulary: `foundation_ready` means the project now has documented contracts, storage/API extension points, safety limits, and validation expectations for additive implementation work under `/api/v1` without breaking existing Windows-agent ingestion.

## SPEC-GAP-001

Secure multi-protocol ingestion and back-pressure controls:

- Source registry fields: source ID, owner/tenant, source type, parser assignment, expected volume band, authentication mode, TLS posture, filtering/sampling policy, and raw preservation limit.
- Transport adapters: native agent (implemented), generic HTTPS/webhook, syslog/RFC3164, syslog/RFC5424, TLS syslog, and message-queue adapter interfaces.
- Controls: per-source payload limits, rate limits, drop/throttle counters, source-volume health, UTC event/original/ingest timestamps, and auditable filter decisions.

## SPEC-GAP-002

Cloud and SaaS audit-log pull collectors:

- Connector registry: provider, tenant/account, scopes, credential reference, cursor/checkpoint, throttle budget, and last successful poll.
- Pull runs store bounded status, counts, checkpoint before/after, and retry/backoff state.
- Secrets remain server-side; docs/tests use fake providers only.

## SPEC-GAP-003

Common schema and parser lifecycle:

- Common event fields: event identity, source identity, observed entities, action/category/outcome, severity, timestamps, and raw/normalized payload references.
- Parser lifecycle: parser ID/version, compatible source types, fixture coverage, deployment status, rollback status, and validation result.
- Incompatible schema changes require a new route/schema version.

## SPEC-GAP-004

Non-blocking enrichment:

- Enrichment queues run after ingest and cannot block raw event acceptance.
- Context types: asset, identity, geo, DNS, vulnerability, application, and cloud metadata.
- Cache TTLs, source confidence, stale markers, and privacy redaction are required.

## SPEC-GAP-005

Threat-intelligence lifecycle:

- Indicator model: value, type, source, confidence, severity, first/last seen, expiry, TLP, tags, and suppression state.
- Match records cite event/alert IDs and store bounded context only.
- Expired/suppressed indicators must not create new alerts unless policy explicitly allows it.

## SPEC-GAP-006

Stateful detection-as-code and correlation:

- Detection rules include version, source prerequisites, fields, state windows, suppression keys, ATT&CK tags, and test fixtures.
- Linux L2 source health now exposes prerequisite and event-family evidence states so future Linux rules can fail closed on missing, stale, degraded, denied, unsupported, excepted, or inapplicable telemetry; built-in executable rules remain Windows-focused in this release.
- Stateful evaluation stores bounded state and supports deterministic replay against synthetic fixtures.
- Mutating rule activation remains operator-approved.

## SPEC-GAP-007

Risk-based alerting and UEBA:

- Entity risk tracks user/host/IP/service scores, contributing signals, decay, and explainability.
- UEBA baselines store bounded aggregates, not raw telemetry copies.
- Alert scores must cite rule, confidence, impact, entity criticality, and recent context.

## SPEC-GAP-008

ATT&CK coverage and detection validation:

- Rules map to ATT&CK tactic/technique/sub-technique with source prerequisites and validation scenario IDs.
- Coverage reports distinguish implemented, validated, partially covered, and planned detections.
- Validation evidence uses synthetic fixtures or approved lab-only data under ignored paths.

## SPEC-GAP-009

Search, entity timelines, dashboards, and query observability:

- Search requests should emit bounded query metrics: filters, duration, result count, and error state without logging secrets.
- Entity timelines join events, alerts, graph nodes, inventory, and source-health summaries by stable entity references.
- Dashboards must label active vs historical counts and avoid raw telemetry in widgets.

## SPEC-GAP-010

Alert context, case management, grouping, and SOC metrics:

- Cases group alerts, evidence, graph links, assignees, status, severity, SLA, and notes.
- SOC metrics include MTTA/MTTR, alert volume, false-positive/suppression rates, and workload counts.
- Notes remain bounded and operator-authored; raw evidence stays linked, not copied.

## SPEC-GAP-011

SOAR playbooks and guarded response integrations:

- Playbooks are proposal-first with validation, risk notes, required approvals, and audit records.
- Connectors must declare mutating capabilities and safe rollback/undo notes when available.
- No autonomous response action may execute from a model prompt alone.

## SPEC-GAP-012

RBAC, SSO/MFA, tenancy, and SIEM self-audit:

- Migration path: retain operator API credential for local MVP, add operator identities, roles, SSO/OIDC, MFA, tenant scoping, and permission checks.
- Self-audit records auth events, config changes, graph/proposal actions, alert/case changes, and export activity without secrets.
- Future roles should separate view, edit, approve, administer, and export permissions.

## SPEC-GAP-013

Scale, performance, HA, and detection-latency SLOs:

- SLOs: ingest availability, queue lag, parse latency, detection latency, search p95, and alert delivery latency.
- HA plan covers stateless API replicas, PostgreSQL resilience, queue/backpressure, and idempotent writes.
- Benchmarks must use synthetic load and aggregate metrics only.

## SPEC-GAP-014

Storage lifecycle, tamper evidence, encryption, residency, and compliance reporting:

- Retention policies define hot/warm/cold windows, legal hold, deletion approvals, and export restrictions.
- Tamper evidence uses chained hashes or immutable audit summaries for selected records.
- Encryption and residency settings must avoid storing keys/secrets in tracked files.

## SPEC-GAP-015

Windows agent EDR-grade telemetry, WEF, ETW, FIM, registry, and AMSI sources:

- Source expansion remains role-pack driven and opt-in with resource budgets.
- New sources require source-health rows, parser fixtures, queue/backpressure handling, and privacy review.
- WEF/ETW/FIM/registry/AMSI events should preserve bounded raw context and normalized entity fields.

## SPEC-GAP-016

Windows agent local detections, response controls, self-protection, resources, updates, mTLS, proxy, and OS matrix:

- Agent hardening plan covers local detection proposals, guarded response, config ACLs, service health, resource ceilings, update channels, mTLS/proxy, and OS support matrix.
- Response controls require explicit server authorization and local audit trails.
- Self-protection must not block operator-approved uninstall or data-preserving maintenance.

## SPEC-GAP-017

Web application monitoring ingestion and context enrichment:

- Web telemetry sources: access logs, application audit logs, error logs, auth/session events, WAF/CDN logs, and API gateway logs.
- Context enrichment maps routes, users, sessions, source IPs, user agents, deployments, and application ownership.
- Sensitive request/response bodies remain excluded by default.

## SPEC-GAP-018

OWASP-aligned web and API detections with validation scenarios:

- Detection catalog maps to OWASP categories such as broken access control, injection, auth failures, SSRF, deserialization, and suspicious API usage.
- Scenarios use synthetic requests and expected normalized fields.
- Alerts cite bounded request metadata and never store secrets, cookies, or full bodies.

## SPEC-GAP-019

Versioned management APIs and downstream event/alert export:

- Management APIs use explicit versioning, review/RBAC authorization, idempotency keys for mutations, and audit records.
- Downstream export supports bounded filters, cursor/checkpoint, redaction, destination health, and retry/backoff.
- Export clients must not receive provider/API tokens or unbounded raw telemetry unless explicitly authorized by policy.
