# Web console product specification

The Challenger SIEM web console is the operator-facing review surface for the ingestion API, PostgreSQL-backed event store, source-health/coverage model, alert/detection foundations, investigation graphs, and `soc-agent` workspace. This document is both the current route reference and the mature console information-architecture specification for future UI work.

Current implementation status is called out explicitly. Target sections describe the product contract future Razor Pages or API work must satisfy; they do not claim unimplemented pages or workflows exist today.

For public-safe visual examples, see the [sanitized web-console demo](web-console-demo.md). Demo screenshots, wireframes, seed data, and examples must use synthetic data only.

## Current implementation boundary

Implemented today in the ASP.NET Core API process:

- `/login`, `/logout`, `/`, `/agents`, `/agents/detail`, `/events`, `/events/detail`, `/alerts`, `/alerts/detail`, `/graphs`, `/graphs/detail`, `/soc-agent`, `/audit-policy`, and `/about` Razor Pages.
- Authenticated `/api/v1` review APIs for events, source health, telemetry coverage, inventory, alerts, detection-rule metadata, platform capabilities, investigation graphs, managed telemetry storage/retention, operators, and `soc-agent`.
- Database-backed operator identities, revocable cookie sessions, operator API credentials, antiforgery-protected Razor forms, and role enforcement described in [auth.md](auth.md).
- Role-aware server-side field policy for events and alerts: admin receives full event raw payload; non-admin roles receive omitted raw payload and redacted sensitive event/alert context.
- Bounded list pagination and page-size limits for current list pages.
- A local, no-CDN dark shell with skip link, semantic landmarks, visible focus, responsive tables, notices, empty states, and current navigation.

Not implemented today and therefore specified as future approved work only:

- First-class `/search`, `/assets`, `/cases`, `/detections`, `/dashboards`, `/health`, and `/administration` console sections.
- Alert triage mutations, case management, case closure, dashboard builder/editing, detection rule activation/editing/backtesting, response/remediation actions, export workflows, SSO/MFA/tenancy, and SOAR playbooks.
- Autonomous `soc-agent` mutation. Current `soc-agent` tools are read-only; graph proposals require explicit operator approval before graph changes.

## Product goals and IA principles

1. **Analyst task flow first.** Navigation and page hierarchy must answer: what is happening, where is it happening, what evidence supports it, what is missing, who owns it, and what audited action occurred.
2. **Coverage-aware everywhere.** Every alert, timeline, search result, and entity view must show source freshness, missing prerequisites, queue/backlog, and retention state when relevant.
3. **Security is server-enforced.** UI hiding improves clarity but is never an authorization boundary. All page handlers and APIs must continue to enforce the [operator role matrix](auth.md#operator-roles).
4. **Sensitive fields are protected by default.** Raw payloads, command lines, account names, paths, registry keys, package names, network addresses/ports, rendered event text, scripts, provider context, and screenshots are sensitive review data.
5. **No secret browser return.** Browser-rendered content, JavaScript-readable responses, client storage, URLs, screenshots, traces, logs, and public docs must never contain enrollment tokens, per-agent tokens, operator API credentials, passwords, provider credentials, connection strings, private keys, raw auth files, or cookie values. The only browser-delivered credential is the current protected `HttpOnly`, `SameSite=Strict`, database-revocable operator session cookie set by the server; it must not be exposed to page content or scripts.
6. **State is explicit.** Loading, empty, stale, degraded, partial, forbidden, conflict, offline, retry, success, and destructive-risk states are first-class UI requirements, not afterthoughts.

## Mature page map and navigation

The mature console should use these top-level sections. Current implemented routes are mapped where available.

| Section | Primary task | Current route(s) | Target contents | Status |
| --- | --- | --- | --- | --- |
| Overview | Start triage, understand current posture, resume work | `/` | Alert/coverage/ingest health summary, assigned cases, high-risk assets, recent signal volume, storage capacity, stale/degraded source notices | Current dashboard subset implemented |
| Search | Find and pivot across events, alerts, entities, and evidence | `/events`, `/events/detail` | Unified event/entity/timeline search with saved filters, field dictionary, retention labels, redaction notices, and query-cost feedback | Event search implemented; unified search future |
| Assets | Review hosts, agents, source coverage, inventory, and entity posture | `/agents`, `/agents/detail`, `/audit-policy` | Asset inventory, host coverage, source matrix, queue/pressure, inventory snapshots, role packs, audit-policy drift | Agent/source-health subset implemented |
| Alerts | Review detection outputs and promote to cases | `/alerts`, `/alerts/detail` | Alert queue, grouping, suppression context, evidence timeline, owner/status transitions, related assets/entities/cases | Review skeleton implemented; triage future |
| Cases | Manage investigations through audited closure | none | Case queue, assignments, notes, evidence links, tasks, severity/status, closure reason, audit trail | Future |
| Detections | Review and engineer detection content | `/api/v1/detections/rules` only | Rule catalog, prerequisites, coverage, versions, test/backtest status, draft/proposal/activation workflows | Metadata API implemented; UI/mutations future |
| Dashboards | Monitor saved operating views | dashboard cards on `/` | Saved SOC, coverage, ingestion, retention, and detection dashboards with chart accessibility and no raw telemetry widgets | Future beyond overview cards |
| Health | Diagnose pipeline and platform health | `/agents/detail`, `/about`, storage APIs | Agent/source/queue/storage/capacity/API health, stale/degraded/partial data, retention status, schema/version status | Scattered current surfaces |
| Administration | Manage operators, credentials, retention, agents, policies | local scripts plus admin APIs | Operator lifecycle, role assignment, agent retirement, storage retention, audit review, system settings | Admin APIs/scripts exist; broad UI future |

Navigation order must prioritize active analyst flow: **Overview → Search → Assets → Alerts → Cases → Detections → Dashboards → Health → Administration**. Role-hidden sections must be omitted from primary nav and represented by an accessible forbidden page or notice when deep-linked.

### Current route map

| Current page | Role access | Purpose | Notes |
| --- | --- | --- | --- |
| `/login` | anonymous | Operator username/password sign-in | Empty fields in public screenshots only. |
| `/` | authenticated | Dashboard metrics | Active/recent/stale/retired agents, ingest volume, queue observations. |
| `/agents` | authenticated view; cleanup admin-only | Agent inventory and non-destructive stale-agent retirement | Cleanup requires admin permission and checkbox confirmation. |
| `/agents/detail` | authenticated | Host coverage/source-health detail | Platform-aware Windows/Linux source matrix and detection prerequisites. |
| `/events` | authenticated | Event search | Viewer searches are server-limited to metadata; analysts/detection engineers can use sensitive filters but responses remain redacted unless admin. |
| `/events/detail` | authenticated | Event detail | Admin gets raw JSON; non-admin raw is `{}` with sensitive fields redacted or restricted. |
| `/alerts` and `/alerts/detail` | authenticated | Alert review skeleton | Non-admin alert summaries/evidence are redacted. No triage mutation today. |
| `/graphs` and `/graphs/detail` | analyst, detection-engineer, admin | Investigation graphs | Create/update nodes/edges, archive graphs, request/apply `soc-agent` proposals with explicit approval for proposal apply. |
| `/soc-agent` | analyst, detection-engineer, admin | Live SIEM-aware chat workspace | Read-only tools; chat deletion requires confirmation and conflicts while a run is active. |
| `/audit-policy` | admin | Audit-policy snapshot review | Admin-only because inventory API is currently operator-management scoped. |
| `/about` | authenticated | Version, environment, database status | No credentials or connection details. |

## Role visibility and action matrix

This matrix summarizes implemented authorization and target UI visibility. The source of truth remains `OperatorRoles`, `OperatorPermission`, page `[Authorize]` policies, and `TokenService.HasOperatorAccess`; UI-only checks are not security controls.

| Capability / surface | viewer | analyst | detection-engineer | admin | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Overview/dashboard metadata | yes | yes | yes | yes | Current `/` page. |
| Asset/agent inventory metadata | yes | yes | yes | yes | Current `/agents`; default active registrations. |
| Host source-health/coverage detail | yes | yes | yes | yes | Current `/agents/detail`. |
| Event metadata search/detail | yes | yes | yes | yes | Viewer sensitive filters are stripped server-side. |
| Sensitive event search filters | no | yes | yes | yes | Analysts/detection engineers can search by sensitive fields; non-admin returned values are redacted. |
| Full raw payload and unredacted protected event fields | no | no | no | yes | Admin only. |
| Alert metadata | yes | yes | yes | yes | Non-admin alert context redacted. |
| Investigation graph mutations | no | yes | yes | yes | Current graph create/update/node/edge/archive/proposal apply. |
| `soc-agent` chat/live workspace | no | yes | yes | yes | Same-origin live endpoints require analyst policy. |
| Detection engineering mutations | no | no | yes | yes | Permission exists; mutable UI/workflow is future. |
| Agent retirement / storage retention / inventory management APIs | no | no | no | yes | Current token-service mapping treats these as operator-management/admin. |
| Operator account management | no | no | no | yes | Admin API plus local bootstrap/recovery scripts. |
| Audit-policy page | no | no | no | yes | Current `/audit-policy`. |
| Administration section | no | no | no | yes | Future UI; current admin APIs/scripts only. |

Unauthorized and forbidden behavior:

- Anonymous browser requests redirect to `/login`; API requests return unauthorized.
- Authenticated but unauthorized browser deep links must show a concise forbidden page or redirect with an accessible notice; API requests return forbidden.
- Role-hidden buttons must not be present in DOM for unauthorized users when practical, but all handlers must still verify permission.

## Protected field and action annotations

### Protected fields

| Field family | Examples | Display semantics |
| --- | --- | --- |
| Raw payload | `raw`, raw XML/JSON, script block content, rendered event text | Admin-only full display. Non-admin responses omit raw (`{}`) and show redaction/restriction text. Never copy into widgets or screenshots unless synthetic. |
| Command/process | command line, executable path, parent image, working directory, process IDs | Sensitive. Searchable by analyst/detection-engineer/admin when server permits; visible unredacted only to admin under current policy. |
| Account/identity | usernames, SIDs, account IDs, realms, group names | Sensitive. Redact or omit for non-admin unless a future approved policy defines narrower disclosure. |
| Paths/registry/package | file paths, registry keys, object names, package names | Sensitive. Avoid in summaries; prefer entity links and redaction labels. |
| Network | source/destination IP, port, hostname/domain, user agent | Sensitive. Use fake documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in public examples. |
| Credentials/secrets | passwords, tokens, cookie values, API keys, connection strings, private keys, auth files | Never return in browser-rendered or JavaScript-readable content, persist in chat, log, screenshot, fixture, docs, issue, or PR text. Only the protected operator session cookie may be sent through `Set-Cookie`, and it must stay `HttpOnly`. Drop or redact secrets before queueing/logging. |
| Provider context | external model tokens, account IDs, auth-file paths, raw provider errors | Server-side only; browser receives safe status codes and setup/connect URLs only. |

Every protected-field display must include one of these explicit semantics: **shown**, **redacted**, **omitted**, **not collected**, **not authorized**, **removed by retention**, or **underlying telemetry missing**. Empty values must not be ambiguous.

### Audited and confirmation-gated actions

| Action | Current/future | Required controls |
| --- | --- | --- |
| Operator login/logout, failed access, API access, credential/account mutation | current | Security audit entry without secrets; no credential echo. |
| Create operator, change password, rotate API credential | current | Admin/self authorization as applicable; credentials shown once; sessions revoked. |
| Retire stale active agents | current | Admin permission, antiforgery, checkbox confirmation, success/empty/error notice; preserves telemetry. |
| Managed retention run | current API | Admin/operator-management credential; dry-run first; execute mode bounded and advisory-locked; no arbitrary data deletion. Future UI needs confirmation phrase for execute/emergency modes. |
| Graph create/update/node/edge/archive/proposal/apply | current | Analyst+ permission, antiforgery/API bearer. Proposal apply requires explicit approval; metadata update uses expected version for conflict handling. Mature UI should add confirmation for archive. |
| `soc-agent` chat send/cancel/delete/connect | current | Analyst+ permission; chat deletion checkbox; active-run delete returns conflict; provider connect uses server-side OAuth state/PKCE when enabled. |
| Alert triage/case transition/detection activation/export/response | future | Proposal/preview first, role permission, CSRF-safe mutation, confirmation for destructive/high-risk actions, optimistic concurrency, audit record, bounded result summary. |
| Case closure | future | Analyst+ or configured closer permission, closure reason, final status, evidence completeness warning, coverage gaps acknowledged, immutable audit trail. |

All unsafe Razor forms require antiforgery. Unsafe `/api` methods must require bearer operator credentials and reject cookie-only authentication to avoid CSRF.

## Status, severity, and lifecycle vocabulary

Use one vocabulary across pages, APIs, badges, charts, and docs. Badges must include text/icons, not color alone.

### Operational status

- `healthy` — fresh and within expected bounds.
- `degraded` — working but impaired; show reason and affected source/capacity.
- `stale` — last observation older than expected.
- `offline` — agent/source/platform not currently communicating.
- `missing` — expected source or record is absent.
- `disabled` — explicitly disabled or retired.
- `permission_denied` — collector/source lacks access; do not treat as no-threat evidence.
- `unsupported` — platform/source not supported by current implementation.
- `not_applicable` — host role/platform makes the source irrelevant.
- `excepted` — approved server-side exception; still visible.
- `unknown` — insufficient evidence; do not imply health.
- `error` — request/processing failure; include safe retry guidance.
- `partial` — some results unavailable or redacted; list missing portions.

### Security severity

Use `critical`, `high`, `medium`, `low`, and `informational` for alert/case severity. Event envelopes retain their v1 event severity values (`verbose`, `information`, `warning`, `error`, `critical`, `audit_success`, `audit_failure`) and should be mapped to alert severity only through detection logic.

### Alert lifecycle (target)

`new → acknowledged → investigating → escalated → contained → resolved → closed` with optional `suppressed`, `false_positive`, `duplicate`, and `retention_limited` annotations. Current alert pages are read-only; these transitions are future.

### Case lifecycle (target)

`draft → open → investigating → pending_external → contained → resolved → closed` with `reopened` possible from `closed`. Closure requires owner, disposition, summary, linked evidence, coverage-gap acknowledgement when present, and audit entry. Cases are not implemented today.

### Detection lifecycle (target)

`catalog → draft → review → test_failed/test_passed → staged → active → deprecated → disabled`. Activation/deactivation must require detection-engineer or admin permission, coverage prerequisite display, backtest/test evidence, confirmation, and audit. Current implementation exposes rule metadata and Linux server-side execution only.

## End-to-end analyst workflows

### 1. Signal → event → entity → alert → case → audited closure (target)

1. **Signal arrives** from an endpoint source. UI health surfaces show source freshness, queue depth, dropped/poison counts, and coverage level.
2. **Event is ingested** through `/api/v1/ingest/events`, validated, deduplicated, persisted, and searchable. Partial acknowledgements and ingestion errors surface as source/health issues, not hidden failures.
3. **Entities are extracted or referenced** from normalized user/process/network/file/service fields. If a field is redacted, the entity card shows `redacted` and explains the role boundary.
4. **Detection evaluates** accepted, non-duplicate events only. Alert evidence stores exact event IDs and rule version. Missing/degraded prerequisites lower confidence or suppress evaluation explicitly.
5. **Alert queue shows** severity, confidence, affected assets/entities, coverage warnings, evidence retention state, owner, status, and first/last seen.
6. **Analyst pivots** from alert to event detail, asset coverage, related entity timeline, graph context, and `soc-agent` summaries. Pivots preserve filters and show breadcrumb context.
7. **Case is opened** from one or more alerts (future). Case creation copies bounded metadata and links evidence; raw payload remains linked and role-protected.
8. **Investigation proceeds** with notes, graph relationships, tasks, timeline, detection/source-health context, and optional `soc-agent` proposal-only assistance.
9. **Closure requires** final status, disposition, owner, coverage-gap acknowledgement, retained evidence links, no unresolved critical confirmations, and audited closure summary.
10. **Audit trail records** actor, action, target, outcome, request ID, timestamp, and bounded non-secret metadata. It never records credentials, raw telemetry, command lines, account values, paths, or network values.

Synthetic workflow example for docs/wireframes only:

```text
DEMO-WIN11 -> Security 4625 -> user: synthetic-user -> alert auth.bruteforce.demo
  -> case CASE-DEMO-0007 -> closure: false_positive / approved test window
```

### 2. Search-first investigation (current plus target)

- Start at Search (`/events` today) with UTC time range, host/agent, source, event code, keyword, and normalized filters.
- Loading state: skeleton filter panel and result table; keep submitted filter summary visible.
- Empty state: show active filters, time range, role redaction caveats, coverage/source-health links, and clear-filter action.
- Partial state: show when a role strips sensitive filters, raw fields are omitted, retention removed evidence, or a source is stale/degraded.
- Pivot targets: event detail, asset detail, alert detail, graph add-node, future entity timeline, future case evidence.
- Error state: safe message with retry and schema/health hint; no SQL/connection details.
- Success state: bounded results, total/visible count when known, query limit, pagination, UTC and host-local time labels.

### 3. Asset/coverage investigation (current plus target)

- Start at Assets (`/agents` today), filter by hostname/agent ID/status/health, and open host detail.
- Review platform, timezone, coverage target, source matrix, prerequisite status, queue/resource metrics, inventory state, detection prerequisites, and recent counts.
- Stale/degraded/denied/unsupported states must show reason, last observed time, affected source, whether mandatory/optional/role-specific, and recommended non-mutating next step.
- Recovery path: compare collected vs acknowledged checkpoints; verify queue drain; check source-health transitions; do not mutate audit/firewall/auth/kernel/service policy from UI unless a future approved runbook exists.
- Admin stale-agent retirement is non-destructive, confirmation-gated, success/error noticed, and preserves telemetry.

### 4. Alert-to-case workflow (target)

- Alert detail shows rule version, severity, confidence, prerequisites, evidence, related entities, source-health gaps, and retention state.
- Analyst actions: acknowledge, assign owner, change status, link/create case, suppress with reason, mark duplicate/false-positive, add note.
- Detection-engineer actions: propose rule tuning or detection change; cannot bypass evidence/audit.
- Admin actions: same plus policy/system management where implemented.
- Conflict state: stale alert/case version requires reload and displays both attempted and current status.
- Destructive-risk state: suppression, bulk close, or evidence export requires clear scope, confirmation, and audit.

### 5. Detection workflow (target)

- Detection catalog groups rules by tactic, platform, source prerequisites, coverage level, severity, confidence, and validation status.
- Rule detail shows version history, required fields, correlation window, suppression keys, false-positive notes, response guidance, coverage impact, and synthetic test fixtures.
- Draft/edit/backtest/activate are future detection-engineer/admin actions with explicit review, optimistic concurrency, validation evidence, and audit.
- Missing prerequisite telemetry must be shown before activation and in every alert created by the rule.

### 6. Health and recovery workflow (current plus target)

- Health consolidates agent heartbeat, source-health, queue pressure, ingest errors, storage accounting/retention, API/schema version, provider status, and browser/API reachability.
- Stale/offline: show last heartbeat, expected interval, source last seen, and queue risk.
- Degraded: show source, reason, gap/drop/poison counters, storage thresholds, and recovery transition.
- Partial data: show unavailable tables/APIs and hide dependent cards behind partial-state notices.
- Offline/retry: browser live features such as `soc-agent` event stream must display reconnect status, retry action, and fallback form.
- Success/recovery: show recovered timestamp and remaining gaps; do not erase historical degradation context.

## Required UI states by page family

| Page family | Loading | Empty | Error | Unauthorized/forbidden | Stale/degraded/partial | Confirmation/destructive | Success/conflict/offline |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Overview | Metric skeletons; last refresh placeholder | No active alerts/agents with setup links | Safe API/schema/db message | Login/forbidden notice | Stale agents, storage thresholds, source gaps | None today; future bulk actions confirm | Refresh success timestamp; partial cards marked |
| Search | Filter/result skeleton | Active filters + coverage hints | Query failed without SQL/connection detail | Login/forbidden | Redacted/retention/source-gap labels | Future export confirms scope | Pagination success; offline retry for live updates |
| Assets | Table/source matrix skeleton | No agents or no filter matches | Inventory/source-health unavailable | Login/forbidden | Stale/offline/degraded/denied/unsupported/excepted rows | Stale retirement admin checkbox | Retirement success; schema/error retry |
| Alerts | Queue skeleton | No alerts for filter | Alert schema/load failure | Login/forbidden | Low confidence, missing evidence, retention labels | Future triage/suppress/bulk actions confirm | Future version conflict on status changes |
| Cases | Queue/timeline skeleton | No cases or no assignments | Case load failure | Login/forbidden | Missing evidence/source gaps | Closure/delete/export confirmations | Version conflict; closure success; reopen path |
| Detections | Catalog skeleton | No rules or no filter matches | Rule/backtest load failure | Login/forbidden | Missing prerequisites/test failures | Activation/deactivation confirmations | Version conflict; validation success/failure |
| Dashboards | Widget skeletons | No widgets/saved views | Widget source failed | Login/forbidden | Partial widgets; stale refresh | Edit/delete confirmations | Save conflict; refresh success |
| Health | Health-card skeleton | No data yet after setup | Health source failed | Login/forbidden | Stale/degraded/partial/offline | Retention execute/emergency confirms | Recovery success; lock conflict for retention |
| Administration | Form/table skeletons | No operators/policies beyond bootstrap | Mutation/load failure | Admin-only forbidden | Disabled/locked/expired states | Credential/role/retention confirmations | Success shown once; conflict/validation errors |

## Reusable UX patterns

### Tables and lists

- Bounded page size with previous/next pagination; never render unbounded telemetry.
- Sticky or repeated filter summary above results.
- Row actions must be keyboard reachable and use descriptive labels (`Open event 3af...`, not `View`).
- Sensitive columns must have per-cell redaction text, not blank cells.
- Column priority may change responsively, but critical status, severity, timestamp, asset/entity, and primary action must remain available.

### Filters and search

- Filters use labels, help text, validation messages, and clear/apply actions.
- Time filters are UTC unless explicitly labelled host-local; host-local displays must include timezone/offset.
- Saved searches and dashboards must store only bounded filter metadata, not raw result payloads.
- Keyword searches over raw/normalized text must show role and performance limits.

### Breadcrumbs and pivots

- Detail pages use breadcrumbs: `Overview / Alerts / Alert demo-alert-001 / Event ...`.
- Pivots preserve context through query parameters where safe; never put secrets or protected raw values in URLs.
- Copy/share links should include IDs and filters only, not sensitive field values when avoidable.

### Notices, badges, and banners

- Use consistent classes and text for `healthy`, `degraded`, `stale`, `offline`, `unknown`, severities, and role restrictions.
- Notices use `role="status"` for non-urgent updates and `role="alert"` for blocking errors.
- Badges include text, icon/shape, and accessible label; color is supplementary.

### Forms and dialogs

- Every input has a visible label and associated error text.
- Destructive/high-risk forms include scope, effect, what is preserved, checkbox or typed confirmation, and cancel path.
- Modal dialogs, when used, must trap focus, restore focus on close, close with Escape unless action is blocking, and expose title/description to assistive tech.
- Prefer inline confirmation panels for complex security actions so full scope remains visible.

### Charts, timelines, and graphs

- Charts require text summary, accessible table alternative, keyboard focus for data points, and non-color encodings.
- Timelines show UTC and host-local labels, coverage gaps, retention markers, and source confidence.
- Graph visualizations require a table/list fallback of nodes and edges, keyboard selection, and textual relationship labels.
- Animations are optional and must respect reduced motion.

### Skeletons, empty, error, and degraded states

- Skeletons approximate final layout without fake data values.
- Empty states explain whether the system has no data, filters are too narrow, role redaction removed results, or telemetry is missing.
- Error states include safe retry guidance and link to Health/About when applicable.
- Degraded states stay visible until a recovery timestamp and remaining gap status are known.

## Text wireframes

Wireframes are sanitized information architecture sketches, not implementation prototypes. Use fake IDs/hosts/users only.

### Overview

```text
[Skip] Challenger SIEM        Overview Search Assets Alerts Cases Detections Dashboards Health Admin
-----------------------------------------------------------------------------------------------
H1 Overview        Last updated 2026-07-14T12:00Z        [Refresh]
[Critical alerts 2] [Open cases 4] [Stale assets 3] [Storage 72% warn] [Queue pressure 1]

Priority work
| Severity | Item              | Asset       | Confidence | Owner       | Action      |
| HIGH     | SSH brute force   | DEMO-LNX-02 | degraded   | unassigned  | Open alert  |
| MEDIUM   | PowerShell signal | DEMO-WIN11  | healthy    | analyst-01  | Open case   |

Coverage notices
! DEMO-WIN11 Sysmon stale for 18m  [Open asset]
! Storage retention dry-run recommended at 72% capacity  [Open health]
```

### Search

```text
H1 Search
[Time UTC from ____ to ____] [Asset DEMO-WIN11] [Source Security] [Event code 4625]
[User redacted by role] [Apply filters] [Clear]

Result summary: 25 shown, limit 100, raw payload omitted for this role.
| Time (UTC) | Host       | Source | Code | Severity | Summary                     | Pivots |
| 12:00:03   | DEMO-WIN11 | Security |4625| warning  | [redacted event text]       | Event Asset Alert |

Side panel: Active filters / Coverage gaps / Retention labels / Saved search (future)
```

### Asset detail

```text
H1 Asset DEMO-WIN11     status: degraded     coverage target: L3
Tabs: Summary | Sources | Inventory | Timeline | Alerts | Cases (future)

Source matrix
| Source ID          | Requirement | Status            | Last event | Gap/queue | Action |
| security           | mandatory   | healthy           | 2m         | 0         | Search |
| sysmon-operational | optional/L3 | stale             | 18m        | 0         | Details |
| defender           | mandatory   | permission_denied | unknown    | n/a       | Runbook |

Notice: permission_denied is a visibility gap, not proof of no threat.
```

### Alert to case

```text
H1 Alert demo-alert-001    severity: high    confidence: low (source degraded)
[Evidence] [Entities] [Timeline] [Coverage] [Case links]

Evidence
- Event 3af457f2... on DEMO-LNX-02, telemetry_retention_state: telemetry_retained
- Source linux-ssh status: degraded, silence 600s

Actions (future): [Acknowledge] [Assign] [Create case] [Suppress]
Create case dialog requires title, owner, severity, linked evidence, and coverage-gap acknowledgement.
```

### Case closure

```text
H1 Case CASE-DEMO-0007     status: investigating     owner: analyst-01
Timeline: alert -> event pivots -> graph notes -> decision
Closure checklist (future)
[ ] All high/critical alerts dispositioned
[ ] Evidence links retained or retention state acknowledged
[ ] Source gaps reviewed
[ ] Closure reason selected
[ ] Summary contains no raw secrets or unbounded telemetry
[Close case]
```

### Detections

```text
H1 Detections
Filters: [Platform linux] [Tactic credential-access] [Status active] [Coverage degraded]
| Rule ID                         | Severity | Sources             | Validation | Action |
| auth.bruteforce.linux           | medium   | linux-ssh/login     | synthetic pass | Open |
| process.suspicious-command.demo | high     | sysmon/security     | future draft   | Open |

Rule detail shows prerequisites, fields, suppression keys, false-positive notes, and response guidance.
Activation/editing remains future detection-engineer/admin workflow.
```

## Accessibility requirements (WCAG 2.2 AA)

The console must meet WCAG 2.2 AA for implemented paths and preserve these requirements in future pages.

### Keyboard and focus

- Provide a skip link to the main landmark before navigation.
- Logical tab order: skip link → brand/nav → account/logout → page heading/actions → filters → results → pagination/detail actions → footer if present.
- Visible focus indicator with at least 3:1 contrast against adjacent colors and no focus removal.
- All controls operable by keyboard; no pointer-only hover menus.
- Current supported shortcut: Ctrl/Cmd+Enter sends `soc-agent` messages. Future shortcuts must be documented in a help dialog, avoid browser/assistive-tech conflicts, and never be required.

### Landmarks, headings, labels, and live regions

- One `h1` per page; headings must not skip levels in the main content.
- Use `header`, `nav aria-label="Primary"`, `main id="main-content"`, and contextual `section`/`aside` labels.
- Every form control has a programmatic label; helper/error text is associated with `aria-describedby`.
- Non-blocking success/update notices use polite live regions; blocking errors use assertive alert semantics sparingly.
- Loading regions set `aria-busy` and retain stable headings so screen-reader users know what is updating.

### Errors, dialogs, and confirmations

- Validation errors identify the field, explain the fix, and are announced after submission.
- Dialogs expose accessible title/description, trap focus, restore focus, and support Escape/cancel except where unsafe.
- Confirmation controls must describe the exact effect and what data is preserved or deleted.

### Tables, charts, timelines, and graph views

- Tables use captions or labelled regions, header cells, row scopes where helpful, and no layout-only table semantics for data.
- Sort/filter state is conveyed textually (`sorted by event time descending`).
- Charts include text summary and accessible table alternative.
- Timelines expose chronological list semantics and label gaps/retention/source confidence.
- Graphs include keyboard-selectable node/edge list fallback.

### Visual presentation

- State is never color-only; include text, icon/shape, and accessible label.
- Text and controls meet WCAG AA contrast in normal, hover, active, disabled, and focus states.
- Minimum target size is 24 by 24 CSS pixels for inline controls and 44 by 44 CSS pixels for primary touch actions where layout permits; adjacent small controls need spacing.
- Support text spacing, 200% zoom, and reflow without two-dimensional scrolling except for data tables/graphs, which must have accessible alternatives.
- Respect `prefers-reduced-motion`; disable non-essential animations and smooth scrolling when requested.
- Density controls (comfortable/compact) are future-safe but must not reduce touch/focus targets below accessibility minimums or hide critical status/actions.

## Responsive behavior

Supported breakpoints are product requirements, not pixel-perfect designs:

| Breakpoint | Width | Requirements |
| --- | ---: | --- |
| Mobile narrow | 320-479px | Single column; nav collapses accessibly; filters stack; primary status/action remains visible; tables become cards or horizontally scroll with summary. |
| Mobile wide | 480-767px | Single column with denser cards; sticky critical action allowed; no hover-only disclosure. |
| Tablet | 768-1023px | Two-column detail summaries when useful; filter drawer/accordion allowed; result tables preserve key columns. |
| Desktop | 1024-1279px | Standard nav, filter/result layout, side panels optional. |
| Wide desktop | >=1280px | Multi-panel analyst workspace allowed; do not require wide viewport for critical actions. |

Critical status/action fields that must never be hidden without an accessible alternative: severity, status, asset/entity identifier, event/alert/case time, owner/assignee where applicable, source-health state, evidence retention state, and the primary safe action (`Open`, `Review`, `Retry`, `Cancel`).

## Time display and filtering

Challenger SIEM stores and filters event timestamps in UTC. Event range inputs are UTC, including offset-less `datetime-local` values from browsers. Host-scoped event, source-health, coverage, audit-policy, alert-evidence, and `soc-agent` event summaries should display endpoint host time when `host_timezone` metadata is available and label the Windows timezone ID or UTC offset. If timezone metadata is missing, display an explicit UTC/unknown-timezone label.

Server-generated timestamps such as ingest time, alert creation time, graph updates, retention runs, audit events, and chat messages are UTC.

## Agent lifecycle and cleanup

The console treats agent registration lifecycle as metadata:

- `active` registrations can authenticate with their current per-agent token, send heartbeats, and ingest events.
- `stale` is a computed health state for active agents whose `last_seen` is older than `Review:StaleAgentMinutes`.
- `disabled` registrations are retired records. Agent-token authentication rejects them and default active views hide them, but their row and historical telemetry remain.

The current `/agents` stale-agent cleanup panel previews active candidates older than the stale cutoff and requires admin permission plus confirmation before setting those registrations to `disabled`. It does not delete events, heartbeats, source-health rows, inventory snapshots, alerts, or evidence. Re-enrollment can return an endpoint to `active` through normal registration with a fresh per-agent token.

## Review settings

Optional configuration values under `Review` tune dashboard and default search behavior:

```json
{
  "Review": {
    "StaleAgentMinutes": 15,
    "RecentEventHours": 24,
    "DefaultEventLimit": 100
  }
}
```

`DefaultEventLimit` is capped to the same maximum of 500 used by the event review API.

The `SocAgent` configuration and provider guardrails are documented in [soc-agent.md](soc-agent.md). The browser page must never receive provider credentials, raw auth-file contents, bearer tokens, or cookie values in rendered or JavaScript-readable content. Same-origin live endpoints use the protected authenticated operator session cookie, and unsafe `/api` calls require bearer credentials.

## Local smoke path

Automated smoke path without Docker:

```bash
./scripts/smoke-test-web.sh
```

The script starts the API, seeds a synthetic agent/event through the v1 API, authenticates to the web console with synthetic operator credentials, creates a synthetic `soc-agent` chat tied to that agent through the non-JavaScript fallback, and verifies dashboard, agent inventory, event search, event detail, investigation graphs, and `soc-agent` HTML. Temporary HTML/cookies/responses stay under ignored `.local/`. Set `SIEM_WEB_SMOKE_CLEANUP=1` for opt-in cleanup of only that per-run `web-smoke-*` agent and its linked `soc-agent` chat history after successful validation, or run `./scripts/cleanup-synthetic-data.sh` separately in dry-run mode first.

Manual path:

1. Start the API with the required database and auth environment variables.
2. Register an agent and ingest synthetic or approved lab events.
3. Open the API base URL in a browser.
4. Log in with a synthetic operator username/password.
5. Confirm current implemented pages render expected data and role-redaction behavior.

## Browser validation and screenshot/wireframe maintenance

When a change affects Razor Pages, web auth/session/CSRF/cookies, review-console routes or view models, web smoke scripts, `docs/web.md`, `docs/web-console-demo.md`, or user-visible browser behavior:

- Run browser E2E against the real app when implementation changes occur; curl/API/HTML checks can supplement but do not replace Playwright or equivalent browser validation for visual/interactive changes.
- For docs-only IA/specification updates, perform a design review against this document, [challenger-family-alignment.md](challenger-family-alignment.md), [auth.md](auth.md), [api.md](api.md), [schema.md](schema.md), current Razor Pages/API source, and synthetic representative data.
- Update the [web-console demo](web-console-demo.md) text or screenshots if page layout, navigation, filters, wireframes, or visible data expectations change.
- Regenerate screenshots only from synthetic data and inspect them for tokens, cookies, connection strings, real host/user identifiers, private lab telemetry, browser profile names, browser/OS chrome, local paths, window titles with private data, and raw API responses before staging.
- Keep raw Playwright artifacts, browser caches, seeded API responses, cookies, traces, videos, and temporary captures under ignored `.local/` paths.
- Text wireframes in docs must use fake hosts, users, IDs, IPs, events, cases, and alerts; they must not be copied from real telemetry and then sanitized.
