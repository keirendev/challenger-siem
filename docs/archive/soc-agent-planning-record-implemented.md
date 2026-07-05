# Archived: soc-agent planning record

> Archived after implementation. The planning record below was superseded by the local `/soc-agent` workspace and `POST /api/v1/soc-agent/ask` API. Use `docs/soc-agent.md`, `docs/api.md`, and `docs/web.md` for current behavior.

# soc-agent planning record

`soc-agent` is the project name for the AI SOC analyst and detection-engineer harness in Challenger SIEM. The current implementation is a safe local provider/tool harness: it runs server-side SIEM tools, returns bounded answers with citations, and persists bounded turn metadata. It does not automate ChatGPT web login, call unofficial provider endpoints, activate detections, change configuration, delete data, or edit source code.

Current routes:

- `/soc-agent` - authenticated web workspace.
- `POST /api/v1/soc-agent/ask` - review-token-protected API for local tool-backed answers.

Current local tools cover agent inventory, source health/coverage, recent events, alert review, detection-rule metadata, and inventory/audit-policy summaries.

## Goals

- Add an authenticated web-console workspace, expected to be `/soc-agent`, using the existing operator authentication/session model or a future RBAC model.
- Ground every answer in Challenger SIEM data returned by explicit, allowlisted tools.
- Let operators investigate stored Windows endpoint telemetry, agents, heartbeats, source health, inventory snapshots, ingestion errors, detection rules, and alerts.
- Support an official OpenAI-compatible provider/model configuration, including `gpt-5.5` when an official provider supports that model.
- Require explicit operator approval before any mutating action such as detection activation, saved-query changes, notes, or configuration changes.
- Persist bounded conversation, tool, artifact, approval, and audit metadata without storing secrets or unnecessary raw endpoint telemetry.

## Provider and authentication guardrails

Only official provider authentication paths are acceptable:

1. **Preferred production path:** server-side provider credentials supplied by environment variables or a secret store.
2. **Optional delegated path:** OAuth/OIDC/PKCE, ChatGPT Team/Enterprise connector auth, or another documented provider flow that explicitly permits this application use case.
3. **Blocked path:** automation of the consumer ChatGPT website, browser-cookie extraction, password capture, browser profile scraping, undocumented session replay, or unofficial endpoints.

Provider credentials must never be committed, rendered into browser local storage, logged, copied into prompts, or included in tool-call transcripts.

## Implemented server components

- `SocAgentOptions`: local provider/model and bounded row limits.
- `SocAgentService`: server-side orchestration over SIEM repositories.
- `SocAgentRepository`: bounded audit persistence in `soc_agent_turns` without provider secrets or raw telemetry dumps.
- `/soc-agent` Razor Page: authenticated operator UI with answer, tool activity, citations, and mutation-safety notice.
- `/api/v1/soc-agent/ask`: review-token-protected JSON endpoint.

## Proposed future server components

- `SocAgentOptions`: enabled flag, provider, model, endpoint/base URL, auth mode, timeout, retry, budget, redaction, and tool-call limits.
- `IModelProvider`: provider abstraction for chat/responses, structured tool calls, optional streaming, and provider-specific authentication.
- `SocAgentConversationService`: prompt assembly, session context, tool-call dispatch, approval enforcement, and audit writing.
- `SocAgentToolRegistry`: typed tool definitions, validation, result bounding, authorization checks, and mutability classification.
- `SocAgentAuditWriter`: bounded audit metadata for provider requests, tool calls, approvals, artifacts, and failures.

The browser should call Challenger SIEM only. Model-provider calls and tool execution stay server-side.

## Initial read-only tools

Initial tool outputs must be bounded, redacted according to policy, and cite records that the operator can open in the SIEM UI.

- `event_search`: time range, host, agent ID, channel, Windows Event ID, keyword, and limit filters.
- `event_detail`: one normalized event by `agent_id` and `event_id`.
- `agent_inventory_search`: host/agent filters, stale/recent state, version, coverage level, source issue counts, and queue depth.
- `heartbeat_summary`: agent health, queue SLOs, source health, configuration hash, and telemetry recency.
- `coverage_summary`: host coverage level, missing/stale/error source counts, and exception state.
- `ingestion_health_summary`: recent validation errors, duplicates, accepted counts, rejected counts, and stale agents.
- `timeline_build`: chronological view from event search results.
- `entity_pivot`: pivots from host, user, process, IP, provider, or event ID when the data is available.

## Future detection-engineering tools

Detection tools start as non-mutating artifacts and require approval gates before any persistent or active change.

- `detection_draft_create`: create a draft artifact only.
- `detection_backtest`: evaluate a draft against bounded stored or synthetic events.
- `detection_save_proposal`: save a proposal awaiting operator approval.
- `detection_activate`: mutating; requires authorized approval and an audit record.
- `saved_query_create_or_update`: mutating; requires approval.
- `runbook_note_create`: mutating; requires approval.
- `change_proposal_create`: produce a reviewable plan or diff; never make autonomous repository commits.

## Data model sketch

Future persistence should prefer summaries and structured metadata over raw provider payloads:

- `soc_agent_sessions`: operator/session reference, title, timestamps, provider, and model metadata.
- `soc_agent_messages`: role, bounded/redacted content, timestamps, and redaction metadata.
- `soc_agent_tool_runs`: tool name, arguments summary, result summary, row counts, duration, status, and redaction metadata.
- `soc_agent_artifacts`: timelines, entity summaries, detection drafts, backtest summaries, and investigation notes.
- `soc_agent_approvals`: requested action, approver, timestamps, before/after summary, risk notes, and execution result.

Raw provider responses should be stored only when explicitly required and redacted.

## Authorization and approval model

The MVP may map capabilities to the existing review-token session, but the design should support future roles:

- `soc_agent_viewer`: chat and read-only tools.
- `soc_agent_analyst`: create investigation artifacts and notes.
- `detection_engineer`: draft, backtest, and save detection proposals.
- `admin`: configure provider auth and approve sensitive or activating changes.

Approval flow:

1. The model proposes an action.
2. The server validates schema, permissions, and mutability.
3. The UI presents a clear summary, risk notes, and before/after diff when applicable.
4. An authorized operator approves.
5. The server executes the tool.
6. The audit trail records the approver, action, timestamps, and bounded result summary.

## Safety, privacy, and data sharing

- Show operators when data will leave the local SIEM and which provider/model receives it.
- Redact configured sensitive fields before provider calls.
- Cap event counts, prompt size, raw JSON inclusion, tool calls per turn, provider timeout, and spend/budget.
- Fail closed when `SocAgent:Enabled=false` or provider configuration is incomplete.
- Treat prompt-injection-like event content as untrusted data that cannot authorize tools or mutate SIEM state.
- Do not put provider secrets in prompts, logs, appsettings files, issue comments, PR text, or browser storage.

## Phased roadmap

1. **Feasibility and decision record:** verify official provider support for the target model and any delegated auth path; choose API-key/service-account auth unless an official delegated flow exists; define AI data-sharing and redaction policy.
2. **Contracts, config, and persistence:** add options, fake provider, schema, repositories, and docs.
3. **Read-only chat MVP:** add `/soc-agent`, session history, fake-provider smoke path, read-only SIEM tools, citations, and audit trail.
4. **Investigation workflows:** add timeline/entity pivots, artifact panel, source/ingestion health summaries, context attachment, and bounded investigation summaries.
5. **Detection engineering:** add rule/draft format, detection draft artifacts, backtesting, proposals, and tests with synthetic events only.
6. **Approved mutations:** add approval UX, authorization checks, activation/saved-query mutations, change proposals, audit, and rollback guidance.
7. **Hardening:** threat model provider auth, prompt injection, tool abuse, data exfiltration, CSRF/rate limits, budget controls, integration tests, docs, and release-readiness checks.

## Open questions

- Is there an official ChatGPT Team/Enterprise delegated-auth flow that permits this embedded application use case?
- Should the first implementation support only API-key/service-account auth until delegated auth is confirmed?
- Which detection format should be introduced first: saved event-search query, Sigma-like YAML, SQL-backed query, C# predicate, or project-specific JSON?
- Which default event fields require redaction before provider calls?
- Should conversation persistence store full redacted messages, metadata only, or deployment-configurable retention modes?
