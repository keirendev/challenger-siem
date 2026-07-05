# soc-agent

`soc-agent` is the project name for the SIEM-aware SOC analyst and detection-engineering harness in Challenger SIEM.

The current implementation is a safe local provider/tool harness. It runs server-side SIEM tools, returns bounded answers with citations, and persists bounded turn metadata. It does **not** automate ChatGPT web login, call unofficial provider endpoints, require external model credentials, activate detections, change configuration, delete data, or edit source code.

The original planning record is archived at `docs/archive/soc-agent-planning-record-implemented.md`.

## Current routes

- `/soc-agent` - authenticated web workspace behind the existing operator session cookie.
- `POST /api/v1/soc-agent/ask` - review-token-protected API for local tool-backed answers.

## Current provider model

The MVP provider is `Local` with model name `soc-agent-local-v1` by default. It is deterministic and uses repository data available to the API process. No endpoint telemetry is sent to an external AI provider.

Configuration:

```json
{
  "SocAgent": {
    "Enabled": true,
    "Provider": "Local",
    "Model": "soc-agent-local-v1",
    "MaxEvents": 5,
    "MaxAgents": 10,
    "MaxAlerts": 10,
    "RequireApprovalForMutations": true
  }
}
```

## Current local tools

`soc-agent` orchestrates bounded read-only views over existing SIEM repositories:

- `agent_inventory_search` - host/agent inventory, stale/recent state, version, coverage level, source issue counts, and queue depth.
- `coverage_summary` - source-health summaries, host coverage, missing/stale/error source counts, and source-health detail links.
- `event_search` - recent normalized events scoped by optional agent context.
- `alert_review` - current alert review rows and alert page citations.
- `detection_rule_metadata` - built-in detection rule metadata and prerequisites.
- `inventory_summary` - bounded inventory/audit-policy snapshot summaries.

Responses include tool-run summaries and citations back to review pages such as agent inventory, host coverage, event detail, alerts, and audit-policy drift.

## Audit persistence

`soc-agent` stores bounded turn metadata in `soc_agent_turns`:

- provider and model name;
- bounded question and answer text with basic secret-pattern redaction;
- tool-run summaries;
- citations;
- optional context agent/event identifiers.

The audit table is not intended to duplicate full raw endpoint telemetry or store provider credentials.

## Safety and provider-auth guardrails

Only official provider authentication paths are acceptable for future external providers:

1. **Preferred production path:** server-side provider credentials supplied by environment variables or a secret store.
2. **Optional delegated path:** OAuth/OIDC/PKCE, ChatGPT Team/Enterprise connector auth, or another documented provider flow that explicitly permits this application use case.
3. **Blocked path:** automation of the consumer ChatGPT website, browser-cookie extraction, password capture, browser profile scraping, undocumented session replay, or unofficial endpoints.

Provider credentials must never be committed, rendered into browser local storage, logged, copied into prompts, or included in tool-call transcripts.

## Mutation policy

The current `soc-agent` implementation is read-only. It does not activate detections, change configuration, delete data, reconfigure agents, or modify repository files.

Future mutating workflows must remain proposal-first and require explicit authorized operator approval. The approval flow should include:

1. model/tool proposes an action;
2. server validates schema, permissions, and mutability;
3. UI presents a clear summary, risk notes, and before/after diff when applicable;
4. authorized operator approves;
5. server executes the action;
6. audit trail records approver, action, timestamps, and bounded result summary.

## Future enhancements

- External official model-provider abstraction and streaming support.
- Conversation/session history beyond bounded turn audit rows.
- Timeline/entity pivot tools.
- Detection draft, backtest, and saved proposal artifacts.
- Approval UX for any future mutating tools.
- Operator RBAC and field-level access controls.
- Additional prompt-injection and data-sharing hardening.
