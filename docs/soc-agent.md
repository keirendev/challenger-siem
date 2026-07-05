# soc-agent

`soc-agent` is the SIEM-aware SOC analyst and detection-engineering chat workspace in Challenger SIEM.

The current implementation is a safe local provider/tool harness with a persistent web chat UI and optional official OpenAI Chat Completions-backed provider paths for server-side API keys or delegated auth files. It runs server-side SIEM tools, returns bounded answers with citations, stores bounded chat/session metadata, and preserves a backwards-compatible one-shot API. External model calls are disabled by default and require server-side OpenAI API-compatible credentials configured outside source control. It does **not** automate ChatGPT web login, call unofficial provider endpoints, ask operators for provider passwords/cookies/tokens in the browser, activate detections, change configuration, delete data, or edit source code.

The original planning record is archived at `docs/archive/soc-agent-planning-record-implemented.md`.

## Current routes

Web:

- `/soc-agent` - authenticated chat workspace behind the existing operator session cookie.

Review-token APIs:

- `GET /api/v1/soc-agent/status` - provider/model/auth status with safe connect/setup metadata and no secrets.
- `GET /api/v1/soc-agent/sessions` - recent bounded chat sessions.
- `POST /api/v1/soc-agent/sessions` - create a chat session.
- `GET /api/v1/soc-agent/sessions/{session_id}` - session detail and bounded messages.
- `POST /api/v1/soc-agent/sessions/{session_id}/messages` - append an operator message and receive a `soc-agent` response.
- `POST /api/v1/soc-agent/ask` - backwards-compatible one-shot local tool-backed answer.

## Chat workspace behavior

The `/soc-agent` page shows:

- provider/model/auth status and whether data may leave the local SIEM;
- a prominent official connect/setup action when external ChatGPT/OpenAI auth is required but unavailable;
- bounded chat history and a message thread with operator and `soc-agent` bubbles;
- a composer with optional agent context;
- inline tool activity, row counts, summaries, and citation links back to SIEM review pages;
- a mutation-safety reminder.

When an external provider is selected but no official server-side auth/setup is configured, budget is exhausted, or the provider returns a safe mapped error, the UI fails closed for external calls and uses the configured local fallback only when `SocAgent:FallbackToLocalWhenUnavailable=true`. The page never asks for ChatGPT passwords, browser cookies, API keys, or unofficial session tokens.

## Provider model and configuration

Default configuration keeps all prompts and tool summaries local:

```json
{
  "SocAgent": {
    "Enabled": true,
    "Provider": "Local",
    "ProviderDisplayName": "Local soc-agent",
    "AuthMode": "Local",
    "Model": "soc-agent-local-v1",
    "FallbackToLocalWhenUnavailable": true,
    "ExternalCallsEnabled": false,
    "ProviderSetupUrl": "https://platform.openai.com/api-keys",
    "AuthFilePath": null,
    "AuthFileProviderKey": "openai",
    "AuthFileExpirySkewSeconds": 300,
    "OpenAiBaseUrl": "https://api.openai.com/v1",
    "OpenAiChatCompletionsPath": "chat/completions",
    "MaxProviderOutputTokens": 1200,
    "RequestTimeoutSeconds": 30,
    "MaxRetries": 1,
    "MaxToolCalls": 8,
    "MaxPromptCharacters": 4000,
    "MaxResultCharacters": 20000,
    "MaxChatMessages": 50,
    "MaxEvents": 5,
    "MaxAgents": 10,
    "MaxAlerts": 10,
    "RequireApprovalForMutations": true
  }
}
```

For official OpenAI/ChatGPT-compatible use, configure provider credentials only server-side through ignored environment variables, an ignored delegated auth file, or a secret store. API-key mode accepts `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY`. Delegated auth-file mode uses `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and optional `SocAgent__AuthFileProviderKey`/`SocAgent__AuthFileExpirySkewSeconds`. Do not put provider credentials in tracked `appsettings.json`, browser local storage, prompts, logs, issue comments, or PR output. The built-in provider client is intentionally pinned to the official `https://api.openai.com/v1/chat/completions` endpoint; tests use injected fake providers or synthetic placeholder files rather than real credentials.

Supported status values are `local`, `disabled`, `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, `connected`, `budget_limited`, `rate_limited`, `auth_failed`, and `provider_error`. The status response may also include `credential_source`, `expires_at`, and `refresh_status`; those fields never contain provider tokens, account IDs, email addresses, raw auth-file contents, or full filesystem paths.

### Official provider-backed execution

When `SocAgent:Provider=OpenAI`, `SocAgent:ExternalCallsEnabled=true`, and either a server-side API key or a supported delegated auth file is configured, `soc-agent` keeps all SIEM data access on the server and sends only a bounded/redacted prompt to the official OpenAI Chat Completions endpoint. The prompt is assembled from the deterministic local tool assessment, tool-run summaries, and citation URLs; raw event JSON, provider credentials, bearer tokens, and unbounded endpoint telemetry are not sent. Provider errors are mapped to operator-safe codes (`auth_failed`, `budget_limited`, `rate_limited`, or `provider_error`) without rendering raw provider responses.

#### Delegated auth-file mode

Delegated auth-file mode is opt-in and fail-closed. It is intended for an operator-managed credential file or secret-manager material that is already authorized for the official OpenAI API. Challenger SIEM does not automate the ChatGPT consumer website, scrape browser cookies/profiles, replay undocumented sessions, or exchange passwords. If a file looks like an unsupported browser/session export or lacks official API audience metadata, status becomes `unsupported_delegated_auth` and no external call is attempted.

A minimal placeholder-only file looks like this; replace placeholders only in an ignored local file such as `.local/soc-agent/auth.json` or a secret-managed path outside the repository:

```json
{
  "providers": {
    "openai": {
      "provider": "OpenAI",
      "auth_type": "delegated_bearer",
      "token_type": "Bearer",
      "access_token": "<placeholder-access-token>",
      "expires_at": "2030-01-01T00:00:00Z",
      "audience": "https://api.openai.com/v1",
      "issuer": "https://auth.openai.com/",
      "refresh_token": "<optional-placeholder-refresh-token>"
    }
  }
}
```

Configure it with ignored environment variables or another server-side configuration provider:

```bash
SocAgent__Provider=OpenAI
SocAgent__ProviderDisplayName="OpenAI delegated"
SocAgent__AuthMode=DelegatedFile
SocAgent__ExternalCallsEnabled=true
SocAgent__AuthFilePath=.local/soc-agent/auth.json
SocAgent__AuthFileProviderKey=openai
```

The loader validates the configured provider key, bearer token type, expiry, official OpenAI API audience, official issuer host when present, and safe file location. Files inside the repository are accepted only when they are under `.local/` or use ignored auth-file names such as `auth.json`, `auth.*.json`, or `*.auth.json`; operator-managed paths outside the repository are also allowed. Refresh material is parsed only to report a safe `refresh_status`; this build does not perform token refresh, so expired delegated credentials return `expired` or `refresh_failed` and require reconnecting/replacing the file.

Delegated OAuth/OIDC/PKCE connect URLs remain setup-only unless a future official flow is deliberately implemented. Connect/setup URLs are allowlisted to official OpenAI/ChatGPT hosts, and unsupported or non-allowlisted URLs are treated as `provider_error`.

## Current local tools

`soc-agent` orchestrates bounded read-only views over existing SIEM repositories:

- `agent_inventory_search` - active host/agent inventory, stale/recent state, version, coverage level, source issue counts, and queue depth.
- `coverage_summary` - source-health summaries, host coverage, missing/stale/error source counts, and source-health detail links.
- `event_search` - recent normalized events scoped by optional agent context.
- `alert_review` - current alert review rows and alert page citations.
- `detection_rule_metadata` - built-in detection rule metadata and prerequisites.
- `inventory_summary` - bounded inventory/audit-policy snapshot summaries.
- `graph_search` - active investigation graph summaries and citations for operator-managed context.

Responses include tool-run summaries and citations back to review pages such as agent inventory, host coverage, event detail, alerts, and audit-policy drift.

## Audit and chat persistence

`soc-agent` stores bounded one-shot turn metadata in `soc_agent_turns` and chat metadata in `soc_agent_sessions` / `soc_agent_messages`:

- provider and model name;
- bounded operator and assistant text with basic secret-pattern redaction;
- tool-run summaries;
- citations;
- optional context agent/event identifiers;
- timestamps and session status.

These tables are not intended to duplicate full raw endpoint telemetry or store provider credentials/provider payloads.

## Safety and provider-auth guardrails

Only official provider authentication paths are acceptable for external providers:

1. **Preferred production path:** server-side provider credentials supplied by environment variables or a secret store.
2. **Optional delegated path:** an ignored server-side delegated auth file containing an official API bearer access token, or a future OAuth/OIDC/PKCE / Team/Enterprise connector flow that explicitly permits this application use case.
3. **Blocked path:** automation of the consumer ChatGPT website, browser-cookie extraction, password capture, browser profile scraping, undocumented session replay, unsupported auth-file exports, or unofficial endpoints.

Provider credentials must never be committed, rendered into browser local storage, logged, copied into prompts, or included in tool-call transcripts.

## Mutation policy

The current `soc-agent` implementation is read-only. It does not activate detections, change configuration, delete data, reconfigure agents, or modify repository files.

Investigation graph assistance follows this policy today: `soc-agent` may read graph summaries and create a bounded pending proposal on a graph page, but nodes/edges are not changed until an operator checks the approval control and applies the proposal.

Future mutating workflows must remain proposal-first and require explicit authorized operator approval. The approval flow should include:

1. model/tool proposes an action;
2. server validates schema, permissions, and mutability;
3. UI presents a clear summary, risk notes, and before/after diff when applicable;
4. authorized operator approves;
5. server executes the action;
6. audit trail records approver, action, timestamps, and bounded result summary.

## Future enhancements

- Streaming support for external provider responses.
- Timeline/entity pivot tools.
- Detection draft, backtest, and saved proposal artifacts.
- Approval UX for any future mutating tools.
- Operator RBAC and field-level access controls.
- Additional prompt-injection and data-sharing hardening.
