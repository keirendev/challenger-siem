# soc-agent

`soc-agent` is the SIEM-aware SOC analyst and detection-engineering chat workspace in Challenger SIEM.

The current implementation is a safe local provider/tool harness with a persistent live web chat UI and optional ChatGPT/OpenAI-backed provider paths. Subscription OAuth is the primary external setup path when an official server-side OAuth client or delegated credential file is available; server-side API keys and delegated API bearer files remain advanced alternatives. It runs server-side SIEM tools, streams live run/tool/progress events to the authenticated browser workspace, returns bounded answers with citations, stores bounded chat/session metadata, and preserves a backwards-compatible one-shot API. External model calls are disabled by default and require server-side credentials configured outside source control. It does **not** automate consumer website login, ask operators for provider passwords/cookies/tokens in the browser, activate detections, change configuration, delete data, or edit source code.

The original planning record is archived at `docs/archive/soc-agent-planning-record-implemented.md`.

## Current routes

Web:

- `/soc-agent` - authenticated live chat workspace behind the existing operator session cookie.
- `POST /soc-agent/live/runs` - same-origin browser endpoint that starts a live run after persisting the operator message.
- `GET /soc-agent/live/runs/{run_id}/events?after=<sequence>` - authenticated `text/event-stream` transport for resume snapshots, run state, tool progress, citations, content deltas, errors, and completion.
- `POST /soc-agent/live/runs/{run_id}/cancel` - cancels an active server-side turn and records a bounded cancelled assistant message when interrupted.
- `GET /soc-agent/live/sessions/{session_id}/active` - lets the page recover an active run after refresh without duplicating messages.

Operator-credential APIs:

- `GET /api/v1/soc-agent/status` - provider/model/auth status with safe connect/setup metadata and no secrets.
- `GET /api/v1/soc-agent/sessions` - recent bounded chat sessions.
- `POST /api/v1/soc-agent/sessions` - create a chat session.
- `GET /api/v1/soc-agent/sessions/{session_id}` - session detail and bounded messages.
- `DELETE /api/v1/soc-agent/sessions/{session_id}` - authenticated chat-history management that deletes one session and cascades its messages, while blocking active live runs.
- `POST /api/v1/soc-agent/sessions/{session_id}/messages` - append an operator message and receive a `soc-agent` response.
- `POST /api/v1/soc-agent/ask` - backwards-compatible one-shot local tool-backed answer.

## Chat workspace behavior

The `/soc-agent` page shows:

- a widened single-page operator workspace where the browser is the primary vertical scroll surface, with a left recent-session rail, wider center thread, sticky page-level composer, and a right rail focused on live tool activity;
- compact provider/model/auth status in the title pill, plus a small inline notice/connect action only when external-provider setup, auth, budget/rate, or provider-error state needs operator attention;
- ChatGPT subscription OAuth as the primary external setup path, with API-key/delegated bearer setup documented as advanced alternatives instead of occupying persistent right-rail space;
- bounded chat history, confirmation-gated per-session deletion controls in the Recent chats rail, and a message thread with plain-text operator bubbles plus safe Markdown-rendered `soc-agent` bubbles;
- no-reload message sending with Enter/Ctrl+Enter/Cmd+Enter-to-send, Shift+Enter-newline, immediate optimistic operator bubbles, a pending assistant/progress placeholder that updates Markdown safely as response deltas arrive, a non-editable agent-context chip, scheduled thread-end-sentinel auto-follow scrolling that keeps new chat content above the sticky composer, auto-grow character counting, active run state, reconnect/offline banners, and cancellation;
- live tool activity cards with running/ok states, bounded row counts/summaries, wrapping for long tool names such as `external_model_provider`, and final citation links back to SIEM review pages;
- loading, empty, running, cancelled, error, reconnect, provider-unavailable, and local-fallback states;
- a mutation-safety reminder.

When an external provider is selected but no supported server-side auth/setup is configured, budget is exhausted, or the provider returns a safe mapped error, the UI fails closed for external calls and uses the configured local fallback only when `SocAgent:FallbackToLocalWhenUnavailable=true`. Assistant output supports a narrow Markdown subset for headings, paragraphs/line breaks, unordered and ordered lists, bold/italic emphasis, inline code, fenced code blocks, blockquotes, and links. Links are active only when they resolve to same-origin SIEM paths or `http`/`https` URLs without embedded credentials; `javascript:`, `data:`, protocol-relative, malformed, image/embed, and raw HTML/script content remains inert text or unlinked text. Operator messages are deliberately plain text. The page never asks for ChatGPT passwords, browser cookies, API keys, or session tokens.

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
    "PreferredExternalAuthMode": "SubscriptionOAuth",
    "ProviderSetupUrl": "https://platform.openai.com/api-keys",
    "SubscriptionProviderSetupUrl": "https://help.openai.com/",
    "AuthFilePath": null,
    "AuthFileProviderKey": "openai",
    "SubscriptionAuthFilePath": null,
    "SubscriptionAuthFileProviderKey": "chatgpt",
    "SubscriptionRequiredScopes": "model.request",
    "SubscriptionTokenEndpoint": "https://auth.openai.com/oauth/token",
    "SubscriptionConnectEnabled": false,
    "SubscriptionAuthorizationUrl": "https://auth.openai.com/oauth/authorize",
    "SubscriptionRedirectPath": "/soc-agent/oauth/callback",
    "SubscriptionRedirectUri": null,
    "SubscriptionClientId": null,
    "SubscriptionClientSecret": null,
    "SubscriptionOAuthAudience": "https://api.openai.com/v1",
    "SubscriptionIssuer": "https://auth.openai.com/",
    "SubscriptionStateLifetimeMinutes": 10,
    "AuthFileExpirySkewSeconds": 300,
    "OpenAiBaseUrl": "https://api.openai.com/v1",
    "OpenAiChatCompletionsPath": "chat/completions",
    "ChatGptCodexResponsesUrl": "https://chatgpt.com/backend-api/codex/responses",
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

For ChatGPT/OpenAI-compatible use, configure provider credentials only server-side through ignored environment variables, an explicit ignored auth file, or a secret store. Subscription OAuth mode uses `SocAgent__Provider=ChatGPT`, `SocAgent__AuthMode=SubscriptionOAuth`, and an explicit `SocAgent__SubscriptionAuthFilePath` plus optional provider-key, scope, and token-endpoint settings. When an official authorization-code/PKCE app is available, set `SocAgent__SubscriptionConnectEnabled=true` with the server-side client configuration so operators can start connect from `/soc-agent`. API-key mode accepts `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY`. Delegated auth-file mode uses `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and optional `SocAgent__AuthFileProviderKey`/`SocAgent__AuthFileExpirySkewSeconds`. Do not put provider credentials in tracked `appsettings.json`, browser local storage, prompts, logs, issue comments, or PR output. Tests use injected fake providers or synthetic placeholder files rather than real credentials.

Supported status values are `local`, `disabled`, `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, `unsupported_subscription_oauth`, `scope_missing`, `connected`, `budget_limited`, `plan_limited`, `rate_limited`, `auth_failed`, and `provider_error`. The status response may also include safe optional metadata such as `credential_source`, `expires_at`, `refresh_status`, `provider_path`, `auth_file_mode`, `setup_priority`, `scope_status`, and `entitlement_status`; those fields never contain provider tokens, account IDs, email addresses, raw auth-file contents, or full filesystem paths.

### Official provider-backed execution

When `SocAgent:Provider=ChatGPT` or `SocAgent:Provider=OpenAI`, `SocAgent:ExternalCallsEnabled=true`, and a supported server-side credential path is configured, `soc-agent` keeps all SIEM data access on the server and sends only a bounded/redacted prompt to the configured official provider endpoint. The prompt is assembled from the deterministic local tool assessment, tool-run summaries, and citation URLs; raw event JSON, provider credentials, bearer tokens, and unbounded endpoint telemetry are not sent. Provider errors are mapped to operator-safe codes (`auth_failed`, `scope_missing`, `budget_limited`, `plan_limited`, `rate_limited`, or `provider_error`) without rendering raw provider responses.

#### ChatGPT subscription OAuth mode

Subscription OAuth mode is opt-in, fail-closed, and the primary external setup path shown in the web workspace. Explicit subscription credential bundles must declare the approved API audience, an allowlisted official issuer, bearer token type, expiry, and the configured model-invocation scope (default `model.request`). If a bundle does not permit model invocation for this application, status becomes `unsupported_subscription_oauth` or `scope_missing`; Challenger SIEM does not use browser cookie/session replay or password-based auth.

A placeholder-only subscription OAuth file looks like this; replace placeholders only in an ignored local file such as `.local/soc-agent/chatgpt-auth.json` or a secret-managed path outside the repository:

```json
{
  "providers": {
    "chatgpt": {
      "provider": "ChatGPT",
      "auth_type": "subscription_oauth",
      "token_type": "Bearer",
      "access_token": "<placeholder-access-token>",
      "refresh_token": "<optional-placeholder-refresh-token>",
      "expires_at": "2030-01-01T00:00:00Z",
      "audience": "https://api.openai.com/v1",
      "issuer": "https://auth.openai.com/",
      "scope": "openid profile offline_access model.request",
      "token_endpoint": "https://auth.openai.com/oauth/token",
      "entitlement_status": "available"
    }
  }
}
```

Configure the placeholder-schema file with ignored environment variables or another server-side configuration provider:

```bash
SocAgent__Provider=ChatGPT
SocAgent__ProviderDisplayName="ChatGPT subscription OAuth"
SocAgent__AuthMode=SubscriptionOAuth
SocAgent__ExternalCallsEnabled=true
SocAgent__SubscriptionAuthFilePath=.local/soc-agent/chatgpt-auth.json
SocAgent__SubscriptionAuthFileProviderKey=chatgpt
SocAgent__SubscriptionRequiredScopes=model.request
```

To let operators trigger the official authorization-code/PKCE flow from the web page, configure a dedicated auth file plus the server-side OAuth client and callback. The callback writes only the minimal access/refresh-token bundle to `SocAgent__SubscriptionAuthFilePath`, and browser clients never receive tokens or raw auth-file content. Use provider-approved values only:

```bash
SocAgent__SubscriptionConnectEnabled=true
SocAgent__SubscriptionAuthorizationUrl=https://auth.openai.com/oauth/authorize
SocAgent__SubscriptionTokenEndpoint=https://auth.openai.com/oauth/token
SocAgent__SubscriptionClientId=<placeholder-client-id>
SocAgent__SubscriptionClientSecret=<optional-placeholder-client-secret>
SocAgent__SubscriptionRedirectUri=https://<siem-host>/soc-agent/oauth/callback
SocAgent__SubscriptionOAuthAudience=https://api.openai.com/v1
SocAgent__SubscriptionIssuer=https://auth.openai.com/
```

The connect start endpoint requires an authenticated SIEM operator session. The callback validates a protected OAuth state/PKCE correlation cookie and is allowed to complete even if the strict review-session cookie is not sent on the cross-site provider redirect. Authorization and token endpoints are allowlisted to official provider hosts and paths; unsupported URLs fail closed.

The loader validates the configured provider key, credential type, bearer token type, expiry, official API audience, official issuer host when present, required model scope, entitlement hints, and safe file location. Files inside the repository are accepted only when they are under `.local/` or use ignored auth-file names such as `auth.json`, `auth.*.json`, or `*.auth.json`; operator-managed paths outside the repository are also allowed. When a near-expiry token has refresh material and an allowlisted official token endpoint, the provider client refreshes it before a model request and atomically persists the updated ignored/secret-managed file. Refresh failures map to `refresh_failed` without exposing provider payloads.

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

Responses include tool-run summaries and citations back to review pages such as agent inventory, host coverage, event detail, alerts, and audit-policy drift. During live runs the browser receives typed event-stream frames with monotonic sequence IDs: `resume_snapshot`, `session_created`, `message_created`, `run_started`, `provider_status`, `tool_started`, `tool_finished`, `citation_added`, `content_delta`, `run_cancel_requested`, `run_error`, and `run_complete`. Reconnects pass the last observed sequence so retained events are replayed without duplicating persisted messages.

## Audit and chat persistence

`soc-agent` stores bounded one-shot turn metadata in `soc_agent_turns` and chat metadata in `soc_agent_sessions` / `soc_agent_messages`:

- provider and model name;
- bounded operator and assistant text with basic secret-pattern redaction;
- tool-run summaries;
- citations;
- optional context agent/event identifiers;
- timestamps and session status.

These tables are not intended to duplicate full raw endpoint telemetry or store provider credentials/provider payloads. Explicit operator deletion of a chat session removes the `soc_agent_sessions` row and associated `soc_agent_messages` rows through `on delete cascade`; independent one-shot `soc_agent_turns` audit rows are retained unless a separate synthetic-data cleanup/runbook action targets them.

## Safety and provider-auth guardrails

Only official provider authentication paths are acceptable for external providers:

1. **Primary external path:** an ignored/server-side subscription OAuth credential bundle that grants the approved API audience and required model-invocation scope.
2. **Advanced production path:** server-side API-key credentials supplied by environment variables or a secret store.
3. **Optional delegated API-bearer path:** an ignored server-side delegated auth file containing an official API bearer access token, or a future OAuth/OIDC/PKCE / Team/Enterprise connector flow that explicitly permits this application use case.
4. **Blocked path:** automation of the consumer ChatGPT website, browser-cookie extraction, password capture, browser profile scraping, password/session replay, or unsupported auth-file exports.

Provider credentials must never be committed, rendered into browser local storage, logged, copied into prompts, or included in tool-call transcripts.

## Mutation policy

The current `soc-agent` tool implementation is read-only. It does not activate detections, change configuration, delete endpoint/SIEM telemetry, reconfigure agents, modify repository files, or initiate chat-history deletion. Chat-session deletion is an explicit authenticated operator UI/API action outside the model/tool loop and is blocked while that session has an active live run.

Investigation graph assistance follows this policy today: `soc-agent` may read graph summaries and create a bounded pending proposal on a graph page, but nodes/edges are not changed until an operator checks the approval control and applies the proposal.

Future mutating workflows must remain proposal-first and require explicit authorized operator approval. The approval flow should include:

1. model/tool proposes an action;
2. server validates schema, permissions, and mutability;
3. UI presents a clear summary, risk notes, and before/after diff when applicable;
4. authorized operator approves;
5. server executes the action;
6. audit trail records approver, action, timestamps, and bounded result summary.

## Future enhancements

- External-provider token-by-token streaming when provider SDK support and persistence semantics are ready.
- Timeline/entity pivot tools.
- Detection draft, backtest, and saved proposal artifacts.
- Approval UX for any future mutating tools.
- Operator RBAC and field-level access controls.
- Additional prompt-injection and data-sharing hardening.
