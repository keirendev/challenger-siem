# soc-agent

`soc-agent` is the SIEM-aware SOC analyst and detection-engineering chat workspace in Challenger SIEM.

The current implementation is a safe local provider/tool harness with a persistent live web chat UI and optional ChatGPT/OpenAI-backed provider paths. The primary ChatGPT setup path is the official Codex app-server account and device-code API, running with a SIEM-only `CODEX_HOME`; explicit subscription OAuth files, server-side API keys, and delegated API bearer files remain advanced alternatives. It runs server-side SIEM tools, streams live run/tool/progress events to the authenticated browser workspace, returns bounded answers with citations, stores bounded chat/session metadata, and preserves a backwards-compatible one-shot API. Operators can select only server-allowlisted models and reasoning efforts for each chat. External model calls remain disabled by default and require an explicit provider/auth-mode configuration outside source control. The page does **not** scrape or automate consumer website login, ask operators for provider passwords/cookies/tokens, reuse a developer's global Codex or Pi credentials, activate detections, change configuration outside this bounded credential workflow, delete telemetry, or edit source code.

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

- a clean two-pane workspace with compact recent chats on the left and a dominant conversation on the right; on narrow screens the conversation comes first and history follows it;
- compact provider status in the title area and an authenticated Settings dialog for safe ChatGPT connection status, allowed-model details, and Codex-managed subscription login;
- an admin-only, explicit-confirmation ChatGPT device-login action backed by the official Codex app-server account APIs; it permits one bounded active attempt with cancel and expiry and affects only the SIEM's isolated Codex account state;
- advanced, explicit server-mediated subscription OAuth-file connect/reconnect when separately enabled, plus confirmation-gated disconnect that can remove only the configured dedicated SIEM credential entry; delegated credentials remain server-managed and are never modified by that action;
- bounded chat history, confirmation-gated per-session deletion controls, and a message thread with plain-text operator bubbles plus safe Markdown-rendered `soc-agent` bubbles;
- no-reload message sending with Enter/Ctrl+Enter/Cmd+Enter-to-send, Shift+Enter-newline, immediate optimistic operator bubbles, a pending assistant/progress placeholder that updates Markdown safely as response deltas arrive, a non-editable agent-context chip, internal transcript auto-follow that preserves the operator's reading position, auto-grow character counting, active run state, reconnect/offline banners, and cancellation;
- server-allowlisted model and reasoning-effort selectors in the composer; local models disable the effort selector, and an unsupported model/effort pair fails validation rather than being forwarded;
- a deliberately quiet primary workspace: live tool events update only the pending response state, detailed tool activity stays out of the chat UI, and citation links remain available on final responses for evidence review;
- loading, empty, running, cancelled, error, reconnect, provider-unavailable, and local-fallback states;
- a mutation-safety reminder.

When an external provider is selected but no supported server-side auth/setup is configured, budget is exhausted, or the provider returns a safe mapped error, the UI fails closed for external calls and uses the configured local fallback only when `SocAgent:FallbackToLocalWhenUnavailable=true`. The selected execution preference remains attached to the chat session, while each assistant message records the provider, model, and reasoning effort that actually produced it; a local fallback therefore records its local model and no reasoning effort without silently changing the session preference. Assistant output supports a narrow Markdown subset for headings, paragraphs/line breaks, unordered and ordered lists, bold/italic emphasis, inline code, fenced code blocks, blockquotes, and links. Links are active only when they resolve to same-origin SIEM paths or `http`/`https` URLs without embedded credentials; `javascript:`, `data:`, protocol-relative, malformed, image/embed, and raw HTML/script content remains inert text or unlinked text. Operator messages are deliberately plain text. The page never asks for ChatGPT passwords, browser cookies, API keys, or session tokens.

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
    "ReasoningEffort": "medium",
    "ReasoningEfforts": ["low", "medium", "high"],
    "ModelOptions": [],
    "FallbackToLocalWhenUnavailable": true,
    "ExternalCallsEnabled": false,
    "PreferredExternalAuthMode": "CodexAppServer",
    "ProviderSetupUrl": "https://platform.openai.com/api-keys",
    "SubscriptionProviderSetupUrl": "https://help.openai.com/",
    "AuthFilePath": null,
    "AuthFileProviderKey": "openai",
    "SubscriptionAuthFilePath": null,
    "SubscriptionAuthFileProviderKey": "chatgpt",
    "CodexAppServer": {
      "Enabled": true,
      "ExecutablePath": null,
      "StateDirectory": ".local/soc-agent/codex",
      "WorkingDirectory": ".local/soc-agent/codex/workspace",
      "StartupTimeoutSeconds": 15,
      "RequestTimeoutSeconds": 45,
      "LoginTimeoutSeconds": 900,
      "MaxJsonLineBytes": 1048576
    },
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

`CodexAppServer.Enabled` defaults to `true`, but the overall provider still defaults to `Local` with external calls disabled. To opt into the primary ChatGPT path, set `SocAgent__Provider=ChatGPT`, `SocAgent__AuthMode=CodexAppServer`, and `SocAgent__ExternalCallsEnabled=true` in ignored server configuration, then have an administrator complete the fresh device login in Settings. The server resolves the official `codex` executable from `SocAgent__CodexAppServer__ExecutablePath`, its service `PATH`, or the service account's `~/.local/bin/codex`, in that order. It never discovers or invokes Pi.

The app-server process receives an isolated `CODEX_HOME` rooted at `SocAgent:CodexAppServer:StateDirectory` (default `.local/soc-agent/codex`) and is forced to use the file credential store there. Relative paths are normalized beneath the repository's `.local/` directory, traversal is rejected, and existing linked/reparse-point ancestors are not followed. It does not use the service account's global Codex credential/configuration state such as `~/.codex/auth.json` or `config.toml`, any Pi credential state, or an arbitrary auth file. The resolved executable may legitimately be a symlink into the official package tree under `~/.codex/packages`; those package files are not credential state. Existing global Codex/Pi credentials and legacy SIEM auth files are not copied or migrated; first use requires a fresh SIEM-managed login. If the isolated login or executable is unavailable, the Codex path fails closed and may use only the configured local response fallback. It does not implicitly fall back to another auth file.

This release enables the native broker only on non-Windows SIEM servers, where it can enforce owner-only directory and credential-file modes. A Windows endpoint agent remains fully supported, but a SIEM API process hosted on Windows reports this optional provider path as unavailable until an owner-only Windows DACL can be set and verified; it never accepts inherited ACLs as sufficient.

Advanced alternatives must be selected explicitly. Subscription OAuth-file mode uses `SocAgent__AuthMode=SubscriptionOAuth` with an explicit `SocAgent__SubscriptionAuthFilePath` and optional provider-key, scope, and token-endpoint settings. When an approved authorization-code/PKCE client is available, `SocAgent__SubscriptionConnectEnabled=true` enables its dedicated connect/reconnect workflow. API-key mode accepts `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY`; delegated auth-file mode uses `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and optional `SocAgent__AuthFileProviderKey`/`SocAgent__AuthFileExpirySkewSeconds`. Do not put provider credentials in tracked `appsettings.json`, browser local storage, prompts, logs, issue comments, or PR output. Tests use injected fake providers or synthetic placeholder files rather than real credentials.

`ModelOptions` is the server-owned allowlist displayed by the web composer and returned by provider status. Each entry has a model ID, optional display name, allowed reasoning efforts, and an optional default effort. At most 20 valid unique model IDs and seven supported effort names per entry are exposed. The configured `Model` is added to the allowlist when it is not already present, using `ReasoningEfforts` and `ReasoningEffort` as its defaults. Local-provider status always advertises no reasoning efforts because local deterministic execution does not invoke a reasoning model.

Example external-model allowlist, with model IDs chosen by the operator for the configured official provider:

```json
{
  "SocAgent": {
    "Model": "approved-reasoning-model",
    "ReasoningEffort": "medium",
    "ReasoningEfforts": ["low", "medium", "high"],
    "ModelOptions": [
      {
        "Model": "approved-reasoning-model",
        "DisplayName": "Approved reasoning model",
        "ReasoningEfforts": ["low", "medium", "high"],
        "DefaultReasoningEffort": "medium"
      },
      {
        "Model": "approved-fast-model",
        "DisplayName": "Approved fast model",
        "ReasoningEfforts": ["low", "medium"],
        "DefaultReasoningEffort": "low"
      }
    ]
  }
}
```

Model IDs and effort names are configuration, not arbitrary browser input: the server resolves every one-shot, session, message, and live-run selection against the current status allowlist before persisting or calling a provider. Invalid model/effort combinations return a validation response. Existing clients may omit both additive fields and receive the configured defaults; an existing chat reuses its persisted preference when a later request omits them and the pair remains allowed.

Supported status values are `local`, `disabled`, `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, `unsupported_subscription_oauth`, `scope_missing`, `connected`, `budget_limited`, `plan_limited`, `rate_limited`, `auth_failed`, and `provider_error`. The status response may also include safe optional metadata such as `credential_source`, `expires_at`, `refresh_status`, `provider_path`, `auth_file_mode`, `setup_priority`, `scope_status`, and `entitlement_status`; those fields never contain provider tokens, account IDs, email addresses, raw auth-file contents, or full filesystem paths.

### Official provider-backed execution

When `SocAgent:Provider=ChatGPT` or `SocAgent:Provider=OpenAI`, `SocAgent:ExternalCallsEnabled=true`, and a supported server-side authentication source is configured, `soc-agent` keeps all SIEM data access on the server and sends only a bounded/redacted prompt to the configured official provider endpoint. The prompt is assembled from the deterministic local tool assessment, tool-run summaries, and citation URLs; raw event JSON, provider credentials, bearer tokens, and unbounded endpoint telemetry are not sent. Provider errors are mapped to operator-safe codes (`auth_failed`, `scope_missing`, `budget_limited`, `plan_limited`, `rate_limited`, or `provider_error`) without rendering raw provider responses.

#### Codex app-server managed ChatGPT login

The SIEM starts the official `codex app-server` as a supervised stdio child process and uses its token-free `account/read`, `account/login/start` with `chatgptDeviceCode`, `account/login/cancel`, and account/login notifications. Codex owns token persistence and refresh in the isolated state directory. The SIEM login controller and browser do not receive OAuth access or refresh tokens from those APIs.

Settings offers start and cancel only to an administrator. Only one bounded login attempt may be active, and the server expires it after `LoginTimeoutSeconds`. The only provider-supplied login artifacts sent to the browser are the exact allowlisted `https://auth.openai.com/codex/device` verification URL and the short-lived user code. It never receives tokens, raw app-server messages, credential-file contents or paths, executable/command details, process IDs, account identifiers, email addresses, or raw provider errors. Analysts and detection engineers can review safe connection status but cannot start or cancel the shared SIEM login.

The app-server account APIs deliberately do not export bearer tokens. For current model execution, Challenger SIEM uses a narrow compatibility adapter that reads only the minimum credential fields from the isolated `CODEX_HOME/auth.json` just in time for the existing bounded, redacted, no-tools request to `https://chatgpt.com/backend-api/codex/responses`. The credential is not returned to the browser or copied to another store. This direct request boundary remains because an app-server turn is a coding-agent execution surface and cannot guarantee tool-free model execution; `soc-agent` must not grant the external model filesystem, shell, MCP, or other tools.

The native request boundary accepts only that exact HTTPS endpoint with no user information, custom port, query, fragment, or redirect. It caps cumulative response bytes and event-line size, bounds retained answer text, and requires a successful terminal response event; truncated, incomplete, failed, malformed, or oversized streams fail closed with an operator-safe error.

Disabling `CodexAppServer`, failing executable validation, or missing isolated account state never triggers a search of global Codex credentials/configuration such as `~/.codex/auth.json` or `config.toml`, Pi credential state, or legacy credential locations. Re-enabling the integration does not migrate those credentials: complete a fresh login into the isolated SIEM state directory.

#### Explicit subscription OAuth-file mode (advanced)

Subscription OAuth-file mode is opt-in and fail-closed. Its path must be a regular, non-linked dedicated credential file with no linked or reparse-point ancestor; global Codex or Pi credential-state directories and the reserved `openai-codex` provider entry are rejected rather than reused. Explicit subscription credential bundles must declare the approved API audience, an allowlisted official issuer, bearer token type, expiry, and the configured model-invocation scope (default `model.request`). Interactive start and callback processing are bound to the initiating administrator browser session, provider token responses are byte-bounded, and supported nested credential shapes are preserved during refresh. If a bundle does not permit model invocation for this application, status becomes `unsupported_subscription_oauth` or `scope_missing`; Challenger SIEM does not use browser cookie/session replay or password-based auth.

The Settings dialog shows only operator-safe status such as provider/auth mode, credential-source category, expiry, refresh/scope/entitlement state, and whether bounded/redacted SIEM context may leave the local server. Dedicated connect and reconnect use the authenticated authorization-code/PKCE flow and write the credential bundle only to the explicitly configured server-side path. Dedicated disconnect is offered only for a safe SIEM credential target, requires explicit confirmation, removes only the configured `providers` entry, preserves other JSON entries, and rewrites atomically. Delegated bearer files and externally managed login files cannot be deleted or disconnected from this page. None of these settings render a token, password, account ID, email address, raw auth-file content, or full filesystem path.

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

- provider, model name, and optional reasoning effort actually used;
- bounded operator and assistant text with basic secret-pattern redaction;
- tool-run summaries;
- citations;
- optional context agent/event identifiers;
- timestamps and session status.

Session rows also retain the currently selected provider/model/reasoning preference so the composer can continue a chat consistently. These tables are not intended to duplicate full raw endpoint telemetry or store provider credentials/provider payloads. Explicit operator deletion of a chat session removes the `soc_agent_sessions` row and associated `soc_agent_messages` rows through `on delete cascade`; independent one-shot `soc_agent_turns` audit rows are retained unless a separate synthetic-data cleanup/runbook action targets them.

## Safety and provider-auth guardrails

Only official provider authentication paths are acceptable for external providers:

1. **Primary external path:** the official Codex app-server account/device-code flow with its isolated SIEM-only `CODEX_HOME` and a fresh login.
2. **Advanced explicit OAuth-file path:** an ignored/server-side subscription OAuth credential bundle that grants the approved API audience and required model-invocation scope.
3. **Advanced API credential paths:** a server-side API key from environment/secret storage, or an explicit ignored delegated API-bearer file authorized for this application.
4. **Blocked paths:** implicit discovery or migration from global Codex credential/configuration state such as `~/.codex/auth.json` or `config.toml`, Pi credentials, consumer ChatGPT website automation, browser-cookie extraction, password capture, browser profile scraping, password/session replay, or unsupported auth-file exports.

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
