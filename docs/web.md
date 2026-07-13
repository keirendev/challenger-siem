# Web review application

The MVP review console is hosted by the ASP.NET Core API process. It uses the same PostgreSQL-backed repositories as the ingestion and review APIs, so the UI displays the same agent, heartbeat, and event data available to the server.

For public-safe visual examples, see the [sanitized web-console demo](web-console-demo.md). The demo screenshots are generated from synthetic data only and must be refreshed whenever user-visible web behavior changes.

## Authentication and authorization

Browse to the API base URL and sign in with a bootstrapped operator username/password. A successful login creates an HttpOnly, strict-SameSite, absolute-expiry cookie backed by a revocable database session. Logout revokes the server session before clearing the cookie. All forms use antiforgery validation.

Pages and actions enforce the exact role matrix from [auth.md](auth.md): viewers can inspect metadata, analysts can use investigations and `soc-agent`, detection engineers additionally manage detection workflows, and admins manage agents/operators and receive full sensitive fields. Non-admin event views omit raw payload and redact command, account, path, and network fields server-side.

## Visual system and operator workflow

The console uses a local, no-CDN dark SIEM shell with:

- sticky authenticated navigation with active-page state;
- a skip link, semantic landmarks, visible focus states, and keyboard-friendly controls;
- reusable cards, metric tiles, status badges, filter panels, empty states, notices, destructive-action guardrails, and responsive table wrappers;
- visible filter/result summaries so operators can tell what is active before pivoting;
- bounded list pages for agents, events, alerts, and investigation graphs with previous/next navigation.

Initial performance/accessibility budgets for local validation:

| Area | Budget |
| --- | --- |
| Static CSS | Keep `site.css` lightweight and local; no external fonts, CDNs, analytics, or browser telemetry. |
| Main list pages | Render at most one bounded page of table rows by default: agents 50, events configured `limit` up to 500, alerts 50, graphs 25. |
| Browser E2E | Exercise login, nav, list/detail pages, logout, unauthenticated redirect, responsive widths, focus behavior, and basic landmark/label checks against the real app. |
| Sensitive fields | Raw JSON and event text stay authenticated and must not be copied into docs, logs, screenshots, public fixtures, or GitHub comments. |

## Pages

- `/login` - operator username/password login.
- `/` - dashboard with API/operator health metrics, active/recent/stale agent counts, retired agent count, historical registration count, recent ingestion volume, latest ingest time, and active agents reporting non-zero queue depth.
- `/agents` - paged agent inventory with hostname, agent ID, OS, agent version, coverage level/status through L3 when Sysmon is healthy, source issue counts, first/last seen, latest queue depth, registration status, and stale/recent state. Supports hostname, agent ID, registration status, and health filters. Defaults to active registrations.
- `/agents/detail?agent_id=<agent>&target_level=L3` - host coverage/source-health detail with a target-level selector, host timezone label when reported, one row per expected Windows source for the selected target, recent normalized event counts, source pack/version/config-hash context such as the Sysmon profile version, explicit completeness gaps, inventory/audit-policy snapshot status, and per-rule detection prerequisite status without implying a confirmed detection miss when evidence is absent.
- `/events` - paged event search form matching the review API filters: UTC time range, hostname, agent ID, channel, Windows Event ID, keyword, normalized category/action/entity filters, active filter pills, and bounded limit. Event rows default to host-local time when event timezone metadata is present and also show UTC for correlation.
- `/events/detail?agent_id=<agent>&event_id=<uuid>` - normalized event detail with host-local event time, UTC event/ingest times, rendered message, entities, and formatted raw JSON.
- `/alerts` and `/alerts/detail?alert_id=<uuid>` - paged alert review skeleton with status filtering, rule metadata, affected entities, and evidence links.
- `/graphs` and `/graphs/detail?graph_id=<uuid>` - paged operator-managed investigation graphs with bounded metadata, typed nodes/edges, source links, archive lifecycle, and approval-gated `soc-agent` proposals.
- `/soc-agent` - local SIEM-aware SOC analyst/detection-engineering live chat workspace using a wider page-specific container, browser/page-level scrolling, a left session rail with confirmation-gated chat deletion, a wider no-reload thread/composer, non-editable agent context chip, Ctrl/Cmd+Enter send support, immediate optimistic send/pending-response state, safe assistant-only Markdown rendering for persisted and live responses, scheduled thread-aware auto-follow scrolling that keeps new content above the sticky composer while respecting manual scroll-away, a collapsible live-tool-activity rail sized for long tool names, cancellation, reconnect recovery, and citations back to review pages.
- `/audit-policy` - audit-policy drift snapshot review skeleton with host-local collected time when snapshot timezone metadata is present.
- `/about` - application version, API/schema version, environment, and database connectivity status without exposing credentials.

## Timezone display and filtering

Challenger SIEM stores and filters event timestamps in UTC. The web console interprets event range inputs as UTC, including offset-less `datetime-local` values from browsers. Host-scoped event, source-health, coverage, audit-policy, alert-evidence, and `soc-agent` event summaries display endpoint host time when `host_timezone` metadata is available and label the Windows timezone ID plus UTC offset. If timezone metadata is missing from older agents, the console falls back to an explicit UTC/unknown-timezone label instead of implying server-local or browser-local time.

Server-generated timestamps such as ingest time, alert creation time, graph updates, and chat messages are displayed as UTC.

## Agent lifecycle and cleanup

The review console treats agent registration lifecycle as metadata:

- `active` registrations can authenticate with their current per-agent token, send heartbeats, and ingest events.
- `stale` is a computed health state for active agents whose `last_seen` is older than `Review:StaleAgentMinutes`.
- `disabled` registrations are retired/cleaned-up records. They are hidden from default dashboard/inventory active views and agent-token authentication rejects them, but their agent row and historical telemetry remain in the database.

The `/agents` page includes a deliberate stale-agent cleanup panel. It previews how many active agents are older than the configured stale cutoff and requires operator confirmation before setting those registrations to `disabled`. The action does not delete events, heartbeats, source-health rows, inventory snapshots, alerts, or evidence. Use the status filter to include retired registrations explicitly. If an endpoint is intentionally re-enrolled later, the existing registration flow sets it back to `active` and issues a fresh per-agent token.

## Review settings

Optional configuration values under `Review` tune dashboard and default search behavior:

```json
{
  "Review": {
    "StaleAgentMinutes": 15,
    "RecentEventHours": 24,
    "DefaultEventLimit": 100
  },
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
    "SubscriptionUsePiAuthFile": true,
    "SubscriptionPiAuthFilePath": "~/.pi/agent/auth.json",
    "SubscriptionPiAuthFileProviderKey": "openai-codex",
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
    "MaxChatMessages": 50,
    "MaxEvents": 5,
    "MaxAgents": 10,
    "MaxAlerts": 10,
    "RequireApprovalForMutations": true
  }
}
```

`DefaultEventLimit` is capped to the same maximum of 500 used by the event review API. `/soc-agent` remains local by default while presenting ChatGPT subscription OAuth as the primary external setup path and API-key/delegated bearer modes as advanced alternatives. Assistant/`soc-agent` chat output is rendered as safe Markdown for headings, paragraphs, lists, emphasis, inline code, fenced code blocks, blockquotes, and sanitized links; operator-entered messages remain plain text, raw HTML is inert text, image/embed syntax is not activated, and unsafe URL schemes such as `javascript:`/`data:`/protocol-relative links are not linked. The normal chat path uses authenticated same-origin live endpoints and `text/event-stream` frames so operator API credentials, provider credentials, cookies, and bearer tokens are never placed in URLs or browser storage. Subscription OAuth can reuse Pi's `~/.pi/agent/auth.json` `openai-codex` entry after Pi `/login` and call the ChatGPT Codex Responses backend for plan-allowed models such as `gpt-5.5`, or use a dedicated ignored/secret-managed credential file for the OpenAI API Chat Completions path. When interactive subscription OAuth connect is enabled, the page shows a compact server-side connect/reconnect action only when operator attention is needed; it starts an official authorization-code/PKCE flow and stores tokens only in the configured ignored/secret-managed auth file. When an external provider mode is connected, the compact title pill carries provider status while live pending text/tool cards communicate bounded/redacted provider progress; an inline notice is reserved for actionable setup, auth, budget, rate-limit, or provider-error states so the normal chat workspace is not dominated by duplicate provider status. The persistent right rail is reserved for live tool activity.

## Local smoke path

Automated smoke path without Docker:

```bash
./scripts/smoke-test-web.sh
```

The script starts the API, seeds a synthetic agent/event through the v1 API, authenticates to the web console with the configured operator API credential, creates a synthetic `soc-agent` chat tied to that agent through the non-JavaScript fallback, and verifies dashboard, agent inventory, event search, event detail, investigation graphs, and `soc-agent` HTML. For live-workspace issue validation, supplement this smoke script with Playwright or equivalent browser E2E covering no-reload send, streamed progress/tool cards, cancellation, refresh/reconnect recovery, provider status/error states, thread-aware scroll-to-latest behavior, initial page-load position with long Recent chats, confirmation-gated chat deletion, responsive layout, keyboard navigation, and logout. Temporary HTML/cookies/responses stay under ignored `.local/`. Set `SIEM_WEB_SMOKE_CLEANUP=1` for opt-in cleanup of only that per-run `web-smoke-*` agent and its linked `soc-agent` chat history after successful validation, or run `./scripts/cleanup-synthetic-data.sh` separately in dry-run mode first.

Manual path:

1. Start the API with the required database and auth environment variables.
2. Register an agent and ingest synthetic or approved lab events.
3. Open the API base URL in a browser.
4. Log in with a synthetic operator username/password.
5. Confirm the dashboard, agent inventory, event search, and event detail pages show the expected data.

## Screenshot and browser-validation maintenance

When a change affects Razor Pages, web auth/session/CSRF/cookies, review-console routes or view models, web smoke scripts, `docs/web.md`, `docs/web-console-demo.md`, or user-visible browser behavior:

- Run browser E2E against the real app; curl/API/HTML checks can supplement but do not replace Playwright or equivalent browser validation.
- Update the [web-console demo](web-console-demo.md) text or screenshots if page layout, navigation, filters, or visible data changes.
- Regenerate screenshots only from synthetic data and inspect them for tokens, cookies, connection strings, real host/user identifiers, private lab telemetry, and browser/OS UI leaks before staging.
- Keep raw Playwright artifacts, browser caches, seeded API responses, cookies, and temporary captures under ignored `.local/` paths.
