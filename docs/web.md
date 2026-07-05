# Web review application

The MVP review console is hosted by the ASP.NET Core API process. It uses the same PostgreSQL-backed repositories as the ingestion and review APIs, so the UI displays the same agent, heartbeat, and event data available to the server.

## Authentication

Browse to the API base URL and sign in with the configured review token:

```bash
export Auth__ReviewToken='<long-random-review-token>'
```

The submitted token is compared server-side, is not logged, and is not stored in browser local storage. A successful login creates an HTTP-only same-origin cookie for the operator session. Logout clears that cookie.

## Pages

- `/login` - operator review-token login.
- `/` - dashboard with API/operator health metrics, active/recent/stale agent counts, retired agent count, historical registration count, recent ingestion volume, latest ingest time, and active agents reporting non-zero queue depth.
- `/agents` - agent inventory with hostname, agent ID, OS, agent version, coverage level/status, source issue counts, first/last seen, latest queue depth, registration status, and stale/recent state. Supports hostname, agent ID, registration status, and health filters. Defaults to active registrations.
- `/agents/detail?agent_id=<agent>` - host coverage/source-health detail with required source status, record ranges, log-size metrics, and gap/clear indicators.
- `/events` - event search form matching the review API filters: time range, hostname, agent ID, channel, Windows Event ID, keyword, normalized category/action/entity filters, and bounded limit.
- `/events/detail?agent_id=<agent>&event_id=<uuid>` - normalized event detail with rendered message, entities, and formatted raw JSON.
- `/alerts` and `/alerts/detail?alert_id=<uuid>` - alert review skeleton with status filtering, rule metadata, affected entities, and evidence links.
- `/soc-agent` - local SIEM-aware SOC analyst/detection-engineering chat workspace with provider status/connect UX, bounded session history, server-side tools for agents, source health, events, alerts, detection rules, and inventory, plus citations back to review pages.
- `/audit-policy` - audit-policy drift snapshot review skeleton.
- `/about` - application version, API/schema version, environment, and database connectivity status without exposing credentials.

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
    "ProviderSetupUrl": "https://platform.openai.com/api-keys",
    "MaxChatMessages": 50,
    "MaxEvents": 5,
    "MaxAgents": 10,
    "MaxAlerts": 10,
    "RequireApprovalForMutations": true
  }
}
```

`DefaultEventLimit` is capped to the same maximum of 500 used by the event review API.

## Local smoke path

Automated smoke path without Docker:

```bash
./scripts/smoke-test-web.sh
```

The script starts the API, seeds a synthetic agent/event through the v1 API, authenticates to the web console with the configured review token, and verifies dashboard, agent inventory, event search, event detail, and `soc-agent` status HTML. For web-app issue validation, supplement this smoke script with Playwright browser E2E covering the relevant pages. Temporary HTML/cookies/responses stay under ignored `.local/`. Set `SIEM_WEB_SMOKE_CLEANUP=1` for opt-in cleanup of only that per-run `web-smoke-*` agent after successful validation, or run `./scripts/cleanup-synthetic-data.sh` separately in dry-run mode first.

Manual path:

1. Start the API with the required database and auth environment variables.
2. Register an agent and ingest fake or real events.
3. Open the API base URL in a browser.
4. Log in with `Auth__ReviewToken`.
5. Confirm the dashboard, agent inventory, event search, and event detail pages show the ingested data.
