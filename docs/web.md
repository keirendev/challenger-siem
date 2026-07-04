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
- `/` - dashboard with API/operator health metrics, agent counts, recent ingestion volume, latest ingest time, stale agents, and agents reporting non-zero queue depth.
- `/agents` - agent inventory with hostname, agent ID, OS, agent version, first/last seen, latest queue depth, and stale/recent state. Supports hostname, agent ID, and health filters.
- `/events` - event search form matching the MVP review API filters: time range, hostname, agent ID, channel, Windows Event ID, keyword, and bounded limit.
- `/events/detail?agent_id=<agent>&event_id=<uuid>` - normalized event detail with rendered message and formatted raw JSON.
- `/about` - application version, API/schema version, environment, and database connectivity status without exposing credentials.

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

## Local smoke path

Automated smoke path without Docker:

```bash
./scripts/smoke-test-web.sh
```

The script starts the API, seeds a synthetic agent/event through the v1 API, authenticates to the web console with the configured review token, and verifies dashboard, agent inventory, event search, and event detail HTML. Temporary HTML/cookies/responses stay under ignored `.local/`.

Manual path:

1. Start the API with the required database and auth environment variables.
2. Register an agent and ingest fake or real events.
3. Open the API base URL in a browser.
4. Log in with `Auth__ReviewToken`.
5. Confirm the dashboard, agent inventory, event search, and event detail pages show the ingested data.
