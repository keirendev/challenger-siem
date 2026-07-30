# REST API v2

All routes return JSON except bounded CSV export. Production traffic requires HTTPS.

Agent routes:

- `POST /api/v2/agents/register` — enrollment token; registers a Linux agent.
- `POST /api/v2/agents/heartbeat` — per-agent bearer.
- `POST /api/v2/agents/inventory` — per-agent bearer.
- `POST /api/v2/ingest/events` — per-agent bearer; validates and deduplicates a bounded batch.

Service-token routes cover event search/timeline/export/saved searches, storage accounting and retention, source health and coverage, inventory, alerts, cases, investigation graphs, detection catalog/settings, summary aggregations, server settings, audit-oriented administration, and platform capabilities.

Manual `POST /api/v2/storage/retention/run` defaults to `dry_run: true`. An executing request with `dry_run: false` must also send the exact additive field `confirm_impact: "CONFIRM RETENTION DELETE"`; the service records a bounded mutation-specific audit outcome. This confirmation does not expand the managed-table allowlist or bypass batch/capacity/advisory-lock limits.

The route prefix, contracts, and JSON Schemas are versioned together as v2. All endpoint, source, and event platform values are Linux-only. Validation errors use standard problem details and never echo raw telemetry or credentials.

Use [examples/agent-registration.json](../examples/agent-registration.json) and [examples/fake-event-batch.json](../examples/fake-event-batch.json) as synthetic shapes. Exact deterministic event IDs should be produced by the shared identity implementation.
