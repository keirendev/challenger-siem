# REST API v2

All routes return JSON except bounded CSV export. Production traffic requires HTTPS.

Agent routes:

- `POST /api/v2/agents/register` — enrollment token; registers a Linux agent.
- `POST /api/v2/agents/heartbeat` — per-agent bearer.
- `POST /api/v2/agents/inventory` — per-agent bearer; one sequential request carries at most 20 inventory pages within the configured serialized-request budget.
- `POST /api/v2/ingest/events` — per-agent bearer; validates and deduplicates a bounded batch.

Service-token routes cover event search/timeline/export/saved searches, storage accounting and retention, source health and coverage, inventory, alerts, cases, investigation graphs, detection catalog/settings, summary aggregations, server settings, audit-oriented administration, and platform capabilities.

`GET /api/v2/network/geography` is the bounded read-only source for `/ui/traffic`. Optional filters are `from`, `to`, `q`, `hostname`, `agent_id`, `destination_ip`, `destination_port`, `protocol`, `process_image`, `country_code`, `asn`, and `limit`. UTC bounds must be ordered; results are naturally limited to retained evidence and `limit` is capped at 2,000. The `challenger-siem.network-geography.v2` response reports retained and active ranges, at most 200 timeline buckets, destination-IP aggregates, action-specific observation/change counts, bounded metadata sets, cached approximate location/ASN state, source coverage, pending/quota-limited geolocation counts, truncation flags, active filters, and explicit evidence limitations.

Time bounds apply to event `event_time`, not ingestion time. The browser converts its presets and custom local-time inputs to explicit UTC `from`/`to` values; the API itself does not accept preset names. The retained range covers only qualifying network-snapshot rows, so it can differ from the database's overall event range.

Only `linux-network-socket-snapshot-diff` rows with a remote IP participate. `socket_observed` and `socket_baseline` are connection observations; `socket_changed`, `socket_disappeared`, and `socket_baseline_disappeared` are lifecycle changes and are not counted as new connections. The endpoint may enqueue missing public IPs for later geolocation and return `pending` immediately; callers should treat geolocation and process ownership as incomplete evidence.

`GET /api/v2/inventory` retains the existing `snapshots` member and adds optional exact
`generation_id` and `page_index` filters plus generation/page/item completeness totals.
Paging summary keys are `generation_id`, one-based `page_index`, `page_count`,
`page_item_count`, `total_item_count`, `source_complete`, and `source_truncated`.
Existing unpaged v2 snapshots are treated as complete one-page generations. The server
derives completeness from received unique pages and counts; it never trusts an endpoint
claim by itself. Latest complete generations are used for coverage and L4 posture, while
missing or source-truncated generations degrade those consumers. Paging keys do not
participate in posture fingerprints.

Telemetry-coverage responses add liveness-monitor attempt/success freshness, active
outage count, per-agent 24-hour/seven-day history readiness, and retention-scheduler
configuration. Liveness freshness and `active_outage_count` describe the global server
monitor pass across all registered active agents even when an agent filter narrows the
coverage rows; use that agent's alert status to determine its own current outage state.
The in-process liveness monitor cannot report an API, database, process,
or host failure that prevents it from running; independent service monitoring remains
required.

Manual `POST /api/v2/storage/retention/run` defaults to `dry_run: true`. An executing request with `dry_run: false` must also send the exact additive field `confirm_impact: "CONFIRM RETENTION DELETE"`; the service records a bounded mutation-specific audit outcome. This confirmation does not expand the managed-table allowlist or bypass batch/capacity/advisory-lock limits.

The deployment profile targets 30 days under the existing 100 GiB ceiling. Its hourly
hosted scheduler is enabled only after an execution dry run shows no unexpected eligible
data; alert/evidence references remain protected.

The route prefix, contracts, and JSON Schemas are versioned together as v2. All endpoint, source, and event platform values are Linux-only. Validation errors use standard problem details and never echo raw telemetry or credentials.

Use [examples/agent-registration.json](../examples/agent-registration.json) and [examples/fake-event-batch.json](../examples/fake-event-batch.json) as synthetic shapes. Exact deterministic event IDs should be produced by the shared identity implementation.
