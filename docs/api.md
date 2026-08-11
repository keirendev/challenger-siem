# REST API v2

All routes return JSON except bounded CSV export. Production traffic requires HTTPS.

Agent routes:

- `POST /api/v2/agents/register` — enrollment token; registers a Linux agent.
- `POST /api/v2/agents/heartbeat` — per-agent bearer.
- `POST /api/v2/agents/inventory` — per-agent bearer; one sequential request carries at most 20 inventory pages within the configured serialized-request budget.
- `POST /api/v2/ingest/events` — per-agent bearer; validates and deduplicates a bounded batch.

Service-token routes cover event search/timeline/export/saved searches, storage accounting and retention, source health and coverage, inventory, alerts, cases, investigation graphs, detection catalog/settings, summary aggregations, server settings, audit-oriented administration, and platform capabilities. The only implied-authentication exception is the direct-loopback traffic-dashboard pair below; `/mcp` and every other review route remain bearer-authenticated.

`GET /api/v2/network/geography` is the bounded read-only source for `/ui/traffic`. Optional filters are `from`, `to`, `q`, `hostname`, `agent_id`, `destination_ip`, `destination_port`, `protocol`, `process_image`, `country_code`, `asn`, and `limit`. UTC bounds must be ordered; results are naturally limited to retained evidence and `limit` is capped at 2,000. The `challenger-siem.network-geography.v2` response reports retained and active ranges, at most 200 timeline buckets, destination-IP aggregates, action-specific observation/change counts, bounded metadata sets, cached approximate location/ASN state, source coverage, pending/quota-limited geolocation counts, truncation flags, active filters, and explicit evidence limitations.

`GET /api/v2/network/geography/events` is the dashboard's bounded destination drill-down. It accepts one exact `destination_ip`, optional RFC 3339 `from`/`to`, and `limit` from 1 through 25. It reads only socket-snapshot and kernel-flow source IDs and returns `challenger-siem.network-geography-evidence.v2` rows with citation, host/source/code/time/severity/message, evidence mode, direction, and optional process image. Raw and normalized event payloads are never returned.

Those two routes accept either a valid service bearer or implied local read-only authentication. Implied authentication requires an exact `GET`/`HEAD`, loopback client and listener socket addresses, a loopback `Host`, no forwarding/proxy headers, and no `Authorization` header. This exception is intended only for a dashboard bound directly to localhost; it does not authorize reverse-proxied, remotely exposed, rebinding-host, or other `/api/v2` requests.

`GET /api/v2/network/activity` correlates retained snapshot and kernel-flow events with process attribution. Filters are `from`, `to`, `hostname`, `agent_id`, `remote_ip`, `remote_port`, `protocol`, `process_image`, `country_code`, `asn`, `direction`, `evidence_mode`, `attributed_only`, `limit`, and `cursor`; the REST limit is 500. Each `challenger-siem.network-activity.v2` row contains its `event:{agent_id}/{event_id}` citation, tuple, evidence mode, direction, bounded process metadata/confidence, interval packet/SKB-byte deltas when available, TCP flags, and cached approximate geography. Authenticated REST may enqueue an on-demand lookup when traffic-map geolocation is enabled. It never returns event raw payloads.

Time bounds apply to event `event_time`, not ingestion time. The browser converts its presets and custom local-time inputs to explicit UTC `from`/`to` values; the API itself does not accept preset names. The retained range covers only qualifying snapshot or kernel-flow rows, so it can differ from the database's overall event range.

Only `linux-network-socket-snapshot-diff` or `linux-network-flow-summary` rows with a remote IP participate. `socket_observed`, `socket_baseline`, `network_flow_started`, `network_flow_sample`, and `network_flow_closed` are retained activity evidence; the three kernel codes distinguish first emission, 60-second active summaries, and FIN/RST or 60-second inactivity closure. Snapshot `socket_changed`, `socket_disappeared`, and `socket_baseline_disappeared` remain polling lifecycle changes rather than new connections. The endpoint may enqueue missing public IPs for later geolocation and return `pending` immediately; callers should treat geolocation, snapshot ownership, and kernel attribution as incomplete evidence with different confidence semantics.

`GET /api/v2/inventory` retains the existing `snapshots` member and adds optional exact
`generation_id` and `page_index` filters plus generation/page/item completeness totals.
Paging summary keys are `generation_id`, one-based `page_index`, `page_count`,
`page_item_count`, `total_item_count`, `source_complete`, and `source_truncated`.
Existing unpaged v2 snapshots are treated as complete one-page generations. The server
derives completeness from received unique pages and counts; it never trusts an endpoint
claim by itself. Latest complete generations are used for coverage and L4 posture, while
missing or source-truncated generations degrade those consumers. Paging keys do not
participate in posture fingerprints.

Current L2 agents report mandatory `linux-package-inventory-diff` health with a sequence
checkpoint and retain `linux-package-management` as supplemental journal health. For an
API-first rolling upgrade, heartbeat validation also accepts the exact pre-2.9 package
descriptor in which the journal source is mandatory. Once the inventory-diff source is
present, the server enforces the current mandatory-diff/supplemental-journal relationship;
known source kind, namespace, checkpoint, requirement, and catalog metadata remain
canonical. This is an additive `/api/v2` compatibility rule and requires no PostgreSQL
schema change.

Telemetry-coverage responses add liveness-monitor attempt/success freshness, active
outage count, per-agent 24-hour/seven-day history readiness, and retention-scheduler
configuration. Liveness freshness and `active_outage_count` describe the global server
monitor pass across all registered active agents even when an agent filter narrows the
coverage rows; use that agent's alert status to determine its own current outage state.
The in-process liveness monitor cannot report an API, database, process,
or host failure that prevents it from running; independent service monitoring remains
required.

Manual `POST /api/v2/storage/retention/run` defaults to `dry_run: true`. An executing request with `dry_run: false` must also send the exact additive field `confirm_impact: "CONFIRM RETENTION DELETE"`; the service records a bounded mutation-specific audit outcome. This confirmation does not expand the managed-table allowlist or bypass batch/capacity/advisory-lock limits.

Storage accounting includes `accounting_mode`. Direct storage-status review uses
`exact_live_rows`. Normal scheduled retention uses `catalog_estimate` for its bounded
before/after summaries so the scheduler does not scan every retained JSON row merely to
measure the pass; if estimated allocation reaches the managed-capacity boundary, the
server performs exact live-row accounting before entering emergency mode. Catalog row
counts are PostgreSQL estimates and allocated table bytes may include reusable space.
Within the unchanged per-run batch cap, scheduled passes reserve bounded primary shares
for optional history, optional events, and mandatory L1 journal events. An unused share
is reclaimed in the existing optional-before-mandatory fallback order, while a sustained
optional backlog cannot indefinitely pin the oldest mandatory event. A pass that reaches
its cap while expired telemetry remains reports `bounded_incomplete` rather than
`completed`.

The deployment profile targets 30 days under the existing 100 GiB ceiling. Its hourly
hosted scheduler is enabled only after an execution dry run shows no unexpected eligible
data; alert/evidence references remain protected.

The route prefix, contracts, and JSON Schemas are versioned together as v2. All endpoint, source, and event platform values are Linux-only. Validation errors use standard problem details and never echo raw telemetry or credentials.

Use [examples/agent-registration.json](../examples/agent-registration.json) and [examples/fake-event-batch.json](../examples/fake-event-batch.json) as synthetic shapes. Exact deterministic event IDs should be produced by the shared identity implementation.
