# Network geography UI

`/ui/traffic` is an optional local, read-only view of remote peers in retained Linux socket-snapshot and kernel-flow telemetry. It is disabled until the operator supplies an approximate origin, a public loopback URL, and a private SQLite cache path. It does not add accounts, cookies, browser sessions, or a second credential system.

## Evidence boundary

Snapshot rows can miss short-lived sockets and do not measure packets, bytes, or direction. Separately labeled `kernel_flow` rows contain aggregate cgroup SKB packet/length counters and direction, never payload; offload/segmentation mean those counters are not wire truth. A remote address may belong to a provider, CDN, VPN, proxy, or anycast deployment. Process ownership remains point-in-time, best-effort evidence and can be absent, racy, or partial. Use `GET /api/v2/network/activity` or `siem_search_network_activity` for cited per-event correlation.

Approximate geolocation is enrichment, not endpoint evidence. Only syntactically valid publicly routable destination IPs may be sent to the configured provider. Private, loopback, link-local, multicast, reserved, benchmark, and documentation ranges are rejected locally. Provider raw responses are never stored; the cache contains only normalized location/ASN fields, status, provider name, and timestamps.

## What the interface provides

- All-retained, 1-hour, 24-hour, 7-day, 30-day, and custom ranges. Presets and custom bounds are converted to UTC; filtering is against telemetry `event_time`, not ingestion time.
- Search across IP, city, region, country, ASN/organization, port, protocol, hostname, agent, and attributed process, plus exact advanced filters.
- Summary counts, retained-evidence range, observation timeline, map markers and origin arcs, sortable destination table, and a destination detail drawer.
- A bounded drill-down to the newest 25 matching `/api/v2/events` records for a selected destination.
- Explicit source-health, process-attribution, unresolved-geolocation, provider-quota, and result-truncation notices.

The map returns at most 2,000 destination aggregates and 200 timeline buckets. When a bound is reached, refine the time or metadata filters rather than treating the displayed rows as the complete result.

## Local configuration

Copy the non-secret shape from `examples/traffic-map.env.example` into an ignored `.local/traffic-map.env`, choose an approximate origin for this deployment, and restrict the file to the operator. Melbourne is not a tracked default; every deployment must choose its own origin.

Required values are:

```text
TrafficMap__Enabled=true
TrafficMap__ReadOnlyDatabase=false
TrafficMap__PublicBaseUrl=http://127.0.0.1:5081
TrafficMap__Origin__Label="<operator-selected label>"
TrafficMap__Origin__Latitude=<decimal latitude>
TrafficMap__Origin__Longitude=<decimal longitude>
TrafficMap__Geolocation__CachePath=.local/traffic-map/geolocation.sqlite3
```

Use an absolute cache path under ignored private storage for service-managed deployments. A relative path is resolved from the ASP.NET content root, which may differ between launch methods.

## Choose the hosting mode

| Mode | Configuration | Use |
| --- | --- | --- |
| Normal backend | `TrafficMap__ReadOnlyDatabase=false` | The regular ingesting service also serves the UI. Agent ingestion, service API auditing, liveness monitoring, managed retention, REST, and MCP keep their configured behavior. |
| Dedicated viewer | `TrafficMap__ReadOnlyDatabase=true` | A separate loopback-only UI process reads an existing compatible SIEM database. PostgreSQL sessions enforce read-only transactions, non-GET `/api/v2` requests are rejected, service API access/auth audit writes are suppressed, and liveness/retention workers do not run. |

A dedicated viewer is not a replacement ingest service. Do not point an agent at it: registration, heartbeat, inventory, and ingestion require the normal writable backend. Do not use the viewer process as the deployment's MCP endpoint; MCP tool audit writes remain part of the normal backend contract. Keep the normal backend running and point the viewer at the same PostgreSQL database only when a separate process is useful.

## Select the telemetry database

The value loaded as `ConnectionStrings__SiemDatabase` is the map's only telemetry source. The map does not read the endpoint agent's SQLite queue, query live sockets, or discover another running backend automatically. A filename such as `.local/dev.env` is only a local convention and does not prove that it contains the connection used by the active backend.

For a dedicated viewer, load the exact database connection used by the writable service that currently receives the agent's telemetry. Obtain it from that service's private configuration or secret manager without printing or copying it into tracked files. After startup, compare the UI's **Retained evidence** end time with the backend's recent event/source-health view. If it is unexpectedly old, stop the viewer and correct the private database configuration before drawing conclusions from the map.

The default provider endpoint is `https://ipwho.is/{ip}` with a 900-request UTC-day safety cap, five-second request timeout, 64 KiB response limit, progressive queue, bounded retry/backoff, and expiring positive/negative cache entries. A compatible HTTPS endpoint can be selected with `TrafficMap__Geolocation__EndpointTemplate`; an optional `TrafficMap__Geolocation__ApiKey` is sent in the `TrafficMap__Geolocation__ApiKeyHeader` header (default `X-Api-Key`) and must remain in private configuration. Disable all provider requests with `TrafficMap__Geolocation__Enabled=false`; destinations then remain searchable but report geolocation as disabled and are not mapped. Review the provider's current [API documentation](https://ipwhois.io/documentation) and [limits](https://ipwhois.io/pricing) before enabling it.

The service rejects symlinked cache directories/files and applies Linux mode 0700 to the cache directory and 0600 to the SQLite file. Keep the cache and its WAL/SHM companions under ignored private storage. It contains destination-network metadata and must not be published or committed.

For a standalone viewer attached to an existing compatible telemetry store, set `TrafficMap__ReadOnlyDatabase=true`. Geolocation enrichment can still update its separate private SQLite cache. Normal deployments using the full backend should leave this setting false so authenticated access remains audited and configured backend services retain their ordinary behavior.

## Build and run

Load the existing private database/authentication environment and the traffic-map environment without printing their values, then launch:

```bash
set -a
source .local/dev.env
source .local/traffic-map.env
set +a
./scripts/run-local-ui.sh
```

Open `http://127.0.0.1:5081/ui/traffic`. In normal mode the launcher validates the fresh Linux v2 schema. In read-only-database mode it instead verifies only the event/source-health fields required by the map, without modifying the retained store. It then performs a clean pinned frontend install/build, writes generated output to the ignored `server/Siem.Api/wwwroot/ui/` directory, and starts the service on loopback port 5081. It never attempts an implicit migration. Ordinary `dotnet build` remains frontend-independent. Use `./scripts/build-ui.sh` when only a production UI build is needed.

Unlock the page with the existing service bearer. The value is held in React memory only, sent only as a same-origin `Authorization` header, and discarded on reload or lock. Filter deep links contain only bounded timeframe/search metadata; never put a token or raw event content in a URL.

## Use the map

1. Start with **All retained** and confirm that the retained-evidence end time is current for the intended backend.
2. Select a time preset or custom range. Clicking a timeline bar changes the selection to that bucket's custom interval.
3. Use global search for any indexed destination metadata, or open **More filters** for exact host, agent, IP, port, protocol, process, country-code, or ASN constraints.
4. Sort destinations by observations, recency, or location. Select a marker or table row to open location, network, port, protocol, host, process, lifecycle, and newest-event detail.
5. Treat coverage and limitation notices as part of the result. An empty or unresolved map is not proof that no network activity occurred.

Credential-free query parameters preserve the selected filters. Custom date inputs are displayed in the browser's local time but encoded as UTC instants in the deep link and API request.

## Empty or stale results

- Start with **All retained** and clear metadata filters. The 1-hour/24-hour/7-day/30-day presets are relative to the browser's current time and match event time, so recently ingested records with older event timestamps do not enter those windows.
- Check the **Retained evidence** end time. If it is older than the expected agent activity, verify that the viewer uses the writable backend's exact database and that the normal agent/backend path has fresh heartbeat, queue delivery, source health, and qualifying `linux-network-socket-snapshot-diff` or `linux-network-flow-summary` events.
- Confirm passive socket telemetry is enabled and healthy for the intended agent. The map deliberately excludes other event sources and rows without a remote IP.
- A peer can remain in the table while unmapped when geolocation is disabled, pending, locally excluded, provider-failed, or quota-limited. Review the status notices before changing filters.
- A blank basemap with destination rows usually indicates tile reachability or CSP/configuration problems; it is distinct from missing telemetry.

## External requests and browser policy

- The browser requests only configured map tiles in the ordinary visible viewport. It performs no tile prefetching and sends no SIEM bearer or telemetry payload to the tile server. OpenStreetMap attribution remains visible when the default tile service is used; deployments using it must follow the [OpenStreetMap tile policy](https://operations.osmfoundation.org/policies/tiles/).
- The server sends validated public destination IPs, and no event records or credentials, to the configured geolocation provider. The free service has no uptime guarantee; pending, quota-limited, provider-error, and unresolved states are shown explicitly.
- Provider HTTP-client information logging is suppressed because request URLs contain destination IPs; failure logging remains bounded and must not include provider response bodies or credentials.
- UI JavaScript/CSS is self-hosted. UI responses use a restrictive content-security policy, deny framing and browser device permissions, and keep API responses uncached.

For a higher-volume provider, review its contract and privacy terms, use a compatible bounded HTTPS response, keep credentials private, and set an operator-approved daily cap. Do not use the free endpoint beyond its documented allowance.

## Validation

```bash
npm --prefix web/Siem.Ui test
npm --prefix web/Siem.Ui run build
dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj --no-restore
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

PostgreSQL-backed geography tests run only against the existing disposable integration database gate. Live telemetry, cache contents, browser screenshots, tokens, and API responses remain private evidence and must stay out of Git.
