# Network geography UI

`/ui/traffic` is an optional local, read-only view of remote peers in retained Linux socket-snapshot telemetry. It is disabled until the operator supplies an approximate origin, a public loopback URL, and a private SQLite cache path. It does not add accounts, cookies, browser sessions, or a second credential system.

## Evidence boundary

The view shows socket observations, not packet captures or flow records. It does not measure packets or bytes, prove traffic direction, or guarantee that short-lived sockets were observed. A remote address may belong to a provider, CDN, VPN, proxy, or anycast deployment. Process ownership is best-effort and can be absent or partial.

Approximate geolocation is enrichment, not endpoint evidence. Only syntactically valid publicly routable destination IPs may be sent to the configured provider. Private, loopback, link-local, multicast, reserved, benchmark, and documentation ranges are rejected locally. Provider raw responses are never stored; the cache contains only normalized location/ASN fields, status, provider name, and timestamps.

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

The default provider endpoint is `https://ipwho.is/{ip}` with a 900-request UTC-day safety cap, five-second request timeout, 64 KiB response limit, progressive queue, bounded retry/backoff, and expiring positive/negative cache entries. A compatible HTTPS endpoint can be selected with `TrafficMap__Geolocation__EndpointTemplate`; an optional `TrafficMap__Geolocation__ApiKey` is sent in the `TrafficMap__Geolocation__ApiKeyHeader` header (default `X-Api-Key`) and must remain in private configuration. Disable all provider requests with `TrafficMap__Geolocation__Enabled=false`; destinations then remain searchable but report geolocation as disabled and are not mapped. Review the provider's current [API documentation](https://ipwhois.io/documentation) and [limits](https://ipwhois.io/pricing) before enabling it.

The service rejects symlinked cache directories/files and applies Linux mode 0700 to the cache directory and 0600 to the SQLite file. Keep the cache and its WAL/SHM companions under ignored private storage. It contains destination-network metadata and must not be published or committed.

For a standalone viewer attached to an existing compatible telemetry store, set `TrafficMap__ReadOnlyDatabase=true`. This forces every PostgreSQL session into `default_transaction_read_only`, blocks non-GET `/api/v2` requests, suppresses database-backed access-audit writes, and does not start the liveness or managed-retention background services. Geolocation enrichment can still update its separate private SQLite cache. Normal deployments using the full backend should leave this setting false so authenticated access remains audited and configured backend services retain their ordinary behavior.

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
