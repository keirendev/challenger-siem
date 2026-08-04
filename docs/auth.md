# Authentication

Three credential domains are intentionally separate:

1. `Auth__EnrollmentToken` authorizes initial Linux agent registration through `X-Enrollment-Token`.
2. Registration returns a per-agent bearer credential for heartbeat, inventory, and ingest routes.
3. `Auth__ServiceToken` is an externally supplied bearer for review, administration, and MCP access, except the two narrowly scoped traffic-dashboard reads described below.

The service token is never generated, stored, rotated, or returned by the application. Supply it through a secret manager or ignored environment file. Do not place credentials in tracked configuration, command history, URLs, logs, examples, or test fixtures.

Production requests require HTTPS. MCP and ordinary REST use `Authorization: Bearer <service-token>` and the normal backend audits access without storing the credential.

The optional `/ui/traffic` dashboard does not request, receive, or store a service bearer. `GET`/`HEAD` requests to exactly `/api/v2/network/geography` and `/api/v2/network/geography/events` receive a local read-only principal only when the listening and client socket addresses are loopback, the `Host` is `localhost`, `127.0.0.0/8`, or `::1`, no forwarding/proxy headers are present, and the request contains no `Authorization` header. The static `/ui` path uses the same direct-loopback transport check. Host-header rebinding, forwarded requests, non-loopback clients, non-read methods, and invalid/present bearer credentials do not fall back to implied authentication. All other `/api/v2` routes and `/mcp` still require their documented credential. Do not publish or reverse proxy this dashboard; use a service-token client against the normal API for remote access.

The dashboard's implied identity can only read bounded aggregate geography and the newest 25 matching synthetic contract fields used by its detail drawer. The drill-down omits raw and normalized event payloads. Filter parameters may be copied as credential-free deep links.

The dedicated `TrafficMap__ReadOnlyDatabase=true` viewer suppresses service API access/auth audit writes because its PostgreSQL sessions are forced read-only. It is a loopback visual-review compatibility mode, not the normal REST/MCP service: use the writable backend when durable API/MCP auditing is required.
