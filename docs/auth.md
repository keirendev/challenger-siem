# Authentication

Three credential domains are intentionally separate:

1. `Auth__EnrollmentToken` authorizes initial Linux agent registration through `X-Enrollment-Token`.
2. Registration returns a per-agent bearer credential for heartbeat, inventory, and ingest routes.
3. `Auth__ServiceToken` is an externally supplied bearer for all review, administration, and MCP access.

The service token is never generated, stored, rotated, or returned by the application. Supply it through a secret manager or ignored environment file. Do not place credentials in tracked configuration, command history, URLs, logs, examples, or test fixtures.

Production requests require HTTPS. MCP and REST use `Authorization: Bearer <service-token>` and the normal backend audits access without storing the credential.

The optional `/ui/traffic` unlock form keeps the service bearer in React memory only and sends it as an `Authorization` header to same-origin `/api/v2` requests. Reloading or closing the page requires unlocking again. The UI does not put credentials in cookies, local storage, session storage, query parameters, history state, or static files. Credential-free filter parameters may be copied as deep links.

The dedicated `TrafficMap__ReadOnlyDatabase=true` viewer suppresses service API access/auth audit writes because its PostgreSQL sessions are forced read-only. It is a loopback visual-review compatibility mode, not the normal REST/MCP service: use the writable backend when durable API/MCP auditing is required.
