# Authentication

Three credential domains are intentionally separate:

1. `Auth__EnrollmentToken` authorizes initial Linux agent registration through `X-Enrollment-Token`.
2. Registration returns a per-agent bearer credential for heartbeat, inventory, and ingest routes.
3. `Auth__ServiceToken` is an externally supplied bearer for all review, administration, and MCP access.

The service token is never generated, stored, rotated, or returned by the application. Supply it through a secret manager or ignored environment file. Do not place credentials in tracked configuration, command history, URLs, logs, examples, or test fixtures.

Production requests require HTTPS. MCP and REST use `Authorization: Bearer <service-token>` and are audited without storing the credential.
