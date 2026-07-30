# Troubleshooting

## Startup fails

Confirm `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ServiceToken` are present without printing them. Confirm PostgreSQL is reachable and the database contains the Linux v2 schema marker.

## Schema apply refuses the database

Version 2 only supports a fresh empty database. Back up any existing data and provision another database; do not bypass the guard or drop data through the helper.

## REST or MCP returns unauthorized

Review routes and `/mcp` require the exact `Auth__ServiceToken` bearer. Agent credentials work only for agent routes. Enrollment uses `X-Enrollment-Token` only for registration.

## Linux agent is silent

Check endpoint network/TLS trust, ignored agent configuration permissions, queue/source health, journal visibility, checkpoint state, and server validation responses. Do not broaden host permissions or alter journal policy merely to make health appear green.

## Coverage is degraded

Inspect applicability, prerequisite evidence, observed time, continuity gaps, queue pressure, and recent events. `missing`, `stale`, `permission_denied`, `unsupported`, and `degraded` are visibility statements, not proof of safety.
