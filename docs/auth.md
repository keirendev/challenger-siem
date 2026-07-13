# Authentication and operator authorization

## Separate credential domains

Endpoint agents and human operators never share credentials or authentication code paths.

- `X-Enrollment-Token` is used only to register an endpoint.
- Per-agent bearer tokens are issued at registration, stored hashed by the server, and authorize only that agent's ingest, heartbeat, and inventory routes.
- Operators authenticate with a database identity and password for the browser, or a separately rotated operator API credential for review API automation. Operator credentials cannot call agent transport routes and agent credentials cannot call operator routes.

## Operator roles

Roles are exact, single-valued assignments:

| Capability | viewer | analyst | detection-engineer | admin |
| --- | ---: | ---: | ---: | ---: |
| Dashboard, inventory, alert and event metadata | yes | yes | yes | yes |
| Sensitive review (with server-side redaction) | no | yes | yes | yes |
| Alert triage, cases, `soc-agent`, and investigation mutations | no | yes | yes | yes |
| Detection engineering mutations | no | no | yes | yes |
| Agent retirement, operator management, storage accounting, full raw fields | no | no | no | yes |

Authorization is checked in endpoint/Razor handlers and mutation boundaries. Event repositories apply field policy before API or Razor serialization: non-admin responses omit raw payloads and redact event text, command lines, account names/identifiers, paths/registry data, and network addresses/ports. UI visibility is not an authorization control.

## Credential and session security

Passwords are salted PBKDF2-HMAC-SHA256 hashes with 210,000 iterations. Passwords must be 14-256 characters and include upper-case, lower-case, numeric, and symbol characters. Operator API credentials and session handles are random 256-bit values; only SHA-256 hashes are persisted.

Five failed password attempts lock an account for 15 minutes. Browser sessions have an absolute eight-hour expiry, are database-validated on each request, do not slide, and are revoked by logout, password change/recovery, or API-credential rotation. The protected cookie is `HttpOnly`, `SameSite=Strict`, and always `Secure` outside Development. Razor forms use ASP.NET Core antiforgery tokens. Unsafe `/api` calls reject cookie-only authentication and require the CSRF-safe operator bearer credential.

## Local bootstrap and recovery

Apply all migrations before account operations. Bootstrap is deliberately local and succeeds only while the operator table is empty. Supply the password through the process environment, never an argument or tracked file:

```bash
SIEM_OPERATOR_PASSWORD='<private-strong-password>' \
  ./scripts/operator-account.sh bootstrap --username local-admin --display-name 'Local administrator' --role admin
```

Create later identities through authenticated `POST /api/v1/operators` as an admin. The body accepts `username`, `display_name`, exact `role`, and `password`; do not retain request bodies or API responses in shell history/logs.

Change a known password or perform local recovery (which also clears lockout) using the same local database path. Both revoke every existing session:

```bash
SIEM_OPERATOR_PASSWORD='<private-new-password>' ./scripts/operator-account.sh change-password --username local-admin
SIEM_OPERATOR_PASSWORD='<private-new-password>' ./scripts/operator-account.sh recover --username local-admin
```

Rotate an API credential locally with `./scripts/operator-account.sh rotate-api-token --username local-admin`, or call `POST /api/v1/operators/me/api-token/rotate` while authenticated. The credential is shown once, all browser sessions are revoked, and it must be moved directly into an external secret store or ignored local environment. There is no review-token configuration, hidden fallback, default account, or production bootstrap endpoint.

## Immutable security audit

`security_audit_events` records successful and failed access attempts plus account/session/security mutations. A database trigger rejects update and delete. Entries contain actor/target identifiers, action/outcome, request ID, a one-way remote-address hash, and bounded non-secret metadata. Passwords, API/session credentials, cookies, authorization headers, raw telemetry, command lines, account data, paths, and network values are never audit details.

## Required server configuration

Startup requires only `ConnectionStrings:SiemDatabase` and `Auth:EnrollmentToken`. Operator identity state is PostgreSQL-backed. Keep both values and all operator credentials outside source control.

## Frontend auth and CSP boundary

The active web-console architecture remains server-rendered ASP.NET Core/Razor Pages as recorded in the [frontend architecture ADR](frontend-architecture-adr.md). Browser pages must not receive operator API credentials, enrollment tokens, per-agent tokens, provider credentials, raw auth files, connection strings, or cookie values in JavaScript-readable content. Protected review fields are filtered by server repositories before Razor rendering or API serialization; client-side hiding is not an authorization boundary.

Do not add a separate frontend origin, client router, API-cookie bridge, external CDN, analytics script, font service, or JavaScript package pipeline without a new security review. Future Content Security Policy hardening should prefer same-origin static assets and requires inventorying existing inline script surfaces before a strict policy is enabled.

## External `soc-agent` provider credentials

Provider credentials remain server-side and separate from operator and endpoint credentials. Supported provider files/environment variables, official endpoint allowlists, expiry/scope checks, and redaction behavior are documented in [soc-agent.md](soc-agent.md). Browser clients never receive provider tokens.

## Transport

All non-local deployment traffic must use HTTPS. Development may use the documented loopback or isolated lab HTTP exception.
