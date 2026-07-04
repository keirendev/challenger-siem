# Authentication design

## MVP mechanisms

### Enrollment token

Used only for initial agent registration.

- Client sends it in `X-Enrollment-Token` to `POST /api/v1/agents/register`.
- Server compares it to `Auth:EnrollmentToken` from configuration.
- It must be long, random, and managed outside source control.
- The Windows agent can use it for first-run enrollment and then clears the enrollment token from the persisted settings file after storing the returned per-agent token.

### Per-agent API token

Issued by the server during registration.

- Client uses it as `Authorization: Bearer <token>` for ingest and heartbeat endpoints.
- Server stores only a SHA-256 hash of the token.
- Re-registering an existing `agent_id` rotates the stored token and invalidates the previous token.

### Review token

Protects the initial search/review API and web review console.

- API clients use `Authorization: Bearer <review-token>` for `GET /api/v1/events`.
- Browser operators submit the token to `/login` for the web console.
- Server compares it to `Auth:ReviewToken` from configuration.
- A successful web login issues an HTTP-only same-origin cookie; the review token is not stored in browser local storage.
- Logout clears the operator session cookie.

## Required server configuration

The API fails startup with non-secret key names if any of these settings are missing or blank:

- `ConnectionStrings:SiemDatabase`
- `Auth:EnrollmentToken`
- `Auth:ReviewToken`

Do not put real values in committed `appsettings.json`; use environment variables, secret stores, or ignored `.local/dev.env` files.

## Transport security

Local development and the authorized lab can use HTTP loopback or the documented VM callback URL. Any non-local production deployment must use HTTPS for registration, ingest, heartbeat, web console, and review API traffic.

## Future improvements

- mTLS certificates for endpoints.
- Token rotation endpoint.
- Role-based operator accounts for review/search.
- Rate limiting per agent.
- Audit logging for all failed authentication attempts without logging secrets.
