# Authentication design

## MVP mechanisms

### Enrollment token

Used only for initial agent registration.

- Client sends it in `X-Enrollment-Token` to `POST /api/v1/agents/register`.
- Server compares it to `Auth:EnrollmentToken` from configuration.
- It must be long, random, and managed outside source control.

### Per-agent API token

Issued by the server during registration.

- Client uses it as `Authorization: Bearer <token>` for ingest and heartbeat endpoints.
- Server stores only a SHA-256 hash of the token.
- Re-registering an existing `agent_id` rotates the stored token.

### Review token

Protects the initial search/review API and web review console.

- API clients use `Authorization: Bearer <review-token>` for `GET /api/v1/events`.
- Browser operators submit the token to `/login` for the web console.
- Server compares it to `Auth:ReviewToken` from configuration.
- A successful web login issues an HTTP-only same-origin cookie; the review token is not stored in browser local storage.
- Logout clears the operator session cookie.

## Future improvements

- mTLS certificates for endpoints.
- Token rotation endpoint.
- Role-based operator accounts for review/search.
- Rate limiting per agent.
- Audit logging for all failed authentication attempts without logging secrets.
