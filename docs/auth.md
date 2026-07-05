# Authentication design

## MVP mechanisms

### Enrollment token

Used only for initial agent registration.

- Client sends it in `X-Enrollment-Token` to `POST /api/v1/agents/register`.
- Server compares it to `Auth:EnrollmentToken` from configuration.
- It must be long, random, and managed outside source control.
- The Windows agent can use it for first-run enrollment and then clears the enrollment token from the persisted settings file after storing the returned per-agent token as `ProtectedApiToken` with Windows DPAPI machine protection.

### Per-agent API token

Issued by the server during registration.

- Client uses it as `Authorization: Bearer <token>` for ingest and heartbeat endpoints.
- Server stores only a SHA-256 hash of the token.
- Windows agents should prefer DPAPI-protected local `ProtectedApiToken` persistence after enrollment; plaintext `ApiToken` remains supported for ignored local lab settings.
- Re-registering an existing `agent_id` rotates the stored token and invalidates the previous token.

### Review token

Protects the initial search/review API and web review console.

- API clients use `Authorization: Bearer <review-token>` for review endpoints such as `GET /api/v1/events`, `/api/v1/source-health`, `/api/v1/inventory`, `/api/v1/alerts`, `/api/v1/detections/rules`, `POST /api/v1/soc-agent/ask`, and the additive `/api/v1/soc-agent/status` / session chat endpoints.
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

## External `soc-agent` provider auth

The `soc-agent` chat UI never asks operators to enter ChatGPT/OpenAI passwords, browser cookies, API keys, or unofficial session tokens. The supported external-provider MVP uses server-side OpenAI API-compatible credentials configured through ignored environment variables or a secret store, such as `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY`. Provider credentials are not rendered to browser clients, copied into prompts, logged, or stored in chat history.

When `SocAgent:Provider=OpenAI`, `SocAgent:ExternalCallsEnabled=true`, and server-side credentials are present, the server may send bounded/redacted tool context to the official `https://api.openai.com/v1/chat/completions` endpoint. If external provider auth is required but unavailable, the configured budget is exhausted, or a provider error is mapped safely, `/soc-agent` shows setup/status guidance and falls back to the configured local provider only when explicitly enabled by `SocAgent:FallbackToLocalWhenUnavailable`.

If an official delegated OAuth/OIDC/PKCE flow is configured in the future, the UI may link only to an allowlisted official provider authorization URL or server-side auth-start endpoint with state/CSRF protections. Non-allowlisted provider URLs fail closed.

## Transport security

Local development and the authorized lab can use HTTP loopback or the documented VM callback URL. Any non-local production deployment must use HTTPS for registration, ingest, heartbeat, web console, and review API traffic.

## Future improvements

- mTLS certificates for endpoints.
- Token rotation endpoint.
- Role-based operator accounts for review/search.
- Rate limiting per agent.
- Audit logging for all failed authentication attempts without logging secrets.
