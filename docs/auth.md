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

- API clients use `Authorization: Bearer <review-token>` for review endpoints such as `GET /api/v1/events`, `/api/v1/source-health`, `/api/v1/inventory`, `/api/v1/alerts`, `/api/v1/detections/rules`, `POST /api/v1/soc-agent/ask`, and the additive `/api/v1/soc-agent/status` / session chat endpoints, including `DELETE /api/v1/soc-agent/sessions/{session_id}`.
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

The `soc-agent` chat UI never asks operators to enter ChatGPT/OpenAI passwords, browser cookies, API keys, or session tokens. External-provider modes use server-side credentials configured through ignored environment variables, ignored auth files, or a secret store. ChatGPT subscription OAuth is the primary external setup path and accepts `SocAgent__Provider=ChatGPT`, `SocAgent__AuthMode=SubscriptionOAuth`, and either Pi's existing `~/.pi/agent/auth.json` `openai-codex` entry after Pi `/login` or an explicit `SocAgent__SubscriptionAuthFilePath` plus optional `SocAgent__SubscriptionAuthFileProviderKey` / `SocAgent__SubscriptionRequiredScopes`. Pi `openai-codex` credentials call the ChatGPT Codex Responses backend for plan-allowed subscription models such as `gpt-5.5`; dedicated subscription bundles use the OpenAI API path and must carry the documented API audience/scope metadata. When `SocAgent__SubscriptionConnectEnabled=true`, the web page can start a server-mediated authorization-code/PKCE flow using official `SocAgent__SubscriptionAuthorizationUrl` and `SocAgent__SubscriptionTokenEndpoint` values plus server-side OAuth client settings; the callback stores credentials only in the configured server-side auth file. API-key mode remains an advanced alternative and accepts `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY`. Delegated API-bearer auth-file mode accepts `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and optional `SocAgent__AuthFileProviderKey`. Provider credentials are not rendered to browser clients, copied into prompts, logged, or stored in chat history.

When `SocAgent:Provider=ChatGPT` or `SocAgent:Provider=OpenAI`, `SocAgent:ExternalCallsEnabled=true`, and server-side credentials are present, the server may send bounded/redacted tool context to a configured provider endpoint. Pi `openai-codex` entries are read from server-side `auth.json`, reported as `pi_auth_json`, left for Pi to refresh/manage, and used with the allowlisted `https://chatgpt.com/backend-api/codex/responses` path. Dedicated subscription OAuth files must declare a supported credential type, bearer token type, explicit expiry, official OpenAI API audience, allowlisted issuer when present, and the configured model-invocation scope; near-expiry non-Pi subscription tokens are refreshed only through an allowlisted official token endpoint before using `https://api.openai.com/v1/chat/completions`. Interactive subscription OAuth uses a protected state/PKCE correlation cookie, requires an authenticated operator to start, and allows the callback to complete with that correlation cookie because the normal review-session cookie is SameSite strict and may not be sent on cross-site provider redirects. Delegated API-bearer auth files must use the documented minimal providers schema, a bearer token type, an explicit expiry, and an official OpenAI API audience. Files in the repository must live under `.local/` or use ignored names such as `auth.json`, `auth.*.json`, or `*.auth.json`; operator-managed paths outside the repository are also allowed. If external provider auth is required but unavailable, expired, scope-missing, plan-limited, unsupported, budget-exhausted, refresh-failed, or safely mapped as a provider error, `/soc-agent` shows setup/status guidance and falls back to the configured local provider only when explicitly enabled by `SocAgent:FallbackToLocalWhenUnavailable`.

If an official delegated OAuth/OIDC/PKCE connect flow is configured in the future, the UI may link only to an allowlisted official provider authorization URL or server-side auth-start endpoint with state/CSRF protections. Non-allowlisted provider URLs and unsupported auth-file exports fail closed.

## Transport security

Local development and the authorized lab can use HTTP loopback or the documented VM callback URL. Any non-local production deployment must use HTTPS for registration, ingest, heartbeat, web console, and review API traffic.

## Future improvements

- mTLS certificates for endpoints.
- Token rotation endpoint.
- Role-based operator accounts for review/search.
- Rate limiting per agent.
- Audit logging for all failed authentication attempts without logging secrets.
