# Troubleshooting and FAQ

Use this page for common local and lab issues. Keep raw responses, logs, cookies, generated configs, and endpoint telemetry under ignored `.local/` paths.

## API does not start

**Symptoms**: `dotnet run` exits during startup or `/health` never returns `ok`.

Checks:

1. Confirm required private configuration is present:

   ```bash
   test -f .local/dev.env && echo "local env present"
   ./scripts/current-version.sh
   ```

2. Ensure `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ReviewToken` are set in the shell or sourced from `.local/dev.env`.
3. Verify PostgreSQL is reachable and the schema has been applied:

   ```bash
   ./scripts/apply-schema.sh
   ./scripts/validate-schema.sh
   ```

4. Check the bounded local API log path used by the smoke script, such as `.local/smoke-api.log`, without copying secrets into issues or PRs.

## Schema validation fails

Run `./scripts/apply-schema.sh` again against the intended development database, then `./scripts/validate-schema.sh`. If a migration or schema file changed, compare [schema.md](schema.md) with `server/Siem.Api/Database/001_initial.sql` and update both in the same change set.

## Registration returns unauthorized

- `POST /api/v1/agents/register` requires `X-Enrollment-Token` equal to `Auth__EnrollmentToken`.
- The enrollment token is only for registration. Event ingest and heartbeat calls use the per-agent API token returned by registration.
- Do not paste tokens into logs, screenshots, docs, or GitHub comments.

## Event ingest returns unauthorized or rejected

- `POST /api/v1/ingest/events` requires `Authorization: Bearer <per-agent-api-token>`.
- The token must belong to the same active agent ID used in the batch.
- Validate the payload against [contracts/v1/ingest-batch.schema.json](../contracts/v1/ingest-batch.schema.json) and [api.md](api.md#ingest-event-batch).
- Check for duplicate `(agent_id, event_id)` behavior before assuming an ingest failed; duplicates are acknowledged separately.

## Review API or web console returns unauthorized

- Review API routes require `Authorization: Bearer <Auth__ReviewToken>`.
- The web console login page uses the same review token but then stores an HTTP-only session cookie.
- If login loops back to `/login`, clear the local test cookie jar/browser context and confirm the API process has the expected `Auth__ReviewToken`.
- Do not put the review token in URLs; use headers for API calls and the login form for the browser.

## Web smoke test fails

Run:

```bash
./scripts/smoke-test-web.sh
```

Then inspect only the needed bounded files under `.local/`, such as the smoke API log or sanitized HTML snippets. Common causes:

- API did not become healthy.
- Development database schema is missing a newer table/index.
- Review token or enrollment token is not set.
- A web route changed and the smoke script/docs need to be updated.

For browser behavior, run a Playwright harness against the real app. Curl/HTML smoke checks do not validate redirects, cookies, form behavior, or user-visible navigation as fully as a browser.

## soc-agent external provider remains unavailable

If `/soc-agent` or `GET /api/v1/soc-agent/status` reports `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, or `provider_error`:

- Confirm `SocAgent__Provider=OpenAI` and `SocAgent__ExternalCallsEnabled=true` are set only in ignored local/server configuration.
- For API-key mode, confirm an ignored server-side key source such as `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY` exists without printing it.
- For delegated auth-file mode, confirm `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and `SocAgent__AuthFileProviderKey` point to a supported placeholder-schema file under `.local/`, an ignored auth-file name, or an operator-managed secret path outside the repository.
- Reconnect/replace the file if status is `expired` or `refresh_failed`; this build does not refresh delegated tokens automatically.
- Treat `unsupported_delegated_auth` as fail-closed: do not use browser cookie exports, consumer website session files, passwords, or unofficial endpoints.

Never paste raw auth files, tokens, account IDs, email addresses, provider error bodies, or full local paths into issues, logs, screenshots, or PRs.

## Dashboard or agent inventory shows unexpected stale agents

`stale` is computed for active registrations whose `last_seen` exceeds `Review:StaleAgentMinutes`. Retiring stale lab registrations through the web console sets registration status to `disabled` and preserves historical telemetry. Do not delete database rows to hide stale agents unless an operator explicitly approves a data cleanup path.

## Host coverage says sources are missing or stale

Coverage depends on heartbeat `source_health` reports. Check that the agent configuration includes the intended channels, that the Windows service account can read them, and that heartbeat payloads include source-health entries. See:

- [agent-config.md](agent-config.md)
- [windows-l2-validation-runbook.md](windows-l2-validation-runbook.md)
- [sysmon-l3-validation-runbook.md](sysmon-l3-validation-runbook.md)

## Windows agent does not send events

Checks that do not require destructive host actions:

1. Confirm `agentsettings.json` sits next to `WindowsAgent.exe` or in the documented protected config path.
2. Confirm `ServerBaseUrl` is reachable from the Windows host. For the authorized lab VM, use `http://192.168.122.1:4444`, not `127.0.0.1`.
3. Confirm the per-agent API token was generated by registration and has not been disabled by stale-agent retirement.
4. Confirm queue and state paths are writable by the process/service account.
5. Run bounded interactive validation before installing as a service when possible.

## WinRM lab validation cannot reach the API

- Start the API on this host with `./scripts/run-server-4444.sh`; it listens on `http://0.0.0.0:4444` by default.
- Health from the host: `curl http://127.0.0.1:4444/health`.
- Health from the VM should target `http://192.168.122.1:4444/health`.
- Do not change firewall/auth settings, reboot, clear event logs, uninstall services, or delete data without explicit operator approval.

## PostgreSQL contains old synthetic smoke data

Synthetic rows from smoke tests may remain in local development databases. Use unique agent IDs and filters for validation and screenshots. Do not delete data as part of routine issue resolution unless the operator explicitly approves the cleanup. The cleanup script is guarded and dry-run by default; read [runbooks.md](runbooks.md) before using it.

## Screenshot contains sensitive data

Do not commit it. Delete the local capture, regenerate from synthetic data, and inspect the replacement before staging. Public screenshots must not show tokens, cookies, connection strings, browser chrome with private context, real hostnames/users, raw endpoint telemetry, customer data, or lab identifiers. Follow [web-console-demo.md](web-console-demo.md#regenerating-screenshots-safely).

## Which version am I running?

Run:

```bash
./scripts/current-version.sh
```

The same value is used for .NET assembly metadata and default agent version values in helper scripts. See [versioning.md](versioning.md).
