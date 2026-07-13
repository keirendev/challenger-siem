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

2. Ensure `ConnectionStrings__SiemDatabase` and `Auth__EnrollmentToken` are set in the shell or sourced from `.local/dev.env`.
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

- Review API routes require `Authorization: Bearer <SIEM_OPERATOR_API_TOKEN>`.
- The web console login page uses an operator username/password and creates a revocable HTTP-only session cookie.
- If login loops back to `/login`, clear the local test cookie jar/browser context and confirm the operator is enabled, unlocked, and the schema is current.
- Do not put the operator API credential in URLs; use bearer headers for API calls and username/password fields for the browser.

## Web smoke test fails

Run:

```bash
./scripts/smoke-test-web.sh
```

Then inspect only the needed bounded files under `.local/`, such as the smoke API log or sanitized HTML snippets. Common causes:

- API did not become healthy.
- Development database schema is missing a newer table/index.
- Operator API credential or enrollment token is not set.
- A web route changed and the smoke script/docs need to be updated.

For browser behavior, run the Playwright release gate against the real app: `./scripts/release-gates.sh install-browsers` and `./scripts/release-gates.sh run`. Curl/HTML smoke checks do not validate redirects, cookies, form behavior, or user-visible navigation as fully as a browser.

## Release gates do not run

Checks:

1. Confirm ignored PostgreSQL admin configuration exists in `.local/release-gates.env` or environment variables: `SIEM_RELEASE_GATE_PGHOST`, `SIEM_RELEASE_GATE_PGADMINUSER`, and `SIEM_RELEASE_GATE_PGADMINPASSWORD`.
2. Confirm local tools are available: `dotnet`, `psql`, `curl`, `python3`, and `pwsh` for browser installation.
3. Install Chromium under the ignored cache: `./scripts/release-gates.sh install-browsers`.
4. If the runner stops after creating resources, use the printed state path with `./scripts/release-gates.sh cleanup --state .local/release-gates/<run-id>/state.env --confirm DELETE-RELEASE-GATE-RESOURCES`.
5. Inspect only bounded local logs under `.local/release-gates/<run-id>/`; do not paste generated credentials, cookies, connection strings, raw API responses, browser profiles, traces, or screenshots into issues or PRs.

A missing prerequisite is a release-gate failure in release mode, not a pass. Normal `dotnet test` keeps the Playwright project inert unless `SIEM_RELEASE_GATE_ENABLED=1` is set by the runner.

## Event times show UTC instead of host time

Host-local event, source-health, coverage, audit-policy, and alert-evidence timestamps require optional `host_timezone` metadata from a current agent. Older agents and older stored events continue to display safely as UTC with a `timezone unknown` label. Time range filters on `/events` are always interpreted as UTC.

## soc-agent external provider remains unavailable

If `/soc-agent` or `GET /api/v1/soc-agent/status` reports `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, `unsupported_subscription_oauth`, `scope_missing`, `plan_limited`, or `provider_error`:

- Confirm `SocAgent__Provider=ChatGPT` (subscription OAuth) or `SocAgent__Provider=OpenAI` (API-key/delegated bearer) and `SocAgent__ExternalCallsEnabled=true` are set only in ignored local/server configuration.
- For subscription OAuth mode, confirm `SocAgent__AuthMode=SubscriptionOAuth`. To reuse Pi login for the ChatGPT Codex Responses backend, point `SocAgent__SubscriptionAuthFilePath=~/.pi/agent/auth.json`, set `SocAgent__SubscriptionAuthFileProviderKey=openai-codex`, choose a plan-allowed model such as `SocAgent__Model=gpt-5.5`, and run Pi `/login` if the file is absent or expired. For dedicated subscription files, confirm `SocAgent__SubscriptionAuthFilePath` and `SocAgent__SubscriptionAuthFileProviderKey` point to a supported placeholder-schema file under `.local/`, an ignored auth-file name, or an operator-managed secret path outside the repository; the credential must declare the official OpenAI API audience, an allowlisted issuer when present, expiry, and the required model scope such as `model.request`. If web connect is enabled, also confirm `SocAgent__SubscriptionConnectEnabled=true`, an official `SocAgent__SubscriptionAuthorizationUrl`, an official `SocAgent__SubscriptionTokenEndpoint`, a server-side client ID, and a callback URI registered with the provider.
- For API-key mode, confirm an ignored server-side key source such as `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY` exists without printing it.
- For delegated auth-file mode, confirm `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and `SocAgent__AuthFileProviderKey` point to a supported placeholder-schema file under `.local/`, an ignored auth-file name, or an operator-managed secret path outside the repository.
- Reconnect/replace the file if status is `expired` or `refresh_failed`; dedicated subscription OAuth refresh is attempted only for near-expiry tokens with an allowlisted official token endpoint, Pi `pi_auth_json` credentials are refreshed by Pi, and delegated API-bearer tokens are not refreshed automatically.
- Treat `unsupported_delegated_auth`, `unsupported_subscription_oauth`, `scope_missing`, and `plan_limited` as fail-closed: do not use browser cookie exports, consumer website session files, passwords, ungranted scopes, plan-bypassing workarounds, or unreviewed endpoints.

Never paste raw auth files, tokens, account IDs, email addresses, provider error bodies, or full local paths into issues, logs, screenshots, or PRs.

## Dashboard or agent inventory shows unexpected stale agents

`stale` is computed for active registrations whose `last_seen` exceeds `Review:StaleAgentMinutes`. Retiring stale lab registrations through the web console sets registration status to `disabled` and preserves historical telemetry. Do not delete database rows to hide stale agents unless an operator explicitly approves a data cleanup path.

## Host coverage says sources are missing or stale

Coverage depends on heartbeat `source_health` reports plus the canonical expected-source matrix shown by agent-scoped review. If `/agents/detail` or `/api/v1/telemetry-coverage` shows many `missing` rows, check that the agent configuration includes the intended channels, that the Windows service account can read them, that heartbeat payloads include source-health entries, and that recent events exist inside the selected lookback. A missing/unknown detection prerequisite means telemetry is not validated, not that a detection definitely missed activity. See:

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

## Managed telemetry retention does not remove expected rows

Checks:

1. Confirm the API is pointed at the intended SIEM database and schema migration `007_managed_retention.sql` has been applied.
2. Call `/api/v1/storage/retention/status` with an admin operator API token. If `advisory_lock_available=false`, another cleanup pass is active; wait or inspect the owning process without forcing deletion.
3. Run `/api/v1/storage/retention/run` with `{"dry_run":true}` and review aggregate categories, counts, and intervals. Dry-run does not delete.
4. If execute returns `bounded_incomplete`, rerun execute; cleanup is intentionally bounded and idempotent.
5. Remember the managed retention allowlist: `events`, `agent_heartbeats`, `asset_inventory_snapshots`, and `ingestion_errors`. Operators, sessions, security audit, agents, source-health current state, alerts/evidence, graphs, detections, `soc-agent`, schemas, files, and arbitrary records are protected.
6. Alert evidence can remain after an event row is removed. Check `telemetry_retention_state`: `telemetry_removed_by_retention` is expected after policy cleanup, while `underlying_telemetry_missing` means the event was absent without a retention marker.

Do not manually delete rows from protected tables to make accounting look smaller. Use the documented runbook and keep raw responses/logs under ignored `.local/` paths.

## PostgreSQL contains old synthetic smoke data

Synthetic rows from smoke tests may remain in local development databases. Use unique agent IDs and filters for validation and screenshots. Choose the least destructive cleanup path:

1. Retire stale active registrations in `/agents` when you want to hide old lab agents but preserve historical telemetry.
2. Run `./scripts/cleanup-synthetic-data.sh` for allowlisted smoke/lab rows selected by exact agent IDs or tight synthetic prefixes.
3. Run `./scripts/reset-test-environment.sh` only for a full fresh start in an operator-owned disposable local test environment.

Both scripts are dry-run by default and print aggregate counts only. Full reset requires `--execute --confirm RESET-TEST-ENVIRONMENT --i-understand-this-deletes-test-data`, refuses production-like/non-local/unclassified databases, preserves secret-bearing local config by default, and should be followed by `./scripts/validate-schema.sh`, `./scripts/platform.sh restart`, `/health`, and smoke tests. Do not delete data as part of routine issue resolution unless the operator explicitly approves the cleanup; read [runbooks.md](runbooks.md) before using destructive modes.

## Screenshot contains sensitive data

Do not commit it. Delete the local capture, regenerate from synthetic data, and inspect the replacement before staging. Public screenshots must not show tokens, cookies, connection strings, browser chrome with private context, real hostnames/users, raw endpoint telemetry, customer data, or lab identifiers. Follow [web-console-demo.md](web-console-demo.md#regenerating-screenshots-safely).

## Which version am I running?

Run:

```bash
./scripts/current-version.sh
```

The same value is used for .NET assembly metadata and default agent version values in helper scripts. See [versioning.md](versioning.md).

## Linux installer preflight fails

Treat unsupported architecture/init, missing locked service identity, non-0600 input configuration, or absent executable payload as blocking. Correct the prerequisite and rerun read-only plan; the workflow performs these checks before creating installation paths. Never bypass the checks or place credentials in command arguments.

## Linux L2 sources show disabled, degraded, denied, or unsupported

- `disabled` on L2 rows is expected while `Agent:Journal:TargetCoverageLevel` is the default `L1`. Use `L2` only in an approved canary.
- `degraded` with `applicability=unknown` means an optional producer or host role has not been established; absence of an event is not proof of applicability. Declare only verified bounded roles.
- `permission_denied` means the fixed journal read failed. Do not retry as root, add groups/ACLs, or weaken service hardening merely to change status; access expansion is a separate security decision.
- `unsupported` on `linux-audit-framework` is intentional in this release. No audit collector or audit-policy enablement exists. The [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) keeps audit and eBPF deferred and does not enable file-integrity monitoring.
- `not_applicable` requires a declared platform/role reason. `excepted` comes only from an active server-side coverage exception.
- `stale` indicates age/discontinuity; inspect collected versus acknowledged cursors, gap state, queue pressure, and recent events by `source_id` without copying raw telemetry into a ticket.

If an expected family remains `not_observed`, verify that its producer already journals the event and that the bounded structured fields/message pattern are supported. For outage/recovery or queue pressure, compare `queue_metrics.pressure_state`, `send_state`, `backoff_seconds`, `last_failed_send_time`, `last_recovery_time`, source `transition_state`, and collected versus acknowledged checkpoints. Treat `null` CPU/RSS/rate values as unsupported or unknown rather than zero; an explicit `0` means the agent measured no queued items, drops, poison records, or event rate. Do not fabricate a test from live logs; use the hand-authored synthetic fixture suite. Keep private rollout diagnostics and soak data under ignored `.local/` or approved runtime storage.
