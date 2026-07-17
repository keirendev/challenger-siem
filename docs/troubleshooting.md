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

## MCP client cannot connect or discover capabilities

- Use the exact Streamable HTTP path `/mcp`; the legacy HTTP+SSE transport is not enabled.
- Send `Authorization: Bearer <operator-api-credential>`. Browser cookies, viewer credentials, enrollment tokens, and per-agent tokens are rejected.
- Use an analyst, detection-engineer, or admin operator. Endpoint inventory item reads additionally require admin.
- Confirm the client supports current MCP Streamable HTTP tool, resource, and prompt discovery.
- Treat empty or truncated results as a reason to narrow filters and inspect source health/coverage, not as proof that no activity exists.
- Keep client configuration, protocol responses, and captures under ignored `.local/` paths. See [MCP server and SIEM-agent integration](mcp.md) for exact setup and validation.

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
- For subscription OAuth mode, confirm `SocAgent__AuthMode=SubscriptionOAuth` and that `SocAgent__SubscriptionAuthFilePath` plus its provider key point to a supported placeholder-schema file under `.local/`, an ignored auth-file name, or an operator-managed secret path outside the repository. The credential must declare the approved API audience, an allowlisted issuer when present, expiry, and the required model scope such as `model.request`. If web connect is enabled, also confirm `SocAgent__SubscriptionConnectEnabled=true`, official authorization/token endpoints, a server-side client ID, and a callback URI registered with the provider.
- For API-key mode, confirm an ignored server-side key source such as `SocAgent__OpenAiApiKey`, `OpenAI__ApiKey`, or `OPENAI_API_KEY` exists without printing it.
- For delegated auth-file mode, confirm `SocAgent__AuthMode=DelegatedFile`, `SocAgent__AuthFilePath`, and `SocAgent__AuthFileProviderKey` point to a supported placeholder-schema file under `.local/`, an ignored auth-file name, or an operator-managed secret path outside the repository.
- Reconnect or replace the file if status is `expired` or `refresh_failed`; subscription OAuth refresh is attempted only for near-expiry tokens with an allowlisted official token endpoint, and delegated API-bearer tokens are not refreshed automatically.
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
2. Confirm `ServerBaseUrl` is reachable from the Windows host. A remote endpoint must use the operator-approved server address, not its own `127.0.0.1`.
3. Confirm the per-agent API token was generated by registration and has not been disabled by stale-agent retirement.
4. Confirm queue and state paths are writable by the process/service account.
5. Run bounded interactive validation before installing as a service when possible.

## WinRM lab validation cannot reach the API

- Start the API on this host with `./scripts/run-server-4444.sh`; it listens on `http://0.0.0.0:4444` by default.
- Health from the host: `curl http://127.0.0.1:4444/health`.
- Health from the endpoint should target the configured agent-reachable server URL.
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

Treat unsupported architecture/init, missing target-side Python 3 for lifecycle planning, missing `getent`/identity data, absent `runuser` for root-triggered L4 preflight, non-0600 input configuration, absent/oversized/linked payload or configuration, a missing/linked adjacent unit, or a symlink/unexpected product target as blocking. The service identity must be non-root (UID not 0) and have the exact `challenger-siem` passwd entry and primary group, `/usr/sbin/nologin`, `/sbin/nologin`, or `/bin/false` shell, and a shadow password beginning `!` or `*`; real-host install verifies the locked password as root before creating paths. Rebuild the portable bundle with `./scripts/publish-linux-agent.sh linux-x64 <private-bundle-dir>` or `linux-arm64`, copy it through a private approved channel, and create a separate private mode-0600 real configuration. The bundled `agentsettings.synthetic.example.json` is a placeholder-only reference, not deployable credentials. On a fresh VM, provision tools/identity and review journal visibility only through their own approved prerequisites; the installer will not install tools, create/correct the identity, join a group, or change an ACL. Correct the prerequisite and rerun `./linux-agent.sh plan --payload . --config <private-config>` before install; the workflow performs lifecycle checks before creating installation paths. L4 posture preflight requires an approved disabled install, the private state directory, and the steady-state identity because a pre-install payload cannot complete the fixed `/opt`/`/etc` integrity boundary; rerun `./linux-agent.sh plan --config /etc/challenger-siem-agent/agentsettings.json` afterwards. That preflight may populate only the private `.dotnet-bundle` runtime cache and changes no policy, L4 state, queue, configuration, or telemetry. Never bypass the checks or place credentials in command arguments.

## Linux L2 sources show disabled, degraded, denied, or unsupported

- `disabled` on L2 rows is expected while `Agent:Journal:TargetCoverageLevel` is the default `L1`. Use `L2` only in an approved canary.
- `degraded` with `applicability=unknown` means an optional producer or host role has not been established; absence of an event is not proof of applicability. Declare only verified bounded roles.
- `permission_denied` means the fixed journal read failed. Do not retry as root, add groups/ACLs, or weaken service hardening merely to change status; access expansion is a separate security decision.
- Check `configured_journal_scope`, `system_journal_visibility`, and `scope_transition`. `system_only` is the default. `all_accessible_local` means only journals already readable by the service identity, and a successful broad read still fails closed when the independent system-journal check is denied, missing, or errors.
- `unsupported` on `linux-audit-framework` is intentional in this release. No audit collector or audit-policy enablement exists. The [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) keeps audit and eBPF deferred and does not enable file-integrity monitoring.
- `not_applicable` requires a declared platform/role reason. `excepted` comes only from an active server-side coverage exception.
- `stale` indicates age/discontinuity; inspect collected versus acknowledged cursors, gap state, queue pressure, and recent events by `source_id` without copying raw telemetry into a ticket.

If an expected family remains `not_observed`, verify that its producer already journals the event in the selected scope and that the bounded structured fields/message pattern are supported. Enabling broader scope does not backfill entries older than the existing cursor and cannot itself prove package, sudo, or other activity; wait for genuine matching producer activity when live injection is not approved. An invalid cursor during a scope transition must appear as an explicit persisted gap/reset followed by bounded recovery. For outage/recovery or queue pressure, compare `queue_metrics.pressure_state`, `send_state`, `backoff_seconds`, `last_failed_send_time`, `last_recovery_time`, source `transition_state`, and collected versus acknowledged checkpoints. Treat `null` CPU/RSS/rate values as unsupported or unknown rather than zero; an explicit `0` means the agent measured no queued items, drops, poison records, or event rate. Do not fabricate a test from live logs; use the hand-authored synthetic fixture suite for parser testing. Keep private rollout diagnostics and soak data under ignored `.local/` or approved runtime storage.

## Linux remains below L4

Requesting `target_level=L4` does not enable endpoint collection. Check these in order:

1. Passive L3 must be enabled with valid bounds and its exact separate approval before `activation_ready` can pass, and all mandatory/applicable L1-L3 sources must be current and exactly `healthy`; a server exception caps strict coverage below L4.
2. `Journal.DeclaredRoles` must contain only supported roles. Empty/unknown roles block resolution. All six L4 role rows must be present as `applicable` or `not_applicable`; every applicable row must be enabled, fresh, and healthy.
3. `L4Telemetry.Enabled` requires both exact approvals. Generate the candidate baseline first, set `ApprovedBaselineHash`, then regenerate and set the resulting `ApprovedPlanHash`. A changed role, baseline, bound setting, collector version, or queue relationship invalidates the plan.
4. `linux-policy-posture-drift` must have a complete approved five-snapshot observation with no active drift/gap. Never alter firewall, SSH, MAC, Secure Boot, or agent posture just to clear the UI.
5. `linux-agent-performance-slo` stays degraded during rolling-window warm-up, unavailable/reset counters, pressure, or a threshold breach. It becomes stale after its short source-specific freshness window; a service restart starts a new current window.

Policy and role observations use a two-hour freshness boundary; the rolling SLO row uses five minutes. Observations more than five minutes in the future degrade rather than satisfying coverage. A quiet declared role can remain healthy after a successful shared-journal read while its event-family state remains `not_observed`; do not generate production activity merely to change that metadata. See [Linux L4 full-target coverage](linux-l4-coverage.md).

On the final disabled-state pass, check `activation_ready` and `activation_blockers` before staging enablement. The preflight distinguishes target/journal/role, freshness-budget, candidate-baseline, hash-format, and hash-mismatch blockers; follow the exact code table in [Linux L4 full-target coverage](linux-l4-coverage.md#preflight-readiness-fields-and-blocker-codes). Do not suppress or reinterpret a blocker.

On minimal images, inspect the private preflight for denied/missing firewall visibility and absent or malformed SSH, `mokutil`, or MAC-provider observations. Only an explicit `not_applicable` returned by the collector can be reviewed as part of a complete fingerprint. `general_server` and `workstation` resolve specialized role rows but do not waive these fixed posture inputs. Do not install packages, enable services, widen permissions, or relabel evidence solely to reach L4.

## Linux local-host validation is blocked

If a Linux rollout issue asks for L1-L4 soak evidence but no operator-authorized systemd target, time window, and exact allowed operations are documented, do not use SSH/WinRM, do not mutate a host, and do not invent evidence. L4 additionally requires a private reviewed plan/baseline and supported role set. Complete repository documentation/template work and publish the sanitized blocker described under [Linux live validation reporting](linux-local-host-validation.md#live-validation-reporting).

If a target is authorized later, keep raw plan output, generated configuration, source-health responses, event samples, logs, screenshots, resource measurements, and recovery drill notes under ignored private evidence. Public status should use only the aggregate template and should mark outage/restart/database/journal/permission/pressure drills as `blocked` when the corresponding operation was not explicitly approved.
