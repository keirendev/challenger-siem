# Operator runbooks

These runbooks reproduce the MVP without Docker and without committing secrets or telemetry.

## 1. Configure PostgreSQL and schema

1. Create a PostgreSQL database and user with local admin tools.
2. Put the connection string and API tokens in an ignored `.local/dev.env`:

   ```bash
   mkdir -p .local
   cat > .local/dev.env <<'EOF'
   ConnectionStrings__SiemDatabase='Host=localhost;Port=5432;Database=challenger_siem;Username=siem;Password=<password>'
   Auth__EnrollmentToken='<long-random-enrollment-token>'
   EOF
   ```

3. Apply and validate the schema:

   ```bash
   ./scripts/apply-schema.sh
   ./scripts/validate-schema.sh
   ```

## 2. Run build and tests

```bash
dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln
```

Optional PostgreSQL tests run when `CHALLENGER_SIEM_TEST_DATABASE` or `ConnectionStrings__SiemTestDatabase` points at an operator-owned test database.

## 3. Run API and web console

For the default local background lifecycle:

```bash
./scripts/platform.sh start
./scripts/platform.sh status
```

Use `./scripts/platform.sh restart` after local configuration changes and `./scripts/platform.sh stop` when finished. For the Windows lab callback binding, run the foreground helper instead:

```bash
./scripts/run-server-4444.sh
```

Open the API base URL in a browser, log in with a synthetic operator username/password, and use:

- `/` for dashboard metrics.
- `/agents` for inventory and queue depth.
- `/events` for event search.
- `/events/detail?agent_id=<id>&event_id=<uuid>` for raw JSON and normalized fields.
- `/about` for version/environment/database status.
- `/api/v1/storage/accounting` with an admin operator API token for managed telemetry bytes, 100 GiB default capacity, 70/85/95/100% warning state, and retention-lag status without connection details.
- `/api/v1/storage/retention/status` and `/api/v1/storage/retention/run` for dry-run-first managed telemetry retention. Execute mode is bounded, advisory-locked, resumable, and scoped only to allowlisted managed telemetry rows.
- `/graphs` for saved investigation graphs with bounded nodes/edges and approval-gated `soc-agent` proposals.
- `/soc-agent` for bounded chat-based SIEM investigation with provider status, graph context, and citations.

## 4. Fake ingest/search smoke test

```bash
./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

The scripts write temporary logs and responses under `.local/` only.

To remove only allowlisted synthetic smoke data after validation, first run the dry-run cleanup and review aggregate counts:

```bash
./scripts/cleanup-synthetic-data.sh
```

Execute deletion only when the selectors are correct and the target database is disposable/local:

```bash
./scripts/cleanup-synthetic-data.sh --execute --confirm DELETE-SYNTHETIC-DATA
```

For a one-off manual run, prefer exact IDs:

```bash
./scripts/cleanup-synthetic-data.sh --no-defaults --agent-id web-smoke-12345 --execute --confirm DELETE-SYNTHETIC-DATA
```

Cleanup is scoped through allowlisted selectors and includes removable dependent rows for targeted agents: events, heartbeats, source health, inventory snapshots, coverage exceptions, ingestion errors, agent-linked investigation graphs/proposals/audit, `soc_agent_turns`, and `soc_agent_sessions`/`soc_agent_messages`. Append-only alert evidence and its alert are never deleted; when either exists, the referenced agent registration is retained in disabled state so immutable investigation history remains attributable. The dry-run reports these protected counts explicitly. For older synthetic `soc-agent` chats without an agent context, use explicit session IDs or a narrow synthetic title prefix:

```bash
./scripts/cleanup-synthetic-data.sh --no-defaults --soc-agent-session-id <synthetic-session-uuid>
./scripts/cleanup-synthetic-data.sh --no-defaults --soc-agent-title-prefix 'Synthetic web smoke '
```

Synthetic investigation graphs can also be selected explicitly when they are not linked to a target agent:

```bash
./scripts/cleanup-synthetic-data.sh --no-defaults --graph-id <synthetic-graph-uuid>
./scripts/cleanup-synthetic-data.sh --no-defaults --graph-title-prefix 'Synthetic cleanup '
```

The smoke scripts also support opt-in cleanup after a successful run with `SIEM_SMOKE_CLEANUP=1` or `SIEM_WEB_SMOKE_CLEANUP=1`. Web smoke creates a synthetic `soc-agent` chat tied to its per-run agent ID, so opt-in cleanup removes that chat history too. Cleanup output remains aggregate-only under `.local/`.

## 5. Release-gate browser/accessibility/security/performance validation

Use the release gate for release candidates and web/auth/security/performance-sensitive changes. It creates a uniquely named disposable PostgreSQL database and role, seeds synthetic operators/data, runs the real app, executes Playwright browser/API gates, and stores all output under ignored `.local/release-gates/`.

```bash
./scripts/release-gates.sh install-browsers
./scripts/release-gates.sh run
```

Required PostgreSQL admin values belong in ignored `.local/release-gates.env`; see [release-gates.md](release-gates.md). Cleanup is destructive and confirmation-gated:

```bash
./scripts/release-gates.sh cleanup \
  --state .local/release-gates/<run-id>/state.env \
  --confirm DELETE-RELEASE-GATE-RESOURCES
```

The cleanup command refuses non-release-gate database/role names and deletes only the owned `.local/release-gates/<run-id>/` artifacts. Do not use it for development databases, shared databases, client data, endpoint queues, Windows Event Logs, or host policy cleanup.

## 6. Managed telemetry retention

Use managed retention for day-two SIEM telemetry lifecycle, not for ad-hoc cleanup of operators, configuration, cases, or arbitrary data. Defaults are a 30-day target retention and a 100 GiB managed telemetry capacity ceiling.

Check accounting and status with an admin operator API token:

```bash
curl --silent --fail \
  -H "Authorization: Bearer $SIEM_OPERATOR_API_TOKEN" \
  http://127.0.0.1:5081/api/v1/storage/accounting

curl --silent --fail \
  -H "Authorization: Bearer $SIEM_OPERATOR_API_TOKEN" \
  http://127.0.0.1:5081/api/v1/storage/retention/status
```

Preview cleanup first. Dry-run reports eligible managed tables, categories, estimated bytes, and oldest/newest intervals without deleting:

```bash
curl --silent --fail \
  -H "Authorization: Bearer $SIEM_OPERATOR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"dry_run":true}' \
  http://127.0.0.1:5081/api/v1/storage/retention/run
```

Execute only after confirming the target database and output. Runs acquire a PostgreSQL advisory lock and delete in small bounded transactions. If a run reports `bounded_incomplete` or is interrupted, rerun the same command; remaining eligible rows resume idempotently.

```bash
curl --silent --fail \
  -H "Authorization: Bearer $SIEM_OPERATOR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"dry_run":false}' \
  http://127.0.0.1:5081/api/v1/storage/retention/run
```

When accounting reaches the configured ceiling, emergency cleanup is deterministic: optional ingestion/heartbeat/inventory history and optional extended events are removed before mandatory event telemetry, oldest first, with exact removed categories and intervals in the response. Alert and evidence rows are not deleted; evidence responses expose whether underlying event telemetry is retained, removed by retention, or missing for another reason.

Do not point retention at non-disposable test databases during validation unless that database is the intended SIEM target. Retention never deletes files, schemas, operators, sessions, security audit, agents, source-health current state, detections, alerts/evidence, graphs, `soc-agent` history, or arbitrary records.

## 7. Fresh-start reset for a disposable local test environment

Use the full reset workflow only when you want a clean, empty Challenger SIEM test environment. Choose the least destructive path:

1. Use the Assets status and freshness filters to review stale or retired registrations without changing them.
2. Use `./scripts/cleanup-synthetic-data.sh` for allowlisted smoke/lab records.
3. Use `./scripts/reset-test-environment.sh` only for an operator-owned disposable local database and ignored local artifacts.

Preview the reset first. Output is aggregate-only and should show table/category counts, not connection strings, tokens, cookies, chat transcripts, raw telemetry, or generated settings:

```bash
./scripts/reset-test-environment.sh
```

Execute database reset only with the exact confirmation phrase and test-data assertion. The script refuses non-local, production-like, shared/client, missing, or unclassified targets and validates that the schema still exists afterward:

```bash
./scripts/reset-test-environment.sh \
  --execute \
  --confirm RESET-TEST-ENVIRONMENT \
  --i-understand-this-deletes-test-data
```

Local generated artifacts are separate and opt-in. By default the script preserves `.local/dev.env`, `.local/winrm.env`, provider auth files, SSH/WinRM credentials, platform logs, and generated agent-copy packages. Stop the local platform before artifact cleanup:

```bash
./scripts/platform.sh stop
./scripts/reset-test-environment.sh --local-artifacts-only
./scripts/reset-test-environment.sh \
  --local-artifacts-only \
  --include-local-artifacts \
  --execute \
  --confirm RESET-TEST-ENVIRONMENT \
  --i-understand-this-deletes-test-data
```

Use `--include-platform-logs` only when local logs are no longer needed, and `--include-generated-agent-files` only when generated `dist/` packages/settings are disposable. After reset, run:

```bash
./scripts/validate-schema.sh
./scripts/platform.sh start
curl --silent --fail http://127.0.0.1:5081/health
./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

Do not use this runbook for endpoint-side cleanup. Windows lab queue/state/config removal, service uninstall, event-log clearing, host reboot, firewall/auth changes, or remote deletion require separate explicit operator approval and a scoped runbook.

## 8. Use investigation graphs and soc-agent chat safely

1. Start the API and sign in to the review console.
2. Open `/graphs`, create a graph with synthetic or bounded operator-authored context, and add nodes/edges that reference SIEM pages instead of copying raw telemetry.
3. On a graph detail page, use the `soc-agent` proposal form only for bounded suggested updates. Review the diff and check the approval box before applying; no graph mutation occurs from a proposal alone.
4. Archive graphs when they should leave the active investigation list.

## 9. Use soc-agent chat safely

1. Start the API and sign in to the review console.
2. Open `/soc-agent` and confirm the provider status pill or any inline provider notice.
3. For the default `Local` provider, ask a bounded investigation question and follow citations back to review pages.
4. If an external ChatGPT/OpenAI provider is selected, confirm `ExternalCallsEnabled` and server-side credentials were configured outside source control before sending sensitive prompts. The primary setup path is subscription OAuth (`SocAgent__AuthMode=SubscriptionOAuth`) with an explicit ignored `SocAgent__SubscriptionAuthFilePath` or the approved server-side connect flow; API-key and delegated API-bearer modes are advanced alternatives. Auth files must stay in `.local/`, an ignored auth-file name, or an operator-managed secret path. If interactive connect is enabled, start it only from the compact `/soc-agent` provider notice; the server uses state/PKCE and writes returned tokens to the configured server-side auth file without rendering them in the browser. If setup is missing, expired, scope-missing, plan-limited, unsupported, refresh-failed, budget-exhausted, or the provider returns an error, use only the setup/connect action shown by the page and the local fallback when enabled. Do not paste provider passwords, API keys, browser cookies, raw auth files, or session tokens into Challenger SIEM.
5. Keep chat prompts and screenshots that contain real host/user data under ignored local paths only.

## 10. Review stale and retired lab agents

The Assets page intentionally does not render stale-agent cleanup controls. Use it to review registration state without mutation:

1. Start the API and sign in to the review console.
2. Open `/agents` and select **Stale** under **Freshness** to inspect inactive active registrations.
3. Select **Retired / disabled** under **Registration status** to review registrations retired by an existing compatible client or prior workflow.
4. Preserve historical events, heartbeats, source-health rows, inventory snapshots, alerts, and evidence.

Do not hard-delete agent rows or telemetry for local cleanup. Use `./scripts/cleanup-synthetic-data.sh` only for allowlisted synthetic records. A deliberately re-enrolled endpoint returns to `active` through the normal enrollment flow and receives a new per-agent token.

## 11. Prepare Windows agent package

```bash
./scripts/publish-windows-agent.sh
./scripts/prepare-windows-agent-files.sh \
  http://127.0.0.1:4444 \
  http://<agent-reachable-server-address>:4444 \
  win11-test-001 \
  WIN11-TEST \
  "Windows 11"
```

Copy only the generated executable, ignored generated `agentsettings.json`, and optional `Sysmon/` profile from `dist/windows-agent-copy/` to the lab VM. Do not print or commit the generated settings because it contains a per-agent token.

## 12. Windows service install/start/stop

Preview without changing the host:

```powershell
.\scripts\install-windows-agent.ps1 -Mode plan -TargetLevel L3
```

From an elevated PowerShell session on Windows:

```powershell
.\scripts\install-windows-agent.ps1 -Mode install -PublishPath .\dist\windows-agent-win-x64
Start-Service ChallengerSiemAgent
Get-Service ChallengerSiemAgent
Stop-Service ChallengerSiemAgent
.\scripts\install-windows-agent.ps1 -Mode validate -TargetLevel L3
```

Upgrade/repair refuses to overwrite files while the service is running unless `-RestartService` is supplied after plan review:

```powershell
.\scripts\install-windows-agent.ps1 -Mode upgrade -PublishPath .\dist\windows-agent-win-x64 -RestartService
```

Uninstall through the same workflow preserves data by default:

```powershell
.\scripts\install-windows-agent.ps1 -Mode uninstall
```

Use `-RemoveData` only for disposable lab cleanup after explicit approval. Use `-ConfigurePrerequisites`, `-ConfigurePrivacySensitiveAuditPolicy`, and `-ManageSysmon` only after reviewing [the installer workflow](windows-agent-installer.md) and obtaining host-mutation approval.

## 13. Windows lab E2E validation

Use only an operator-approved lab endpoint and record its address in ignored local configuration, never in tracked documentation.

1. Start the API on this host with `./scripts/run-server-4444.sh`.
2. Verify host health locally: `curl http://127.0.0.1:4444/health`.
3. Verify endpoint-to-server health from Windows: `Invoke-RestMethod http://<agent-reachable-server-address>:4444/health`.
4. Use a unique temporary agent ID and paths under `C:\Temp\ChallengerSIEM\issue-<number>\`.
5. For bounded collection, set `Channels` to `["System"]`, leave optional channels empty, set `StartAtEndWhenNoState` to `false`, and use low poll/heartbeat intervals.
6. Run `WindowsAgent.exe` as a temporary process long enough to heartbeat and ingest; stop only that temporary process if needed.
7. Prove success with small outputs: API health, process exit/status, and `GET /api/v1/events?agent_id=<agent-id>&limit=10` returning events.
8. For outage retry, start with a config pointing at an unused local port, confirm active queue depth remains non-zero, then update to the live API URL and confirm the queue drains and events are searchable.

Do not reboot hosts, change firewall/auth settings, uninstall services, delete operator data, clear event logs, print secrets, or copy raw telemetry into tracked files.

## Known operational limitations

- Built-in detection, alert, evidence, case, graph, and prerequisite workflows are implemented, but automated host response remains deliberately out of scope.
- Local operator authentication, RBAC, session controls, and field-level redaction are implemented; enterprise identity-provider/SSO federation remains future work.
- APIs and pages are deliberately bounded; some collections use offset/limit pagination while event search uses bounded continuation behavior.
- Agents quarantine repeatedly failing events locally and report poison counters; centralized poison-payload review is intentionally absent because payloads can contain sensitive endpoint data.

## Linux agent lifecycle and L2-L4 canary preparation

Build the target bundle with `./scripts/publish-linux-agent.sh linux-x64 <private-bundle-dir>` or `linux-arm64`; use a non-symlink absent/empty destination, and place repository-local output only below ignored `dist/` or `.local/`. The helper enforces private mode-0700 output, rejects stale contents and output over 64 MiB, and adds the self-contained compressed single executable, lifecycle helper, unit, and placeholder-only synthetic configuration reference. The target needs Python 3 for this lifecycle plan helper, but not for the steady-state self-contained service; the bundle does not install it. Copy that private bundle to the authorized target, create a separate private mode-0600 real configuration, and run `./linux-agent.sh plan --payload . --config <private-config>` from the bundle before install. Review its effective journal scope and privacy text. Never treat its synthetic reference as deployable credentials; keep the bundle and real configuration private and ignored. `upgrade` stages the reviewed executable/unit/config without starting or restarting the service; activation requires a separate explicit restart approval. Follow [the Linux agent guide](linux-agent.md) and [Linux local-host validation runbook](linux-local-host-validation.md). Routine lifecycle operations never configure audit, firewall, authentication, kernel, journal retention, groups, capabilities, eBPF, live file-integrity watches, application logging, or mandatory-access-control policy. Missing/denied/unsupported source access is a visible coverage state, not permission to mutate policy. L3 is limited to independently approved agent-owned/procfs snapshots. L4 adds only an exact approved posture-baseline comparison, rolling process resource evidence, and structured role classification on the existing journal cursor; it does not add application-file readers or host-policy lifecycle steps.

The tracked synthetic validation path is:

```bash
dotnet test tests/LinuxAgent.Tests/LinuxAgent.Tests.csproj
dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj --filter 'FullyQualifiedName~LinuxL2|FullyQualifiedName~LinuxDetection'
./scripts/validate-contracts.sh
```

Production configuration defaults to `Journal.TargetCoverageLevel=L1`, `Journal.IncludeAccessibleUserJournals=false`, `SelfIntegrity.Enabled=false`, `PassiveTelemetry.Enabled=false`, and `L4Telemetry.Enabled=false`. The broader journal option selects all local journals already readable by the service identity; it grants no access, may include high-sensitivity user-service text, and invalidates passive-L3/L4 plan hashes. Stage only a reviewed protected configuration, obtain approval for the agent-only restart, then verify `configured_journal_scope`, `system_journal_visibility`, `scope_transition`, cursor/gap state, queue drain, and privacy/volume limits. Roll back through the same path with the option false and regenerated enabled approvals. For a separately approved canary, select the intended L2-L4 target and declare only operator-reviewed roles; a target value does not enable an advanced pack. For either L3 pack, first review its non-mutating plan, then set only that pack's enable flag and exact hash; approval for one pack does not approve another. For L4, install the target/roles with L4 disabled, run the installed-identity non-policy-mutating preflight (which may populate only the private `.dotnet-bundle` cache), review/set `ApprovedBaselineHash`, regenerate/review the baseline-bound plan, and set its exact `ApprovedPlanHash` before enablement. Any required config application/restart remains separately approval-gated. Empty/unknown roles, drift, warm-up/breach, or any mandatory/applicable exception block L4. Review `/api/v1/source-health` and `/api/v1/telemetry-coverage` for requirement, applicability, freshness, prerequisite/event-family, approval, rolling-window, pressure, gap/drop/sample, and strict L4 states.

Linux detection alerts are server-side review signals only. They persist exact rule versions and evidence event IDs, and degraded prerequisite telemetry lowers confidence instead of implying safety. Do not treat unit benchmarks or one healthy rolling-SLO row as the required private L1/L2/L3/L4 soaks. Live systemd testing and any host mutation require separate approval; raw telemetry, configs, plans, baselines, logs, benchmark samples, screenshots, and detailed results stay under ignored `.local/` or approved OS runtime paths. The staged rollout gate owns outage/rotation/restart/pressure, role workload, aggregate and per-collector SLO, strict no-exception, and rollback evidence. When no authorized target/window is supplied, publish the sanitized blocker instead of fabricating evidence.
