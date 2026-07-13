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

Cleanup is scoped through allowlisted selectors and includes dependent rows for targeted agents: events, heartbeats, source health, inventory snapshots, coverage exceptions, ingestion errors, alerts/evidence, agent-linked investigation graphs/proposals/audit, `soc_agent_turns`, and `soc_agent_sessions`/`soc_agent_messages`. For older synthetic `soc-agent` chats without an agent context, use explicit session IDs or a narrow synthetic title prefix:

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

## 5. Fresh-start reset for a disposable local test environment

Use the full reset workflow only when you want a clean, empty Challenger SIEM test environment. Choose the least destructive path:

1. Retire stale active agents in the web UI when you want to keep historical telemetry.
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

## 6. Use investigation graphs and soc-agent chat safely

1. Start the API and sign in to the review console.
2. Open `/graphs`, create a graph with synthetic or bounded operator-authored context, and add nodes/edges that reference SIEM pages instead of copying raw telemetry.
3. On a graph detail page, use the `soc-agent` proposal form only for bounded suggested updates. Review the diff and check the approval box before applying; no graph mutation occurs from a proposal alone.
4. Archive graphs when they should leave the active investigation list.

## 7. Use soc-agent chat safely

1. Start the API and sign in to the review console.
2. Open `/soc-agent` and confirm the provider status pill or any inline provider notice.
3. For the default `Local` provider, ask a bounded investigation question and follow citations back to review pages.
4. If an external ChatGPT/OpenAI provider is selected, confirm `ExternalCallsEnabled` and server-side credentials were configured outside source control before sending sensitive prompts. The primary setup path is ChatGPT subscription OAuth (`SocAgent__AuthMode=SubscriptionOAuth`) using either Pi's `~/.pi/agent/auth.json` `openai-codex` entry after Pi `/login` for the ChatGPT Codex Responses backend, or a dedicated `SocAgent__SubscriptionAuthFilePath` for the OpenAI API path; API-key and delegated API-bearer modes are advanced alternatives. Auth files must stay in `.local/`, an ignored auth-file name, or an operator-managed secret path. If interactive connect is enabled, start it only from the compact `/soc-agent` provider notice; the server uses state/PKCE and writes the returned tokens to the configured server-side auth file without rendering them in the browser. If setup is missing, expired, scope-missing, plan-limited, unsupported, refresh-failed, budget-exhausted, or the provider returns an error, use only the setup/connect action shown by the page and the local fallback when enabled. Do not paste provider passwords, API keys, browser cookies, raw auth files, or session tokens into Challenger SIEM.
5. Keep chat prompts and screenshots that contain real host/user data under ignored local paths only.

## 8. Retire stale lab agents safely

Use the web console instead of destructive database deletes when old smoke-test or lab registrations inflate inventory counts:

1. Start the API and sign in to the review console.
2. Open `/agents` and review the stale-agent cleanup panel. The preview only counts `active` registrations with `last_seen` older than `Review:StaleAgentMinutes`.
3. Optionally click **Review stale active agents** to inspect candidates.
4. Confirm the non-destructive cleanup checkbox and click **Retire stale active agents**.
5. Use the **Retired / disabled** status filter to verify retired registrations. Historical events, heartbeats, source-health rows, inventory snapshots, alerts, and evidence are preserved.

Do not hard-delete agent rows or telemetry for local cleanup. A deliberately re-enrolled endpoint returns to `active` through the normal enrollment flow and receives a new per-agent token.

## 9. Prepare Windows agent package

```bash
./scripts/publish-windows-agent.sh
./scripts/prepare-windows-agent-files.sh \
  http://127.0.0.1:4444 \
  http://192.168.122.1:4444 \
  win11-test-001 \
  WIN11-TEST \
  "Windows 11"
```

Copy only the generated executable, ignored generated `agentsettings.json`, and optional `Sysmon/` profile from `dist/windows-agent-copy/` to the lab VM. Do not print or commit the generated settings because it contains a per-agent token.

## 10. Windows service install/start/stop

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

## 11. Windows lab E2E validation

Authorized current lab VM: `192.168.122.240`.

1. Start the API on this host with `./scripts/run-server-4444.sh`.
2. Verify host health locally: `curl http://127.0.0.1:4444/health`.
3. Verify VM-to-host health from Windows: `Invoke-RestMethod http://192.168.122.1:4444/health`.
4. Use a unique temporary agent ID and paths under `C:\Temp\ChallengerSIEM\issue-<number>\`.
5. For bounded collection, set `Channels` to `["System"]`, leave optional channels empty, set `StartAtEndWhenNoState` to `false`, and use low poll/heartbeat intervals.
6. Run `WindowsAgent.exe` as a temporary process long enough to heartbeat and ingest; stop only that temporary process if needed.
7. Prove success with small outputs: API health, process exit/status, and `GET /api/v1/events?agent_id=<agent-id>&limit=10` returning events.
8. For outage retry, start with a config pointing at an unused local port, confirm active queue depth remains non-zero, then update to the live API URL and confirm the queue drains and events are searchable.

Do not reboot hosts, change firewall/auth settings, uninstall services, delete operator data, clear event logs, print secrets, or copy raw telemetry into tracked files.

## Known MVP limitations

- Detection/correlation rules and alert workflow are post-MVP.
- Operator authentication is a operator API credential and HTTP-only session cookie, not full RBAC/SSO.
- Pagination is bounded by `limit` rather than full cursor pagination.
- The agent poison-event strategy quarantines repeated failures locally for operator review; centralized poison review can be added later.

## Linux agent lifecycle and L2 canary preparation

Use the read-only `./scripts/linux-agent.sh plan` before every deployment and follow [the Linux agent guide](linux-agent.md). Routine lifecycle operations never configure audit, firewall, authentication, kernel, journal retention, groups, capabilities, eBPF, file-integrity watches, or mandatory-access-control policy. Missing/denied/unsupported source access is a visible coverage state, not permission to mutate policy.

The tracked synthetic validation path is:

```bash
dotnet test tests/LinuxAgent.Tests/LinuxAgent.Tests.csproj
dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj --filter 'FullyQualifiedName~LinuxL2'
./scripts/validate-contracts.sh
```

Production configuration defaults to `Journal.TargetCoverageLevel=L1`. For a separately approved canary only, set `TargetCoverageLevel` to `L2` and declare bounded host roles such as `ssh_server`/`bastion` only when the operator has established them. Empty roles intentionally leave role applicability unknown. Review `/api/v1/source-health` and `/api/v1/telemetry-coverage` for requirement, applicability, prerequisite/event-family, denied/degraded/unsupported/stale/excepted states and recent counts by portable `source_id`.

Do not treat unit benchmarks as the required private 24-hour L1 or seven-day L1+L2 soak. Live systemd testing and any host mutation require separate approval; raw telemetry, configs, logs, benchmark samples, screenshots, and detailed results stay under ignored `.local/` or approved OS runtime paths. The staged rollout gate owns the private soak, outage/rotation/restart/pressure windows, aggregate SLO decision, and rollback evidence.
