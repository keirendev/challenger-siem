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
   Auth__ReviewToken='<long-random-review-token>'
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

```bash
./scripts/run-server-4444.sh
```

Open the API base URL in a browser, log in with `Auth__ReviewToken`, and use:

- `/` for dashboard metrics.
- `/agents` for inventory and queue depth.
- `/events` for event search.
- `/events/detail?agent_id=<id>&event_id=<uuid>` for raw JSON and normalized fields.
- `/about` for version/environment/database status.

## 4. Fake ingest/search smoke test

```bash
./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

The scripts write temporary logs and responses under `.local/` only.

## 5. Retire stale lab agents safely

Use the web console instead of destructive database deletes when old smoke-test or lab registrations inflate inventory counts:

1. Start the API and sign in to the review console.
2. Open `/agents` and review the stale-agent cleanup panel. The preview only counts `active` registrations with `last_seen` older than `Review:StaleAgentMinutes`.
3. Optionally click **Review stale active agents** to inspect candidates.
4. Confirm the non-destructive cleanup checkbox and click **Retire stale active agents**.
5. Use the **Retired / disabled** status filter to verify retired registrations. Historical events, heartbeats, source-health rows, inventory snapshots, alerts, and evidence are preserved.

Do not hard-delete agent rows or telemetry for local cleanup. A deliberately re-enrolled endpoint returns to `active` through the normal enrollment flow and receives a new per-agent token.

## 6. Prepare Windows agent package

```bash
./scripts/publish-windows-agent.sh
./scripts/prepare-windows-agent-files.sh \
  http://127.0.0.1:4444 \
  http://192.168.122.1:4444 \
  win11-test-001 \
  WIN11-TEST \
  "Windows 11"
```

Copy only the generated executable and ignored generated `agentsettings.json` from `dist/windows-agent-copy/` to the lab VM. Do not print or commit the generated settings because it contains a per-agent token.

## 7. Windows service install/start/stop

Preview without changing the host:

```powershell
.\scripts\install-windows-agent.ps1 -PublishPath .\dist\windows-agent-win-x64 -PlanOnly
.\scripts\uninstall-windows-agent.ps1 -PlanOnly
```

From an elevated PowerShell session on Windows:

```powershell
.\scripts\install-windows-agent.ps1 -PublishPath .\dist\windows-agent-win-x64
Start-Service ChallengerSiemAgent
Get-Service ChallengerSiemAgent
Stop-Service ChallengerSiemAgent
```

The uninstall script preserves data by default:

```powershell
.\scripts\uninstall-windows-agent.ps1
```

Use `-RemoveData` only for disposable lab cleanup after explicit approval.

## 8. Windows lab E2E validation

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
- Operator authentication is a review token and HTTP-only session cookie, not full RBAC/SSO.
- Pagination is bounded by `limit` rather than full cursor pagination.
- The agent poison-event strategy quarantines repeated failures locally for operator review; centralized poison review can be added later.
