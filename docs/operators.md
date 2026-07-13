# Operator guide

This guide gives a safe end-to-end path for running Challenger SIEM in a local or lab environment without Docker. It links to the deeper design, API, agent, and runbook pages instead of duplicating every option.

## Safety first

Challenger SIEM stores endpoint telemetry and uses multiple token types. Treat every real deployment artifact as private:

- Keep `.local/dev.env`, generated `agentsettings.json`, connection strings, tokens, cookies, logs, queue/state databases, Windows Event Log exports, and raw API responses out of git.
- Use synthetic data for screenshots, examples, demos, tests, and public issue/PR comments.
- Do not expose the local development HTTP listener outside an isolated lab. Use HTTPS for production-style deployments; see [tls.md](tls.md).

## Minimum local environment

Required components:

1. .NET SDK compatible with the solution.
2. PostgreSQL reachable from the API process.
3. A private environment file, commonly `.local/dev.env`, with:

   ```bash
   ConnectionStrings__SiemDatabase='Host=127.0.0.1;Database=challenger_siem;Username=<db-user>;Password=<db-password>'
   Auth__EnrollmentToken='<long-random-enrollment-token>'
   Auth__ReviewToken='<long-random-review-token>'
   ```

4. Optional WinRM credentials in ignored local configuration when validating the authorized Windows lab VM.

Apply and validate the database schema:

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
```

See [schema.md](schema.md) for table/index details.

## Start the server and web console

Run build/test first when possible:

```bash
dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln
```

Start the API and web console:

```bash
./scripts/platform.sh start
./scripts/platform.sh status
```

The helper runs the API/web-console process in the background, stores PID/log state under `.local/platform/`, and checks `/health` without printing secrets. Use `./scripts/platform.sh restart` after local configuration changes and `./scripts/platform.sh stop` when finished. Then browse to `http://127.0.0.1:5081/login` and sign in with `Auth__ReviewToken`. The web console uses an HTTP-only same-origin session cookie after login; the review token is not stored in browser local storage.

## Validate with synthetic data

Run the non-Docker smoke paths:

```bash
./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

The scripts register a synthetic agent, ingest a synthetic event, exercise the review API or web console, and keep temporary responses/cookies under ignored `.local/` paths. They do not require real endpoint telemetry.

## Register and run a Windows agent

1. Publish the standalone agent:

   ```bash
   ./scripts/publish-windows-agent.sh
   ```

2. Start the API for the authorized lab VM callback path:

   ```bash
   ./scripts/run-server-4444.sh
   ```

3. Prepare copy-ready agent files. The first URL is used by the helper to register the agent locally; the second URL is what the Windows VM calls back to:

   ```bash
   ./scripts/prepare-windows-agent-files.sh \
     http://127.0.0.1:4444 \
     http://192.168.122.1:4444 \
     demo-agent-001 DEMO-WIN11 "Windows 11"
   ```

4. Copy `dist/windows-agent-copy/WindowsAgent.exe`, `dist/windows-agent-copy/agentsettings.json`, and the optional `dist/windows-agent-copy/Sysmon/` profile together to the Windows host. Do not print or commit `agentsettings.json`; it contains a per-agent API token.

5. Run the executable interactively for bounded validation or install it as a service by following [agent.md](agent.md), [windows-agent-installer.md](windows-agent-installer.md), and [runbooks.md](runbooks.md#windows-service-installstartstop).

## Review console workflow

Common operator path:

1. Open [dashboard](web.md#pages) to check active, stale, retired, queued, and recent-ingest metrics.
2. Use **Agents** to filter by hostname/agent ID/status/health and open host coverage details.
3. Use **Events** to filter by time, host, agent, channel, Windows Event ID, keyword, normalized category/action, user, process, or destination IP.
4. Open event detail to inspect normalized fields, entities, message text, and raw JSON for that event.
5. Use **Alerts** to review the current alert foundation and empty-state handling until detection execution is expanded.
6. Use **Graphs** to create operator-managed relationship graphs and optionally request proposal-only `soc-agent` graph updates.
7. Use **soc-agent** for bounded local SIEM-aware summaries with citations to review pages. External provider mode must use server-side provider authentication only: ChatGPT subscription OAuth is the primary setup path and can reuse Pi's server-side `~/.pi/agent/auth.json` after Pi `/login` for ChatGPT Codex Responses models such as `gpt-5.5`, while API-key credentials and documented delegated API-bearer auth files remain advanced alternatives kept out of git.
8. Use **Audit policy** and **About** for drift/status views without secret values.

The [sanitized web-console demo](web-console-demo.md) contains screenshot examples generated from synthetic data.

## Source health and coverage

Agent heartbeats can include source manifests and per-channel health. The server stores source-health rows, overlays expected-but-unreported L2/L3 sources for agent-scoped review, and calculates coverage summaries used by the review API, dashboard, inventory, and host detail pages. Use `/api/v1/telemetry-coverage` or `/agents/detail?agent_id=<agent>` to validate recent normalized events, expected source rows, inventory/audit-policy snapshots, and detection prerequisites over a defined lookback. Start with:

- [windows-host-full-coverage-spec.md](windows-host-full-coverage-spec.md) for target levels and source requirements.
- [windows-l2-validation-runbook.md](windows-l2-validation-runbook.md) for safe L2 validation.
- [windows-agent-installer.md](windows-agent-installer.md) for plan/install/upgrade/repair/validate/uninstall and guarded prerequisite/Sysmon management.
- [sysmon-l3-validation-runbook.md](sysmon-l3-validation-runbook.md) for safe Sysmon validation.

Linux collection is future work, not an available deployment path. Operators evaluating that design should review the [planned Linux coverage levels, SLOs, and soak/rollback gates](linux-host-coverage-spec.md) together with the [least-privilege, privacy, and explicit-change-approval requirements](linux-agent-security.md). Do not mutate a Linux host's audit, firewall, authentication, kernel, service, or security policy on the basis of these planning documents.

Keep any future Linux generated configuration and credentials under a restrictive OS configuration location, durable queue/state outside source checkouts under `/var/lib`, transient state under `/run`, and bounded diagnostics under `/var/log` or the system journal. Keep journal/audit exports, captures, database copies, logs, traces, screenshots, benchmark/soak results, and local review evidence out of git; developer-only evidence belongs under ignored `.local/`. Public demonstrations use only hand-authored `synthetic-` fixtures and must never be produced by sanitizing real host output.

## Routine operations

- Apply/validate schema after pulling changes: [schema.md](schema.md#applying-and-validating-the-schema).
- Check local health: `curl http://127.0.0.1:<port>/health`.
- Search events through `GET /api/v1/events` with the review token; see [api.md](api.md#search-events).
- Retire stale lab registrations through the deliberate web/API workflow when preserving telemetry; use scoped synthetic cleanup for smoke/lab rows and `./scripts/reset-test-environment.sh` only for a full fresh start in a disposable local test environment.
- Follow [release-readiness.md](release-readiness.md) before tagging or publishing a release.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for common database, auth, schema, web login, smoke-test, Windows agent, WinRM, source-health, and screenshot issues.
