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
   ```

4. Optional WinRM credentials in ignored local configuration when validating an operator-approved Windows lab endpoint.

Apply and validate the database schema:

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
SIEM_OPERATOR_PASSWORD='<private-strong-password>' ./scripts/operator-account.sh bootstrap --username local-admin --role admin
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

The helper runs the API/web-console process in the background, stores PID/log state under `.local/platform/`, and checks `/health` without printing secrets. Use `./scripts/platform.sh restart` after local configuration changes and `./scripts/platform.sh stop` when finished. Then browse to `http://127.0.0.1:5081/login` and sign in with an operator username/password. The web console uses an HTTP-only, strict-SameSite, database-revocable session cookie after login.

## Validate with synthetic data

Run the non-Docker smoke paths:

```bash
./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

For release candidates, run the real-app browser/accessibility/security/performance gates against disposable PostgreSQL synthetic data:

```bash
./scripts/release-gates.sh install-browsers
./scripts/release-gates.sh run
```

All release-gate output stays under ignored `.local/release-gates/`; cleanup requires `./scripts/release-gates.sh cleanup --state .local/release-gates/<run-id>/state.env --confirm DELETE-RELEASE-GATE-RESOURCES`.

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
     http://<agent-reachable-server-address>:4444 \
     demo-agent-001 DEMO-WIN11 "Windows 11"
   ```

4. Copy `dist/windows-agent-copy/WindowsAgent.exe`, `dist/windows-agent-copy/agentsettings.json`, and the optional `dist/windows-agent-copy/Sysmon/` profile together to the Windows host. Do not print or commit `agentsettings.json`; it contains a per-agent API token.

5. Run the executable interactively for bounded validation or install it as a service by following [agent.md](agent.md), [windows-agent-installer.md](windows-agent-installer.md), and [runbooks.md](runbooks.md#12-windows-service-installstartstop).

## Review console workflow

Common current operator path (aligned to the Overview/Search/Assets/Alerts/Cases/Detections/Dashboards/Health/Administration IA in [web.md](web.md)):

1. Open **Overview** to check active, stale, retired, queued, and recent-ingest metrics.
2. Use **Search** for bounded event search by time, host, agent, platform/source/source ID, provider/facility/unit, Windows Event ID or native event code, severity/outcome, detection rule, entity, keyword, user, process, service, file/registry/package, or network fields. Search results use server-side validation, cursor pagination, configurable columns, active-filter/result-scope labels, UTC timeline buckets with explicit host-local metadata, saved searches, and role-redacted event detail pivots. Admin CSV export is confirmation-gated, audited, bounded, sanitized for spreadsheet safety, and never includes raw JSON.
3. Use **Assets** to filter by hostname, agent ID, platform, registration status/freshness, coverage level, degraded source, queue pressure/throttle, gap/drop, and queue-capacity state, then open host coverage details. Host detail distinguishes missing, unsupported, not applicable, excepted, disabled, permission denied, stale, throttled, gap, and error states; shows queue/resource/source rate/lag/checkpoint/retention/capacity metrics; and displays bounded time-labelled inventory/posture changes with role redaction. Admin-only stale-agent retirement remains confirmation-gated and preserves telemetry.
4. Use **Alerts** to review detection output, assign/acknowledge/investigate, suppress with reason/expiry, close/reopen with disposition, and promote synthetic or real review signals into cases. Evidence rows explicitly state whether underlying telemetry is retained, removed by retention, or missing.
5. Use **Cases** to manage investigations with owner, severity, priority, status, notes, evidence links, related alerts/entities/graphs, activity timeline, confirmed closure, and reopen.
6. Use the role-aware implemented workspace links for **Investigation graphs** and **soc-agent** when your role permits analyst workflows. `soc-agent` remains citation-oriented and cannot mutate detections, configuration, agents, stored data, or repository files.
7. Use **Detections** to review stable rule versions, required sources/fields, coverage/confidence impact, synthetic validation metadata, tuning/suppression notes, and response guidance. Detection-engineer/admin operators can update bounded server-side rule metadata with confirmation, audit, and optimistic concurrency; the page cannot enable host collection or upload arbitrary detection code.
8. Use **Dashboards** for bounded server-side aggregations with explicit time ranges, freshness/partial-data state, accessible chart/table alternatives, and saved owner/visibility/version layouts. Saved layouts store widget metadata only, not raw telemetry.
9. Use **Administration** (admin only) for non-secret operator/session metadata, source review notes, retention/capacity effective settings, and audit history. Settings mutations are allowlisted server changes, require confirmations, and do not alter endpoint audit/firewall/authentication/kernel/service policy or L3 collection.
10. Use **Health** for runtime/status metadata and **Audit policy** (admin) for drift/status views without secret values.

The [web-console visual capture guide](web-console-demo.md) records current screenshot status and the synthetic-data, inspection, and browser-validation gates for publishing replacements.

## Source health and coverage

Agent heartbeats can include source manifests and per-channel health. The server stores source-health rows, overlays expected-but-unreported L2/L3 sources for agent-scoped review, and calculates coverage summaries used by the review API, dashboard, inventory, and host detail pages. Queue/resource/source observability is machine-readable in `/api/v1/source-health`, `/api/v1/telemetry-coverage`, and `/api/v1/storage/accounting`: review queue bytes/depth/oldest age, pressure and send/backoff/recovery state, poison/drop counters, source silence/gaps/permission loss, and storage 70/85/95% warnings. Treat `null` as unknown or unsupported and `0` as an observed zero. Use `/api/v1/telemetry-coverage` or `/agents/detail?agent_id=<agent>` to validate recent normalized events, expected source rows, inventory/audit-policy snapshots, and detection prerequisites over a defined lookback. Start with:

- [windows-host-full-coverage-spec.md](windows-host-full-coverage-spec.md) for target levels and source requirements.
- [windows-l2-validation-runbook.md](windows-l2-validation-runbook.md) for safe L2 validation.
- [windows-agent-installer.md](windows-agent-installer.md) for plan/install/upgrade/repair/validate/uninstall and guarded prerequisite/Sysmon management.
- [sysmon-l3-validation-runbook.md](sysmon-l3-validation-runbook.md) for safe Sysmon validation.

The Linux agent passively collects L1 through one system-journal cursor, can opt into the L2 logical security catalog with `TargetCoverageLevel=L2`, and can separately opt into the L3 `linux-agent-self-integrity-snapshot` only after operator approval of its exact preflight plan hash. Heartbeats report L1 plus login/session, SSH, sudo/su, cron/timer, package, firewall, kernel/security-module, service-change, agent/log-tamper, explicitly unsupported audit rows, and the disabled/enabled self-integrity row with requirement/applicability/prerequisite/event-family metadata. Server overlays now use the Linux catalog and distinguish stale, degraded, denied, unsupported, excepted, not-applicable, self-integrity approval mismatch, pressure gaps, and cleanup states. Linux server-side detections add alert signals for authentication abuse, privilege escalation, SSH/process activity, service/timer, package/security-control, firewall, tamper/source-silence, and self-integrity events when approved telemetry is present; see [Linux server-side detections](linux-detections.md). Inventory presence alone does not establish event health. Review the [Linux coverage levels and rollout gates](linux-host-coverage-spec.md) with the [least-privilege/privacy design](linux-agent-security.md). Do not mutate audit, firewall, authentication, kernel, service, journal-retention, permissions, groups, capabilities, or security policy to improve results.

Keep Linux generated configuration and credentials under `/etc/challenger-siem-agent`, durable queue/state under `/var/lib/challenger-siem-agent`, and private diagnostics outside source checkouts. Keep journal/audit exports, host inventory exports, captures, database copies, logs, traces, screenshots, benchmark/soak results, and local review evidence out of git; developer-only evidence belongs under ignored `.local/`. Public demonstrations use only hand-authored `synthetic-` fixtures and must never be produced by sanitizing real host output.

## Routine operations

- Apply/validate schema after pulling changes: [schema.md](schema.md#applying-and-validating-postgresql).
- Check local health: `curl http://127.0.0.1:<port>/health`.
- Search events through `GET /api/v1/events` with the operator API credential; see [api.md](api.md#search-events).
- Connect an approved read-only SIEM assistant through `/mcp` with a least-privileged operator API credential; see [MCP server and SIEM-agent integration](mcp.md).
- Review managed telemetry storage with `/api/v1/storage/accounting`, `/api/v1/storage/retention/status`, Overview, and host detail. Treat 70% as warning, 85% as warning, 95% as critical, and 100% as over capacity; these states are labelled in text and not conveyed by color alone. Use retention dry-run first; execute only against the intended SIEM database. The default target is 30 days with a hard 100 GiB managed telemetry ceiling and deterministic emergency cleanup that removes optional telemetry before mandatory telemetry while preserving alert/evidence references.
- Retire stale lab registrations through the deliberate web/API workflow when preserving telemetry; use scoped synthetic cleanup for smoke/lab rows and `./scripts/reset-test-environment.sh` only for a full fresh start in a disposable local test environment.
- Follow [release-readiness.md](release-readiness.md) before tagging or publishing a release.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for common database, auth, schema, web login, MCP, smoke-test, Windows agent, WinRM, source-health, and screenshot issues.

## Linux endpoints

The Linux service supports secure enrollment, heartbeat, passive cursor-based L1 journald collection, opt-in structured L2 security normalization on that same cursor, durable Agent.Core delivery, and 16 bounded inventory categories. See [Linux agent](linux-agent.md). L1 is the configuration default; L2 remains canary-only until the private seven-day non-disruption soak passes.

Inventory starts after a 30-second default delay and runs independently of heartbeat and queue delivery. The default interval is one hour with a five-minute enforced minimum. Each upload is capped at 20 snapshots, 200 items per snapshot, and a default 256 KiB serialized payload. Review `summary.state` for the exact `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed` result and inspect truncation markers instead of treating missing items as healthy.

Self-integrity starts disabled. Use `./scripts/linux-agent.sh plan` to review the non-mutating L3 snapshot plan, strict allowlist, current missing/denied/type findings, privacy/resource impact, sequencing/loss/pressure behavior, and rollback. Enable only by setting `Agent:SelfIntegrity:Enabled=true` and the matching `ApprovedPlanHash`; disable by setting it false. If collector cleanup is approved, `CleanupStateOnDisable=true` removes only `/var/lib/challenger-siem-agent/self-integrity-state.json` and never the monitored binary, service unit, configuration, directories, or host policy.

Collection uses fixed read-only commands/files with timeouts, byte caps, cancellation, and allowlisted output fields. The one journal source uses fixed machine-readable `journalctl`; structured evidence wins and only the first 4,096 message characters may supplement missing fields through bounded parsers. It neither broad-scans nor mutates the host. Secret-shaped assignments, binary/non-text values, and over-limit content are handled before queueing with explicit markers. No audit, eBPF, or file-integrity collector is included. The [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) documents the current audit/eBPF/file-integrity adopt/defer/reject decisions without enabling any collector.

Treat `permission_denied`, `degraded`, `unsupported`, `stale`, invalid cursor/rotation/vacuum gaps, malformed/reordered input, and pressure as distinct review states. Compare collected and acknowledged cursors for backlog. Check requirement/applicability before treating optional or role-specific sources as mandatory; only the server applies approved exceptions. Do not grant root or change journal/group policy merely to turn health green. Synthetic benchmarks are not the required private soak.
