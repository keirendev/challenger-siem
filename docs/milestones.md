# Milestone status

The original MVP milestone checklist has been implemented and archived at `docs/archive/mvp-milestone-tracker-implemented.md`.

## Implemented baseline through 0.5.0

- Windows endpoint agent with configurable Windows Event Log collection, deterministic event IDs, durable SQLite queueing, bounded retry/backoff, poison-event handling, channel state, first-run enrollment, DPAPI-protected persisted token support, source-health probing, queue SLO metrics, configuration/binary hash telemetry, and L2/L3 source manifests.
- ASP.NET Core API with agent registration, heartbeat, event ingestion, deduplication, source-health persistence, inventory snapshots, alert/evidence storage, detection rule metadata, expanded event search, and `soc-agent` ask endpoint.
- PostgreSQL schema for agents, events, heartbeats, ingestion errors, source health, coverage exceptions, asset inventory, detection rules, alerts/evidence, and `soc_agent_turns`.
- Shared v1 contracts and JSON schemas for registration, heartbeat, event envelopes, ingest acknowledgement, source health, alerts, detection rules, and `soc-agent` requests/responses.
- Server-hosted web console with operator login, dashboard, agent inventory, host coverage/source-health detail, event search/detail, alert list/detail, audit-policy drift, about page, and `soc-agent` workspace.
- Windows host full-coverage foundation docs, validation runbooks, role-pack designs, security-hardening roadmap, web/API/schema/operator docs, and synthetic test coverage.

The Linux baseline additionally includes one durable L1 journal path, bounded inventory, and an opt-in L2 structured security catalog with platform-aware server coverage. L2 remains canary-only pending the private seven-day soak; Linux Audit Framework, eBPF, and file-integrity collection are not enabled.

## Current validation baseline

Before release-oriented changes, run the relevant subset of:

```bash
./scripts/current-version.sh
dotnet test Challenger.Siem.sln --no-restore
./scripts/apply-schema.sh
./scripts/validate-schema.sh
./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

For web-console changes, add Playwright browser E2E covering login, dashboard, affected pages, logout, and unauthenticated redirect behavior.

For agent/server integration changes, use the authorized Windows lab runbook and keep all generated configs, responses, logs, traces, screenshots, and telemetry under ignored `.local/` paths.

## Next milestone themes

- Production hardening for operator accounts/RBAC and field-level access controls.
- Official external `soc-agent` provider abstraction when an approved provider/auth flow is selected.
- Detection proposal/backtest/approval workflows beyond the current metadata and alert skeleton.
- Deeper inventory diffing, ETW/file-integrity L4 sources, Sysmon profile management, and role-pack implementation depth.
- Release packaging/signing, upgrade/migration guidance, and production TLS/mTLS rollout decisions.
