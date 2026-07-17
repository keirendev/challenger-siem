# Milestone status

The original MVP milestone checklist has been implemented and archived at `docs/archive/mvp-milestone-tracker-implemented.md`.

## Implemented baseline

- Windows endpoint agent with configurable Windows Event Log collection, deterministic event IDs, durable SQLite queueing, bounded retry/backoff, poison-event handling, channel state, first-run enrollment, DPAPI-protected persisted token support, source-health probing, queue SLO metrics, configuration/binary hash telemetry, and L2/L3 source manifests.
- ASP.NET Core API with agent registration, heartbeat, event ingestion, deduplication, source-health persistence, inventory snapshots, alert/evidence storage, detection rule metadata, expanded event search, and `soc-agent` ask endpoint.
- PostgreSQL schema for agents, events, heartbeats, ingestion errors, source health, coverage exceptions, asset inventory, detection rules, alerts/evidence, and `soc_agent_turns`.
- Shared v1 contracts and JSON schemas for registration, heartbeat, event envelopes, ingest acknowledgement, source health, alerts, detection rules, and `soc-agent` requests/responses.
- Server-hosted web console with operator login, dashboard, agent inventory, host coverage/source-health detail, event search/detail, alert list/detail, audit-policy drift, about page, and `soc-agent` workspace.
- Windows host full-coverage foundation docs, validation runbooks, role-pack designs, security-hardening roadmap, web/API/schema/operator docs, and synthetic test coverage.

The Linux baseline additionally includes one durable L1 journal path with default system-only and opt-in all-accessible-local scopes, independent system-visibility health, bounded inventory, an opt-in L2 structured security catalog, disabled-by-default L3 snapshots, and disabled-by-default L4 policy-posture, rolling process-SLO, and six declared-role journal families. Scope selection uses the existing non-root identity and fixed reader, grants no new access, and is bound into passive-L3/L4 plan approvals. Server search, coverage, and prerequisite-aware detections understand the portable nested fields and apply strict healthy/no-exception L4 semantics. L2-L4 remain canary-only pending private approval and soak gates; the L4 VM canary has not been run. Linux Audit Framework, eBPF, broad/live file-integrity, and role-application file collection are not enabled.

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

- Production identity-provider/SSO integration beyond the implemented local operator RBAC and field-level redaction controls.
- Official external `soc-agent` provider abstraction when an approved provider/auth flow is selected.
- Detection proposal/backtest/approval workflows beyond the implemented built-in evaluation, prerequisite, suppression, alert/evidence, and case foundations.
- Audit/eBPF feasibility, richer separately approved Linux role sources beyond structured journald, ETW/file-integrity expansion, Sysmon profile management, and role-pack implementation depth.
- Release packaging/signing, upgrade/migration guidance, and production TLS/mTLS rollout decisions.
