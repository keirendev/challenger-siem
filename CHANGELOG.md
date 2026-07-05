# Changelog

All notable project changes should be recorded here.

## Unreleased

- Documented the planned `soc-agent` web-console harness, official provider-auth guardrails, tool/approval model, and phased roadmap.
- Added startup validation for required database, enrollment-token, and review-token configuration with non-secret error messages.
- Added PostgreSQL schema apply/validation scripts plus opt-in PostgreSQL integration coverage for registration, token rotation, ingest/dedup/search, heartbeat persistence, ingestion error recording, and web console data display.
- Persisted authenticated ingest validation failures to `ingestion_errors` with bounded secret-safe context.
- Added additive v1 ingest acknowledgement event-id arrays so agents can delete only accepted/duplicate queued events after partial acknowledgements.
- Added Windows agent first-run enrollment, per-agent token persistence, bounded retry/backoff, queue attempt tracking, poison-event quarantine, queue limit warnings, and unit coverage for normalization/queue/state behavior.
- Hardened Windows agent service install documentation and scripts for LocalSystem MVP service account, Administrators/SYSTEM-only config/data ACLs, Security log permission validation, and safe generated config handling.
- Added non-Docker web smoke, operator runbooks, TLS deployment guidance, Windows lab E2E guidance, packaging validation notes, and MVP release readiness checklist.
- Added a server-hosted web review console with review-token login, dashboard metrics, agent inventory, event search, event detail, and system/about pages.
- Ensured web console static assets are also covered by production HTTPS enforcement.
- Added web authentication/session tests and web review console operator documentation.
- Documented the current WinRM lab VM and VM-to-host API callback address for Pi-managed E2E validation.
- Clarified that Pi/coding-agent local files remain ignored and are not versioned project artifacts.
- Added project versioning workflow for Pi-managed changes.
- Centralized project version metadata in `VERSION` and .NET assembly metadata.

## 0.1.0 - 2026-07-04

- Established the MVP baseline for the Windows agent, ingestion API, contracts, and local development docs.
