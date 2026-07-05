# Changelog

All notable project changes should be recorded here.

## Unreleased

- Added opt-in delegated auth-file support for `soc-agent` OpenAI provider mode with safe local/secret path validation, official API audience checks, token-expiry status metadata, provider credential selection, redacted web/API status, docs, and synthetic test coverage.
- Added an optional official OpenAI Chat Completions-backed `soc-agent` provider path with server-side credential handling, safe status/error mapping, bounded redacted prompts, local fallback, and web/API documentation.
- Fixed stale-agent cleanup redirects in the web console so success and validation paths return safely to agent inventory with filters preserved.
- Expanded guarded synthetic-data cleanup to cover agent-linked `soc-agent` turns, sessions/messages, investigation graphs/proposals/audit, explicit synthetic chat/graph selectors, and web-smoke `soc-agent` chat cleanup.
- Revamped the web review console with a cohesive dark operator shell, active navigation, accessible focus/skip-link behavior, responsive cards/tables, visible filter/result state, bounded pagination for list workflows, and updated web validation/docs.
- Refreshed the public documentation into a wiki-style docs set with a concise README, operator/contributor/troubleshooting guides, sanitized web-console screenshots, and a documentation-maintenance checklist.
- Added a platform capability foundation catalog and authenticated API covering SPEC-GAP-001 through SPEC-GAP-019 with documented implementation guardrails and contracts.
- Added operator-managed investigation graphs with v1 APIs, PostgreSQL storage, web workflows, bounded `soc-agent` graph context, and approval-gated graph proposals.
- Added a guarded synthetic web/API test-data cleanup script with dry-run defaults, explicit execution confirmation, smoke-script cleanup hooks, docs, and integration coverage.
- Added a persistent `soc-agent` chat workspace with provider status/connect UX, additive chat APIs, bounded session/message persistence, and official ChatGPT/OpenAI setup guardrails.
- Added authenticated stale-agent cleanup controls that retire inactive registrations from default dashboard/inventory views without deleting telemetry.
- Added an authenticated local `soc-agent` web/API workspace with SIEM-aware tool orchestration, citations, bounded audit persistence, and current coverage/event/alert/detection/inventory context.
- Added a Windows host full-coverage foundation with source-health contracts/storage/API/web review, coverage and inventory models, parser/detection catalogs, alert and detection skeletons, validation runbooks, and role-pack designs.
- Documented the planned `soc-agent` web-console harness, official provider-auth guardrails, tool/approval model, and phased roadmap.
- Added a comprehensive Windows host full-coverage SIEM target specification and a bite-sized GitHub issue backlog covering sources, telemetry requirements, normalization, health, detections, validation, and roadmap.
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
