# Changelog

All notable project changes should be recorded here.

## Unreleased

- **MINOR 1.3.0:** Added a disabled-by-default explicit-opt-in Linux L3 self-integrity snapshot collector, safe managed telemetry retention with a 30-day target and hard 100 GiB ceiling, and prerequisite-aware Linux server-side detections with exact rule/evidence metadata; the release preserves `/api/v1` and `contracts/v1` compatibility, keeps audit/eBPF/broad live file monitoring deferred, scopes retention deletion to managed telemetry only, and adds synthetic validation plus operator documentation.
- **MINOR 1.2.0:** Added bounded v1 agent/source/queue/resource/storage observability with timestamped resource metrics, queue bytes/pressure/send/backoff/recovery state, poison/drop counters, per-source rate/lag/silence/gap/permission transitions, persisted coverage/API exposure, and 100 GiB managed-storage capacity warnings at 70/85/95% while preserving existing Windows payload compatibility.
- Documented the optional Linux L3 telemetry ADR: audit and eBPF remain deferred, broad/live file-integrity approaches are not selected, and only a future snapshot-based agent self-integrity design candidate is adopted; no audit, eBPF, file-integrity collector, runtime dependency, or host-policy mutation is added.
- **MINOR 1.1.0:** Added an opt-in Linux L2 journald security source pack with structured-first normalization for login/session, SSH, sudo/su, cron/timers, package, firewall, kernel/security-module, service-change, and agent/log-tamper activity; first-class requirement/applicability/evidence health metadata; platform-aware server coverage and portable package search; and bounded synthetic fixtures and performance guards. L1 remains the default while the private seven-day L1+L2 host soak remains a rollout gate; no audit, eBPF, or file-integrity collector is included.
- **MAJOR 1.0.0:** Replaced shared production review-token operator authentication with database-backed operator identities. Existing review-token API clients and `Auth:ReviewToken` browser login configuration require operator bootstrap and new per-operator credentials. Endpoint-agent enrollment/ingest/heartbeat contracts remain compatible under `/api/v1`.
- Added passive cursor-based Linux L1 system-journal collection for kernel, boot, systemd service, authentication, and core-system records with deterministic v1 IDs, bounded redaction/normalization, durable queue-before-checkpoint and acknowledgement-before-delete semantics, explicit source/gap/permission/pressure health, and synthetic restart/replay/failure/benchmark coverage.
- Replaced the production operator review credential with PostgreSQL-backed operator identities, exact viewer/analyst/detection-engineer/admin RBAC, hardened revocable sessions, CSRF-safe mutations, lockout and credential lifecycle controls, role-aware sensitive-field redaction, a secure local bootstrap/recovery command, and append-only secret-safe security audit events while preserving endpoint-agent authentication and `/api/v1` agent contracts.

- Added bounded read-only Linux host and security-posture inventory snapshots for host/kernel identity, users/groups, services/units/timers, packages/available updates, interfaces/listeners, mounts, firewall, SSH, mandatory access controls, Secure Boot, and observable agent file-permission/fingerprint posture, with explicit collection states, fixed source policies, independent scheduling, and deterministic payload/item limits while preserving the generic v1 inventory contracts.

- Added a first-class .NET 8 Linux agent foundation using Agent.Core for enrollment, durable queueing, acknowledgement-aware recovery, heartbeat and bounded inventory transport, with a least-privilege systemd unit and preflight-first plan/install/upgrade/validate/uninstall workflows.

- Extracted a platform-neutral Agent.Core reliability library for the durable queue, v1 transport, acknowledgement/retry handling, deterministic identity, serialization, and configuration hashing while preserving the Windows agent collection/checkpoint semantics.

- Added numbered idempotent PostgreSQL migrations, multi-platform event persistence/search, portable-source indexes, and authenticated managed event-storage accounting while preserving Windows v1 rows and semantics.

- Added backward-compatible v1 cross-platform telemetry contracts with Linux-native journal/audit sources and platform-neutral Windows-or-Linux inventory-diff/agent-health sources, including explicit source/checkpoint/deduplication/applicability/health metadata, bounded structured concepts and raw-data handling, old-valid Windows boundary regressions, synthetic schema/golden validation, and an honest storage-migration boundary while preserving the exact legacy Windows Event Log payload allowances and semantics.
- Added host timezone metadata across registration, heartbeat, source-health, inventory, event ingest/search, storage, schemas, and web review displays so host-scoped timelines default to clearly labelled endpoint-local time while UTC remains canonical for filtering and correlation.
- Added a full-capability Windows agent installer workflow with plan/install/upgrade/repair/validate/uninstall modes, guarded Windows prerequisite configuration, Microsoft-signed Sysmon management, a versioned Sysmon L3 profile, source-manifest prerequisite/event-family validation metadata, and Sysmon profile hash reporting in source health.
- Added agent-scoped Windows telemetry coverage validation with expected-source matrix overlays, recent event counts, agent-uploaded bounded inventory/audit-policy snapshots, detection prerequisite status, a `/api/v1/telemetry-coverage` review endpoint, expanded host coverage web detail, and clearer missing-vs-error source status handling for readable empty Windows logs.
- Added a guarded fresh-start reset script and runbook for disposable local test environments with dry-run default, local target safety checks, confirmation-gated database reset, and opt-in local artifact cleanup.
- Added safe Markdown rendering for `/soc-agent` assistant chat output in persisted and live messages while keeping operator messages plain text and blocking unsafe links/raw HTML.
- Fixed `/soc-agent` chat auto-follow scrolling so live conversation updates keep the latest message above the sticky composer while still respecting manual scroll-away behavior.
- Fixed the `/soc-agent` live workspace so normal connected/local provider states use the compact title pill instead of a large inline status box, activity cards fit long tool names, and no-reload sends show immediate operator/pending progress while live events stream.
- Added authenticated `soc-agent` chat-session deletion from the web workspace and v1 review API, with active-run conflict handling and message cascade semantics.
- Expanded the `/soc-agent` workspace width, widened the conversation column, moved provider setup into compact status/notice surfaces, and kept the right rail focused on live tool activity.
- Fixed `/soc-agent` auto-follow scrolling to target the active chat thread sentinel instead of jumping to the document bottom on initial page load.
- Added a local platform lifecycle helper for starting, stopping, restarting, and checking the Challenger SIEM API/web console process without printing secrets.
- Updated the `/soc-agent` chat workspace to use browser/page-level scrolling instead of nested scroll panels while preserving live send, activity, provider status, and scroll-to-latest behavior.
- Refined the `/soc-agent` chat workspace with hidden manual agent context, a non-editable context chip, reliable activity-panel collapse/expand controls, user-controlled auto-follow scrolling, and Ctrl/Cmd+Enter send support.
- Added a live `soc-agent` workspace with same-origin event-stream run transport, no-reload chat sends, tool/progress events, cancellation, reconnect recovery, compact provider/activity panels, and docs/tests for the additive browser workflow.
- Added ChatGPT Codex Responses support for `soc-agent` Pi `openai-codex` auth-file mode so ChatGPT subscription credentials from `~/.pi/agent/auth.json` can call plan-allowed models such as `gpt-5.5` without requiring OpenAI API `model.request` scope.
- Added Pi agent auth-file reuse for `soc-agent` ChatGPT subscription OAuth mode so a successful Pi `/login` can supply the server-side `~/.pi/agent/auth.json` `openai-codex` credential without creating a separate auth file.
- Added a server-mediated ChatGPT subscription OAuth connect flow for `soc-agent` so authenticated operators can start official authorization-code/PKCE setup from the web console while credentials stay server-side.
- Added ChatGPT subscription OAuth as the primary external `soc-agent` provider setup path with safe auth-file parsing, official audience/scope/endpoint validation, near-expiry refresh, additive status metadata, web setup guidance, docs, and synthetic test coverage.
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
