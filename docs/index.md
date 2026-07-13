# Challenger SIEM documentation wiki

This directory is the canonical, versioned documentation set for Challenger SIEM. It is safe to mirror into a GitHub Wiki, but repository docs remain the source of truth so documentation changes can be reviewed with code, contracts, schemas, screenshots, and release notes.

## Start here

- [README landing page](../README.md) - concise project summary, safe quickstart, and repository layout.
- [Operator guide](operators.md) - end-to-end setup and day-two operation overview.
- [Contributor guide](contributors.md) - development workflow, review expectations, and documentation-maintenance checklist.
- [Challenger family alignment](challenger-family-alignment.md) - shared branding, UX, engineering, safety, and contract-boundary expectations.
- [Troubleshooting and FAQ](troubleshooting.md) - common local, API, agent, web-console, and lab validation issues.

## Architecture and design

- [Architecture](architecture.md) - pipeline, agent/server flow, reliability, and security decisions.
- [Schema design](schema.md) - PostgreSQL tables, indexes, and schema application/validation.
- [Windows host full-coverage SIEM specification](windows-host-full-coverage-spec.md) - target coverage model and implementation status.
- [Linux host coverage specification](linux-host-coverage-spec.md) - implemented L1 plus opt-in journald L2 security families, planned advanced sources, performance SLOs, benchmarks, and rollout gates.
- [Linux agent security and privacy design](linux-agent-security.md) - implemented structured journal/inventory controls, threat model, least-privilege boundaries, exclusions, and change approval.
- [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) - selection/defer report for optional audit, eBPF, and file-integrity telemetry; only the explicit-opt-in agent self-integrity snapshot is implemented, while audit/eBPF/broad live FIM remain deferred.
- [Specification gap foundations](spec-gap-foundations.md) - implemented SPEC-GAP foundation catalog.
- [Windows role source-pack designs](windows-role-packs.md) - role-specific source packs and validation ideas.
- [Security hardening roadmap](security-hardening-roadmap.md) - future RBAC, redaction, mTLS, and tamper-hardening work.

## Server, APIs, and contracts

- [API contract v1](api.md) - registration, heartbeat, ingest, review search, source-health, telemetry coverage validation, inventory, alerts/detections, graphs, capabilities, and `soc-agent` routes.
- [Linux server-side detections](linux-detections.md) - bounded prerequisite-aware Linux rule metadata, execution, suppression, evidence, and response guidance.
- [JSON Schema contracts](../contracts/v1/) - external v1 payload schemas.
- [C# shared contracts](../shared/Contracts/) - in-process contract models used by the agent, server, and tests.
- [Authentication design](auth.md) - enrollment token, per-agent token, operator API credential, and external `soc-agent` provider guardrails.
- [HTTPS/TLS deployment path](tls.md) - local HTTP exception, production HTTPS options, and agent trust expectations.

## Linux endpoint agent

- [Linux agent](linux-agent.md) - L1/L2 journald source catalog, structured normalization, cursor/health semantics, configuration, systemd hardening, lifecycle workflows, and validation.
- [Linux server-side detections](linux-detections.md) - authentication abuse, privilege escalation, SSH/process, service/timer, package/security-control, firewall, tamper/source-silence, and self-integrity alert rules.

## Windows endpoint agent

- [Windows agent](agent.md) - current capabilities, build, install, state/queue behavior, and Windows validation notes.
- [Windows agent installer workflow](windows-agent-installer.md) - plan/install/upgrade/repair/validate/uninstall modes, guarded prerequisite configuration, and Sysmon L3 management.
- [Agent configuration format](agent-config.md) - configuration keys, enrollment modes, queue fields, and channel state paths.
- [L2 Windows validation runbook](windows-l2-validation-runbook.md) - safe L2 source-health validation.
- [Sysmon L3 validation runbook](sysmon-l3-validation-runbook.md) - safe Sysmon validation path.

## Web console and operator workflows

- [Web console product specification](web.md) - current routes, mature IA/page map, role-aware workflows, lifecycle states, sensitive-field rules, accessibility, responsive behavior, and smoke path.
- [Frontend architecture ADR](frontend-architecture-adr.md) - measured high-density search/timeline spike selecting enhanced ASP.NET Core/Razor Pages as the single active frontend architecture.
- [Sanitized web-console demo](web-console-demo.md) - screenshot/wireframe gallery, synthetic data rules, leakage inspection, and regeneration checklist.
- [Operator runbooks](runbooks.md) - database setup, smoke tests, graph/`soc-agent` use, stale-agent retirement, packaging, and Windows lab E2E.
- [soc-agent](soc-agent.md) - live workspace, local/external provider model, tools, persistence, citations, and mutation policy.

## Development, validation, and release

- [Local development without Docker](development.md) - prerequisites, environment variables, schema, build/test, API run, optional WinRM, and smoke tests.
- [Dependencies and ownership policy](dependencies.md) - approved components and optional tooling boundaries.
- [MVP release readiness checklist](release-readiness.md) - required checks, Windows evidence, repository hygiene, and issue disposition.
- [Release gates](release-gates.md) - real-app PostgreSQL-backed browser, accessibility, security, and performance validation with ignored artifacts and cleanup.
- [Milestone status](milestones.md) - implemented baseline and next milestone themes.
- [Versioning](versioning.md) - SemVer policy, `VERSION`, changelog, and compatibility tracks.
- [Archived planning docs](archive/README.md) - completed planning records kept for historical context.

## Public-data rules for docs and screenshots

- Use only synthetic hostnames, users, IDs, IPs, event messages, prompts, graph nodes, and screenshots in tracked docs.
- Keep raw API responses, cookies, browser traces, generated agent settings, queue/state databases, endpoint telemetry, event-log exports, and lab evidence under ignored `.local/` paths.
- Never paste operator API credentials, enrollment tokens, per-agent API tokens, connection strings, private keys, cookies, real Windows usernames/hostnames, or collected client data into docs, examples, screenshots, issues, or pull requests.
- If a screenshot or example might contain private data, discard it locally and regenerate from synthetic fixtures before committing.

## Maintaining the wiki

When implementation changes affect behavior, contracts, setup, validation, screenshots, or operator workflows, update the relevant docs in the same change set. Use the checklist in [contributors.md](contributors.md#documentation-maintenance-checklist) before opening a pull request.
