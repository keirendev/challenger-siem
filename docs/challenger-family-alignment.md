# Challenger family alignment

Challenger SIEM follows the shared Challenger family principles for branding, operator UX, engineering practice, public-repository safety, and contract-driven compatibility.

## Product role

Challenger SIEM is the family security event ingestion and review platform. It owns:

- Windows-first SIEM ingestion and review APIs;
- event storage and query behavior;
- SIEM web-console workflows;
- detection, alert, investigation-graph, and source-health foundations;
- SIEM contracts consumed by compatible clients such as Challenger XDR.

Challenger SIEM should not absorb the responsibilities of sibling products. XDR owns endpoint telemetry client behavior, Challenger VM owns vulnerability management workflows, and Challenger SysAdmin owns reviewed administration operations.

## Branding and UX

- Use **Challenger SIEM** on first reference and **SIEM** only when context is clear.
- Keep operator-facing copy precise about current capability, MVP/lab-only behavior, and future work.
- Align web-console information architecture, workflows, badges, status language, accessibility, responsive behavior, and sensitive-field annotations with the product specification in [web.md](web.md).
- Use family terms such as `healthy`, `degraded`, `stale`, `offline`, `unknown`, `critical`, `high`, `medium`, `low`, and `informational` consistently across pages and docs.
- Use safety-focused confirmation flows for cleanup or mutation workflows.
- Keep screenshots, wireframes, examples, and issue/PR text synthetic and clearly labeled.

## Engineering and contracts

- Maintain SIEM/XDR compatibility through documented SIEM API and schema contracts, not shared implementation internals.
- Preserve `/api/v1` and `contracts/v1/` compatibility unless a deliberate new version is introduced.
- Keep PostgreSQL schema, API, agent, web, and contract changes documented with tests where practical.
- Follow [`versioning.md`](versioning.md) for version/changelog decisions.

## Safety baseline

The public-repository safety rules remain mandatory: do not commit secrets, tokens, connection strings, raw endpoint telemetry, event exports, queue/state databases, screenshots with real host/user data, local validation output, or Pi/coding-agent files.

Local multi-repo maintainers may also have access to shared Challenger developer guidance. Tracked SIEM docs must remain understandable from this repository alone; local agent guidance may reference workspace-level instructions when available.
