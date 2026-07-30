# Architecture

The Linux agent collects approved journal, inventory, health, and opt-in higher-tier sources. Linux Audit Framework ingestion remains an explicit unsupported capability; the agent does not install rules or read audit records through a separate collector. Collected records are normalized into the v2 envelope, persisted in a local SQLite queue, and sent in bounded HTTPS batches. The server validates identity and deduplication metadata before writing PostgreSQL.

The ASP.NET Core service owns registration, ingestion, search, coverage, inventory, detections, alerts, cases, investigation graphs, administrative settings, and managed retention. It serves JSON only. Human or agent-driven review happens through `/api/v2` or the read-only `/mcp` Streamable HTTP endpoint.

MCP runs in the same process and reads the same repositories. It cannot mutate SIEM state, execute host commands, call model providers, or make outbound AI requests. REST remains the versioned automation and mutation boundary.

Version 2 requires a fresh database. The schema installer refuses databases with existing public tables; there is no 1.x in-place migration path.

## Trust and reliability flow

The endpoint treats Linux sources as untrusted bounded input, writes an event to the private SQLite queue before advancing its collected checkpoint, and deletes it only after an accepted/duplicate acknowledgement is durable. The server authenticates the claimed agent, validates canonical v2 identity/source/data-handling metadata, writes PostgreSQL transactionally, and evaluates detections from the canonical stored row. Deterministic IDs make retries idempotent.

Review repositories apply query, row, time, nested-collection, and retention bounds. MCP adds a final secret-shape filter, omits raw payloads from event search, labels telemetry untrusted, and records read-only tool audit metadata. Collected content never enters authorization or tool-selection logic. See [Threat model](threat-model.md).

## Deployment and recovery boundary

The normal personal deployment is one service identity and dedicated fresh PostgreSQL database behind HTTPS. Endpoint install/upgrade is preflight-first and limited to fixed product paths and a systemd unit; optional L3/L4 collection is disabled until exact plans and private validation pass. PostgreSQL backup/restore, VM snapshot/recreation, and the agent's durable queue/checkpoints are separate recovery layers. Challenger SIEM never changes endpoint boot, firewall, authentication, audit, kernel, package, or network policy to improve coverage.
