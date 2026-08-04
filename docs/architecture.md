# Architecture

The Linux agent collects approved journal, paged inventory, health, and opt-in higher-tier sources. A disabled-by-default privacy router intercepts trusted Linux Audit Framework journal transport before L1; its allowlisted parser requires a separate declaration and exact approval and never installs rules or adds a second reader. Collected records are normalized into the v2 envelope, persisted in a local SQLite queue, and sent in bounded HTTPS batches. The server validates identity and deduplication metadata before writing PostgreSQL.

The ASP.NET Core service owns registration, ingestion, search, coverage, inventory, detections, alerts, cases, investigation graphs, administrative settings, and managed retention. Human or agent-driven review happens through `/api/v2` or the read-only `/mcp` Streamable HTTP endpoint. When explicitly configured, the same process also serves self-hosted static assets for the local read-only `/ui/traffic` interface; generated assets are not committed and normal .NET builds remain backend-only. A second loopback-only viewer process may enforce read-only PostgreSQL transactions, but it remains a view over the writable service's database and is not an ingestion or MCP replacement.

MCP runs in the same process and reads the same repositories. It cannot mutate SIEM state, execute host commands, call model providers, or make outbound AI requests. REST remains the versioned automation and mutation boundary.

Network geography aggregates retained `linux-network-socket-snapshot-diff` and optional `linux-network-flow-summary` events with a remote IP and applies time ranges to `event_time`. PostgreSQL remains the event source of truth; the browser never reads an agent queue or current host sockets. A separate private SQLite file holds normalized approximate geolocation/ASN cache entries and provider quota counters, never raw provider responses. The progressive worker sends only validated public destination IPs to the configured provider; MCP correlation is cache-only and cannot initialize or write that cache. Browser tile requests go directly to the configured tile service and contain neither the SIEM bearer nor telemetry.

Version 2 requires a fresh database. The schema installer refuses databases with existing public tables; there is no 1.x in-place migration path.

## Trust and reliability flow

The endpoint treats Linux sources as untrusted bounded input, writes an event to the private SQLite queue before advancing its collected checkpoint, and deletes it only after an accepted/duplicate acknowledgement is durable. The server authenticates the claimed agent, validates canonical v2 identity/source/data-handling metadata, writes PostgreSQL transactionally, and evaluates detections from the canonical stored row. Deterministic IDs make retries idempotent.

Review repositories apply query, row, time, nested-collection, and retention bounds. MCP adds a final secret-shape filter, omits raw payloads from event search, labels telemetry untrusted, and records read-only tool audit metadata. Collected content never enters authorization or tool-selection logic. See [Threat model](threat-model.md).

## Deployment and recovery boundary

The normal personal deployment is one service identity and dedicated fresh PostgreSQL database behind HTTPS. Endpoint install/upgrade is preflight-first and limited to fixed product paths and a systemd unit; optional L3/L4 collection is disabled until exact plans and private validation pass. The optional kernel-flow lifecycle separately installs a signed fixed helper, locked identity, socket, and exact three-capability profile; it never changes boot, firewall, authentication, audit, sysctl, module, package, or network policy. PostgreSQL backup/restore, VM snapshot/recreation, and the agent's durable queue/checkpoints are separate recovery layers.
