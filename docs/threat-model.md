# Threat model

Challenger SIEM is a Linux-only service whose primary boundary is headless REST/MCP, with an optional local read-only traffic interface. Its trust boundaries are the Linux host, the endpoint agent and private queue, HTTPS transport, the ASP.NET Core ingestion/review service, PostgreSQL, the private geolocation cache and provider, the browser/tile service, and authenticated external REST/MCP clients. Collected text is evidence, never an instruction or authorization source.

## Protected assets

- enrollment, per-agent, and service credentials;
- endpoint configuration, executable, queue, checkpoints, and source-health state;
- normalized events, bounded raw payloads, inventory, alerts, evidence, cases, graphs, audit records, and retention metadata;
- the optional normalized geolocation cache, operator-selected origin, and direct-loopback dashboard boundary;
- host availability and existing boot, network, authentication, firewall, audit, kernel, mandatory-access-control, package, and service policy;
- contract integrity across `/api/v2`, `contracts/v2`, and `Challenger.Siem.Contracts.V2`.

## Adversaries and failure modes

The design assumes an unprivileged local user may try to read or inject telemetry; a compromised producer or registered agent may send malicious, conflicting, secret-bearing, oversized, replayed, or instruction-bearing content; a network attacker may intercept or replay traffic; an external agent may over-trust collected text; an operator may misconfigure credentials, retention, or coverage; and storage, queues, sources, services, or networks may fail.

Root or kernel control can suppress or forge host evidence. Challenger SIEM reports observable gaps and changes but does not claim tamper-proof collection against that adversary.

## Security controls

| Threat | Primary controls |
| --- | --- |
| Credential theft or confusion | Separate enrollment, per-agent, and service credential domains; constant-time checks; no credential logging; HTTPS outside isolated development; ignored/secret-managed configuration |
| Cross-agent spoofing or replay | Authenticated agent identity, deterministic event IDs, `(agent_id,event_id)` uniqueness, canonical stored-row detection retry, durable acknowledgements |
| Malformed or unbounded telemetry | Linux-only closed source catalog, schema/request validation, byte/row/time limits, structured-field bounds, database query limits, queue limits |
| Secret-bearing collected content | Agent-side sanitation and data-handling metadata plus an independent final MCP secret-shape filter; MCP event search omits raw payloads |
| Prompt injection through evidence | MCP result metadata marks telemetry untrusted/read-only; prompts require fact/inference separation; collected content cannot select tools, expand scope, authorize mutations, or change instructions |
| Unauthorized mutation | MCP tools are read-only, idempotent, non-destructive, and closed-world; REST mutations require service authentication, validation, auditing, optimistic versioning, and explicit confirmation for high-impact actions |
| Unauthorized dashboard access or loopback-origin confusion | No browser credential; only exact bounded geography `GET`/`HEAD` routes receive an implied read-only principal, and only when client socket, listener socket, and `Host` are loopback with no forwarding headers or `Authorization`; other REST and all MCP remain service-authenticated; self-hosted bundles, restrictive CSP, framing/device denial, and cross-origin referrer path suppression |
| Viewer pointed at the wrong telemetry store | PostgreSQL is the explicit sole event source; operator guide requires matching the writable backend connection and checking retained-evidence freshness; presets are documented as `event_time` ranges; the dedicated viewer is not presented as an ingest/MCP replacement |
| Read-only viewer mutation | PostgreSQL sessions force `default_transaction_read_only`; non-GET `/api/v2` requests are rejected; the implied principal reaches only bounded aggregate geography and a 25-row event projection that omits raw/normalized payloads; liveness and retention writers do not start; agents remain pointed at the normal writable backend; geolocation writes only its separate private cache |
| Geolocation database tampering, disclosure, or provider abuse | Feature disabled by default; local mode requires absolute operator-managed MMDB paths, rejects direct symlinks and oversized files, performs no provider request, versions cache records by database build, and stores only normalized results. Remote mode retains the public-address allowlist, HTTPS endpoint, bounded queue/body/timeout/retry and UTC-day quota; no raw provider response or secret-bearing log is retained. |
| Tile-service disclosure or overload | Visible-viewport browser requests only; configurable HTTPS URL; no prefetching; ordinary cache behavior; no SIEM bearer or telemetry body; visible attribution |
| Destructive retention | Managed-table allowlist, protected-table denylist, dry-run default, hard capacity bound, advisory lock, bounded batches, exact confirmation phrase for manual execution, audit record |
| Silent collection loss | Queue-before-checkpoint, acknowledgement-before-delete, bounded retry/backoff, poison/gap counters, source freshness, explicit missing/degraded/denied/stale states |
| Agent/server version skew | Coordinated major-version deployment, authenticated versioned-route preflight before endpoint replacement, durable queue preservation, and exact prior-state rollback; generic health alone is not treated as compatibility evidence |
| Privilege or host-policy expansion | Non-root steady-state agent and empty capability set by default; optional process visibility is separately plan-bound to only `CAP_SYS_PTRACE`; optional kernel network telemetry is signed and isolated in a locked helper with exactly `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_ADMIN`; both require VM validation and exact rollback, with no audit/firewall/authentication/sysctl/module mutation |
| Supply-chain or release leakage | Public-repository safety validation, synthetic fixtures only, generated/runtime paths ignored, bounded self-contained agent bundle |

## MCP-specific boundary

`/mcp` uses the deployment-supplied service bearer and records secret-safe tool audit metadata. Agent registration/heartbeat/inventory/ingest routes bypass that service scheme and validate only their enrollment or per-agent credential, preventing valid agent traffic from becoming false service-auth failures. Every MCP tool is declared read-only, non-destructive, idempotent, closed-world, and structured. Search is capped at 100 rows and 168 hours, cursor paginated, and raw event payloads are omitted. One-event review returns only the already bounded record after final secret-shape filtering. Nested collections, inventory, timelines, offsets, links, and prompts have independent limits. `siem_get_traffic_map_link` validates credential-free filters and never queries the provider or embeds the bearer. There is no model-provider client or outbound AI request in the service.

## Residual risks

- Best-effort pattern filtering cannot prove arbitrary text contains no secret; protect MCP credentials and restrict network access even when filtering is enabled.
- A valid service bearer has the single-user deployment's full review/administration authority on REST. Use it only with trusted clients and never place it in URLs or tracked files.
- Any process or browser already running as the local user may request the loopback dashboard's bounded geography projection. The loopback exception is a single-user convenience boundary, not user isolation; do not expose, proxy, or bind the dashboard to another interface.
- Snapshot polling can miss short-lived processes/sockets and cannot prove exact lifecycle timing or process-to-socket attribution. Boot-scoped process identities prevent known PID-reuse merging when present, but nullable or fallback PID/image correlations remain explicitly uncertain; observed command lines are provenance-labeled observations and are not proof of execution or network causality.
- Remote mode discloses public destination IPs to a geolocation provider, while local mode avoids that disclosure but depends on the provenance, freshness, and integrity of separately obtained databases. Browser tile requests remain an external dependency. Approximate results may be stale, wrong, provider/CDN/VPN/anycast-oriented, unavailable, or incomplete.
- Journal visibility depends on existing host permissions and producer logging. Missing evidence must not be interpreted as safety.
- Live audit parsing, eBPF sources other than the fixed no-payload kernel network flow helper, broad file integrity, packet payloads, process memory/environment, application log files, and automatic response remain deliberately absent.
- Long-duration private VM/current-host soaks are release evidence, not properties unit tests can establish.
- A 2.x agent cannot deliver to a v1-only backend. Failed delivery remains durable but creates a coverage gap until the matching v2 service is available or the prior agent is restored.
- The managed .NET agent JIT needs executable-memory transitions and is incompatible with systemd `MemoryDenyWriteExecute`; the unit retains non-root execution, `NoNewPrivileges`, filesystem/device/kernel/control-group restrictions, and resource bounds. Capability sets remain empty unless the separately approved process-visibility profile grants only `CAP_SYS_PTRACE`; that profile materially increases compromise impact even with its direct process-inspection syscall deny list.

The detailed endpoint privacy and least-privilege model remains in [Linux agent security](linux-agent-security.md). Operational stop gates are in [Linux local-host validation](linux-local-host-validation.md).
