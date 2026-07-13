# Architecture

## Goal

Build a custom SIEM pipeline focused first on Windows endpoints.

```text
Windows Endpoint -> Custom Windows Agent --\
Linux Endpoint   -> Custom Linux Agent -----> HTTPS Log Ingestion Server
  -> PostgreSQL Event Storage
  -> Search / Review API
  -> Web Review Console
```

## MVP scope

- Windows-first endpoints plus the supported Linux L1/L2 service path.
- Custom C#/.NET Windows and Linux service agents.
- Custom ASP.NET Core ingestion, review API, and server-hosted web console.
- PostgreSQL storage with structured columns plus JSONB raw event data.
- No Docker and no proprietary SIEM/logging products.

## Server flow

```text
Agent registration
  -> validate enrollment token
  -> create/update agent record
  -> issue per-agent API token

Event ingestion
  -> validate per-agent bearer token
  -> validate batch and event schema
  -> deduplicate by agent_id + event_id
  -> assign server ingest_time
  -> store structured fields and raw JSON

Search/review API
  -> validate review API token
  -> apply filters
  -> return normalized event envelopes

Web review console
  -> validate operator API credential on login
  -> issue HTTP-only operator session cookie
  -> query PostgreSQL-backed repositories
  -> render dashboard, agent inventory, event search, event detail, and about pages
```

## Agent flow

```text
Read Windows Event Log record
  -> normalize to v1 EventEnvelope
  -> persist to local queue before send
  -> send queued events in batches
  -> delete only after server acknowledgement
  -> update channel position/bookmark after durable queue write
```

## Initial Windows channels

Required for agent MVP:

- `Security`
- `System`
- `Application`

Default optional L2/L3 source manifest channels:

- `Windows PowerShell`
- `Microsoft-Windows-PowerShell/Operational`
- `Microsoft-Windows-Windows Defender/Operational`
- `Microsoft-Windows-TaskScheduler/Operational`
- `Microsoft-Windows-WMI-Activity/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`
- `Microsoft-Windows-WinRM/Operational`
- `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`
- `Microsoft-Windows-GroupPolicy/Operational`
- `Microsoft-Windows-CodeIntegrity/Operational`
- `Microsoft-Windows-AppLocker/EXE and DLL`
- `Microsoft-Windows-AppLocker/MSI and Script`
- `Microsoft-Windows-AppLocker/Packaged app-Execution`
- `Microsoft-Windows-Sysmon/Operational`

## Linux host coverage

The Linux agent implements passive L1 system-journal collection, an opt-in L2 logical security source pack, bounded host/security inventory, and a disabled-by-default explicit-opt-in L3 agent self-integrity snapshot. One fixed systemd machine-readable reader/cursor carries L1 plus structured login/session, SSH, sudo/su, scheduler, package, firewall, kernel/security-module, service-change, and agent/log-tamper normalization. The self-integrity source snapshots only strict agent-owned paths using metadata and bounded digests, emits additive `agent_health` events, and changes no host policy. Audit is explicitly unsupported by the current pack; syslog-file, role, eBPF, broad/live file-integrity, and other advanced collectors remain planned or deferred. L2 and L3 rollout recommendations remain blocked on private approval/soak gates. The authoritative design is split between the [Linux host coverage specification](linux-host-coverage-spec.md), [Linux agent security design](linux-agent-security.md), and L3 ADR.

## Cross-platform contract boundary

The additive v1 contract represents typed Linux journal, audit, inventory-diff, and agent-health records without Windows identifiers. Portable manifest/health now also carry optional requirement/applicable-role and prerequisite/event-family state metadata plus explicit degraded/denied/unsupported states. PostgreSQL ingestion, deduplication, persistence, portable search, Linux catalog coverage overlays, and bounded Linux detection alert execution continue through `/api/v1`. Linux alerts persist exact rule versions and evidence event IDs while prerequisite gaps lower confidence or suppress evaluation. The deployed agent emits only `linux_journal` events; its audit manifest is intentionally unsupported and no audit event collector is enabled.

## Reliability decisions

- Server deduplication is based on `(agent_id, event_id)`.
- Existing Windows deterministic IDs retain their current inputs; new Linux contracts declare ordered `sha256_uuid` inputs explicitly.
- Agents must maintain durable local source position state and a durable queue.
- Events are queued before the collected checkpoint advances; queue deletion and acknowledged checkpoint advancement happen only after accepted/duplicate acknowledgement.
- Collected and acknowledged cursor/sequence positions are reported independently so backlog/gaps remain visible.
- Heartbeats report bounded queue bytes/depth/oldest age, send/backoff/recovery state, poison/drop counters, and source silence/gap/permission transitions where available; unsupported values remain null/unknown rather than fabricated zero.
- Managed telemetry retention targets 30 days by default, reports 70/85/95/100% capacity state against a default 100 GiB ceiling, and deletes only allowlisted PostgreSQL telemetry rows in advisory-locked bounded batches. Emergency cleanup removes optional telemetry before mandatory event telemetry, oldest first, and alert evidence remains as immutable references with explicit missing-underlying-telemetry state.
- Server ingest time is generated server-side and does not trust client-provided ingest timestamps.

## Security decisions

- HTTPS is required outside local development.
- Registration uses an enrollment token.
- Registration returns a per-agent API token.
- Agent API tokens are stored hashed server-side.
- Review/search API uses a separate operator API credential for the MVP.
- Web review login uses the same operator API credential and stores only an HTTP-only session cookie in the browser.
- Secrets must not be logged or committed.


## Shared agent reliability core

`agent/Agent.Core/` targets platform-neutral `net8.0` and owns the durable SQLite queue, deterministic identity, JSON serialization, secret-redacted configuration hashing, HTTP v1 transport, acknowledgement selection, and bounded retry schedule. `WindowsAgent` consumes that single implementation while retaining Event Log collection, DPAPI secret protection, Windows state paths, inventory, and service hosting. The core project has no Windows target framework or Event Log, registry, DPAPI, PowerShell, or Windows-service package dependency. Queue-before-checkpoint and accepted/duplicate-before-delete ordering remain unchanged.
