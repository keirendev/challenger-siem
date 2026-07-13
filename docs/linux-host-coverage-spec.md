# Linux host coverage specification

Status: agent/service foundation implemented; Linux collectors remain planned
Specification version: 0.1
Primary audience: SIEM engineers, Linux agent engineers, detection engineers, operators

## Purpose and current boundary

This document defines the target Linux host visibility model for Challenger SIEM. It is a design contract for future work, not a statement of current product behavior. Challenger SIEM remains Windows-first: a supported Linux agent/service foundation now provides enrollment, heartbeat, inventory transport, durable queueing, and safe lifecycle packaging; Linux collection and source-health remain planned.

Like the [Windows full-coverage specification](windows-host-full-coverage-spec.md), this specification treats collection, reliability, source health, operational verification, and detection prerequisites as one coverage problem. It differs where Linux distributions, init systems, audit frameworks, and role logs are heterogeneous. A host can report only the level whose mandatory applicable sources are healthy; unavailable or operator-disabled sources must be shown as gaps or approved exceptions, never silently treated as covered.

## Coverage levels

| Level | Name | Mandatory applicable capability | Intended use |
| --- | --- | --- | --- |
| L0 | No coverage | Agent absent, unsupported, or not heartbeating | Not acceptable for monitored assets |
| L1 | Passive native baseline | Read-only system/service logs, authentication/account activity, agent health, durable queue, and source positions | Safe initial rollout and 24-hour soak |
| L2 | Linux security baseline | L1 plus read-only Linux Audit Framework events when already configured, process/package/service/scheduler/firewall/security-control telemetry, inventory diffs, and source-health checks | Planned practical default after seven-day soak |
| L3 | Enhanced endpoint telemetry | L2 plus explicitly approved eBPF or equivalent kernel telemetry and targeted file-integrity watches | Optional higher-fidelity coverage |
| L4 | Full target coverage | L3 plus applicable role packs, policy-drift checks, correlation/detections, and validated source/performance SLOs | Planned target for high-value hosts |

`L1` and `L2` are principally passive: the agent consumes sources already available and reports missing prerequisites. A source is not mandatory when the host platform or role makes it inapplicable, but the reason must be reported. L3/L4 never authorize automatic host-policy changes.

## Source classes

### Mandatory passive sources

These sources are mandatory when present on a supported host and must be consumed without changing their producer configuration:

| Source | Minimum level | Target signal | Position/reliability expectation |
| --- | --- | --- | --- |
| systemd journal | L1 on systemd hosts | Kernel, service, authentication, scheduler, and application unit events | Durable cursor plus boot ID; detect vacuum/rotation and cursor invalidation |
| Syslog files (`/var/log/syslog`, `/var/log/messages`, or distribution equivalent) | L1 when journal coverage is absent or incomplete | System and daemon events | Device/inode, offset, rotation identity, truncation detection |
| Authentication logs (`auth.log`, `secure`, journal equivalents) | L1 | Login, SSH, PAM, `sudo`, account and session activity | Same durable source-position guarantees |
| Agent self-health | L1 | Queue, send/acknowledgement, collector state, resource use, config identity, gaps | Heartbeat independent of event volume |
| Kernel log stream exposed through journal/syslog | L1 | Boot, module, OOM, audit and security-control messages | Use passive journal/file source; do not reconfigure kernel logging |
| Linux audit log | L2 only when audit is already enabled and readable | Authentication, identity, execution, policy, syscall, integrity, and tamper records selected by existing policy | Track serial/boot identity and rotation; report policy limitations |
| Package manager history/logs | L2 | Install, update, remove, repository and signature outcomes | File cursor or bounded snapshots/diffs |
| Service and scheduler state | L2 | systemd unit changes, cron/at configuration and execution metadata | Passive logs plus bounded metadata snapshots |
| Host/security inventory | L2 | OS/kernel, packages, users/groups, services, listeners, modules, security-control state | Periodic bounded snapshots and change events |

A future implementation must define supported distributions and exact paths/providers through tested source manifests rather than assuming every host uses systemd or a particular log layout.

### Optional advanced sources

These sources require an explicit operator decision and cannot be prerequisites for L1 or a default install:

- eBPF-based process, network, DNS, file, or kernel-security telemetry, with pinned resource limits and kernel compatibility checks;
- targeted file-integrity monitoring for approved high-value paths;
- Linux Security Module events from SELinux, AppArmor, or another active framework;
- firewall telemetry from nftables, iptables, firewalld, or uncomplicated firewall when already logged;
- audit rules added for an approved use case;
- container runtime and orchestration audit sources;
- targeted application audit plugins or structured logs.

Optional collectors must degrade independently. Failure or overload in one must not stop heartbeats, queue delivery, or other collectors.

### Unsupported or not applicable

The target does not include packet payload capture, keystroke capture, unrestricted file-content collection, memory scraping, secret-store harvesting, browser/session-store collection, or general-purpose command execution. Windows Event Log, ETW, Sysmon, Defender, registry, and Windows role channels are not applicable to Linux. Unsupported kernels, distributions, absent facilities, and host-role mismatches must be reported as `unsupported` or `not_applicable`, distinct from `disabled`, `error`, and `stale`.

## Role-specific source packs

A host claiming L4 must enable each applicable approved pack or record an exception. Planned packs include:

| Role | Additional passive/approved sources |
| --- | --- |
| SSH bastion | sshd/PAM logs, session metadata, `sudo`, account/group changes, approved shell-audit metadata without keystrokes |
| Web server | nginx/Apache access and error metadata, service/unit events, TLS/config metadata, approved web-root integrity watches |
| Database server | PostgreSQL/MySQL/MariaDB audit and error logs when configured, service/config metadata, authentication outcomes; never database contents or credentials |
| DNS server | BIND/Unbound/systemd service and query-security logs when already enabled, zone/config metadata; query logging remains policy-controlled |
| File server | Samba/NFS authentication and access audit logs when configured, export/share metadata, targeted integrity watches |
| Container host | Docker/containerd/CRI runtime events and daemon logs; orchestrator control-plane audit is a separate explicitly configured source |
| Identity server | SSSD, Kerberos, LDAP/FreeIPA authentication and service logs with strict sensitive-field handling |

Each future pack must declare supported software/versions, source paths, privilege needs, volume model, sensitive fields, normalized fields, detection prerequisites, validation fixtures, and rollback steps.

## Telemetry and privacy contract

### Target normalized fields

Future Linux events should use the existing common envelope where possible and add structured fields only compatibly. Collect the minimum fields available and necessary for security review:

- event identity, provider/source, action/category/type/outcome/severity, source sequence or cursor, and bounded message;
- event, observed, queued, and server-ingest timestamps, boot ID, and clock-skew metadata;
- agent/host identity, distribution, OS/kernel version, architecture, timezone, and host role;
- user and group names/IDs, effective identity, session/login ID, authentication method and outcome;
- process ID/entity ID, parent, executable, bounded command line, working directory, capabilities, namespace/container context, and hashes only when policy permits;
- network direction/protocol and source/destination address/port, DNS metadata when available, and process correlation;
- file path/metadata/change type and hashes for targeted paths, without unrestricted content;
- package, service/unit, scheduler, kernel module, audit rule/status, firewall/security-control state, and collector-health metadata;
- original source record in bounded structured form, with truncation/redaction markers.

Command lines, paths, hostnames, usernames, addresses, and raw messages are sensitive telemetry. Collection, retention, access, and display must follow least-data principles and future role-based access/redaction controls.

### Explicit exclusions

Full telemetry **must not collect or retain**:

- credentials, passwords, tokens, cookies, authorization headers, or connection strings;
- secret stores, password databases, credential caches, wallet/keyring contents, or cloud credential files;
- private keys or private certificate material;
- browser profiles, browser/session stores, or unrestricted shell history;
- environment-value dumps (environment variable names may be collected only for an approved detection need without values);
- keystrokes, terminal input capture, clipboard contents, or screen contents;
- packet payloads or full packet capture;
- unrestricted file-content collection.

Parsers must redact known secret-bearing fields before queue insertion. Bounded raw records do not override these exclusions. Unexpected sensitive values require dropping or redacting the field, emitting secret-safe health metadata, and testing with synthetic fixtures only.

## Reliability and pressure behavior

The future agent must preserve the Windows design's durable queue, acknowledgement, deduplication, checkpoint-after-durable-write, bounded retry, poison-event isolation, and explicit gap reporting. Linux file rotation, journal vacuum, reboot/boot-ID changes, cursor invalidation, audit backlog/loss counters, and source truncation need first-class health states.

Under CPU, memory, disk, event-rate, or queue pressure, the agent must:

1. preserve heartbeat, source-health, queue integrity, and already-durable events;
2. apply bounded batches, rate limits, backoff, and collector-specific buffers;
3. throttle or pause optional L3 collectors before mandatory L1/L2 sources;
4. reduce expensive enrichment before dropping source records;
5. never delete unacknowledged records merely to hide pressure;
6. emit a bounded health event before any pause or drop when capacity permits;
7. record dropped/coalesced counts, affected source, reason, and interval without payload data;
8. recover gradually and expose the gap to operators.

Queue limits and retention policy must be explicit. Exhausted disk limits trigger safe collection pause/controlled shedding, not unbounded host disk consumption.

## Performance SLOs and benchmark method

Default planning SLOs for a supported, normally loaded host are:

- average agent CPU below **2%**;
- p95 agent CPU below **5%**;
- resident set size (RSS) below **250 MB**;
- average agent writes below **1 MB/s**;
- no sustained individual collector above **10% CPU for more than 60 seconds**.

Benchmarks must separate idle baseline, representative steady state, burst, server outage/queue growth, reconnect/drain, source rotation, and optional-collector workloads. The test matrix must include each supported distribution/kernel/init combination and each enabled level or role pack. Measure per-process and per-collector CPU, RSS, bytes written, queue size/age, collection-to-queue latency, delivery latency, event counts, loss/gap indicators, and source workload rate.

Only synthetic events and operator-owned test hosts may be used. Record benchmark tooling, host class, workload generator, configuration hash, sample interval, run duration, warm-up, percentiles, and pass/fail result under ignored local paths. Averages must cover the steady-state window; p95 uses the same fixed sampling interval. Bursts must demonstrate bounded recovery without silent loss. Failure of any SLO blocks rollout of the responsible level/collector until tuned or explicitly excepted.

## Staged rollout, soak, and rollback

1. **Preflight:** produce a read-only plan listing detected platform, requested level, sources, paths, groups/capabilities, expected volume, limits, exclusions, and all proposed host changes. L1 must propose no security-policy mutation.
2. **L1 canary:** deploy to a small representative cohort and soak for at least **24 continuous hours**. Validate source positions, queue/acknowledgements, restart/rotation handling, privacy exclusions, source health, and every performance SLO.
3. **L1 decision:** expand only after reviewed evidence passes. Roll back or disable the offending collector on any immediate rollback condition.
4. **L1+L2 canary:** after L1 passes, enable applicable passive L2 sources for a representative cohort and soak for at least **seven continuous days**. Include normal workload, rotation, outage/drain, upgrade/restart, and role-pack windows.
5. **Advanced rollout:** L3/L4 sources require separate plans, approvals, benchmarks, rollback commands, and increasingly broad canaries. No cohort expansion is automatic.

Immediate rollback criteria are: suspected credential/secret or excluded-data collection; unauthorized audit, firewall, authentication, kernel, service, or security-policy mutation; host instability or application impact; queue/state corruption or confirmed silent event loss; persistent source duplication/gaps; uncontrolled disk growth; inability to uninstall/disable safely; or breach of any resource SLO after bounded automatic throttling. Stop expansion, disable/remove the responsible component using the approved rollback plan, preserve only sanitized diagnostics in approved runtime storage, verify host policy/state, and document the gap before retry.

## Acceptance and implementation gates

A future implementation is not ready until it has synthetic parser/normalization fixtures, queue and checkpoint tests, rotation/reboot/gap tests, permissions and secret-redaction tests, supported-platform packaging tests, benchmark evidence, install/upgrade/uninstall plans, and operator-visible coverage states. Any API/schema additions must preserve `/api/v1` and `contracts/v1/` or introduce an explicit new version.

Security boundaries and mutation approval are authoritative in [linux-agent-security.md](linux-agent-security.md). Public examples and evidence must follow [the repository public-data rules](index.md#public-data-rules-for-docs-and-screenshots).
