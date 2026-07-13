# Linux host coverage specification

Status: agent/service foundation, bounded host/security inventory, passive L1, opt-in structured journald L2 security pack, and explicit-opt-in L3 agent self-integrity snapshot implemented; audit/eBPF/broad file collectors remain deferred
Specification version: 0.1
Primary audience: SIEM engineers, Linux agent engineers, detection engineers, operators

## Purpose and current boundary

This document defines the target Linux host visibility model for Challenger SIEM and distinguishes implemented L1/L2 journal/inventory capability from optional L3+ coverage. Challenger SIEM remains Windows-first: the supported Linux agent/service provides enrollment, heartbeat, durable queueing, safe lifecycle packaging, bounded read-only host/security-posture inventory, one passive cursor-based system-journal reader, an opt-in L2 logical security source pack, and a disabled-by-default explicit-opt-in L3 agent self-integrity snapshot. Linux Audit Framework, syslog-file, role, eBPF, and broad/live file-integrity collectors remain planned or deferred; server-generated Linux source-catalog overlays are implemented. The [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) defers audit/eBPF and permits only the no-watch allowlisted agent self-integrity source.

Like the [Windows full-coverage specification](windows-host-full-coverage-spec.md), this specification treats collection, reliability, source health, operational verification, and detection prerequisites as one coverage problem. It differs where Linux distributions, init systems, audit frameworks, and role logs are heterogeneous. A host can report only the level whose mandatory applicable sources are healthy; unavailable or operator-disabled sources must be shown as gaps or approved exceptions, never silently treated as covered.

## Coverage levels

| Level | Name | Mandatory applicable capability | Intended use |
| --- | --- | --- | --- |
| L0 | No coverage | Agent absent, unsupported, or not heartbeating | Not acceptable for monitored assets |
| L1 | Passive native baseline | Read-only system/service logs, authentication/account activity, agent health, durable queue, and source positions | Safe initial rollout and 24-hour soak |
| L2 | Linux security baseline | L1 plus structured login/session, SSH, sudo/su, package, service, scheduler, firewall, kernel/security-control, and agent/log-tamper journal telemetry with bounded inventory/source-health evidence; audit remains explicitly unsupported | Opt-in canary only until the private seven-day soak passes |
| L3 | Enhanced endpoint telemetry | L2 plus the explicitly approved agent self-integrity snapshot; later eBPF/kernel or broader targeted integrity sources require separate approval and evidence | Optional higher-fidelity coverage |
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
| Linux audit log | L2 optional future source | Authentication, identity, execution, policy, syscall, integrity, and tamper records selected by existing policy | Current catalog reports `unsupported`; no collector or policy enablement is included |
| Package manager journal records | L2 | Install, update, and remove outcomes where package-manager journal evidence exists | Implemented as one logical family on the durable journal cursor |
| Service and scheduler journal records | L2 | systemd unit changes, cron execution, and systemd timer metadata | Implemented as logical service/scheduler families plus bounded inventory |
| Host/security inventory | L2 | OS/kernel, packages, users/groups, services, listeners, mounts, firewall/SSH/MAC/Secure Boot state, and agent permission posture | Bounded current-state snapshots are implemented; inventory-diff events remain planned |

The implemented inventory catalog uses fixed providers and exact paths for host/kernel identity, users/groups, systemd services/units/timers, dpkg/rpm packages, apt/dnf available updates, interfaces/listeners, filesystem types, nftables/firewalld/UFW state, selected SSH settings, AppArmor/SELinux, Secure Boot, and agent file permission/fingerprint metadata. A non-systemd host reports service/unit/timer snapshots as `not_applicable`; the agent does not assume that a missing provider is healthy. Server-side Linux detections use this same prerequisite model: missing, stale, denied, throttled, or gapped source evidence lowers confidence or suppresses evaluation and is documented as a visibility gap, not as no-threat evidence.

The implemented `linux-journal-l1` source directly invokes the fixed systemd `journalctl` machine-readable JSON interface, with no shell or arbitrary command/path configuration. L1 retains kernel, boot, service, authentication, and core-system classification. When configured for L2, the same reader/cursor additionally classifies stable logical sources for login/session, SSH, sudo/su, cron/timers, package management, firewall, kernel/security modules, service changes, and agent/log tamper. Structured process/user/PAM/network/result/action/unit/package/module fields take precedence; fixed 4,096-character/50 ms message parsing may supplement missing evidence only. It persists each normalized event to Agent.Core before its collected cursor and persists accepted/duplicate acknowledgement before deletion. Rotation/vacuum/invalid cursor, denial, empty source, malformed/binary data, reorder/duplicate, backlog, and throttle remain explicit.

### Optional advanced sources

These sources require an explicit operator decision and cannot be prerequisites for L1 or a default install:

- eBPF-based process, network, DNS, file, or kernel-security telemetry, with pinned resource limits and kernel compatibility checks;
- targeted file-integrity monitoring beyond the implemented agent-owned snapshot source;
- producer/configuration changes that enable additional Linux Security Module logging (normalization of already-journaled AppArmor/SELinux evidence is implemented);
- producer/configuration changes that enable firewall logging (normalization of already-journaled UFW/nftables/firewalld evidence is implemented as optional L2);
- audit rules added for an approved use case;
- container runtime and orchestration audit sources;
- targeted application audit plugins or structured logs.

Optional collectors must degrade independently. Failure or overload in one must not stop heartbeats, queue delivery, or other collectors. See the [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) for the current adopt/defer/reject decision. The only enabled-by-configuration L3 source is the explicit-opt-in agent self-integrity snapshot; audit, eBPF, and broad/live FIM remain absent.

### Unsupported or not applicable

The target does not include packet payload capture, keystroke capture, unrestricted file-content collection, memory scraping, secret-store harvesting, browser/session-store collection, or general-purpose command execution. Windows Event Log, ETW, Sysmon, Defender, registry, and Windows role channels are not applicable to Linux. Unsupported kernels, distributions, absent facilities, and host-role mismatches must be reported as `unsupported` or `not_applicable`, distinct from `disabled`, `error`, and `stale`.

## Implemented L1 and opt-in L2 journal boundary

Journal polling defaults to 500 records every five seconds and accepts only bounded machine-readable records. Input is capped before parsing; allowlisted retained fields, messages, command lines, and raw JSON are capped and disclose redaction/truncation through v1 `data_handling`. Secret-shaped assignments and non-text values are removed before durable queue insertion. Deterministic IDs bind agent/logical-source/cursor and are validated by the existing server contract. `TargetCoverageLevel=L1` is the default; only `L1`/`L2` are accepted.

The shared Linux catalog declares mandatory, optional, and role-specific sources, applicable roles, prerequisites, event families, validation scenarios, and applicability. Health adds prerequisite/event-family state maps plus distinct `degraded`, `permission_denied`, and `unsupported` values. Mandatory applicable entries determine level; an applicable role-specific entry becomes mandatory, while optional, not-applicable, and server-approved excepted entries are accounted separately. The Linux Audit Framework entry is explicitly unsupported and cannot be mistaken for healthy collection.

Health reports latest event/lag/silence/rate, durable collected cursor, accepted/duplicate acknowledged cursor, gap/error/permission/throttle and degraded/recovery transition state, empty/collector/config/version state, resource RSS where available, queue bytes/depth/oldest age, send/backoff state, poison/drop counters, and bounded anomaly counters. Queue pressure pauses reads without dropping unacknowledged events. The collector does not alter journal retention, service settings, authentication, groups, ACLs, kernel state, or policy. Linux Audit Framework, syslog-file fallback, and role sources are not part of this source.

## Implemented inventory boundary

The inventory service starts after a default 30-second delay and runs independently of heartbeat, durable queue drain, and future passive work. Its default interval is one hour, with an enforced five-minute minimum; runs cannot overlap. A collection is capped at 20 snapshots, 200 items per snapshot, and a default 256 KiB serialized payload. Fixed command/file operations have individual timeouts and output caps, cancellation, a whole-collection deadline, and explicit deterministic truncation.

Each snapshot uses one exact state: `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`. Absence, denied access, unsupported applicability, malformed output, and timeouts are visible rather than inferred as healthy. These snapshots use the existing generic `/api/v1/agents/inventory` contract. Server telemetry coverage now maps those states honestly for Linux, but inventory presence alone never establishes journal event coverage.

The collection is read-only and does not broadly scan the host. It does not mutate packages, services, audit, firewall, SSH, kernel, AppArmor/SELinux, Secure Boot, or agent permissions. Allowlisted parsers omit secrets and raw source output. Agent configuration/executable ownership, mode, and regular-file status plus a bounded SHA-256 executable fingerprint are observable change posture only, not trusted or tamper-proof attestation.

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

The repository includes a bounded 5,000-record synthetic normalization regression test. It requires at least 500 records/second, less than 250 MiB managed allocation, raw records below 4 KiB, and completion within ten seconds. These thresholds catch gross regressions and align memory/throughput with the L1 SLO, but they do not measure steady-state process CPU, RSS, disk-write rate, distribution compatibility, or soak duration. Those measurements remain rollout gates and must not be inferred from the unit benchmark.

## Staged rollout, soak, and rollback

1. **Preflight:** produce a read-only plan listing detected platform, requested level, sources, paths, groups/capabilities, expected volume, limits, exclusions, and all proposed host changes. L1 must propose no security-policy mutation.
2. **L1 canary:** deploy to a small representative cohort and soak for at least **24 continuous hours**. Validate source positions, queue/acknowledgements, restart/rotation handling, privacy exclusions, source health, and every performance SLO.
3. **L1 decision:** expand only after reviewed evidence passes. Roll back or disable the offending collector on any immediate rollback condition.
4. **L1+L2 canary:** after L1 passes, set `TargetCoverageLevel=L2` for a representative cohort and soak for at least **seven continuous days**. Include normal workload, rotation, outage/drain, upgrade/restart, and role windows. This private gate has not been performed or claimed by the L2 implementation.
5. **Advanced rollout:** L3/L4 sources require separate plans, approvals, benchmarks, rollback commands, and increasingly broad canaries. No cohort expansion is automatic.

Immediate rollback criteria are: suspected credential/secret or excluded-data collection; unauthorized audit, firewall, authentication, kernel, service, or security-policy mutation; host instability or application impact; queue/state corruption or confirmed silent event loss; persistent source duplication/gaps; uncontrolled disk growth; inability to uninstall/disable safely; or breach of any resource SLO after bounded automatic throttling. Stop expansion, disable/remove the responsible component using the approved rollback plan, preserve only sanitized diagnostics in approved runtime storage, verify host policy/state, and document the gap before retry.

## Acceptance and implementation gates

The bounded inventory slice has synthetic parser, state, cancellation, scheduling, item/payload-cap, large-list, privacy, and queue/passive non-interference coverage. L1 has deterministic identity, queue/checkpoint, restart, acknowledgement/outage/replay, rotation/vacuum/invalid-cursor, permission, malformed/binary, empty, duplicate/reorder, pressure, and benchmark coverage. L2 adds hand-authored positive/negative fixtures for every source family, structured precedence, ambiguous/malformed/oversized behavior, catalog/coverage/portable ingest-search tests, and a 5,000-record bounded performance guard. These checks do not satisfy supported-distribution host benchmarks, the private 24-hour L1 canary, or the private seven-day L1+L2 soak; none is claimed. Additive API/schema work preserves `/api/v1` and `contracts/v1/`.

Security boundaries and mutation approval are authoritative in [linux-agent-security.md](linux-agent-security.md). Use [linux-local-host-validation.md](linux-local-host-validation.md) for the sanitized L1/L2 soak runbook, recovery-check template, L3 opt-in guardrails, and truthful live-soak blocker when no authorized target/window is supplied. Public examples and evidence must follow [the repository public-data rules](index.md#public-data-rules-for-docs-and-screenshots).
