# Linux host coverage specification

Status: agent/service foundation, paged host/security inventory, passive L1/L2, approval-gated L3/L4, the disabled-by-default journal-audit router, and a separately signed/approval-gated no-payload Linux x86_64 eBPF network-flow source are implemented; long-duration private soaks, live audit parsing, and broad file collectors remain separately gated
Specification version: 0.1
Primary audience: SIEM engineers, Linux agent engineers, detection engineers, operators

## Purpose and current boundary



## Coverage levels

| Level | Name | Mandatory applicable capability | Intended use |
| --- | --- | --- | --- |
| L0 | No coverage | Agent absent, unsupported, or not heartbeating | Not acceptable for monitored assets |
| L1 | Passive native baseline | Read-only system/service logs, authentication/account activity, agent health, durable queue, and source positions | Safe initial rollout and 24-hour soak |
| L2 | Linux security baseline | L1 plus structured login/session, SSH, sudo/su, package, service, scheduler, firewall, kernel/security-control, agent/log-tamper, and optionally approved journal-backed audit telemetry with bounded inventory/source-health evidence | Opt-in canary only until the private seven-day soak passes; audit remains separately disabled by default |
| L3 | Enhanced endpoint telemetry | L2 plus explicitly approved process/socket snapshot differences and host behaviour health; agent self-integrity remains a separate optional L3 source | Optional higher-fidelity coverage with honest polling limitations |
| L4 | Full target coverage | L3 plus approval-gated policy-posture drift, a healthy rolling performance-SLO window, explicit role resolution, and every applicable role journal pack | Implemented for controlled VM validation; not a default or rollout claim until private canary/soak evidence passes |

`L1` and `L2` are principally passive: the agent consumes sources already available and reports missing prerequisites. A source is not mandatory when the host platform or role makes it inapplicable, but the reason must be reported. L3/L4 never authorize automatic host-policy changes.

## Source classes

### Mandatory passive sources

These sources are mandatory when present on a supported host and must be consumed without changing their producer configuration:

| Source | Minimum level | Target signal | Position/reliability expectation |
| --- | --- | --- | --- |
| systemd journal | L1 on systemd hosts | System-only by default; optional system plus user-journal records already readable by the service identity | Durable cursor plus boot ID; independently verify system visibility and detect scope transition, vacuum/rotation, and cursor invalidation |
| Syslog files (`/var/log/syslog`, `/var/log/messages`, or distribution equivalent) | L1 when journal coverage is absent or incomplete | System and daemon events | Device/inode, offset, rotation identity, truncation detection |
| Authentication logs (`auth.log`, `secure`, journal equivalents) | L1 | Login, SSH, PAM, `sudo`, account and session activity | Same durable source-position guarantees |
| Agent self-health | L1 | Queue, send/acknowledgement, collector state, resource use, config identity, gaps | Heartbeat independent of event volume |
| Kernel log stream exposed through journal/syslog | L1 | Boot, module, OOM, audit and security-control messages | Use passive journal/file source; do not reconfigure kernel logging |
| Linux audit log | L2 optional source | Allowlisted authentication/session, authorization syscall, MAC, policy, and integrity records already present on trusted audit journal transport | Router/collector implemented but disabled and undeclared; fixed exact approval required; no policy or producer enablement is included |
| Package manager journal records | L2 | Install, update, and remove outcomes where package-manager journal evidence exists | Implemented as one logical family on the durable journal cursor; bounded dpkg/rpm/pacman inventory resolves producer applicability separately from journal visibility |
| Service and scheduler journal records | L2 | systemd unit changes, cron execution, and systemd timer metadata | Implemented as logical service/scheduler families plus bounded inventory |
| Host/security inventory | L2 | OS/kernel, packages, users/groups, services, listeners, mounts, firewall/SSH/MAC/Secure Boot state, and agent permission posture | Bounded current-state snapshots are implemented |
| Process and network snapshot differences | L3 | Bounded procfs process metadata, TCP/UDP sockets/listeners, and observed/disappeared/changed polling evidence | Durable sequence checkpoints; incomplete scans cannot assert disappearance |
| Host behaviour samples | L3 | Coalesced load, CPU/memory/pressure, disk, and interface counters | Durable bounded samples; skipped intervals are reported and not backfilled in a storm |
| Approved policy-posture drift | L4 | Fixed bounded posture compared with an exact operator-approved baseline | Durable sequence checkpoints; incomplete scans cannot establish or clear drift |
| Declared-role journal packs | L4 when role applies | Structured web, database, DNS, file-server, container, or identity service journal evidence | Same durable journal cursor; successful quiet reads establish health separately from event-family observation |

The implemented inventory catalog uses fixed providers and exact paths for host/kernel identity, users/groups, systemd services/units/timers, dpkg/rpm/pacman packages, apt/dnf/pacman available updates, interfaces/listeners, filesystem types, nftables/firewalld/UFW state, selected SSH settings, AppArmor/SELinux, Secure Boot, and agent file permission/fingerprint metadata. Pacman collection uses only the read-only `-Q` and `-Qu` operations; a silent exit code 1 from `-Qu` is treated as an empty update set, while any output on stderr remains a visible failure. Aggregate package-inventory evidence resolves `linux-package-management` applicability without claiming journal visibility; see [Linux package-management evidence](linux-package-management-evidence.md) for the producer matrix and deterministic state table. Firewall evidence uses fixed read-only nftables JSON, firewalld state/log-denied, UFW status, and legacy iptables presence probes; it retains only aggregate producer/logging state and discards raw rules. See [Linux firewall evidence](linux-firewall-evidence.md) for the deterministic absent, disabled, quiet-enabled, unsupported, and denied matrix. A non-systemd host reports service/unit/timer snapshots as `not_applicable`; the agent does not assume that a missing provider is healthy. Server-side Linux detections use this same prerequisite model: missing, stale, denied, throttled, or gapped source evidence appears as an unavailable readiness state, while a directly matching accepted event is still evaluated at low confidence and documented as a visibility gap rather than no-threat evidence.

CachyOS/Arch-family posture additionally has fixed, bounded, unprivileged fallbacks for `/etc/ufw/ufw.conf`, `/etc/ssh/sshd_config.d/99-archlinux.conf`, `/sys/module/apparmor/parameters/enabled`, and the one UEFI `SecureBoot` variable. The UFW fallback emits only active/inactive and logging-enabled/disabled state; the SSH fallback emits only the three approved effective settings and applies documented OpenSSH defaults when neither fixed file sets them; the kernel/EFI fallbacks emit one enabled/disabled state. Malformed or unrecognized values fail closed. No fallback scans a directory, reads rules or unrelated configuration, installs a command, adds privilege, or changes host policy.

The implemented `linux-journal-l1` source directly invokes the fixed systemd `journalctl` machine-readable JSON interface, with no shell or arbitrary command/path configuration. It uses the fixed `--system` selector by default. The explicit `IncludeAccessibleUserJournals=true` mode omits both `--system` and `--user`, allowing the same reader to see all local journals already readable under existing service permissions while an independent system-only probe prevents user-only success from satisfying L1. L1 retains kernel, boot, service, authentication, and core-system classification. When configured for L2, the same reader/cursor additionally classifies stable logical sources for login/session, SSH, sudo/su, cron/timers, package management, firewall, kernel/security modules, service changes, and agent/log tamper. Package classification includes structured apt, dpkg, dnf, yum, rpm, PackageKit, and pacman/ALPM journal records, but does not read distribution-specific package-manager log files or treat an interactive package-manager command line as proof that a package change occurred. `linux-login-session`, `linux-cron-timers`, `linux-agent-log-tamper`, and `linux-kernel-security` are quiet event-driven sources whose established source freshness follows the last successful bounded system-journal observation rather than the age of matching activity. Scheduler health additionally requires durable prior evidence from either `cron` or `systemd_timer`; without either family, producer visibility remains degraded. Each family keeps separate observed/not-observed evidence, and one scheduler family can establish the combined source without inventing evidence for the other. A quiet observation does not replace a recent login/session, scheduler, or kernel event for detection evaluation. Missing or degraded journal prerequisites, expired observations, permission denial, and active continuity failures still prevent a healthy result. Applicable L4 role packs reuse this reader and classify only fixed structured identifier/unit evidence; they do not add message-regex guessing, paths, commands, privileges, or cursors. Structured process/user/PAM/network/result/action/unit/package/module fields take precedence; fixed 4,096-character/50 ms message parsing may supplement only the documented L2 families. Events persist to Agent.Core before the collected cursor advances, and accepted/duplicate acknowledgement persists before deletion. Rotation/vacuum/invalid cursor, denial, empty source, malformed/binary data, reorder/duplicate, backlog, throttle, and scope transitions remain explicit.

### Optional advanced sources

These sources require an explicit operator decision and cannot be prerequisites for L1 or a default install:

- the implemented procfs process/socket/host-behaviour pack, which is approval-hash gated and documents polling gaps explicitly;
- the implemented signed no-payload Linux x86_64 eBPF network-flow source, with fixed resource limits, compatibility checks, exact capabilities, and rollback; any process, DNS, file, or other kernel-security eBPF source remains deferred;
- targeted file-integrity monitoring beyond the implemented agent-owned snapshot source;
- producer/configuration changes that enable additional Linux Security Module logging (normalization of already-journaled AppArmor/SELinux evidence is implemented);
- producer/configuration changes that enable firewall logging (normalization of already-journaled UFW/nftables/firewalld evidence is implemented as optional L2);
- separately approved live use of the implemented journal-audit parser over an already configured facility; audit rule changes remain out of scope;
- container runtime and orchestration audit sources;
- targeted application audit plugins or structured logs.

Optional collectors must degrade independently. Failure or overload in one must not stop heartbeats, queue delivery, or other collectors, except that loss of the audit privacy router must stop the shared reader before trusted audit can reach L1. Enabled-by-configuration advanced sources are limited to explicit-opt-in self-integrity, passive procfs, the separately signed kernel network source, L4 posture/SLO, structured journal roles, and the separately approved journal-audit parser; broad/live FIM, other eBPF sources, and role-application file readers remain absent.

### Unsupported or not applicable


## Implemented L1 and opt-in L2 journal boundary

Journal polling defaults to 500 records every five seconds and accepts only bounded machine-readable records. Input is capped before parsing; allowlisted retained fields, messages, command lines, and raw JSON are capped and disclose redaction/truncation through v2 `data_handling`. Secret-shaped assignments and non-text values are removed before durable queue insertion. Deterministic IDs bind agent/logical-source/cursor and are validated by the existing server contract. `Journal.IncludeAccessibleUserJournals=false` is the system-only default; true selects all accessible local journals without granting root, a group/capability/ACL, remote access, arbitrary paths/arguments, producer logging, or retention changes. Scope changes preserve the cursor and begin observing newly accessible records after it rather than backfilling older entries. An invalid cursor becomes a durable gap/reset followed by the existing bounded recovery. `Journal.TargetCoverageLevel=L1` is the default and accepts `L1` through `L4`; selecting L3/L4 only expands the expected catalog and role classifier and does not enable the independently disabled advanced collectors or approve their hashes. L4 additionally requires non-empty known roles and approved `L4Telemetry`.

The shared Linux catalog declares mandatory, optional, and role-specific sources, applicable roles, prerequisites, event families, validation scenarios, and applicability. Health adds prerequisite/event-family state maps plus distinct `degraded`, `permission_denied`, `unsupported`, `disabled`, and `not_applicable` values. Mandatory applicable entries determine level; an applicable role-specific entry becomes mandatory, while optional, not-applicable, and server-approved excepted entries are accounted separately. Linux audit health reflects implementation/interface, declaration, approval, router attestation, journal access, private state, quiet observation, gaps, pressure, poison, and recovery. Its optional disabled state stays visible without becoming collected evidence.

Health reports latest event/lag/silence/rate, durable collected cursor, accepted/duplicate acknowledged cursor, gap/error/permission/throttle and degraded/recovery transition state, configured scope, independently verified system visibility, scope transition, empty/collector/config/version state, resource RSS where available, queue bytes/depth/oldest age, send/backoff state, poison/drop counters, and bounded anomaly counters. A broad read cannot hide denied or unavailable system-journal visibility. Queue pressure pauses reads without dropping unacknowledged events. The collector does not alter journal retention, service settings, authentication, groups, ACLs, kernel state, or policy. The audit router and L4 role rows are logical consumers of this same physical journal source; syslog-file fallback and role-application file readers are not implemented.

## Implemented inventory boundary

The inventory service starts after a default 30-second delay and runs independently of heartbeat, durable queue drain, and passive work. Its default interval is one hour, with an enforced five-minute minimum; runs cannot overlap. Each type is capped at 4,096 items, 200 items per page, 32 pages, and 512 KiB source output; a collection is capped at 4 MiB in memory. Sequential requests carry no more than 20 pages and the configured serialized budget. Fixed command/file operations have individual timeouts/output caps, cancellation, a whole-collection deadline, and explicit deterministic truncation. Interfaces come from fixed procfs/sysfs name/state reads with no address or MAC data.

Each snapshot uses one exact state: `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`. Absence, denied access, unsupported applicability, malformed output, timeouts, missing pages, and source truncation are visible rather than inferred as healthy. The server derives generation completeness, accepts legacy unpaged v2 as a one-page generation, reassembles only the latest complete generation for coverage/L4 consumers, and excludes transport paging keys from posture fingerprints.

## Implemented approval-gated L3 procfs boundary

The passive L3 pack uses fixed procfs/sysfs paths and v2 `inventory_diff`/`agent_health` events. It has no configurable arbitrary paths or commands. Process identity binds PID to start ticks so PID reuse is distinct; process flags distinguish kernel threads and zombies, eligibility visibility ratios expose command/executable coverage, and deleted/memfd/temporary execution plus dangerous effective capabilities are bounded markers. Socket identity binds tuple/state/inode; plan-approved ownership uses the same scan with fixed descriptor/link/owner caps and explicit partial attribution. The initial observation is a baseline, and subsequent actions remain `observed`, `disappeared`, or `changed` rather than claiming exact kernel lifecycle events.

Each scan has a deadline, process/socket/read-byte/event cap, deterministic ordering, queue-pressure pause, and explicit partial/truncated/gap health. A partial scan never generates disappearance events. Command lines pass bounded common credential-pattern sanitation before queue insertion; uncertain or invalid values are omitted, and remaining text is still treated as high sensitivity rather than guaranteed secret-free. Network collection excludes payloads, DNS contents, Unix-socket paths, and non-socket descriptor targets. Host samples are coalesced, add bounded whole-device operation/time/queue/latency diagnostics, and never backfill missed intervals or collect continuous per-process I/O.

The pack remains disabled unless both its enable flag and exact preflight plan hash match. Its default service profile has no capabilities. A separately plan-bound `CrossUserExecutableVisibility=true` selection may stage only the fixed non-root `CAP_SYS_PTRACE` drop-in needed for cross-user procfs executable/link checks; direct ptrace/process-memory/kcmp/pidfd/performance-event syscalls remain denied, and activation/removal each require an agent-only restart plus ratio/effective-capability validation. Enabling or upgrading passive telemetry on a live installed service requires the operator-approved lifecycle path, and normal install/upgrade never installs that profile. See [Linux passive process, network, and behaviour telemetry](linux-passive-telemetry.md) for fields, privacy exclusions, sequencing, rollback, and validation gates.

The collection is read-only and does not broadly scan the host. It does not mutate packages, services, audit, firewall, SSH, kernel, AppArmor/SELinux, Secure Boot, or agent permissions. Allowlisted parsers omit secrets and raw source output. Agent configuration/executable ownership, mode, and regular-file status plus a bounded SHA-256 executable fingerprint are observable change posture only, not trusted or tamper-proof attestation.

## Implemented approval-gated L4 boundary

L4 adds mandatory `linux-policy-posture-drift` and `linux-agent-performance-slo` sources. Both remain disabled until `Journal.TargetCoverageLevel=L4`, at least one known role is declared, `Agent:L4Telemetry:Enabled=true`, and the exact plan and posture-baseline approvals match. The plan binds the source/collector version, supported declared roles, fixed observation boundary, cadence, deadlines, queue priority, event limits, state path, and rollback behavior. The separately reviewed baseline hash prevents a first runtime scan or a drifted state from becoming an implicit approved baseline.

Complete posture scans emit deterministic sequence evidence through the shared durable queue. Missing, denied, partial, truncated, timed-out, mismatched, or corrupt state cannot establish or clear drift. The rolling SLO source requires a complete current window and measured process CPU, RSS, and write-rate evidence plus healthy poison/drop/pressure/oldest-age queue state; managed memory is context, while per-collector CPU and broader delivery/recovery performance remain private validation gates. Warm-up, counter discontinuity, unavailable metrics, pressure, or any implemented threshold breach stays non-healthy. This online source is an operational guardrail; it does not replace private host-class benchmarks and canary evidence.

L4 coverage uses strict semantics. Every mandatory source from L1 through L4 and every applicable role-specific source must be `healthy`; `excepted` does not satisfy L4 even when it can document a lower-level gap. Empty or unknown role declarations block L4. Optional disabled/not-applicable sources remain visible but do not become collected evidence or degrade aggregate health. See [Linux L4 full-target coverage](linux-l4-coverage.md). The implemented [Linux Audit Framework boundary](linux-audit-framework-adr.md) remains optional and separately approval-gated; requesting L4 does not enable it.

## Role-specific source packs

A host claiming L4 must explicitly declare at least one supported role and keep each applicable pack healthy. The implemented role packs are structured classifications on the one shared journal reader:

| Role | Implemented L4 source | Current boundary |
| --- | --- |
| General server/workstation | No additional role source | Explicit `general_server` or `workstation` declaration resolves the host as baseline-only |
| SSH server/bastion | Existing L2 `linux-ssh` | Existing SSH/PAM journal normalization; no shell audit or policy change |
| Web server | `linux-role-web` | Fixed structured web-service identifier/unit evidence already in journald |
| Database server | `linux-role-database` | Fixed structured database-service identifier/unit evidence already in journald; never database contents or credentials |
| DNS server | `linux-role-dns` | Fixed structured DNS-service identifier/unit evidence already in journald; query logging is not enabled |
| File server | `linux-role-file-server` | Fixed structured file-service identifier/unit evidence already in journald; no share/file-content crawl |
| Container host | `linux-role-container` | Fixed structured runtime/orchestrator identifier/unit evidence already in journald; no control-plane audit enablement |
| Identity server | `linux-role-identity` | Fixed structured identity-service identifier/unit evidence already in journald with normal sensitive-field controls |

The role classifiers do not open application log files or invent application semantics from arbitrary messages. A successful shared-journal read can keep a declared role source healthy during a quiet period while its event-family status remains `not_observed`. Every pack still requires private supported-software, representative-workload, volume, privacy, detection, SLO, and rollback validation before rollout. Rich application audit plugins, file sources, config metadata, integrity watches, DNS query logging, database auditing, orchestrator control-plane auditing, and shell-audit metadata remain future separately approved capabilities.

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

Command lines, paths, hostnames, usernames, addresses, and raw messages are sensitive telemetry. All-accessible-local scope can additionally expose user-service/session stdout and stderr and arbitrary application text. Collection, retention, access, and display must follow least-data principles and role-based access/redaction controls; bounded sanitation cannot guarantee arbitrary messages are secret-free.

### Explicit exclusions

Collectors **must not directly access or deliberately retain** these prohibited sources and known secret-bearing fields:

- credentials, passwords, tokens, cookies, authorization headers, or connection strings;
- secret stores, password databases, credential caches, wallet/keyring contents, or cloud credential files;
- private keys or private certificate material;
- browser profiles, browser/session stores, or unrestricted shell history;
- environment-value dumps (environment variable names may be collected only for an approved detection need without values);
- keystrokes, terminal input capture, clipboard contents, or screen contents;
- packet payloads or full packet capture;
- unrestricted file-content collection.

Parsers must discard known secret-bearing fields and redact recognized common credential forms before queue insertion. Bounded raw records do not override these exclusions. Approved command lines, paths, messages, hostnames, usernames, and addresses can nevertheless contain arbitrary sensitive values that pattern matching cannot guarantee it will recognize; they are restricted high-sensitivity telemetry, not an authorization to target credentials. Suspected prohibited-content collection requires dropping the affected field or disabling the collector, emitting only secret-safe health metadata, and testing remediation with synthetic fixtures.

## Reliability and pressure behavior


Under CPU, memory, disk, event-rate, or queue pressure, the agent must:

1. preserve heartbeat, source-health, queue integrity, and already-durable events;
2. apply bounded batches, rate limits, backoff, and collector-specific buffers;
3. throttle or pause optional L3/L4 work before mandatory L1/L2 sources;
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
- resident set size (RSS) below **250 MiB**;
- average agent writes below **1 MiB/s**;
- no sustained individual collector above **10% CPU for more than 60 seconds**.

The implemented `linux-agent-performance-slo` L4 source evaluates these thresholds over its configured bounded rolling window. It reports healthy only after complete interval samples span the full endpoint-inclusive configured duration and every required current measurement is available. Covered seconds and maximum managed memory are bounded context; managed memory is not a pass/fail threshold. A rolling pass is necessary for L4 but is not sufficient rollout evidence: it cannot by itself prove distribution compatibility, a seven-day L2 soak, outage/drain recovery, rotation, role workload, or an approved L4 canary.

Benchmarks must separate idle baseline, representative steady state, burst, server outage/queue growth, reconnect/drain, source rotation, and optional-collector workloads. The test matrix must include each supported distribution/kernel/init combination and each enabled level or role pack. Measure per-process and per-collector CPU, RSS, bytes written, queue size/age, collection-to-queue latency, delivery latency, event counts, loss/gap indicators, and source workload rate.

Only synthetic events and operator-owned test hosts may be used. Record benchmark tooling, host class, workload generator, configuration hash, sample interval, run duration, warm-up, percentiles, and pass/fail result under ignored local paths. Averages must cover the steady-state window; p95 uses the same fixed sampling interval. Bursts must demonstrate bounded recovery without silent loss. Failure of any SLO blocks rollout of the responsible level/collector until tuned or explicitly excepted.

The repository includes a bounded 5,000-record synthetic normalization regression test. It requires at least 500 records/second, less than 250 MiB managed allocation, raw records below 4 KiB, and completion within ten seconds. These thresholds catch gross regressions and align memory/throughput with the L1 SLO, but they do not measure steady-state process CPU, RSS, disk-write rate, distribution compatibility, or soak duration. Those measurements remain rollout gates and must not be inferred from the unit benchmark.

## Staged rollout, soak, and rollback

1. **Preflight:** produce a non-policy-mutating plan listing detected platform, requested level, effective journal scope, sources, paths, groups/capabilities, expected volume, limits, exclusions, and all proposed host changes. The broader journal scope requires explicit privacy/volume review and invalidates passive-L3/L4 plan approvals. Installed L4 preflight may populate only the private product-owned `.dotnet-bundle` runtime cache; it does not alter collector state, queue, configuration, telemetry, or host policy. L1 must propose no security-policy mutation.
2. **L1 canary:** deploy to a small representative cohort and soak for at least **24 continuous hours**. Validate source positions, queue/acknowledgements, restart/rotation handling, privacy exclusions, source health, and every performance SLO.
3. **L1 decision:** expand only after reviewed evidence passes. Roll back or disable the offending collector on any immediate rollback condition.
5. **L3 canary:** each requested L3 pack requires its own reviewed hash, at least the documented first-host soak, workload/resource validation, and rollback evidence.
6. **L4 private VM canary:** generate and approve the exact L4 plan and posture baseline for an explicitly declared supported role set. Validate policy drift/restoration, rolling-window warm-up/breach/recovery, every applicable role pack, strict no-exception coverage, outage/restart/pressure behavior, privacy, and all performance SLOs. The bounded functional campaign passed for one declared web role, including approval, post-reboot rolling warm-up, outage/recovery, and strict coverage; the required long-duration soak and broader performance matrix have not yet passed.
7. **Advanced rollout decision:** expand beyond the VM only after reviewed aggregate evidence passes for the same build, configuration, distribution/kernel/init combination, and comparable host/role class. No cohort expansion is automatic.

Immediate rollback criteria are: suspected credential/secret or excluded-data collection; unauthorized audit, firewall, authentication, kernel, service, or security-policy mutation; host instability or application impact; queue/state corruption or confirmed silent event loss; persistent source duplication/gaps; uncontrolled disk growth; inability to uninstall/disable safely; or breach of any resource SLO after bounded automatic throttling. Stop expansion, disable/remove the responsible component using the approved rollback plan, preserve only sanitized diagnostics in approved runtime storage, verify host policy/state, and document the gap before retry.

## Acceptance and implementation gates

The bounded inventory slice has synthetic parser, state, cancellation, scheduling, item/payload-cap, large-list, privacy, and queue/passive non-interference coverage. L1 has deterministic identity, queue/checkpoint, restart, acknowledgement/outage/replay, rotation/vacuum/invalid-cursor, permission, malformed/binary, empty, duplicate/reorder, pressure, and benchmark coverage. L2 adds hand-authored positive/negative fixtures for every source family, structured precedence, ambiguous/malformed/oversized behavior, catalog/coverage/portable ingest-search tests, and a 5,000-record bounded performance guard. L3/L4 add synthetic baseline/diff, approval mismatch, sequence/acknowledgement, pressure, rolling-window, role applicability, quiet-source, and strict coverage calculations. A bounded exact-2.0.2 VM campaign additionally passed the implemented live L1-L4 path for one declared web role. These checks do not satisfy supported-distribution host benchmarks, the private 24-hour L1 canary, the private seven-day L1+L2 soak, or the long-duration L3/L4 private VM canaries. Additive API/schema work preserves `/api/v2` and `contracts/v2/`.

Security boundaries and mutation approval are authoritative in [linux-agent-security.md](linux-agent-security.md). Use [linux-local-host-validation.md](linux-local-host-validation.md) for the sanitized L1-L4 soak runbook, recovery-check template, advanced opt-in guardrails, and truthful live-soak blocker when no authorized target/window is supplied. Public examples and evidence must follow [the repository public-data rules](index.md#public-data-rules-for-docs-and-screenshots).
