# ADR: optional Linux L3 telemetry selection

Status: adopted narrow design; independently approval-gated self-integrity and passive procfs snapshots implemented; audit remains unimplemented under a separate accepted read-only design
Date: 2026-07-14
Scope: Linux L3 audit, eBPF, file-integrity, and passive procfs telemetry decisions

## Decision summary

Challenger SIEM does **not** add or enable Linux audit, eBPF, broad/live file-integrity collection, or any host-policy mutation. The supported Linux endpoint includes the existing passive L1 journal reader, opt-in L2 logical journal classification, bounded read-only inventory, the disabled-by-default explicit-opt-in L3 snapshot-based agent self-integrity source, and a separately approval-gated passive procfs L3 pack for polling-honest process/socket snapshots and coalesced host-behaviour samples. No audit rules, audit backlog settings, kernel parameters, capabilities, packages, modules, firewall/authentication/security policy, fanotify/inotify watches, IMA policy, or live file-integrity watches are installed or changed.

The selected file-integrity candidate remains only the **snapshot-based, allowlisted agent self-integrity design** described below. Audit implementation and eBPF remain deferred until separately approved implementation work plus private compatibility and resource evidence exists. The accepted design/security/privacy boundary for a possible audit implementation is documented in [Read-only Linux Audit Framework collector boundary](linux-audit-framework-adr.md); it authorizes no implementation, live reads, or host changes. Broad or live file-integrity monitoring remains rejected as an L3 default.

A later implementation added a distinct passive procfs snapshot pack, documented in [Linux passive process, network, and behaviour telemetry](linux-passive-telemetry.md). It does not revise the eBPF decision: procfs polling cannot provide kernel-hook ordering or complete short-lived process/connection coverage, so its events deliberately use non-alertable `baseline` followed by `observed`, `disappeared`, and `changed` semantics and expose partial/truncated health. The pack is disabled until its explicit plan hash is approved, needs no new capability or host-policy change, and pauses itself before consuming the queue headroom reserved for L1/L2.

| Option | Decision | Reason |
| --- | --- | --- |
| Existing journal-backed Linux Audit Framework integration | **Design accepted; implementation deferred** | The exact future boundary is the already-configured local systemd journal, reused through a required pre-L1 privacy router with no rule/backlog/failure/service/permission mutation. Implementation still needs separate authorization, synthetic verification, and private evidence. |
| Narrow eBPF process/network visibility | **Defer** | Correctness potential is high for process/network metadata, but verifier/program/kernel/BTF/capability/package complexity and unmeasured overhead are above the current L3 gate. |
| Bounded procfs process/socket/resource snapshots | **Adopt as explicit opt-in** | Provides useful polling evidence with ordinary read-only files, deterministic diff/health semantics, strict privacy/volume bounds, and no kernel program or policy mutation; it explicitly cannot claim complete lifecycle capture. |
| Allowlisted file-integrity approaches | **Adopt narrow snapshot design only** | A small, explicit, no-watch agent self-integrity snapshot can extend existing inventory with bounded overhead and rollback. Broader path watches, fanotify permission workflows, IMA policy, and role config hashing remain deferred. |

## Authoritative source facts

- `auditctl(8)` configures the kernel audit system, including backlog size, rate limit, failure mode, enable/lock state, rule deletion, and status counters for `lost` records and current backlog. It also notes that locked audit configuration can only be changed by rebooting. Source: <https://man7.org/linux/man-pages/man8/auditctl.8.html>.
- `audit.rules(7)` states that audit rules are loaded by the audit daemon, that filesystem watches and syscall rules are evaluated in the syscall exit filter, and that syscall rules affect performance; it recommends `arch` fields because omitting them can cause all system calls to be evaluated. Source: <https://man7.org/linux/man-pages/man7/audit.rules.7.html>.
- Linux capabilities split root privileges; `CAP_AUDIT_CONTROL` changes audit rules/status, `CAP_AUDIT_READ` reads audit logs via multicast netlink, `CAP_BPF` and `CAP_PERFMON` were added in Linux 5.8 for privileged BPF/performance operations, and `CAP_SYS_ADMIN` remains overloaded and includes BPF/perf and `fanotify_init(2)` fallbacks. Source: <https://man7.org/linux/man-pages/man7/capabilities.7.html>.
- `bpf(2)` describes eBPF maps/programs, verifier loading, attachments, and kernel lifetime behavior; the kernel statically analyzes BPF programs before loading them. Source: <https://man7.org/linux/man-pages/man2/bpf.2.html>.
- The kernel eBPF verifier documentation describes control-flow, register, stack, pointer, bounds, and helper-call checks that determine program safety. Source: <https://docs.kernel.org/bpf/verifier.html>.
- The kernel BPF ring buffer documentation states that ringbuf preserves cross-CPU event ordering better than perf buffers, but reservation can fail when no space is available and helper queries are momentary snapshots. Source: <https://docs.kernel.org/bpf/ringbuf.html>.
- `fanotify(7)` supports mount/filesystem monitoring, permission decisions, file descriptors to affected objects, event merging, and `FAN_Q_OVERFLOW` when the queue limit is exceeded; content/permission modes can interfere with workloads. Source: <https://man7.org/linux/man-pages/man7/fanotify.7.html>.
- `inotify(7)` monitors files/directories, has per-user/watch/queue limits, reports `IN_Q_OVERFLOW` after dropping excess events, coalesces identical unread events, has no user/process attribution, and cannot monitor some pseudo/network filesystem activity. Source: <https://man7.org/linux/man-pages/man7/inotify.7.html>.
- Kernel IMA template documentation shows measurement templates and template selection through kernel configuration or kernel command line parameters, making IMA useful but policy/boot-configuration heavy rather than a default agent feature. Source: <https://docs.kernel.org/security/IMA-templates.html>.
- libbpf is the official userspace BPF library mirror, supports CO-RE but depends on BTF availability for portability, and is dual licensed `BSD-2-Clause OR LGPL-2.1`; it also depends on libelf/zlib and build-time Clang/LLVM for BPF programs. Sources: <https://github.com/libbpf/libbpf/blob/master/README.md>, <https://github.com/libbpf/libbpf/blob/master/LICENSE>.

## Evaluation gates

All future L3 telemetry must satisfy the existing Linux security and coverage gates:

- explicit operator opt-in distinct from install, enrollment, or requested coverage level;
- read-only preflight before any mutation, with detected platform/kernel/init, exact sources, privileges, packages, paths, rates, limits, expected events, privacy impact, SLO risk, and rollback;
- no silent host-policy mutation;
- least privilege per collector/helper rather than steady-state root;
- deterministic source position or loss accounting;
- redaction and explicit exclusions before durable queueing;
- bounded CPU, memory, disk, queue, event-size, and batch behavior;
- independent degradation: optional L3 pauses before L1/L2, heartbeat, queue drain, or source-health;
- private distribution/kernel matrix and soak evidence before rollout.

Project SLOs remain: average agent CPU below 2%, p95 below 5%, RSS below 250 MB, average writes below 1 MB/s, and no sustained individual collector above 10% CPU for more than 60 seconds. This spike produced no live measurements; every option that lacks host evidence is blocked from shipping until measured in an operator-owned private canary.

## Option 1: existing auditd/audit-journal integration

### Visibility and correctness

Audit can provide high-fidelity authentication, authorization, syscall, execution, policy, and file-access records when the host already has auditd and rules. It has native sequence/counter concepts and explicit kernel backlog/lost counters. It also captures data from a host-wide policy domain that may predate Challenger SIEM and may be regulated by local security baselines.

Correctness risk is policy coupling: adding, deleting, reordering, or excluding audit rules changes what other tools and compliance workflows see. Audit records can be multi-record event groups; parsing must preserve event serial/time identity, missing-record gaps, and source-specific normalization without fabricating complete coverage.

### Compatibility

Audit is common on major Linux distributions but not guaranteed to be installed, running, permitted in containers, or exposed through journald. Audit lock mode (`auditctl -e 2`) intentionally denies later rule changes until reboot. Bi-arch syscall rules require separate `arch=b32`/`arch=b64` handling; rule availability and generated fields vary by kernel, architecture, and distribution policy.

### Privileges and conflicts

Safe read-only integration should require at most host-granted audit read access (`CAP_AUDIT_READ` for multicast netlink or restricted log/journal read access). Rule management requires `CAP_AUDIT_CONTROL` and is not selected. The agent must not call `auditctl -D`, change `-b`, `-r`, `-f`, `-e`, loginuid immutability, watch rules, exclude filters, or audit daemon settings.

### Loss, pressure, and rate behavior

Audit exposes kernel backlog and lost counters. A future passive collector must report:

- kernel audit enabled/disabled/locked state;
- backlog, backlog limit, backlog wait-time state, rate limit, failure mode;
- last serial/event time read, lost counter deltas, parser malformed count, queue backlog, and acknowledgement position;
- gap reason when counters jump, input rotates, journal cursor is invalid, or auditd is absent.

Under pressure it must pause optional audit reads before journal L1/L2, preserve heartbeat and queue drain, and emit bounded health. It must never increase audit backlog/rate/failure settings to hide drops.

### Privacy and exclusions

Audit can include path, command, UID/GID, syscall arguments, SELinux/AppArmor labels, and sometimes command-line-like or subject data. It must preserve the repository exclusions: no credentials, secret stores, private key material, environment values, packet payloads, keystrokes, screen/clipboard, unrestricted file content, or raw audit dumps in public artifacts. Raw audit payload retention would need a stricter field allowlist and redaction tests before queueing.

### Packaging, maintenance, and rollback

No audit userspace package is added by this change. A future passive reader may use host facilities only. Bundling or linking audit-userspace/libaudit requires a separate legal/release review because the public upstream repository is GPL-2.0. Rollback for a passive reader is removal of the source manifest/collector and persisted checkpoint only; because no policy is changed, host rollback should have nothing to restore. If any later task proposes rules, rollback must restore the exact prior audit state and prove no unrelated rule changed.

### Decision

**Defer.** Conditions to reconsider:

1. Implement read-only audit preflight that records effective audit status and existing policy hash without changing it.
2. Define parser/event contracts for serial grouping, lost-counter deltas, and cursor/sequence acknowledgement.
3. Prove no rule/backlog/failure/loginuid mutation in tests.
4. Run private distro/kernel/container compatibility and resource canaries.

## Option 2: narrowly scoped eBPF process/network visibility

### Visibility and correctness

Narrow BPF can observe process lifecycle and connection metadata close to kernel execution, potentially covering events that journald and audit miss. Ring buffers can preserve fork/exec/exit ordering better than per-CPU perf buffers, but BPF event production is still bounded: ring reservations can fail, data structures are finite, verifier restrictions limit program shape, and attachment semantics vary by hook.

A safe scope would be metadata only: process exec/exit/fork and network connect/accept/close tuples, with no packet payloads, no environment values, no memory scraping, no file content, and no DNS payload capture unless a later role pack justifies a separate source.

### Compatibility

A portable CO-RE design needs kernel BTF availability, compatible kernel hooks, libbpf behavior on older kernels, architecture coverage, and build/release paths for BPF objects. libbpf documents BTF availability by distribution and says kernels without BTF need custom kernel support. Kernels before Linux 5.8 often require overloaded `CAP_SYS_ADMIN` for operations that newer systems split into `CAP_BPF`/`CAP_PERFMON`; LSM lockdown, container boundaries, and distro hardening may block attachment.

### Privileges and interference

Loading and attaching tracing programs is privileged. Least privilege would require a separate helper with only the capabilities needed for the chosen kernel/hook combination, never broad steady-state root. Network observation may additionally require `CAP_NET_ADMIN`/`CAP_NET_RAW` depending on hook choice, which is not acceptable without a reviewed need. BPF programs can be persistent depending on attachment; rollback must detach links, close FDs, unpin maps/programs, and verify no pinned objects remain.

### Loss, pressure, and rate behavior

A future eBPF collector must maintain per-source counters:

- ring producer/consumer positions when available;
- reservation-failure/drop counters emitted by the BPF program;
- userspace read, normalization, queue, acknowledged, and coalesced counts;
- map pressure and parser truncation/redaction counts;
- explicit interval gaps when the userspace reader restarts, verifier attach fails, or counters reset.

Pressure order must be: keep heartbeat/queue/source-health, reduce enrichment, sample/coalesce optional eBPF, then pause eBPF before any L1/L2 source. No silent dropping is acceptable.

### Privacy and packaging

BPF toolchains increase supply-chain and maintenance burden: BPF object build, kernel header/BTF compatibility, verifier logs, libbpf/libelf/zlib runtime, Clang/LLVM build-time, and package signing/provenance. libbpf's dual `BSD-2-Clause OR LGPL-2.1` license is compatible in principle, but adding it changes packaging and native dependency posture. BCC-style runtime compilation is rejected for this project because it would add Clang/LLVM and kernel headers to endpoints.

### Overhead

No host measurement was performed. The ringbuf documentation supports efficient design, but it is not a project measurement. eBPF remains blocked until private tests cover idle, steady-state, burst, outage/drain, restart, detach/reattach, and high-connection workloads against the Linux SLOs.

### Decision

**Defer.** Conditions to reconsider:

1. Fixed metadata-only hook plan with exact kernel hooks and no payload/content capture.
2. CO-RE build pipeline with signed BPF object, libbpf dependency review, no endpoint compiler, and BTF/kernel fallback matrix.
3. Helper protocol with minimal capabilities, no arbitrary program loading, bounded verifier logs, and deterministic detach/unpin rollback.
4. Loss/drop counters tested under ring-full and userspace-reader outage.
5. Private resource and compatibility evidence passes all SLOs.

## Option 3: allowlisted file-integrity approaches

### Compared approaches

| Approach | Assessment |
| --- | --- |
| Periodic snapshot hash/metadata for exact allowlisted files | Lowest interference and best fit for current inventory/queue model. It can bound files, bytes, cadence, and privacy before queueing. |
| inotify hints on allowlisted directories | Defer for broader use. It has queue limits and overflow events, coalesces identical unread events, lacks user/process attribution, and cannot cover all filesystems. It may be useful only as a hint that triggers a later bounded snapshot. |
| fanotify live monitoring | Defer. It can monitor mounts/filesystems and deliver file descriptors or permission events, but privilege, queue overflow, event merging, and permission-response workflows create interference risk. |
| Audit file watches | Defer with audit option. It changes audit policy and can affect global syscall performance. |
| IMA/EVM measurements | Defer. Useful for high-assurance environments already operating IMA, but template/policy/boot-time configuration is host security policy and not an agent default. |
| Broad third-party FIM tools | Reject for this product path. They add separate policy engines, package/runtime dependencies, and duplicate collection paths outside the current agent reliability model. |

### Selected narrow design implemented for explicit opt-in

This concept is implemented as a disabled-by-default Linux agent source. Operator approval and private soak remain separate rollout gates.

**Name:** `linux-agent-self-integrity-snapshot`

**Default:** disabled until explicit operator opt-in. It is offered as an optional L3 source and is never mandatory for L1/L2.

**Exact built-in allowlist:**

| Path | Handling |
| --- | --- |
| `/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent` | Regular-file metadata plus streaming SHA-256 under the existing 64 MiB executable hash cap. |
| `/etc/systemd/system/challenger-siem-agent.service` | Regular-file metadata plus streaming SHA-256, max 256 KiB. |
| `/etc/challenger-siem-agent/agentsettings.json` | Metadata only: regular file, numeric owner/group, mode, size bucket, mtime bucket. No content hash because it is credential-bearing configuration. |
| `/etc/challenger-siem-agent/` and `/var/lib/challenger-siem-agent/` | Directory owner/group/mode and no-follow type checks only. No recursive scan. |

No symlinks, hard-link surprises, devices, FIFOs, sockets, secret stores, browser profiles, shell history, private keys, `/etc/shadow`, arbitrary `/home`, package database content, application logs, or unbounded operator paths are allowed. A future role pack may propose additional non-secret config paths, but each path must be literal, reviewed, purpose-bound, and separately gated.

**Compatibility and packaging:**

- Uses ordinary read-only file metadata and bounded streaming reads on the same supported Linux/systemd platforms as the current agent; no kernel module, fanotify/inotify, audit, IMA, or eBPF feature is required.
- No third-party runtime dependency is selected; implementation should use existing .NET file APIs and Agent.Core queue/transport.
- Unsupported path type, denied access, oversize, or absent path is source health, not installer failure and not permission to mutate ownership/mode.

**Defensible overhead model:**

- The default allowlist has two content hashes and two metadata-only directory/config checks, with total content-read caps below the existing inventory hash cap.
- Non-overlap, five-minute minimum cadence, and pause-before-L1/L2 ordering make the design testable against CPU/RSS/write SLOs, but it still needs synthetic tests and private canary measurements before release.

**Preflight and opt-in:**

- Print the exact allowlist, collection interval, per-file byte cap, expected event schema, privacy classification, SLO budget, and rollback.
- Validate path existence/type, owner/mode expectations, filesystem support, file size cap, and service identity read access without changing permissions.
- Require explicit operator approval bound to config hash and allowlist. Requested coverage level alone is not approval.

**Least privilege:**

- Run in the existing Linux agent identity when files are readable.
- Do not add groups, capabilities, ACLs, or root helper for the default allowlist.
- If a file is denied, emit `permission_denied` source health rather than expanding access.

**Event and loss accounting:**

- Emit bounded `inventory_diff` or `agent_health`-style records only when metadata/hash changes, plus periodic source health.
- Use deterministic IDs over agent ID, source ID, path ID, observed hash/metadata version, and observed timestamp bucket.
- Track scanned, changed, denied, skipped_oversize, skipped_type, malformed_path, hash_error, queue_depth, collected checkpoint, acknowledged checkpoint, and last successful scan time.
- If an interval is skipped because of pressure or deadline, emit one bounded gap record when capacity permits.

**Rate limits and pressure ordering:**

- Default cadence no faster than the inventory interval; minimum five minutes.
- Whole scan deadline 30 seconds, 20 path entries maximum, per-file cap above, one non-overlapping scan.
- Pause this source before journald L1/L2, heartbeat, inventory, or queue drain when queue depth or CPU/memory/disk pressure appears.
- Never delete unacknowledged rows; no catch-up storm after outage.

**Rollback:**

- Disable the source and remove its source manifest/checkpoint state.
- Leave host files untouched because the collector never changes them.
- Verify no watcher, fanotify group, audit rule, IMA policy, package, capability, group, ACL, or kernel object was created.

**Rollout gates:**

- Synthetic unit tests for no-follow regular-file handling, metadata-only secret config, hash caps, denied files, oversized files, queue-before-checkpoint, acknowledged-before-delete, redaction, and deterministic IDs.
- Private 24-hour L1 and seven-day L1+L2+snapshot canary on supported distributions before default recommendation.
- SLO evidence for idle, steady state, file churn, server outage, restart, and uninstall/rollback.

### Decision

**Implement only the narrow snapshot design behind explicit opt-in; defer broader allowlisted FIM and reject broad/live defaults.** This is the only selected concept from this spike and is intentionally small enough to preserve the no-mutation boundary.

## Resource and overhead conclusion

This issue performed design/load analysis only. Existing repository tests already include synthetic journald normalization throughput/allocation guards, but those are not evidence for audit, eBPF, fanotify/inotify, IMA, or broader FIM. The only defensible overhead claim from this ADR is qualitative: the selected snapshot design is bounded by exact files, byte caps, non-overlap, and inventory-like cadence, so it is plausible to test against SLOs. It is not approved to ship until those tests and private canaries pass.

## Compatibility and maintenance conclusion

- Audit and IMA are best treated as integrations with host-owned security policy, not agent-managed features.
- eBPF is a separate native/kernel compatibility product surface requiring signed objects, native dependencies, capability design, and rollback tooling.
- Snapshot self-integrity reuses existing product concepts and has the smallest maintenance surface, but still requires separate operator approval and private #208 soak/review before rollout recommendation.

## Validation and cleanup for this ADR

- The explicit-opt-in snapshot collector uses existing .NET/POSIX file APIs and no new runtime dependency.
- No package, policy, kernel, audit, firewall, authentication, service, or security setting was changed.
- Future tasks must keep private host evidence under ignored local/runtime paths and publish only synthetic aggregate summaries.
