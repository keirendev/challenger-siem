# Linux passive process, network, and behaviour telemetry

## Status and boundary

Challenger SIEM provides an optional Linux L3 passive telemetry pack for process snapshots, network socket snapshots, and host resource/pressure samples. The pack is disabled by default and runs only when its explicit configuration flag and approval-plan hash both match.

The collector reads bounded procfs files that already exist. Its default profile does not install packages, load kernel programs, add audit rules, change journal retention, widen firewall or authentication policy, add groups or capabilities, inspect process memory, or restart services. A deployment may explicitly select `CrossUserExecutableVisibility=true` and separately stage the fixed systemd profile that grants only `CAP_SYS_PTRACE` to the non-root agent for Linux cross-user procfs link access. Direct ptrace/process-memory/performance syscalls remain denied, normal install/upgrade never installs the profile, and service restart remains a separate activation step.

The pack is complementary to the L1/L2 journal path. It does not claim the exactness of kernel exec/exit or socket hooks: every event name and health record identifies snapshot/polling evidence and reports gaps, truncation, pressure, and incomplete visibility.

Collector `linux-passive-snapshot-v6` exposes the existing opaque boot-scoped process key as `process_instance_id` and propagates same-scan parent/socket-owner identities. That compatible output change invalidates older passive approval hashes; it does not enable the pack, add a reader, or widen procfs permissions. Because the socket baseline signature now binds an owner's process instance as well as its PID, the first complete approved v6 ownership scan after preserved v5 state may emit bounded `socket_changed` evidence for retained attributed sockets. That transition is not a claim that a new connection occurred.

## Sources and v2 contracts

The pack uses Linux source IDs inside the v2 event envelope:

| Source | Existing event source kind | Purpose |
|---|---|---|
| `linux-process-snapshot-diff` | `inventory_diff` | Bounded process baseline and observed/disappeared/changed differences |
| `linux-network-socket-snapshot-diff` | `inventory_diff` | Bounded TCP/UDP socket and listener baseline/differences |
| `linux-host-behaviour-metrics` | `agent_health` | Coalesced host load, memory, pressure, and counter-derived disk/network deltas |

No separate ingestion route or additional database event-source value is required. Events retain deterministic IDs, source-local sequence checkpoints, explicit data-handling metadata, and server deduplication. A sequence range is durably reserved before queue insertion, and the collected baseline/checkpoint advances only after all events are queued. For fully committed rows, accepted/duplicate acknowledgement is recorded before queue deletion. Rows left by an interrupted reservation can be accepted and deleted without advancing the committed acknowledgement; the reservation remains an explicit, non-reused sequence gap and its semantic changes are retried from the prior baseline at new sequences.

## Process observations

The process source first reads bounded `/proc/self/mountinfo` evidence so restrictive `hidepid` policy cannot be mistaken for full visibility. It then reads only fixed, bounded fields from `/proc/<pid>/stat`, `status`, `exe`, `cmdline`, `cgroup`, and `loginuid`. When the exact passive plan approves socket ownership it additionally inspects bounded `/proc/<pid>/fd` links, retains only exact `socket:[inode]` targets, and discards every other descriptor target. It may report:

- PID and parent PID;
- numeric user/group identity;
- executable and bounded command line with common credential-pattern redaction when readable;
- a public nullable `process_instance_id`, preserving the existing lowercase 64-character boot-scoped SHA-256 key derived from the already-hashed boot identity, PID, and start ticks so PID reuse is distinct; start ticks and the boot identifier are not sent as separate fields;
- kernel-thread and zombie classification from fixed process flags/state, plus eligible-process command-line and executable readability ratios;
- deleted, memfd, and temporary executable markers and a fixed decoded subset of dangerous effective capabilities;
- selected capability, seccomp, no-new-privileges, tracer, login-user, and hashed cgroup metadata;
- `process_baseline`, non-alertable `process_baseline_disappeared`, `process_observed`, `process_disappeared`, and `process_changed` event codes, with polling-honest normalized actions.

Baseline establishment can span multiple complete polls when the event cap is lower than the initial population; it becomes established only after a complete poll has no deferred baseline differences. All such baseline and baseline-disappeared evidence is non-alertable and is not an assertion that an existing process just executed. A poll can miss short-lived processes. A numeric PID entry that disappears, or changes start identity, between the two bounded `stat` reads is an expected race: it increments the separate expected-race counter but does not by itself create a coverage gap or degraded health. Core stat/status/loginuid/cgroup denial, malformed text, I/O failure, budget exhaustion, truncation, or mount restriction remains a coverage gap; a readable process identity can still be emitted with `enrichment_partial=true`. Missing, truncated, invalid-text, or safely dropped command-line/executable fields remain optional omissions on that process. When at least ten non-kernel, non-zombie eligible processes exist, either readability ratio below 80% produces one scan-level `process_visibility_below_threshold` gap.

Linux applies ptrace access checks to cross-user `/proc/<pid>/exe` and descriptor-link reads even though the collector does not call `ptrace(2)`. On multi-user hosts the unprivileged executable ratio can therefore remain below the required threshold. The optional capability profile is the supported high-visibility design: one capability, fixed reader paths, non-root identity, `NoNewPrivileges=yes`, the existing filesystem/device/kernel sandbox, an explicit syscall deny list, self-integrity monitoring of the drop-in, aggregate-only health, and reversible profile removal. Residual risk remains because `CAP_SYS_PTRACE` is broader than a path-specific procfs permission; compromise of the in-process agent has greater cross-process read potential than the default profile. Operators choosing full executable visibility accept that risk and must validate effective capabilities, blocked syscalls, privacy bounds, readability ratios, and rollback in a disposable VM first.

## Network observations

The network source parses bounded `/proc/net/tcp`, `tcp6`, `udp`, and `udp6` snapshots. It reports canonical local/remote addresses and ports, protocol, socket state, listener category, inode identity, numeric socket UID when available, coalesced tuple count, and polling lifecycle actions including non-alertable baseline/baseline-disappeared evidence followed by observed, disappeared, or changed differences.

It does not capture packets, payloads, DNS contents, Unix-domain socket paths, TLS material, or unrelated `/proc/<pid>/fd` targets. Ownership is `not_collected` unless the passive approval binds `CollectSocketOwnership=true`. Enabled ownership inspects at most 256 descriptors per process and 32,768 links per scan, retains no more than four PID/process-instance/executable/command/UID owner summaries per inode, and labels stale, capped, denied, or ambiguous attribution as partial instead of fabricating certainty. A unique owner carries its process-instance identity only from the same bounded process scan, with `snapshot_inode_owner` provenance and the process-scan observation time. Socket baseline establishment uses the same potentially multi-poll, non-alertable boundary as processes. Snapshot polling can miss short connections, and a truncated or partial scan must not generate false disappearance events.

## Host behaviour samples

Host samples are coalesced bounded aggregates from fixed procfs resource files. They provide load, computed CPU-busy permille, available/total memory, free swap, uptime, running/blocked process counts, pressure-stall gauges, and deltas derived from disk-sector and interface-byte counters when readable. Each metrics scan also reads `/proc/sys/kernel/random/boot_id`, hashes it locally, and resets previous absolute counters on an epoch change so cross-boot deltas cannot be fabricated; the identifier is not emitted as event content. The private state retains the prior hash and previous absolute counters only for that reset and delta calculation. The collector considers at most 32 whole devices under fixed `/sys/block`, derives operation/time, queue-depth, weighted-I/O, and latency context, and retains only the eight most active summaries per event. Network inputs sum visible interfaces, including loopback or virtual interfaces. These are trend context, not physical-disk/external-traffic accounting, continuous per-process I/O, or permission to tune storage.

Samples are current-state context rather than per-operation audit records. Missed intervals are not backfilled into an event storm. Queue pressure pauses this optional pack at a configured row threshold no higher than the journal threshold and at a conservative byte threshold that reserves one maximum journal poll. The maximum passive batch must fit below that byte boundary even from an empty queue. A pause records a bounded active visibility gap and a cumulative skipped-scan counter without inventing a dropped event; a later complete healthy scan clears the active gap while retaining historical counters.

## Privacy and exclusions

The collector treats hostnames, users, command lines, paths, cgroups, addresses, ports, and raw observations as sensitive endpoint data. They belong only in the protected local queue, authenticated SIEM storage, and role-controlled review surfaces. Real output, configs, state, queues, API responses, screenshots, benchmarks, and validation evidence must remain under ignored `.local/` or approved OS runtime paths and must never be committed.

The collector never reads or retains:

- process environments, memory, maps, stacks, or arbitrary syscall arguments;
- shell history, browser/session stores, credential stores, private keys, clipboard, screen, or keystrokes;
- packet or application payloads;
- arbitrary filesystem contents or unrelated file-descriptor targets;
- `/etc/shadow` or other secret-bearing account databases.

Command lines are bounded and treated as high-sensitivity telemetry. Common credential-bearing switches, assignments, authorization headers, and URI user information are redacted before durable queue insertion; invalid/control text and redaction failures are omitted or marked. This is a defensive pattern filter, not proof that arbitrary command text contains no sensitive value, so access remains restricted even after redaction. Agent logs contain only error classes and aggregate counters, never raw process/socket values.

## Reliability and health

Each source exposes enabled/approval state, collected and acknowledged sequence, latest scan attempt, observed/deferred counts, visibility/permission status, truncation, active gaps, cumulative historical gap/drop/pressure counters, and recovery. Process health separately persists total read skips, expected process-lifecycle race skips, and coverage-gap read skips; expected races are diagnostic history, not dropped events. A bounded unclassified count preserves older total-only state without guessing its cause. Latest process diagnostics promote aggregate-only failure classes, core malformed-record count, and optional-enrichment omission count within the portable 32-detail limit; they never include a PID, path, command line, or raw procfs value. Missing, bounded, invalid-text, or safely dropped command-line/executable values keep the individual observation partial and are counted in the existing eligible-process readability ratios. They become a source-wide gap only when either ratio is below 80%; core stat/status/loginuid/cgroup failures remain fail-closed gaps. A partial or degraded attempt still advances the observation timestamp while retaining its non-healthy status, even when process event families continue to be observed. Partial enrichment recovers only after a later complete, non-truncated, non-deferred healthy scan; merely emitting another process event does not recover it. That healthy scan clears an active collection gap without erasing its historical count.

An interrupted durable sequence reservation is different from a collection gap. Its abandoned sequence range is never reused, the prior baseline is retried at new sequences, and the active bookmark-gap flag survives restart. When the healthy retry emits replacement events, the bookmark gap clears only after those committed events are durably acknowledged. A healthy retry that needs no event may clear it immediately only when every previously collected sequence is already acknowledged. An acknowledgement-state write failure remains an explicit runtime error until a later acknowledgement write succeeds. These bounded health fields, sequence progress, and baselines survive agent restart in the private state. State replacement flushes the file and parent directory, uses mode `0600`, rejects an existing state file with broader permissions, and remains bounded and corruption-aware.

The operational priority is:

1. heartbeat and existing queue drain;
2. L1/L2 journal continuity;
3. process/network snapshots;
4. host behaviour enrichment.

An incomplete scan, event limit, state corruption, deadline, or queue threshold is never treated as a healthy empty result. The collector reports the condition and avoids disappearance claims from incomplete input. Baseline growth is structurally capped; an entry absent from twelve consecutive incomplete scans is evicted with explicit gap accounting so stale partial evidence cannot grow state indefinitely. That eviction is degraded data-loss/coverage evidence, not an expected process-exit race, because the incomplete polls could not prove a disappearance event.

A successful empty poll is still a current observation and can keep source readiness healthy without inventing an event. The server expires a healthy passive source after two hours without a successful `observed_at` scan (a bounded grace above the allowed one-hour metrics interval), and treats observations more than five minutes in the future as degraded. Active collection and bookmark gap flags drive current posture; cumulative `gap_count`, read-skip classes, and `dropped_events` remain visible historical counters after recovery and do not keep dashboards or detections permanently gapped.

## Preflight, enablement, and rollback

Run the agent's passive-telemetry plan mode first and store the private output under an ignored path. Review the exact plan hash, interval and limits, sensitive-field handling, expected read permissions, queue threshold, state location, and rollback boundary.

Before installation, the lifecycle helper calculates the same canonical hash from the protected candidate configuration without starting a collector:

```bash
./scripts/linux-agent.sh plan --config <private-mode-0600-agentsettings.json>
```

The helper first applies the same passive interval, timeout, item, byte, event/headroom, fixed-state-path, queue bounds, and passive-versus-journal row/byte-priority checks as the agent. The approval hash binds every passive setting except `Enabled` and the self-referential `ApprovedPlanHash`, plus the queue size/warning, journal pause/poll-size inputs, and effective journal scope used by the reviewed collection and priority boundary. It accepts case-insensitive JSON keys with native integer/Boolean primitives and deliberately rejects looser string coercions. An invalid candidate produces no approvable passive plan hash. If a plan-bound passive, queue, or journal setting is supplied through an environment override, the helper refuses to guess; use the published agent's `--passive-telemetry-plan` output as authoritative for the effective configuration. Changing `IncludeAccessibleUserJournals` invalidates the passive approval even though it does not change procfs inputs. Supported values and relations are listed in [Linux agent configuration](linux-agent.md#configuration).

An already published agent also exposes `--passive-telemetry-plan` for a configuration selected through `CHALLENGER_SIEM_AGENT_CONFIG`. Both modes are read-only and must not have their real-host output copied into tracked files.

Enabling the pack requires both the explicit enable flag and the matching plan hash in the protected agent configuration. `CrossUserExecutableVisibility` is also plan-bound and defaults to false. When true, run `linux-agent.sh process-visibility-plan`, stage the exact profile through `process-visibility-enable`, restart only after separate approval, and require `process-visibility-validate` plus both readability ratios at or above 800 permille. Roll back with `process-visibility-disable` followed by an approved agent-only restart. The collector never grants itself additional access when reads are denied.

Rollback disables the pack and removes only its fixed-path, symlink-rejecting owned state when cleanup is explicitly requested. It does not delete the shared queue, collected server events, journal state, inventory, agent credentials, or any host process/network data source. Service stop/restart and package rollback remain separately approved lifecycle operations.

## Validation gates

Synthetic tests cover parsing bounds, malformed, denied, and disappearing procfs entries, aggregate command-line/executable readability and per-process partial enrichment, expected-race versus coverage-gap counters, PID/inode reuse, bounded partial-baseline eviction, initial and reboot baseline behavior, deterministic ordering and IDs, common credential-pattern redaction, IPv4/IPv6 decoding, committed-row acknowledgement ordering, restart-safe interrupted-reservation replay and acknowledgement recovery, pressure, truncation, health transitions, and source-manifest compatibility.

Live rollout additionally requires a private preflight, a bounded canary window, resource measurements, source-health review, outage/recovery evidence, and confirmation that no excluded data or unauthorized host change occurred. Unit tests do not substitute for that live evidence.
