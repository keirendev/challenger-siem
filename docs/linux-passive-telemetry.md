# Linux passive process, network, and behaviour telemetry

## Status and boundary

Challenger SIEM provides an optional Linux L3 passive telemetry pack for process snapshots, network socket snapshots, and host resource/pressure samples. The pack is disabled by default and runs only when its explicit configuration flag and approval-plan hash both match.

The collector reads bounded procfs files that already exist. It does not install packages, load kernel programs, add audit rules, change journal retention, widen firewall or authentication policy, add groups or capabilities, inspect process memory, or restart services. Enabling it on an installed agent is still an operator-controlled configuration and lifecycle change.

The pack is complementary to the L1/L2 journal path. It does not claim the exactness of kernel exec/exit or socket hooks: every event name and health record identifies snapshot/polling evidence and reports gaps, truncation, pressure, and incomplete visibility.

## Sources and v1 compatibility

The pack uses additive source IDs inside the existing v1 portable event envelope:

| Source | Existing event source kind | Purpose |
|---|---|---|
| `linux-process-snapshot-diff` | `inventory_diff` | Bounded process baseline and observed/disappeared/changed differences |
| `linux-network-socket-snapshot-diff` | `inventory_diff` | Bounded TCP/UDP socket and listener baseline/differences |
| `linux-host-behaviour-metrics` | `agent_health` | Coalesced host load, memory, pressure, and counter-derived disk/network deltas |

No `/api/v2`, incompatible schema, or new database event-source enum is required. Events retain deterministic IDs, source-local sequence checkpoints, explicit data-handling metadata, and server deduplication. A sequence range is durably reserved before queue insertion, and the collected baseline/checkpoint advances only after all events are queued. For fully committed rows, accepted/duplicate acknowledgement is recorded before queue deletion. Rows left by an interrupted reservation can be accepted and deleted without advancing the committed acknowledgement; the reservation remains an explicit, non-reused sequence gap and its semantic changes are retried from the prior baseline at new sequences.

## Process observations

The process source first reads bounded `/proc/self/mountinfo` evidence so restrictive `hidepid` policy cannot be mistaken for full visibility. It then reads only fixed, bounded fields from `/proc/<pid>/stat`, `status`, `exe`, `cmdline`, `cgroup`, and `loginuid`. It may report:

- PID and parent PID;
- numeric user/group identity;
- executable and bounded command line with common credential-pattern redaction when readable;
- an opaque boot-scoped process key derived from PID and start ticks so PID reuse is distinct; start ticks are not sent as a separate field;
- selected capability, seccomp, no-new-privileges, tracer, login-user, and hashed cgroup metadata;
- `process_baseline`, non-alertable `process_baseline_disappeared`, `process_observed`, `process_disappeared`, and `process_changed` event codes, with polling-honest normalized actions.

Baseline establishment can span multiple complete polls when the event cap is lower than the initial population; it becomes established only after a complete poll has no deferred baseline differences. All such baseline and baseline-disappeared evidence is non-alertable and is not an assertion that an existing process just executed. A poll can miss short-lived processes. A numeric PID entry that disappears, or changes start identity, between the two bounded `stat` reads is an expected race: it increments the separate expected-race counter but does not by itself create a coverage gap or degraded health. Denied, malformed, invalid-text, I/O-failed, budget-limited, truncated, or mount-restricted reads remain coverage gaps; a readable process identity can still be emitted with `enrichment_partial=true`. Missing optional enrichment alone is omitted rather than treated as permission denial. No condition causes a privilege retry or permission widening.

## Network observations

The network source parses bounded `/proc/net/tcp`, `tcp6`, `udp`, and `udp6` snapshots. It reports canonical local/remote addresses and ports, protocol, socket state, listener category, inode identity, numeric socket UID when available, coalesced tuple count, and polling lifecycle actions including non-alertable baseline/baseline-disappeared evidence followed by observed, disappeared, or changed differences.

It does not capture packets, payloads, DNS contents, Unix-domain socket paths, TLS material, or unrelated `/proc/<pid>/fd` targets. Process attribution is deliberately not collected and is labelled `not_collected`; it is never fabricated. Socket baseline establishment uses the same potentially multi-poll, non-alertable boundary as processes. Snapshot polling can miss short connections, and a truncated or partial scan must not generate false disappearance events.

## Host behaviour samples

Host samples are coalesced bounded aggregates from fixed procfs resource files. They provide load, computed CPU-busy permille, available/total memory, free swap, uptime, running/blocked process counts, pressure-stall gauges, and deltas derived from disk-sector and interface-byte counters when readable. Each metrics scan also reads `/proc/sys/kernel/random/boot_id`, hashes it locally, and resets previous absolute counters on an epoch change so cross-boot deltas cannot be fabricated; the identifier is not emitted as event content. The private state retains the prior hash and previous absolute counters only for that reset and delta calculation. Disk inputs sum visible kernel disk-stat rows, including stacked devices or partitions, and network inputs sum visible interfaces, including loopback or virtual interfaces; they are trend context, not physical-disk or external-traffic accounting.

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

Each source exposes enabled/approval state, collected and acknowledged sequence, latest scan attempt, observed/deferred counts, visibility/permission status, truncation, active gaps, cumulative historical gap/drop/pressure counters, and recovery. Process health separately persists total read skips, expected process-lifecycle race skips, and coverage-gap read skips; expected races are diagnostic history, not dropped events. A bounded unclassified count preserves older total-only state without guessing its cause. A partial or degraded attempt still advances the observation timestamp while retaining its non-healthy status, even when process event families continue to be observed. Partial enrichment recovers only after a later complete, non-truncated, non-deferred healthy scan; merely emitting another process event does not recover it. That healthy scan clears an active collection gap without erasing its historical count.

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

The helper first applies the same passive interval, timeout, item, byte, event/headroom, fixed-state-path, queue bounds, and passive-versus-journal row/byte-priority checks as the agent. The approval hash binds every passive setting except `Enabled` and the self-referential `ApprovedPlanHash`, plus the queue size/warning, journal pause/poll-size inputs, and effective journal scope used by the reviewed collection and priority boundary. It accepts case-insensitive JSON keys with native integer/Boolean primitives and deliberately rejects looser string coercions. An invalid candidate produces no approvable passive plan hash. If a plan-bound passive, queue, or journal setting is supplied through an environment override, the helper refuses to guess; use the published agent's `--passive-telemetry-plan` output as authoritative for the effective configuration. Changing `IncludeAccessibleUserJournals` invalidates the passive approval even though it does not change procfs inputs. Supported values and relations are listed in [Agent configuration format](agent-config.md#linux-passive-l3-fields).

An already published agent also exposes `--passive-telemetry-plan` for a configuration selected through `CHALLENGER_SIEM_AGENT_CONFIG`. Both modes are read-only and must not have their real-host output copied into tracked files.

Enabling the pack requires both the explicit enable flag and the matching plan hash in the protected agent configuration. On a running installed service, obtain approval before changing the config or restarting/upgrading the service. The collector does not grant itself additional access when reads are denied.

Rollback disables the pack and removes only its fixed-path, symlink-rejecting owned state when cleanup is explicitly requested. It does not delete the shared queue, collected server events, journal state, inventory, agent credentials, or any host process/network data source. Service stop/restart and package rollback remain separately approved lifecycle operations.

## Validation gates

Synthetic tests cover parsing bounds, malformed, denied, and disappearing procfs entries, expected-race versus coverage-gap counters, PID/inode reuse, bounded partial-baseline eviction, initial and reboot baseline behavior, deterministic ordering and IDs, common credential-pattern redaction, IPv4/IPv6 decoding, committed-row acknowledgement ordering, restart-safe interrupted-reservation replay and acknowledgement recovery, pressure, truncation, health transitions, and source-manifest compatibility.

Live rollout additionally requires a private preflight, a bounded canary window, resource measurements, source-health review, outage/recovery evidence, and confirmation that no excluded data or unauthorized host change occurred. Unit tests do not substitute for that live evidence.
