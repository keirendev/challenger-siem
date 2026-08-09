# Troubleshooting

## Startup fails

Confirm `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ServiceToken` are present without printing them. Confirm PostgreSQL is reachable and the database contains the Linux v2 schema marker.

## Schema apply refuses the database

Version 2 only supports a fresh empty database. Back up any existing data and provision another database; do not bypass the guard or drop data through the helper.

## REST or MCP returns unauthorized

Review routes and `/mcp` require the exact `Auth__ServiceToken` bearer. Agent credentials work only for agent routes. Enrollment uses `X-Enrollment-Token` only for registration.

## Traffic map has no recent data

Select **All retained**, clear metadata filters, and inspect the **Retained evidence** end time. Presets use telemetry `event_time`, not ingestion time. If the retained end is stale, confirm the viewer loaded the exact PostgreSQL connection used by the active writable backend; the viewer does not read the endpoint queue or discover another service automatically. Then verify agent heartbeat, queue delivery, source health, and qualifying `linux-network-socket-snapshot-diff` or `linux-network-flow-summary` events through the normal backend. Do not point an agent at a `TrafficMap__ReadOnlyDatabase=true` viewer.

If destination rows exist but markers do not, review their geolocation state and provider quota before diagnosing collection. If both the basemap and markers are absent while table rows exist, check the configured HTTPS tile template, browser network access, and CSP response without recording credentials or telemetry in screenshots/logs. See the [traffic-map operator guide](network-geography-ui.md).

## Linux agent is silent

Check endpoint network/TLS trust, ignored agent configuration permissions, queue/source health, journal visibility, checkpoint state, and server validation responses. Do not broaden host permissions or alter journal policy merely to make health appear green.

## Linux delivery stalls after reboot or upgrade

Server 2.8.3 or later resolves a boot warm-up timestamp once per agent/boot ID for each bounded ingest batch and uses the existing normalized-event JSONB index. Agent 2.8.4 or later also emits the required original-size metadata for truncated Linux Audit Framework events and repairs only the known 2.8.3 omission in memory when transmitting an already durable audit row. Preserve the queue and allow deterministic accepted/duplicate acknowledgement processing to complete; confirm validation failures stop, acknowledgement gaps converge, and oldest-row age falls. The repair must not rewrite queue/WAL/checkpoint state. Do not delete or edit durable state, merely extend the transport timeout, or treat delivery recovery as approval of a new self-integrity or policy-posture baseline.

## Coverage is degraded

Inspect applicability, prerequisite evidence, observed time, continuity gaps, queue pressure, and recent events. `missing`, `stale`, `permission_denied`, `unsupported`, and `degraded` are visibility statements, not proof of safety.

## Kernel flow reconnects, map loss, or strict L4 falls to L3

On 2.9.1 or later, inspect the bounded kernel-source diagnostics together: last/high-water output count and bytes, last/high-water kernel transfer count, capped and residual-backlog ticks, current backlog, split kernel map-update and helper tracked-table loss, enrichment identities/cache hits, receive/persist duration, helper connection and IPC failures, active/cumulative sequence gaps, acknowledgement lag, queue depth/age, poison/drop totals, and parser/ring/IPC loss. The agent converts restart-scoped helper counters into monotonic agent-lifetime totals by retaining a private raw snapshot for each helper epoch. `flow_map_full` is the saturating aggregate of the two split loss counters plus any legacy unclassified total; `flow_map_entries=16384` is capacity and must not be reported as live or historical occupancy. A cumulative recovered gap or loss is historical evidence and must not be reset merely to make health look clean. Treat any backward cumulative movement as a migration or state-continuity failure and stop the rollout. Active loss requires three consecutive frames with no gap, new loss, or kernel backlog to clear, and an active agent-sequence gap remains until its replacement work is durably acknowledged.

Collector v3 transfers at most 500 kernel rows every second into the helper accumulator while retaining at most 500 emitted events per ten-second health interval. Residual backlog without new loss is pressure, not proof of omission; persistent backlog or either split counter increasing is a stop condition. If receive time approaches the helper send-stall boundary, persist time grows, acknowledgement lag does not return to zero, or the queue grows across several outputs, stop the rollout and use the reviewed version-compatible rollback. Preserve the queue, WAL/SHM, credentials, checkpoints, source state, and signed helper; do not delete state, vacuum the queue, resize maps, or restart the helper as a diagnostic shortcut.

## L4 stays in warm-up after an approved baseline replacement

An exact approved baseline change triggers an immediate complete posture observation and emits `baseline_reapproved` while preserving sequence, gap, and acknowledgement history. It does not bypass the independent performance-SLO warm-up: strict L4 returns only after a complete healthy rolling window and every applicable lower-tier/role source is healthy. If the reapproval event is absent, inspect plan/baseline hash matching and posture completeness; do not delete the L4 state file or reset historical counters to force adoption.

## Linux I/O pressure stays severe

Treat `/proc/pressure/io` as scheduler stall evidence, not as device-utilization or process-attribution evidence. Reconfirm the trend from bounded `linux-host-behaviour-metrics` samples, then compare a short current PSI window with `/proc/diskstats`, `vmstat`, per-process `/proc/<pid>/io`, and the `io.pressure` files for the agent, API, PostgreSQL, user-session, machine, and other material cgroups. Use `io.stat` where the controller exposes it. Attribute virtual-machine activity with read-only libvirt domain and block statistics. Do not infer that the largest writer caused the pressure merely from byte volume.

An async I/O waiter can keep PSI and `procs_blocked` high even when the backing device is lightly utilized. For example, a Linux Ghostty process using the `io_uring` async backend can leave renderer and I/O threads in `io_cqring_wait`. Confirm the process start boundary, persistent waiter count, user-session cgroup pressure, and near-zero SIEM service-cgroup pressure before treating this as the cause. Ghostty supports `async-backend = epoll` as an alternative, but changing that user configuration and fully restarting the application are external, disruptive operator actions and require separate approval.

Do not suppress or weaken the host-pressure detection solely for this signature: similar PSI can represent genuine local, virtual-machine, swap, or network-filesystem stalls. Verify remediation over at least 30 minutes after the change: sustained I/O PSI below 50%, no growing agent queue or poison/drop/backoff, healthy API and database-backed reads, strict source continuity, and no new OOM, crash, kernel/device, retention, or capacity impact. Keep real measurements and process evidence only in ignored operator storage.
