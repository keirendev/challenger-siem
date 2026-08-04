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

## Coverage is degraded

Inspect applicability, prerequisite evidence, observed time, continuity gaps, queue pressure, and recent events. `missing`, `stale`, `permission_denied`, `unsupported`, and `degraded` are visibility statements, not proof of safety.

## Kernel flow reconnects or strict L4 falls to L3

On 2.8.1 or later, inspect the bounded kernel-source drain diagnostics together: last/high-water drain count and bytes, unique enrichment identities/cache hits, receive/persist duration, helper connection and IPC failures, active/cumulative sequence gaps, acknowledgement lag, queue depth/age, poison/drop totals, and parser/ring/map/IPC loss. A cumulative recovered gap is historical evidence and must not be reset merely to make health look clean. Active helper loss requires three consecutive clean health frames to clear, and an active agent-sequence gap remains until its replacement work is durably acknowledged.

The 2.8.1 collector receives the full helper drain through its health delimiter before procfs enrichment. If receive time approaches the helper send-stall boundary, persist time grows, acknowledgement lag does not return to zero, or the queue grows across several drains, stop the rollout or use the reviewed agent-only rollback. Preserve the queue, WAL/SHM, credentials, checkpoints, source state, and unchanged helper; do not delete state, vacuum the queue, or restart the helper as a diagnostic shortcut.

## L4 stays in warm-up after an approved baseline replacement

An exact approved baseline change triggers an immediate complete posture observation and emits `baseline_reapproved` while preserving sequence, gap, and acknowledgement history. It does not bypass the independent performance-SLO warm-up: strict L4 returns only after a complete healthy rolling window and every applicable lower-tier/role source is healthy. If the reapproval event is absent, inspect plan/baseline hash matching and posture completeness; do not delete the L4 state file or reset historical counters to force adoption.

## Linux I/O pressure stays severe

Treat `/proc/pressure/io` as scheduler stall evidence, not as device-utilization or process-attribution evidence. Reconfirm the trend from bounded `linux-host-behaviour-metrics` samples, then compare a short current PSI window with `/proc/diskstats`, `vmstat`, per-process `/proc/<pid>/io`, and the `io.pressure` files for the agent, API, PostgreSQL, user-session, machine, and other material cgroups. Use `io.stat` where the controller exposes it. Attribute virtual-machine activity with read-only libvirt domain and block statistics. Do not infer that the largest writer caused the pressure merely from byte volume.

An async I/O waiter can keep PSI and `procs_blocked` high even when the backing device is lightly utilized. For example, a Linux Ghostty process using the `io_uring` async backend can leave renderer and I/O threads in `io_cqring_wait`. Confirm the process start boundary, persistent waiter count, user-session cgroup pressure, and near-zero SIEM service-cgroup pressure before treating this as the cause. Ghostty supports `async-backend = epoll` as an alternative, but changing that user configuration and fully restarting the application are external, disruptive operator actions and require separate approval.

Do not suppress or weaken the host-pressure detection solely for this signature: similar PSI can represent genuine local, virtual-machine, swap, or network-filesystem stalls. Verify remediation over at least 30 minutes after the change: sustained I/O PSI below 50%, no growing agent queue or poison/drop/backoff, healthy API and database-backed reads, strict source continuity, and no new OOM, crash, kernel/device, retention, or capacity impact. Keep real measurements and process evidence only in ignored operator storage.
