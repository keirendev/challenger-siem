# Runbooks

## Start and verify

1. Load ignored environment configuration containing database, enrollment, and service credentials.
2. Apply the schema to a new empty database with `./scripts/apply-schema.sh`.
3. Validate with `./scripts/validate-schema.sh`.
4. Start `dotnet run --project server/Siem.Api` behind HTTPS.
5. Verify `/health`, then use `./scripts/register-agent.sh` for a synthetic Linux registration.

## Investigate

Use service-authenticated REST or read-only MCP to review events, source health, coverage, alerts, cases, inventory, detections, and graphs. Preserve exact event IDs and time bounds. Treat missing or stale sources as visibility gaps. Use REST confirmation fields for mutations; MCP cannot mutate state.

For visual network review, start `/ui/traffic` through the [traffic-map operator guide](network-geography-ui.md). Confirm the **Retained evidence** end time before using a recent preset, because ranges use telemetry `event_time`. A separate read-only viewer must use the writable backend's exact PostgreSQL database and must never replace the agent ingestion or audited MCP endpoint.

For a question such as “which process contacted an IP in China?”, call `siem_search_network_activity` with `country_code=CN` and `attributed_only=true`, or the equivalent authenticated REST filters. MCP can answer only from matching cached geography, while authenticated REST can synchronously populate that cache from configured local MMDB files. Both still require retained process attribution; report unresolved geography, snapshot blind spots, kernel loss counters, and attribution confidence rather than inferring missing facts. Kernel-source rollout and rollback use the [signed helper runbook](linux-kernel-network.md).

## Retention

Review storage accounting and perform a dry run before executing managed retention. Manual execution requires the exact `CONFIRM RETENTION DELETE` confirmation and is security-audited. The allowlist is limited to events, heartbeat history, inventory snapshots, and ingestion errors. Current source state, alerts/evidence, cases, graphs, detection metadata, audit, and agents are protected.

Direct storage status uses exact live-row accounting. Normal scheduled retention reports
`catalog_estimate`, uses allocated PostgreSQL relation sizes and catalog row estimates,
and uses separate event-time-ordered phases with bounded primary shares for history,
optional events, and mandatory L1 journal rows. Unused shares return to the existing
optional-before-mandatory fallback, but a sustained optional backlog cannot consume every
batch and pin the oldest mandatory event indefinitely. A capped pass with expired rows
remaining reports `bounded_incomplete`. Reaching the managed-capacity boundary triggers
an exact live-row check before emergency deletion. During an ingest-latency incident,
correlate the retention run window and accounting mode with PostgreSQL statement and I/O
latency; an available GET path does not prove that bounded ingest completed inside the
agent's acknowledgement deadline.

For the 2.2.0 deployment profile, keep `Storage:Retention:HostedServiceEnabled=false`
until an execution dry run against the target database reports no unexpected eligible
rows. Then enable the 60-minute scheduler while retaining the 30-day target and 100 GiB
ceiling. Verify the telemetry-coverage scheduler fields after the API restart. A short
observed history on a new deployment is deployment age, not evidence that configured
retention is too short.

## Heartbeat loss

The server checks active agents every 30 seconds. It infers cadence from the median of
the newest 20 heartbeat intervals, clamps cadence to 30–300 seconds, falls back to 60
seconds, and declares an outage after three inferred intervals bounded to 2–15 minutes.
One deterministic critical `tamper.agent-heartbeat-loss.linux` alert is created per
outage boundary. A later authenticated heartbeat resolves only an active outage alert,
preserves disposition and closed alerts, and records idempotent recovery activity.

Review monitor freshness and 24-hour/seven-day readiness before interpreting silence.
The SIEM cannot self-report an API, database, process, or host failure that prevents its
monitor from running; deploy independent service/endpoint monitoring for that failure
domain.

## 2.2.0 agent/API rollout

1. Pass the full synthetic, contract, repository-safety, shell, disposable PostgreSQL,
   publish, and disposable Linux VM gates. Keep audit disabled and undeclared.
2. Store exact rollback copies and hashes under ignored private storage. Confirm the
   installed queue is healthy and drained; run retention dry-run and passive,
   self-integrity, L4, audit, and lifecycle preflights without printing configuration,
   credentials, plan values, or telemetry.
3. Activate and health-check the API first. Stage the agent through the lifecycle
   helper, preserving protected configuration, credentials, queue, checkpoints, TLS,
   sandboxing, and unrelated drop-ins.
4. Generate and separately approve the changed passive, self-integrity, and L4 hashes.
   Set `CollectSocketOwnership=true` only as part of that reviewed passive plan. Leave
   `Agent:Audit:Enabled=false`, `FacilityDeclaration=undeclared`, and its approval empty.
   If full cross-user executable visibility is approved, also set the plan-bound
   `CrossUserExecutableVisibility=true`, run `process-visibility-plan`, stage only the
   fixed profile through `process-visibility-enable`, and retain its exact removal
   plus agent-only restart as rollback. Normal install/upgrade does not add it.
5. Restart only the Challenger SIEM agent. When the optional profile is staged, run
   `process-visibility-validate` and verify direct ptrace/process-memory/performance
   syscalls remain denied. Verify fresh heartbeat, an empty or draining
   queue, source health, interface inventory, generation completeness, eligible-process
   visibility ratios, bounded socket attribution, disk diagnostics, liveness freshness,
   service restart counts, and absence of audit content in generic L1.
6. Roll back both product artifacts and private configuration if either service fails
   health within five minutes, the queue grows without recovery, mandatory journal
   coverage regresses, trusted audit reaches L1, bounds fail, or state/cursor integrity
   is uncertain.

Perform read-only 24-hour and seven-day follow-ups. Report only sanitized aggregates:
heartbeat availability, active versus cumulative gaps, alert dispositions, pressure
percentiles, inventory completeness, attribution coverage, retention readiness, and
remaining blind spots. After 24 hours, remove only a verified validation-specific
memory-limit override when RSS p95 is below 175 MiB, no OOM/restart occurred, and the
tracked 250 MiB limit retains adequate headroom; preserve TLS and a recoverable backup.

## 2.4.1 agent-only oversized-journal recovery rollout

Preparing or reviewing this patch does not authorize deployment or a service restart.
Activation requires separate operator approval naming the endpoint, maintenance window,
candidate artifact, agent-only restart, verification window, and exact rollback artifact.

1. Pass the synthetic Linux journal suite, full solution build/test, contract validation,
   repository-safety validation, and shell syntax checks. Confirm the greater-than-128-KiB
   parser case, 500-record omission burst, persisted restart, next-cursor resume, and
   recovery-state transition all pass without real journal fixtures.
2. Under ignored private storage, retain exact rollback copies and hashes for the installed
   agent artifact and protected configuration. Record only secret-safe aggregates for
   service state, restart count, heartbeat age, queue depth/bytes, collected-versus-
   acknowledged position presence, active/cumulative gaps, and oversized counters. Do not
   print cursor values, boot IDs, raw records, settings, credentials, or queue/state content.
3. Stage only the 2.4.1 agent artifact. Do not change the API, database, `/api/v2`,
   `contracts/v2`, journal scope/retention, producer logging, configuration, credentials,
   permissions, groups, ACLs, capabilities, audit policy, firewall, authentication, kernel,
   or MAC policy. Complete the authenticated versioned-route preflight before replacement.
4. After the separate activation approval, replace only the agent artifact while preserving
   its configuration, queue, state, TLS trust, systemd unit/drop-ins, and ownership/modes;
   restart only the Challenger SIEM agent within the approved window.
5. Verify a fresh heartbeat, stable single service instance/restart count, available queue
   delivery, no poison/drop increase, and cursor advancement beyond the omission burst.
   Source health must show bounded omitted-record/byte counters, an explicit
   `oversized_record_omitted` gap, and recovery after a later clean poll; omitted content
   must produce no event or source-family evidence. Keep L4 failed while any applicable
   journal gap remains active.
6. Stop and roll back if the cursor does not advance within two normal poll intervals,
   heartbeat/queue delivery regresses, state cannot be persisted, the service loops,
   omission counters grow unexpectedly, content appears in telemetry, or mandatory source
   health remains worse after the bounded recovery window. Preserve queue/state and logs;
   do not clear the journal, reset cursors, delete runtime data, or widen access. Restoring
   the prior artifact and performing the agent-only restart also require the approved
   rollback authority.
7. Perform read-only checks after 15 minutes and 24 hours. Report only sanitized aggregate
   availability, queue, gap/recovery, omission, restart, and coverage results; keep all live
   evidence under ignored or approved private storage.

## Kernel-flow performance-SLO incident review and collector-v2 rollout

Use the normal authenticated backend, never the dedicated traffic viewer, for the read-only confirmation. Query the exact UTC window beginning 20 minutes before the breach through the latest retained post-breach evidence, with bounded pagination, for performance-SLO events, kernel-flow activity, L4 coverage, and source health. Privately aggregate per-minute event family, serialized size, and anonymized process identity alongside rolling agent writes, queue depth/age, acknowledgements, and helper failure/gap counters. Do not print credentials, raw events, process names, IP addresses, plan hashes, or private paths. Sample current agent/helper process and cgroup I/O read-only and keep agent, helper, API, PostgreSQL, and unrelated writers separate. Treat byte-volume correlation as contributor evidence, not proof. If kernel flow is not the largest time-aligned event/payload contributor, block protected-host rollout pending a revised source-specific diagnosis.

The collector-v2 patch changes only the agent receive/persist path and compatible queue initialization. The native helper, IPC protocol v1, event schema v1, helper capabilities/attachments, `/api/v2`, MCP, JSON Schemas, PostgreSQL, and payload/privacy boundaries remain unchanged. Before any new protected-host action, require the focused/full synthetic validations, an authorized 30-minute disposable-VM workload at 500 records per ten-second drain, a newly signed bundle, refreshed kernel and L4 approvals, and exact prior agent/configuration rollback copies. The VM must satisfy the resource, queue, acknowledgement, loss, API/database, and strict-L4 criteria in [Linux kernel network flow telemetry](linux-kernel-network.md), unless the explicitly designated single-host development workflow records why same-host validation is authoritative for that deployment.

A protected-host canary requires fresh exact approval for the target, window, artifact, agent-only restart, read-only checks, stop gates, and rollback. Preserve the queue, WAL/SHM, credentials, checkpoints, source state, and unchanged helper; do not restart the helper. Verify one full healthy rolling window after warm-up, then continue the documented 24-hour read-only soak. Stop and restore the prior agent/configuration on another SLO breach, helper discontinuity, queue growth, poison/drop/loss increase, crash/restart, host impact, silent loss, or inability to preserve queue/state during rollback.

Current sanitized status (2026-08-04): the exact 2.8.1 single-host agent-only rollout passed the initial 30-minute acceptance window and one additional complete healthy L4 rolling window. Strict L4 recovered, acknowledgement lag returned to zero, queue pressure and loss counters remained normal, and the unchanged helper did not restart. The 24-hour read-only soak is in progress; keep its private measurements outside the repository and update only the aggregate decision when it completes.

## Kernel-flow burst-capacity correction and helper-v3 rollout

Preparing or validating collector v4/helper v3 does not authorize a live helper replacement, detach, service restart, or agent restart. Keep the affected live source read-only until an exact protected-host activation and rollback window is separately approved.

1. Privately review bounded aggregate evidence around each split-loss boundary: unique flow-key cardinality, event count and serialized bytes, output drain count, queue depth/oldest age, acknowledgement lag, send outcome, helper epoch/sequence, parser/ring/IPC counters, and current counter stability. Treat capacity fields as fixed bounds, not measured occupancy. Do not print tuples, process identities, credentials, plan hashes, raw events, or state files.
2. Build the 2.11.0 candidate and helper, pass native, focused/full managed, lifecycle, contract, repository-safety, and shell validations, and create a newly signed bundle. Generate and review the new kernel plan plus dependent L4 plan/baseline. Helper/collector version, map, drain, output, coalescing, and enrichment changes invalidate prior approvals.
3. In an explicitly authorized disposable Linux x86_64 VM, run the incident-shaped 120,000-distinct-key burst and bounded 18,000-per-minute steady phase from [Linux kernel network flow telemetry](linux-kernel-network.md). Require kernel-map, helper-table, parser, ring, and IPC loss counters to stay fixed, tracked backlog to be truthful and drain within six minutes after the burst, queue age below 30 seconds without sustained growth, acknowledgement lag returning to zero, zero poison/drop/backoff, healthy API/database reads, and the existing CPU/RSS/write and strict-L4 gates. Run the above-envelope overload case only in the disposable VM; any resulting loss remains real.
4. Preserve exact private rollback copies and hashes of the prior signed helper/agent bundle and protected configuration. Stage the reviewed candidate without restarting the running helper or agent. Re-run the lifecycle plan against the staged files and stop if versions, signer, hashes, capabilities, attachment catalog, privacy boundary, or rollback materials differ.
5. After separate approval naming the target, maintenance window, commands, verification duration, and rollback authority, stop the agent, restart the helper so the old links detach and the reviewed v3 object attaches, then start the compatible candidate agent. Do not make ad hoc runtime map, capability, cgroup, queue/checkpoint, audit/firewall/authentication/kernel/MAC, or unrelated service changes.
6. Validate exact installed hashes and service identities, one expected helper epoch/restart boundary, the fixed attachment catalog with no leftover pins, source freshness, split loss counters, capped/backlog diagnostics, queue/acknowledgement recovery, delivery, and strict L4 after a complete warm-up window. Continue a 24-hour read-only soak.
7. Stop and use the coordinated rollback on either split loss counter increasing, backlog persisting beyond one health interval after workload subsides, unexpected helper gaps/restarts, queue growth, acknowledgement failure, poison/drop/backoff, SLO breach, host impact, attachment mismatch, or inability to preserve state. Restore the exact prior helper and compatible agent; never delete, reset, vacuum, or edit queue/checkpoint/source state to make health appear clean.

## Package visibility and recurring write-rate rollout

For 2.9, deploy the API before the agent. Verify two heartbeat cycles from the still-running 2.8.x agent: its exact mandatory `linux-package-management` descriptor remains the legacy package requirement. After the current agent appears, require the mandatory `linux-package-inventory-diff` plus supplemental journal shape; mixed or spoofed descriptors must be rejected.

Stage the agent without restart, run installed lifecycle validation, and repeat the two-pass L4 baseline/plan approval because the agent binary and L4 collector version changed. Activation is agent-only: do not restart the eBPF helper or change packages, capabilities, audit, firewall, journal access, or other host policy. Preserve the prior API drop-in, agent payload, protected configuration, queue/WAL/SHM, checkpoints, and all collector state.

Soak for at least 20 minutes and one complete SLO window. Require heartbeat/ingestion success, a drained queue, zero acknowledgement lag, no poison/drop/backoff/network-loss increase, a healthy package-inventory source after its first complete non-alerting baseline, correct strict coverage, and no write-rate breach. Review SLO attribution as serialized queue work rather than physical-write proof. A representative private synthetic replay must exceed the historical event rate, reduce queue-attributed writes by at least 25% versus the per-row path, stay below 1,048,576 process-write bytes/second for the full 15-minute window, drain, and lose no event.

On any failed gate, restore only the affected prior API drop-in or prior agent payload/protected configuration and restart only that service. Never delete, reset, vacuum, or edit queue/checkpoint/collector state to make the gate pass.

## Incident safety

The SIEM does not execute endpoint response commands. Reboots, service changes, firewall/authentication changes, package changes, and data deletion require a separate authorized host procedure. Keep all real evidence under ignored local or approved runtime paths.
