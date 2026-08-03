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

## Retention

Review storage accounting and perform a dry run before executing managed retention. Manual execution requires the exact `CONFIRM RETENTION DELETE` confirmation and is security-audited. The allowlist is limited to events, heartbeat history, inventory snapshots, and ingestion errors. Current source state, alerts/evidence, cases, graphs, detection metadata, audit, and agents are protected.

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

## Incident safety

The SIEM does not execute endpoint response commands. Reboots, service changes, firewall/authentication changes, package changes, and data deletion require a separate authorized host procedure. Keep all real evidence under ignored local or approved runtime paths.
