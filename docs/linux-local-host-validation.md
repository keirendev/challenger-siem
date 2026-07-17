# Linux local-host rollout validation runbook

This runbook stages Challenger SIEM Linux agent rollout validation on an operator-authorized systemd host without publishing private host evidence. It is the issue-status and evidence template for the Linux local-host validation gate described by the Linux agent, security, and coverage documents.

This document is **not** authorization to use SSH, WinRM, reboot a host, restart production services, change firewall/authentication/audit/kernel/MAC policy, add groups/capabilities/ACLs, force journal retention changes, or execute L3 collection. If an operator-authorized Linux systemd target, maintenance window, and exact permitted operations are not already documented for the work item, complete only the repository documentation/template work and record live soak as blocked.

## Scope and compatibility

- Applies to the bounded Linux agent service on a systemd host: passive L1 journal collection with default system-only and opt-in all-accessible-local scopes, opt-in L2 logical journal classification, bounded read-only inventory, disabled-by-default L3 self-integrity/procfs packs, and disabled-by-default L4 posture/SLO/role-journal sources.
- Uses the existing `/api/v1` ingest, heartbeat, source-health, telemetry-coverage, and inventory surfaces. No `/api/v2`, `contracts/v2`, or incompatible `contracts/v1` change is introduced by this runbook.
- Publishes only synthetic or aggregate pass/fail content. Raw host telemetry, generated settings, logs, queues, database dumps, screenshots, benchmark output, package lists, hostnames, usernames, IP addresses, private paths, command transcripts, event payloads, and secrets remain private and untracked.
- No host-policy mutation is allowed by default. Missing, denied, stale, degraded, unsupported, or unknown sources are evidence states, not permission to broaden access.

## Public repository safety and evidence handling

Before, during, and after validation:

1. Keep live evidence under ignored local paths such as `.local/linux-validation/<run-id>/` or under approved OS runtime/log locations on the target.
2. Keep real `agentsettings.json`, enrollment tokens, per-agent tokens, connection strings, operator API credentials, queue/state databases, raw journal records, raw API responses, logs, screenshots, traces, dumps, and benchmark samples out of tracked files.
3. Redact before writing any public issue/PR/comment: host identity, network location, usernames, group names, exact paths outside product paths, package lists, service lists, command transcripts, raw messages, event IDs tied to a real host, and detailed timing/resource measurements.
4. Publish only aggregate status such as `pass`, `fail`, `blocked`, `not run`, `count bucket`, `SLO met/not met`, and a private evidence reference that does not reveal local paths.
5. If sensitive or excluded data is observed, stop validation, preserve private evidence locally for the operator, revoke/rotate credentials if needed, and publish only a sanitized stop-gate summary.

Recommended ignored private layout:

```text
.local/linux-validation/<run-id>/
  README-private.md              # local-only target/window/evidence map
  preflight/                     # plan output and approval record
  l1-soak/                       # private 24-hour evidence
  l2-soak/                       # private seven-day evidence
  l3-soak/                       # private bounded passive/self-integrity evidence
  l4-soak/                       # private exact plan/baseline, role, rolling-SLO, and strict coverage evidence
  recovery/                      # outage/restart/rotation/pressure notes
  rollback/                      # cleanup verification notes
```

Do not move anything from this layout into tracked docs, examples, fixtures, tests, issues, or pull requests unless it has been rewritten as a synthetic aggregate.

## Required preflight and approval plan

A validation run may start only when all items are true:

- The operator has identified an authorized systemd target and a validation time window in private coordination notes.
- The operator has approved the exact operations for that window: plan only, install/upgrade, service start/stop/restart, API outage drill, database restart drill, permission-loss drill, pressure drill, uninstall, and each requested L3 pack. Unlisted operations remain forbidden.
- The target is operator-owned for this validation, not a customer/client system unless separate data-handling approval exists.
- The server/API endpoint and database are designated for validation and can tolerate the approved outage/restart drills.
- Rollback owner, stop-gate contact, credential revocation path, and private evidence location are recorded locally.
- Repository checkout is clean enough that generated configs/logs/queues cannot be accidentally staged.

Preflight evidence must include, in private storage only:

- product version from `./scripts/current-version.sh`;
- target-architecture portable bundle produced into a non-symlink absent/empty mode-0700 destination by `./scripts/publish-linux-agent.sh linux-x64 <private-ignored-output>` or `linux-arm64`, with repository-local output under ignored `dist/`/`.local/`, the self-contained/compressed/single-file and 64 MiB checks passed, and its lifecycle helper/unit present;
- transferred binary, private configuration, and unit remain bounded regular non-symlink files, and no `/opt`, `/etc`, state, or unit product target is a symlink or unexpected file type;
- separate private mode-0600 real configuration created for the authorized target, with the bundle's placeholder-only synthetic reference explicitly excluded from deployment;
- pre-existing reviewed non-root `challenger-siem` passwd entry (UID not 0) with matching primary group, exact nologin/false shell, locked `!`/`*` shadow password, and adequate existing journal visibility; identity creation/correction and any group/ACL change are separate approval-gated prerequisites, not installer behavior;
- non-policy-mutating Linux lifecycle plan from the bundled `./linux-agent.sh plan` and, after disabled installation, the installed-identity L4 preflight; the latter may populate only the private product-owned `.dotnet-bundle` runtime cache;
- requested target level (`L1` for first soak; `L2` only after L1 passes and canary approval exists);
- requested journal scope (`system_only` by default; `all_accessible_local` only after explicit privacy/volume review), existing service-identity visibility, and the fact that scope selection grants no new access;
- whether `SelfIntegrity.Enabled` and `PassiveTelemetry.Enabled` are false or, for a separately approved L3 drill, each independently approved exact plan hash;
- product paths and permission expectations for `/etc/challenger-siem-agent`, `/var/lib/challenger-siem-agent`, `/opt/challenger-siem-agent`, and the systemd unit;
- expected source catalog, applicability, and known unsupported sources;
- expected volume/resource limits and SLOs;
- proposed host changes, which should be none for L1/L2 collection beyond the approved agent lifecycle operation.

For an L4 candidate, preflight must additionally record the explicit supported role declarations, exact L4 plan hash, exact candidate posture-baseline hash, fixed posture snapshot types, rolling-window inputs/limits, applicable role journal rows, strict no-exception expectation, and the fact that host-policy changes remain none. Install with L4 disabled first. On the real-root installed target, run the L4 plan through the lifecycle helper with the private mode-0600 config so it executes as `challenger-siem` with a clean environment; a missing identity/binary/private writable state directory or alternate-root context is a blocker, not permission to probe as root. The only expected preflight write is the single-file runtime cache under the private state directory.

Public preflight summary should say only whether the plan was reviewed and whether it proposed unauthorized mutation. Do not publish the plan output.

## Bounded validation commands

The commands below are examples of bounded product validation surfaces. Run them locally on an authorized validation system or in an authorized private shell only; do not run them through SSH/WinRM for this issue unless the operator explicitly authorizes that target and operation.

```bash
./scripts/current-version.sh
./scripts/publish-linux-agent.sh linux-x64 <private-ignored-output>
# On the authorized target, from the private copied bundle:
./linux-agent.sh plan --payload . --config <separate-private-mode-0600-config>
# After separately approved disabled install:
./linux-agent.sh plan --config /etc/challenger-siem-agent/agentsettings.json
./linux-agent.sh validate
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

When querying a running validation API, use small limits, timeouts, and aggregate status extraction. Store raw responses only under ignored private evidence. Public summaries should report status counts and pass/fail decisions, not response bodies.

## L1 24-hour soak procedure

Purpose: prove non-disruptive default Linux collection with `Journal.TargetCoverageLevel=L1`, `Journal.IncludeAccessibleUserJournals=false`, `SelfIntegrity.Enabled=false`, and `PassiveTelemetry.Enabled=false`.

Minimum duration: **24 continuous hours** after the agent reaches steady state.

Entry gates:

- Preflight plan reviewed and no unauthorized host-policy mutation proposed.
- Generated config is private, mode-restricted, and not in the repository.
- Agent lifecycle action was explicitly approved for the target/window.
- Server, database, and API health are known before the soak begins.

During the soak, privately verify:

- agent starts, heartbeats, and reports source-health without raw telemetry leakage;
- `linux-journal-l1` source positions advance and acknowledged checkpoints do not advance before accepted/duplicate acknowledgement;
- source health reports `configured_journal_scope=system_only`, truthful system visibility, and no unexplained scope transition;
- queue depth/age, send/backoff/recovery, poison/drop counters, and pressure state remain within planned limits;
- resource SLOs are met: average CPU below 2%, p95 CPU below 5%, RSS below 250 MiB, average writes below 1 MiB/s, and no individual collector above 10% CPU for more than 60 seconds;
- privacy exclusions hold for credentials, tokens, connection strings, private key material, environment values, browser/session data, packet payloads, keystrokes, screenshots, and unrestricted file content;
- source-health distinguishes `healthy`, `permission_denied`, `stale`, `degraded`, `unsupported`, `not_applicable`, and `unknown` without pretending missing evidence is healthy;
- restart, outage, journal rotation, permission, and pressure recovery checks in this runbook are completed or recorded as not approved/not applicable.

L1 pass criteria:

- No stop gate triggered.
- All mandatory L1 evidence states are healthy or truthfully explained as denied/unsupported/not applicable/blocked.
- Queue and checkpoint behavior shows no silent loss or corruption.
- All resource SLOs pass, or the rollout is blocked with an approved exception decision recorded privately.
- Public result contains only sanitized aggregate status.

## L1+L2 seven-day soak procedure

Purpose: prove the opt-in Linux security baseline canary after L1 passes. `L2` remains canary-only until this private gate passes.

Minimum duration: **seven continuous days** with representative workload and ordinary maintenance windows.

Entry gates:

- L1 24-hour soak passed for the same product build and comparable host class.
- Operator separately approved `Journal.TargetCoverageLevel=L2` for the target/window.
- Any `IncludeAccessibleUserJournals=true` expansion was separately approved for the target/window after reviewing user-service/session text exposure, expected volume, restart, cursor continuity, and rollback; otherwise it remains false.
- Declared roles are bounded and privately justified. Empty roles are acceptable and should leave role-specific applicability unknown rather than guessed.
- No audit, eBPF, broad file-integrity, firewall, authentication, kernel, group, ACL, capability, journal-retention, service-policy, or MAC-policy mutation is bundled into the L2 canary.

During the soak, privately verify L1 criteria plus:

- logical L2 families classify only from the shared durable journal cursor;
- the effective scope and independent system-journal visibility are reported truthfully; a successful broad read cannot hide missing or denied system visibility;
- SSH, login/session, sudo/su, scheduler, package, firewall, kernel/security-module, service-change, and agent/log-tamper families report truthful applicable/not-applicable/unknown/degraded states;
- scope expansion preserves the durable cursor, does not claim historical backfill, and treats any rejected cursor as a persisted gap/reset before bounded recovery;
- `linux-audit-framework` remains explicitly `unsupported` unless a future approved implementation exists;
- structured fields take precedence and ambiguous messages do not invent users, addresses, packages, processes, or outcomes;
- detections with degraded prerequisites lower confidence or suppress evaluation instead of implying safety;
- normal rotation/maintenance, API outage/drain, API restart, database restart, agent restart, and queue-pressure windows recover without silent loss.

L2 pass criteria:

- Seven-day continuity is preserved or interruptions are explained and the soak is restarted if continuity was required.
- Every mandatory applicable L2 source is healthy or has an approved, truthful exception outside the agent payload.
- Each family counted as observed has genuine matching producer activity; selecting a broader scope alone does not satisfy package, sudo, or other evidence.
- No private evidence indicates secret/excluded-data collection, host impact, unbounded resource use, or unauthorized mutation.
- Public result remains an aggregate canary decision, not detailed measurements.

## Recovery and non-disruption checks

Each drill needs explicit approval before it changes service availability or host state. If approval is absent, mark the drill `blocked - no approved operation` rather than simulating or fabricating evidence.

| Check | Default-safe method | Approval needed for mutation | Pass signal |
| --- | --- | --- | --- |
| API outage/drain | Use a controlled validation API outage window; observe aggregate queue growth, retry/backoff, and later drain. | Required before stopping/restarting an API or blocking traffic. | Heartbeat/source-health remain independent where expected; accepted/duplicate acknowledgements drain without deleting unacknowledged rows. |
| API restart | Restart only an owned validation API during the approved window. | Required. | Agent reconnects; no duplicate storm beyond deterministic duplicate acknowledgements. |
| Database restart | Use only an owned validation database and bounded restart window. | Required. | API returns to healthy state; agent backs off and drains after recovery. |
| Agent restart | Restart only the Challenger SIEM agent service in the approved window. | Required. | Cursor/queue/checkpoint state resumes; no collected checkpoint skips non-durable events. |
| Journal scope transition | Change only `IncludeAccessibleUserJournals` in the protected configuration and restart only the agent in the approved window. | Required. | Effective scope/system visibility are truthful; cursor is preserved or an invalid cursor becomes a durable explicit reset/gap; no historical backfill or new privilege is claimed. |
| Journal rotation/vacuum | Prefer naturally occurring rotation. Do not force journal retention changes by default. | Required for any forced rotation/vacuum. | Rotation or cursor invalidation is explicit; recovery records a gap rather than silent loss. |
| Permission loss/recovery | Prefer naturally observed denied state or synthetic tests. Do not change groups/ACLs by default. | Required for any deliberate permission change and exact rollback. | `permission_denied` appears without privilege escalation; restored access reports recovery without hidden mutation. |
| Disk/queue pressure | Prefer bounded API outage and normal workload. Do not fill disks or run unbounded benchmarks. | Required for any workload generator or quota change. | Optional sources pause before mandatory sources; heartbeat/queue integrity remain; pressure state and recovery are explicit. |
| Journal malformed/oversized data | Use hand-authored synthetic tests, not live log injection, unless separately approved. | Required for producer changes or log injection. | Malformed/binary/oversized records produce bounded health/gap metadata without raw payload publication. |

## L3 opt-in guardrails

Implemented Linux L3 sources are `linux-agent-self-integrity-snapshot` and the passive procfs process/socket/host-behaviour pack. Both remain disabled by default and have independent approval hashes and rollback boundaries.

L3 validation is blocked unless all are true:

- Separate operator approval names each L3 source, target/window, exact preflight plan, and rollback.
- Each enabled L3 pack is paired with its exact matching `ApprovedPlanHash`; approval for self-integrity does not approve passive process/network collection or vice versa.
- The plan confirms no audit/eBPF/fanotify/inotify/IMA/broad file-integrity collector, host-policy change, package install, group/capability/ACL grant, arbitrary path, recursive scan, unrelated file-descriptor traversal, packet capture, process environment/memory read, or secret-bearing telemetry source.
- The self-integrity collector treats the credential-bearing configuration as metadata-only and never content-reads or hashes it. Plan helpers necessarily parse the protected configuration to derive approval hashes but emit no credential values; their output remains private.
- A separate L3 soak and rollback gate is recorded. L3 success cannot be inferred from L1 or L2.

If any L3 condition is missing, report `blocked - L3 approval absent` and keep the affected pack disabled. Never infer one pack's approval from another.

## L3 bounded canary procedure

Run an L3 canary only after the requested pack passes its exact preflight and the operator approves the configuration change, service lifecycle action, duration, stop gates, and rollback. A host cannot claim L3 coverage until its mandatory L1, L2, and passive L3 sources are all healthy; an isolated collector exercise may still be recorded as a blocked/partial L3 canary.

Use at least 24 continuous hours for the first passive-procfs canary unless the operator defines a longer host-class gate. Privately verify:

- all requested L3 source IDs report the expected enablement, matching plan hash, recent scan observation, family evidence, and bounded collected/acknowledged checkpoints;
- baseline and reboot-baseline evidence is non-alertable, while post-baseline differences remain polling-honest and do not claim exact lifecycle timing or process-to-socket attribution;
- partial, permission, timeout, event-cap deferral, queue pressure, state recovery, and interrupted reservation behavior is explicit and does not block heartbeat, journal collection, inventory, or unrelated queue rows;
- CPU, RSS, write rate, queue growth/age, event volume, gap/drop/deferred counts, and server detection noise remain inside the approved resource and operational SLOs;
- no process environment/memory, packet payload, arbitrary file content, credential value, private validation output, or other excluded data enters tracked files; and
- disable/cleanup and, if approved, package rollback touch only declared Challenger SIEM resources.

Stop immediately on any privacy, unauthorized mutation, host-impact, silent-loss, unbounded-growth, false-healthy coverage, or persistent detection-noise gate. Record only aggregate pass/fail/blocked results publicly.

## L4 private VM canary

Purpose: validate the highest implemented Linux level without turning implementation availability into a rollout claim. The L4 VM gate has not yet been run.

Use at least 24 continuous hours after the mandatory rolling-SLO window reaches steady state, in addition to the prerequisite L1 24-hour, L1+L2 seven-day, and requested L3 validation evidence. A materially different build, distribution/kernel/init combination, configuration, posture baseline, or role set requires a new applicable decision.

Entry gates:

- The VM, validation window, lifecycle operations, private evidence location, rollback owner, and stop contact are explicitly authorized.
- Passive L3 is enabled with valid bounds and its exact separately reviewed plan before L4 readiness is evaluated, and all three mandatory passive sources are healthy for the requested L4 target. Optional L3 self-integrity is reviewed independently and is not silently made mandatory.
- `Journal.TargetCoverageLevel=L4` and `Journal.DeclaredRoles` contains one or more supported reviewed roles. Use `general_server` or `workstation` only after confirming no specialized pack applies; those declarations do not waive any fixed posture input. Empty/unknown roles fail configuration and block the run.
- The exact disabled-state L4 preflight is stored privately. Its candidate baseline was reviewed, `ApprovedBaselineHash` was set first, the resulting `ApprovedPlanHash` was regenerated and reviewed, and both match before enablement.
- The final disabled-state pass reports `activation_ready=true`, no `activation_blockers`, `candidate_baseline_complete=true`, `approval_hash_matches=true`, and `baseline_hash_matches=true`. Any bounded blocker code remains a stop gate rather than being overridden.
- The plan proposes no audit/eBPF, package, service, firewall, authentication, kernel, MAC-policy, logging-policy, group, ACL, capability, arbitrary-path, application-file-reader, or other host mutation.
- Agent configuration application and any required agent restart are separately approved. Enabling L4 is not approval for a role service or posture change.
- A pre-install payload is not accepted as posture evidence because it cannot observe the fixed installed `/opt` executable and `/etc` configuration boundary; `upgrade` staging is not activation and does not replace the separately approved restart.

Privately verify:

- `linux-policy-posture-drift` establishes only the approved five-snapshot baseline, retains no raw inventory value, requires both exact integrity child items plus explicit valid AppArmor/SELinux alternative-provider child states with at least one observed provider, reports stable complete samples, and cannot become healthy from partial, missing, denied, corrupt, or mismatched evidence;
- any observed posture drift blocks strict L4 until restored or deliberately re-baselined through a new approval. Do not change firewall, SSH, MAC, Secure Boot, agent, or service posture merely to exercise drift unless that exact change and rollback have separate approval;
- `linux-agent-performance-slo` reports warm-up until complete interval samples span the full endpoint-inclusive configured window, then measures the implemented average/p95 process CPU, maximum RSS, and average process-write thresholds; covered seconds and maximum managed memory remain bounded context, and unknown/reset/discontinuous counters never become zero or healthy by assumption;
- separate private tooling covers per-collector CPU, steady-state process resource use, disk writes, queue age/growth, outage/drain, reconnect, restart, burst, role workload, and host impact not proven by the rolling row;
- every applicable role source resolves from the explicit declaration, shares the durable journal cursor, uses structured identifier/unit classification, and uses the persisted last successful journal-read observation for quiet health without letting a heartbeat timestamp pretend an event family was observed or refresh a stopped reader;
- every mandatory L1-L4 and applicable role source is `healthy`, with no exception used to satisfy L4 and no stale, denied, degraded, missing, disabled, error, pressure, poison, active-gap, or acknowledgement-failure state;
- accepted/duplicate acknowledgement advances each L4 sequence before queue deletion; restart, server outage/drain, and pressure recovery preserve state and do not starve L1/L2;
- role/application payloads, query/database contents, file/share contents, DNS query data, container environments, raw policy values, credentials, and prohibited sources remain absent; and
- disable/cleanup removes only the fixed L4 state when requested and leaves posture, services, journals, the shared queue, credentials, and server evidence untouched.

L4 pass criteria:

- The full approved period completes without a stop gate.
- Strict server assessment reports L4 from current healthy evidence, not an exception or synthetic/live activity assumption.
- All documented rolling thresholds and the broader private performance/recovery matrix pass.
- Role-specific workload and quiet-window behavior are both truthful for each declared role.
- Public output contains only an aggregate `passed`, `failed`, or `blocked` decision; all plan, baseline, telemetry, and measurement detail remains private.

Any failed prerequisite, active posture drift, rolling or private SLO breach, unresolved role, exception, false-healthy state, privacy concern, unauthorized mutation, silent loss, or persistent gap blocks L4 rollout. Follow [Linux L4 full-target coverage](linux-l4-coverage.md) for the contract boundary.

## Cleanup and rollback

Rollback must be planned before validation starts and must be bounded to Challenger SIEM-owned resources.

Default cleanup:

- Stop expansion and leave the target in the last known safe state.
- Remove or disable the agent only when uninstall/disable was approved for the target/window.
- Preserve private evidence locally until the operator decides retention/disposal.
- Revoke or rotate enrollment/per-agent credentials if generated settings or transport credentials may have been exposed.
- Verify product paths, service state, queue/state preservation or approved removal, and source-health after rollback.
- Do not delete system logs, clear journals, wipe databases, remove unrelated users/groups, change firewall/authentication/audit/kernel/MAC policy, or destroy evidence unless separately approved.

Immediate rollback/stop gates:

- suspected credential, secret, private key, connection string, browser/session, packet payload, keystroke, screenshot, unrestricted file-content, or excluded-data collection;
- unauthorized audit, firewall, authentication, kernel, service-policy, group, ACL, capability, journal-retention, MAC-policy, package, or L3 mutation;
- unapproved L4 baseline adoption, role/source expansion, posture mutation, or application logging change;
- host instability, application impact, queue/state corruption, silent loss, persistent source gaps/duplication, uncontrolled disk growth, or SLO breach after bounded throttling;
- inability to disable/uninstall safely using the approved plan;
- any private evidence that cannot be summarized safely for a public repository.

## Sanitized aggregate result template

Copy this template into an issue/PR/status comment only after replacing private details with aggregate values. Do not attach raw files.

```markdown
## Linux local-host validation summary

Run status: <blocked | in-progress | passed | failed>
Product version: <version from VERSION>
Contract compatibility: /api/v1 unchanged; contracts/v1 unchanged
Published evidence class: sanitized aggregate only
Private evidence reference: <operator-held reference, no local path>
Authorized target/window: <yes | no>
Host mutation outside approved agent lifecycle: <none | blocked | failed stop gate>
Generated configs/logs/queues/raw telemetry/screenshots/benchmarks tracked: no

### Preflight
- Read-only plan reviewed: <yes | no | blocked>
- Unauthorized mutation proposed by plan: <no | yes stop gate | not run>
- Requested level: <L1 | L2 | L3 self-integrity | L3 passive procfs | both L3 packs | L4 | not run>
- Journal scope and approval: <system_only | all_accessible_local approved | broader scope blocked/not run>
- System-journal visibility and scope transition: <verified/steady | recovered | denied/missing/error blocked | not run>
- L3 approval and matching plan hash present for each requested pack: <not applicable | yes | no blocked>
- L4 role resolution and exact plan/baseline hashes: <not applicable | matched | unresolved/mismatch blocked>

### L1 24-hour soak
- Status: <not run | blocked | passed | failed>
- Continuous duration met: <yes | no | not applicable>
- Mandatory L1 source states: <aggregate pass/fail/status-count summary>
- Queue/checkpoint/ack recovery: <passed | failed | not run>
- Resource SLO decision: <met | breached | not measured>
- Privacy exclusions: <passed | failed stop gate | not run>

### L1+L2 seven-day soak
- Status: <not run | blocked | passed | failed>
- Continuous duration met: <yes | no | not applicable>
- Mandatory applicable L2 states: <aggregate pass/fail/status-count summary>
- Genuine family observation versus not-observed: <aggregate summary; no generated activity>
- Role-specific applicability: <aggregate summary>
- Detection prerequisite behavior: <passed | failed | not run>

### L3 bounded canary
- Requested pack(s): <self-integrity | passive procfs | both | not run>
- Status and continuous duration: <not run | blocked | passed | failed; aggregate duration>
- Mandatory passive L3 source health/families: <aggregate pass/fail/status-count summary>
- Baseline/reboot and polling semantics: <passed | failed | not run>
- Queue/reservation/recovery behavior: <passed | failed | blocked | not run>
- Resource and detection-noise decision: <met | breached | not measured>
- Privacy exclusions: <passed | failed stop gate | not run>

### L4 private VM canary
- Declared role resolution: <aggregate supported/applicable summary | unresolved blocked | not run>
- Exact plan and baseline approval: <matched | mismatched blocked | not run>
- Mandatory L4 policy/SLO source state: <aggregate pass/fail/status-count summary>
- Applicable role journal sources: <aggregate pass/fail/status-count summary>
- Strict healthy/no-exception L1-L4 assessment: <L4 met | lower level | not run>
- Rolling process CPU/RSS/write SLO: <met | breached | warming/unavailable | not run>
- Private per-collector/outage/recovery/workload matrix: <passed | failed | incomplete blocked | not run>
- Posture/privacy/rollback boundary: <passed | failed stop gate | not run>

### Recovery drills
- API outage/drain: <passed | failed | blocked | not applicable>
- API restart: <passed | failed | blocked | not applicable>
- Database restart: <passed | failed | blocked | not applicable>
- Agent restart: <passed | failed | blocked | not applicable>
- Journal rotation/vacuum: <passed | failed | blocked | natural-only | not applicable>
- Permission loss/recovery: <passed | failed | blocked | synthetic-only | not applicable>
- Disk/queue pressure: <passed | failed | blocked | not applicable>

### Rollback/cleanup
- Approved rollback verified: <yes | no | blocked>
- Credentials requiring rotation: <none | rotated privately | operator action required>
- Public-data safety check: <passed | failed>

### Decision
- Rollout decision: <do not roll out | continue L1 | continue L2 canary | continue bounded L3 canary | continue private L4 VM canary | block pending evidence>
- Reason: <sanitized aggregate reason>
```

## Live validation reporting

Run live validation only for an explicitly authorized target, time window, telemetry level, and operation list. A missing approval or a recovery drill that would change system, service, database, journal, permission, pressure, or host-policy state must be reported as `blocked` or `not run`; never infer a pass from unit, smoke, or synthetic checks.

Private evidence remains operator-held and untracked. Public release notes, issues, and pull requests may contain only the sanitized aggregate template above, without target identity, local paths, command transcripts, raw telemetry, credentials, generated settings, screenshots, or detailed host state.

## Related documentation

- [Linux agent](linux-agent.md)
- [Linux agent security and privacy design](linux-agent-security.md)
- [Linux host coverage specification](linux-host-coverage-spec.md)
- [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md)
- [Linux L4 full-target coverage](linux-l4-coverage.md)
- [Operator runbooks](runbooks.md)
- [Troubleshooting and FAQ](troubleshooting.md)
- [Versioning](versioning.md)
