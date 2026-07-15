# Linux local-host rollout validation runbook

This runbook stages Challenger SIEM Linux agent rollout validation on an operator-authorized systemd host without publishing private host evidence. It is the issue-status and evidence template for the Linux local-host validation gate described by the Linux agent, security, and coverage documents.

This document is **not** authorization to use SSH, WinRM, reboot a host, restart production services, change firewall/authentication/audit/kernel/MAC policy, add groups/capabilities/ACLs, force journal retention changes, or execute L3 collection. If an operator-authorized Linux systemd target, maintenance window, and exact permitted operations are not already documented for the work item, complete only the repository documentation/template work and record live soak as blocked.

## Scope and compatibility

- Applies to the bounded Linux agent service on a systemd host: passive L1 journal collection, opt-in L2 logical journal classification, bounded read-only inventory, and the disabled-by-default L3 `linux-agent-self-integrity-snapshot` source.
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
  recovery/                      # outage/restart/rotation/pressure notes
  rollback/                      # cleanup verification notes
```

Do not move anything from this layout into tracked docs, examples, fixtures, tests, issues, or pull requests unless it has been rewritten as a synthetic aggregate.

## Required preflight and approval plan

A validation run may start only when all items are true:

- The operator has identified an authorized systemd target and a validation time window in private coordination notes.
- The operator has approved the exact operations for that window: plan only, install/upgrade, service start/stop/restart, API outage drill, database restart drill, permission-loss drill, pressure drill, uninstall, and any L3 self-integrity action. Unlisted operations remain forbidden.
- The target is operator-owned for this validation, not a customer/client system unless separate data-handling approval exists.
- The server/API endpoint and database are designated for validation and can tolerate the approved outage/restart drills.
- Rollback owner, stop-gate contact, credential revocation path, and private evidence location are recorded locally.
- Repository checkout is clean enough that generated configs/logs/queues cannot be accidentally staged.

Read-only preflight content must include, in private evidence only:

- product version from `./scripts/current-version.sh`;
- non-mutating Linux installer plan from `./scripts/linux-agent.sh plan`;
- requested target level (`L1` for first soak; `L2` only after L1 passes and canary approval exists);
- whether `SelfIntegrity.Enabled` is false or, for a separately approved L3 drill, the exact approved plan hash;
- product paths and permission expectations for `/etc/challenger-siem-agent`, `/var/lib/challenger-siem-agent`, `/opt/challenger-siem-agent`, and the systemd unit;
- expected source catalog, applicability, and known unsupported sources;
- expected volume/resource limits and SLOs;
- proposed host changes, which should be none for L1/L2 collection beyond the approved agent lifecycle operation.

Public preflight summary should say only whether the plan was reviewed and whether it proposed unauthorized mutation. Do not publish the plan output.

## Bounded validation commands

The commands below are examples of bounded product validation surfaces. Run them locally on an authorized validation system or in an authorized private shell only; do not run them through SSH/WinRM for this issue unless the operator explicitly authorizes that target and operation.

```bash
./scripts/current-version.sh
./scripts/linux-agent.sh plan
./scripts/linux-agent.sh validate
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

When querying a running validation API, use small limits, timeouts, and aggregate status extraction. Store raw responses only under ignored private evidence. Public summaries should report status counts and pass/fail decisions, not response bodies.

## L1 24-hour soak procedure

Purpose: prove non-disruptive default Linux collection with `Journal.TargetCoverageLevel=L1` and `SelfIntegrity.Enabled=false`.

Minimum duration: **24 continuous hours** after the agent reaches steady state.

Entry gates:

- Preflight plan reviewed and no unauthorized host-policy mutation proposed.
- Generated config is private, mode-restricted, and not in the repository.
- Agent lifecycle action was explicitly approved for the target/window.
- Server, database, and API health are known before the soak begins.

During the soak, privately verify:

- agent starts, heartbeats, and reports source-health without raw telemetry leakage;
- `linux-journal-l1` source positions advance and acknowledged checkpoints do not advance before accepted/duplicate acknowledgement;
- queue depth/age, send/backoff/recovery, poison/drop counters, and pressure state remain within planned limits;
- resource SLOs are met: average CPU below 2%, p95 CPU below 5%, RSS below 250 MB, average writes below 1 MB/s, and no individual collector above 10% CPU for more than 60 seconds;
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
- Declared roles are bounded and privately justified. Empty roles are acceptable and should leave role-specific applicability unknown rather than guessed.
- No audit, eBPF, broad file-integrity, firewall, authentication, kernel, group, ACL, capability, journal-retention, service-policy, or MAC-policy mutation is bundled into the L2 canary.

During the soak, privately verify L1 criteria plus:

- logical L2 families classify only from the shared durable journal cursor;
- SSH, login/session, sudo/su, scheduler, package, firewall, kernel/security-module, service-change, and agent/log-tamper families report truthful applicable/not-applicable/unknown/degraded states;
- `linux-audit-framework` remains explicitly `unsupported` unless a future approved implementation exists;
- structured fields take precedence and ambiguous messages do not invent users, addresses, packages, processes, or outcomes;
- detections with degraded prerequisites lower confidence or suppress evaluation instead of implying safety;
- normal rotation/maintenance, API outage/drain, API restart, database restart, agent restart, and queue-pressure windows recover without silent loss.

L2 pass criteria:

- Seven-day continuity is preserved or interruptions are explained and the soak is restarted if continuity was required.
- Every mandatory applicable L2 source is healthy or has an approved, truthful exception outside the agent payload.
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
| Journal rotation/vacuum | Prefer naturally occurring rotation. Do not force journal retention changes by default. | Required for any forced rotation/vacuum. | Rotation or cursor invalidation is explicit; recovery records a gap rather than silent loss. |
| Permission loss/recovery | Prefer naturally observed denied state or synthetic tests. Do not change groups/ACLs by default. | Required for any deliberate permission change and exact rollback. | `permission_denied` appears without privilege escalation; restored access reports recovery without hidden mutation. |
| Disk/queue pressure | Prefer bounded API outage and normal workload. Do not fill disks or run unbounded benchmarks. | Required for any workload generator or quota change. | Optional sources pause before mandatory sources; heartbeat/queue integrity remain; pressure state and recovery are explicit. |
| Journal malformed/oversized data | Use hand-authored synthetic tests, not live log injection, unless separately approved. | Required for producer changes or log injection. | Malformed/binary/oversized records produce bounded health/gap metadata without raw payload publication. |

## L3 opt-in guardrails

The only implemented Linux L3 collector is `linux-agent-self-integrity-snapshot`. It remains disabled by default.

L3 validation is blocked unless all are true:

- Separate operator approval names the L3 source, target/window, exact self-integrity preflight plan, and rollback.
- `SelfIntegrity.Enabled=true` is paired with the exact matching `ApprovedPlanHash` for the reviewed allowlist.
- The plan confirms no audit/eBPF/fanotify/inotify/IMA/broad file-integrity collector, host-policy change, package install, group/capability/ACL grant, arbitrary path, recursive scan, symlink following, or secret-bearing content read.
- The credential-bearing configuration is metadata-only; no content hash or content read is allowed.
- A separate L3 soak and rollback gate is recorded. L3 success cannot be inferred from L1 or L2.

If any L3 condition is missing, report `blocked - L3 approval absent` and keep `SelfIntegrity.Enabled=false`.

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
- Requested level: <L1 | L2 | L3 self-integrity | not run>
- L3 approval and plan hash present: <not applicable | yes | no blocked>

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
- Role-specific applicability: <aggregate summary>
- Detection prerequisite behavior: <passed | failed | not run>

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
- Rollout decision: <do not roll out | continue L1 | continue L2 canary | block pending evidence>
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
- [Operator runbooks](runbooks.md)
- [Troubleshooting and FAQ](troubleshooting.md)
- [Versioning](versioning.md)
