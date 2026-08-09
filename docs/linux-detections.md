# Linux server-side detections

Status: implemented server-side rule metadata and bounded alert execution for accepted Linux v2 events.


## Rule metadata contract

Every built-in rule, including Linux rules, exposes:

- stable `rule_id` and integer `version`;
- severity, confidence, category, ATT&CK techniques, and tactics;
- required source IDs and structured required fields;
- a bounded correlation window in seconds;
- false-positive notes; and
- response guidance.

Alert rows persist `rule_id` and exact `rule_version`. Alert evidence rows store the exact accepted `event_id` values used by the detection. Linux duplicate suppression uses a deterministic alert ID derived from rule ID/version, agent, suppression key, and correlation-window bucket, then appends only new evidence event IDs.

## Implemented Linux rules

| Rule ID | Signal | Primary sources | Window | Notes |
| --- | --- | --- | --- | --- |
| `auth.bruteforce.linux` | Repeated authentication failures | `linux-login-session`, `linux-ssh` | 15m | Requires at least five failure events sharing structured account or remote address evidence. |
| `auth.success-after-failures.linux` | Successful authentication after failures | `linux-login-session`, `linux-ssh` | 30m | Requires a success after at least three preceding failures. |
| `privilege.sudo-su-root.linux` | Sudo/su privileged session or command | `linux-sudo-su` | 15m | Uses structured user, target user, action, outcome, and command fields. |
| `ssh.root-login.linux` | Root/privileged SSH login | `linux-ssh` | 15m | Uses structured SSH user, source address, outcome, and session/authentication action. |
| `process.suspicious-privileged-command.linux` | Suspicious privileged command pattern | `linux-sudo-su` | 15m | Uses structured command-line fields; rendered-message-only matches are not required. |
| `process.suspicious-snapshot-command.linux` | Conservative high-risk process command pattern | `linux-process-snapshot-diff` | 15m | Matches only `observed`/`changed` structured command lines with download-to-shell, reverse-shell, encoded execution, or chained download-and-execute patterns. |
| `persistence.service-start.linux` v2 | Service lifecycle/persistence activity | `linux-service-change` | 30m | Suppresses routine starts during the first five boot minutes and exact systemd session scaffolding; failures and unexplained later activity remain alertable. |
| `persistence.scheduler-activity.linux` v2 | Cron or systemd timer activity | `linux-cron-timers` | 30m | Known timers in a recent complete inventory are suppressed; stale/incomplete inventory preserves a low-confidence alert. |
| `package.change.linux` v2 | Observed package install/update/remove | `linux-package-inventory-diff`, `linux-package-management` | 60m | Accepts bounded inventory differences or direct journal evidence with the existing package/action suppression key; active source gaps lower confidence. |
| `kernel.security-control-change.linux` | Kernel module or security-control event | `linux-kernel-security` | 30m | Covers module and LSM/security-control journal evidence. |
| `policy.security-posture-drift.linux` | Approved L4 posture fingerprint changed | `linux-policy-posture-drift` | 60m | Alerts only on post-baseline `drift`; baseline, sample, gap, and restored evidence is non-alerting. |
| `firewall.change.linux` | Firewall allow/deny/policy event | `linux-firewall` | 30m | Requires firewall logging already present; the agent does not enable it. |
| `network.listener-observed.linux` | Non-loopback or wildcard listener observed | `linux-network-socket-snapshot-diff` | 60m | Requires a valid local port and a post-baseline `observed`/`changed` listener snapshot; baseline establishment is non-alerting. |
| `behavior.host-resource-pressure.linux` v2 | Sustained severe host-pressure cause | `linux-host-behaviour-metrics` | 15m | Requires three samples of the same cause within five minutes and retains bounded diagnostic evidence. |
| `tamper.agent-log-source-silence.linux` | Agent/log tamper or source-health gap event | `linux-agent-log-tamper`, `agent_health` | 15m | Treats gaps as visibility loss, never proof of safety. |
| `tamper.agent-self-integrity.linux` | Approved self-integrity snapshot change | `linux-agent-self-integrity-snapshot`, `inventory_diff`, `agent_health` | 60m | Evaluates the narrow approved self-integrity telemetry only when such events are present. |
| `tamper.agent-heartbeat-loss.linux` | Three-interval agent heartbeat outage | `agent_health` | 2–15m | Server-created deterministic critical alert; the next authenticated heartbeat resolves an active alert without disposition or closure. |
| `tamper.audit-policy-change.linux` | Audit policy/lifecycle change | `linux-audit-framework` | 15m | Requires normalized allowlisted evidence from the separately approved audit source. |
| `process.temporary-deleted-execution.linux` | Deleted, memfd, or temporary execution marker | `linux-process-snapshot-diff` | 15m | Post-baseline polling evidence; updaters/builds remain expected alternatives. |
| `privilege.dangerous-effective-capabilities.linux` | Dangerous effective capability subset | `linux-process-snapshot-diff` | 15m | Post-baseline polling evidence; service/container provenance must be reviewed. |

### Passive telemetry interpretation

The three passive rules require their exact canonical source-health IDs; generic `inventory_diff` or `agent_health` health rows do not substitute for the process, socket, or host-behaviour collector. They preserve the collector's polling semantics:

- Process detection examines `normalized.process_command_line`/`process_command_line` only. Rendered event messages are never pattern-matched. A match means the command was present in an `observed` or `changed` snapshot, not that the SIEM witnessed an exact exec time or complete parent/child sequence.
- Listener detection accepts valid TCP local ports from 1 through 65535 on wildcard or non-loopback addresses. It rejects loopback listeners, invalid addresses/ports, generic network rows, `disappeared` snapshots, and initial baseline establishment. Polling cannot prove exact bind time. Process ownership, when the passive plan enables it, is bounded and may remain stale, capped, denied, or ambiguous.
- Host-pressure detection accepts bounded integer fields from the `host_metrics_sample` raw object. It matches CPU busy at least 950 permille (95%), available memory at most 5% when a positive total is present, at least eight blocked processes, or CPU/memory/I/O `some avg10` PSI at least 50,000 milli-percent (50%). CPU is bounded to 0–1000 permille, PSI to 0–100,000 milli-percent, and other counters to conservative non-negative ranges before comparison.

The pressure rule correlates at least three severe samples for the same normalized cause within five minutes; one spike is non-alerting context. Evidence is bounded and includes the triggering samples plus available whole-device diagnostics. Missing intervals are not backfilled, malformed/missing raw numeric fields never match, and partial/unknown metrics force low confidence. Confirm with authoritative host monitoring before disruptive response.

Systemd service v2 suppression is exact and narrow: routine starts at or before five
minutes after the matching boot record and exact session scaffolding are excluded,
while failures remain alertable. Timer v2 correlation trusts neither an endpoint's
completeness flag nor an isolated page; it uses the latest server-derived complete,
recent timer generation. Unknown timer activity with stale/incomplete inventory remains
visible at low confidence.

Self-integrity v2 signatures ignore state-directory mtime/size churn but continue to
detect owner, group, mode, type, deletion, and unreadable changes. Initial baselines and
audit recovery-only rows are non-alerting.

### L4 posture and role interpretation

The L4 posture rule sees only the changed bounded snapshot type and SHA-256 posture signatures. It does not reveal or infer the exact firewall, SSH, MAC, Secure Boot, or agent-integrity value that changed. Review the approved plan/change window and use a separately approved authoritative host procedure before response. A baseline mismatch or active drift also prevents strict L4 coverage; the alert is not a remediation instruction.

The six L4 role journal sources add correlation context but no application-payload detections in this release. They classify fixed structured unit/identifier evidence already in journald. If a role record also matches an L2 family, the role source remains the single queued event; one fixed canonical secondary source/family pair preserves L2 source health and lets that same event continue to satisfy the corresponding existing L2 rule. It does not create a duplicate event, a second evidence row, or a new payload-based role rule. Quiet declared-role health is not proof that an application event occurred, and `not_observed` activity is not proof of absence. Database contents, DNS queries, file/share contents, container environments, identity secrets, and application log files are not collected by these packs.

`linux-agent-performance-slo` is primarily a coverage/rollout health source. Rolling warm-up, breach, pressure, queue-counter discontinuity, or unavailable-counter state blocks strict L4; it does not create a threat alert by itself. Its top-eight-plus-remainder queue attribution contains counts and serialized bytes only and does not expose event content. The existing host-resource-pressure detection uses the separate L3 host-behaviour source and must not be treated as the L4 agent-process SLO.

## Prerequisite-aware confidence

Detections consult current source-health rows for the source that satisfied the rule. Healthy prerequisites keep the rule's catalog confidence. Stale, degraded, throttled, or actively gapped prerequisite evidence lowers confidence to `low`; non-passive sources also retain the existing conservative lowering when their dropped-event counter is nonzero. Passive polling sources keep cumulative gap/drop counters as history, but those historical counters alone do not permanently lower later detections after a complete healthy scan has cleared the active gap. A directly matching accepted event is always evaluated: missing, disabled, permission-denied, unsupported, errored, or not-applicable current health lowers that event's confidence and the alert summary states the visibility gap instead of discarding the evidence. Rule-readiness views can still report the unhealthy or unavailable prerequisite when no matching event is being evaluated.

This behavior prevents the server from implying that no threat exists when telemetry is missing or unhealthy. Operators should read low-confidence and unavailable readiness states as visibility gaps and review `/api/v2/source-health` and `/api/v2/telemetry-coverage` before closing an investigation.

After storage commits, detection evaluates the canonical stored envelope rather than the request copy. A retry whose IDs are now duplicates re-runs idempotent detection, recovering from a failure between event commit and alert creation without allowing a conflicting retry representation to replace evidence. Coalesced alerts retain at most 128 unique evidence rows under a database transaction lock, report bounded evidence metadata, refresh the retained evidence count, and conservatively keep the lowest confidence seen in the correlation bucket.

## Operator response boundaries

Linux detection alerts are review signals. They do not implement UI case workflows, host remediation, service restarts, firewall changes, authentication changes, audit-policy changes, kernel changes, package actions, or agent-side mutation. Use the exact evidence event IDs, source-health state, and synthetic-safe runbooks to decide whether separate approved response action is needed.


## Validation

Tracked validation uses hand-authored synthetic data only:

- positive and negative unit fixtures for every Linux rule;
- prerequisite degradation and suppression tests;
- duplicate/suppression and exact-evidence persistence coverage with optional PostgreSQL integration;
- a 5,000-event in-memory bounded execution benchmark; and
- contract/schema checks for additive detection-rule metadata.

These tests do not replace the private Linux L1-L4 soaks, role workloads, strict coverage review, or host resource/SLO gates documented in the Linux coverage specification.
