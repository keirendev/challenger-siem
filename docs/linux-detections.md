# Linux server-side detections

Status: implemented server-side rule metadata and bounded alert execution for accepted Linux v1 events.

Linux detections run on the server after a valid `/api/v1/ingest/events` batch is stored. They are additive to the existing Windows-focused rule catalog and preserve `/api/v1` compatibility. The engine evaluates only accepted, non-duplicate events from bounded batches; duplicate ingest acknowledgements do not create duplicate alerts.

## Rule metadata contract

Every built-in rule, including Linux rules, exposes:

- stable `rule_id` and integer `version`;
- severity, confidence, category, ATT&CK techniques, and tactics;
- required source IDs and structured required fields;
- a bounded correlation window in seconds;
- suppression keys used to deduplicate alert windows;
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
| `persistence.service-start.linux` | Service start/reload/failure activity | `linux-service-change` | 30m | Correlate with package/change windows before escalation. |
| `persistence.scheduler-activity.linux` | Cron or systemd timer activity | `linux-cron-timers` | 30m | Intended as persistence review signal, not a case workflow. |
| `package.change.linux` | Package install/update/remove | `linux-package-management` | 60m | Highlights package/security-control drift context. |
| `kernel.security-control-change.linux` | Kernel module or security-control event | `linux-kernel-security` | 30m | Covers module and LSM/security-control journal evidence. |
| `firewall.change.linux` | Firewall allow/deny/policy event | `linux-firewall` | 30m | Requires firewall logging already present; the agent does not enable it. |
| `tamper.agent-log-source-silence.linux` | Agent/log tamper or source-health gap event | `linux-agent-log-tamper`, `agent_health` | 15m | Treats gaps as visibility loss, never proof of safety. |
| `tamper.agent-self-integrity.linux` | Approved self-integrity snapshot change | `linux-agent-self-integrity-snapshot`, `inventory_diff`, `agent_health` | 60m | Evaluates the narrow approved self-integrity telemetry only when such events are present. |

## Prerequisite-aware confidence

Detections consult current source-health rows for the source that satisfied the rule. Healthy prerequisites keep the rule's catalog confidence. Stale, degraded, throttled, gapped, or dropped-event prerequisite evidence lowers confidence to `low`. Missing, disabled, permission-denied, unsupported, errored, or not-applicable prerequisite evidence suppresses evaluation unless the event itself is the only available source-health evidence, in which case confidence is lowered and the alert summary states the gap.

This behavior prevents the server from implying that no threat exists when telemetry is missing or unhealthy. Operators should read degraded/suppressed states as visibility gaps and review `/api/v1/source-health` and `/api/v1/telemetry-coverage` before closing an investigation.

## Operator response boundaries

Linux detection alerts are review signals. They do not implement UI case workflows, host remediation, service restarts, firewall changes, authentication changes, audit-policy changes, kernel changes, package actions, or agent-side mutation. Use the exact evidence event IDs, source-health state, and synthetic-safe runbooks to decide whether separate approved response action is needed.

False positives are common during maintenance, patch windows, agent upgrades, planned package or unit changes, vulnerability scans, and approved administrative access. Preserve real investigation evidence only under ignored local/runtime paths and publish only synthetic summaries.

## Validation

Tracked validation uses hand-authored synthetic data only:

- positive and negative unit fixtures for every Linux rule;
- prerequisite degradation and suppression tests;
- duplicate/suppression and exact-evidence persistence coverage with optional PostgreSQL integration;
- a 5,000-event in-memory bounded execution benchmark; and
- contract/schema checks for additive detection-rule metadata.

These tests do not replace the private Linux L1/L2 soak or host resource SLO gates documented in the Linux coverage specification.
