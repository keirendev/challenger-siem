# Linux firewall applicability and prerequisite evidence

`linux-firewall` is an optional L2 logical source carried by the existing bounded systemd-journal reader. The agent never installs a firewall, enables a service, adds or changes rules, enables logging, or changes permissions. It reports whether a supported producer and already-enabled logging are visible through fixed read-only inventory, then keeps actual allow, deny, and policy-change families separate from quiet source health.

## Deterministic decision table

| Bounded evidence | Applicability | Health after a current successful journal read | Operator interpretation |
| --- | --- | --- | --- |
| Inventory has not arrived and no structured firewall event was observed | `unknown` | `degraded` | The optional row remains visible, but this unresolved applicability does not lower aggregate health by itself. It is not proof of firewall coverage. |
| No active or installed supported producer is found | `not_applicable` | `not_applicable` | No nftables, firewalld, or UFW source applies. Do not install or enable one solely to change telemetry status. |
| A supported producer is present but inactive or logging is off | `applicable` | `disabled` | Firewall telemetry is intentionally unavailable at the producer prerequisite. Enabling it requires a separate operator-approved firewall change. |
| A supported producer has logging enabled and the shared journal observation is current, but no matching event occurred | `applicable` | `healthy` while current | Quiet visibility is established; every firewall event family remains `not_observed`, and no recent-event detection prerequisite is invented. |
| A real structured UFW, firewalld, or nftables record is observed | `applicable` | follows current journal health | Direct event evidence wins over older inventory and marks only the exact observed family. |
| An active legacy iptables producer is found without a supported producer | `unsupported` | `unsupported` | The optional row records a capability boundary. Do not replace or reconfigure the firewall merely to make it supported. |
| Fixed inventory access is denied | `unknown` unless a real event was observed | `permission_denied` | Review the existing least-privilege boundary separately; the agent does not retry as root or change groups, capabilities, ACLs, or policy. |
| Inventory times out or returns malformed bounded state | `unknown` | `stale` or `degraded` | Retry safe diagnostics and verify the producer/version. Do not expose raw rules or mutate policy to force a result. |

An observed event is stronger positive evidence than an older inventory result. Conversely, a newer disabled, denied, unsupported, or absent inventory observation overrides durable historical event-family history, including after agent restart; only structured firewall evidence observed after that inventory can recover direct producer precedence. A current journal read alone is not sufficient: quiet health additionally requires `firewall_logging_already_enabled=satisfied`. A logging-disabled source reports that prerequisite as `disabled`; absence and unsupported/denied states remain distinct.

## Fixed bounded probes

The hourly inventory pass invokes only fixed executable paths and fixed read-only arguments:

- nftables: `nft -j list ruleset`; the parser counts table objects and checks structured rule expressions for a journal-capable `log` expression. An NFLOG-only `log group N` expression is not journal visibility and remains logging-disabled. Raw rules, addresses, prefixes, and comments are discarded.
- firewalld: `firewall-cmd --state` plus `firewall-cmd --get-log-denied`; the documented `NOT_RUNNING` exit code 252 is accepted only for the enumerated inactive state, and only the running state plus enabled/disabled logging decision are retained.
- UFW: `ufw status`; only exact active/inactive and on/off logging fields are retained.
- legacy iptables: `iptables -S`; only an aggregate active/inactive decision and bounded rule count are retained so the out-of-scope producer can be reported honestly.

Every command has the existing process timeout and output ceiling, uses no shell, and cannot be configured with arbitrary paths or arguments. Source-health details expose only `firewall_inventory_state`, `firewall_producer`, `firewall_inventory_reason`, `firewall_logging`, and `firewall_journal_visibility`. They never contain rule text or journal records.

Only an unavailable fixed executable (`command_missing`) counts toward producer absence. A generic start or command failure, truncated output, or unparseable result remains unresolved and fails closed; it cannot turn into `not_applicable` merely because no usable output was returned.

## Operator review

Review `linux-firewall` after the normal inventory startup delay in `/api/v1/source-health`, `/api/v1/telemetry-coverage`, or the host coverage page.

- `logging_enabled` plus `supported_quiet` means the already-enabled producer and current journal were observed; it does not mean traffic was allowed, denied, or safe.
- `logging_disabled` is an operator decision point, not an invitation for the agent or web console to enable logging. Use the firewall owner's normal change-control and rollback process only when that additional telemetry is actually required.
- `absent`, `unsupported`, `permission_denied`, `timeout`, `malformed`, and pre-inventory `unknown` stay machine-readable and distinct. Do not install packages, switch firewall implementations, widen privilege, or generate traffic solely to turn the row green.
- Search recent events only when an exact family is `observed`; quiet health never satisfies a detection rule's recent-event requirement.

Public validation uses only the hand-authored aggregate fixture `synthetic-linux-firewall-evidence-cases.json`. Real firewall rules, command output, journal records, hostnames, inventory exports, screenshots, and validation captures remain private and outside the repository.
