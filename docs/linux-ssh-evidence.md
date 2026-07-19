# Linux SSH applicability and quiet-source evidence

`linux-ssh` is an L2 role-specific logical source carried by the one bounded systemd-journal reader. It does not start, stop, enable, reconfigure, probe, or authenticate to an SSH service. Applicability and health are separate decisions: the declared host role says whether SSH coverage is required, while existing read-only service inventory and journal observations say whether that coverage is available.

## Deterministic decision table

| Declared role and bounded evidence | Applicability | Health after a current successful journal read | Operator interpretation |
| --- | --- | --- | --- |
| No declared role, no SSH event, and no active supported service evidence | `unknown` | `degraded` | Role applicability is unresolved. This is not `not_applicable` and cannot satisfy strict L4. |
| No declared role, but exact active `ssh.service` or `sshd.service` inventory | `applicable` | `healthy` while current, even when quiet | Existing bounded inventory resolves applicability; event families remain `not_observed` until real activity occurs. |
| `ssh_server` or `bastion`, with an exact active supported service | `applicable` | `healthy` while current, even when quiet | The declaration requires SSH coverage and the existing producer is visible. |
| A declared supported role other than `ssh_server` or `bastion` | `not_applicable` | `not_applicable` | The explicit declaration is authoritative. Review a contradictory active service or event as a role-declaration mismatch; it is not silently promoted. |
| `ssh_server` or `bastion`, but the exact service is present and inactive/failed | `applicable` | `degraded` | Producer visibility is not active; a general journal read cannot prove quiet SSH collection. |
| Required SSH inventory or journal access is denied | `applicable` when declared | `permission_denied` | Preserve least privilege and review the denied boundary; the agent does not retry as root or change groups/ACLs. |
| No exact service and the fixed primary OpenSSH configuration path is absent | `unsupported` | `unsupported` | The implemented OpenSSH/systemd producer is not present. This is a capability result, not evidence that the host is safely non-SSH. |
| A real normalized SSH record is already observed, with no declared role | `applicable` | follows current journal health | Direct producer evidence resolves applicability and its exact family becomes `observed`. |

An SSH event is never generated merely to make a row healthy. A current successful shared-journal observation establishes quiet freshness only when an exact active supported SSH service has already been established. `ssh_authentication` and `ssh_session` remain independently `not_observed`, and quiet health does not satisfy a detection rule's recent-event requirement.

## Bounded evidence and precedence

The agent reuses two existing inventory snapshots:

- `linux_services`, limited to already returned systemd service items, recognizes only exact `ssh.service` and `sshd.service` names and their bounded active state.
- `linux_ssh`, read from the existing fixed `/etc/ssh/sshd_config` inventory policy, retains only the three already allowlisted posture settings. Its contents are not copied into source-health details.

No process scan, socket probe, recursive configuration include traversal, alternate SSH path, shell command, service mutation, authentication attempt, or permission expansion is added. An observed normalized SSH record is stronger positive producer evidence than an older inventory state. Newer inactive, denied, malformed, or unsupported inventory overrides durable historical SSH event-family history across restart until a later structured SSH record is observed. An explicit non-SSH role declaration remains `not_applicable` even when an SSH record exists; operators should correct the agent role through the normal reviewed configuration workflow if that declaration is wrong, without changing the SSH service merely to affect telemetry health.

## Operator review

Review the `linux-ssh` manifest and health row after the normal inventory startup delay. The bounded details expose `ssh_inventory_state`, `ssh_inventory_producer`, `ssh_inventory_reason`, and `ssh_journal_visibility`; prerequisite state is reported under `sshd_journal_visibility`.

- `supported_quiet` plus `healthy` means the active producer and shared journal were observed, not that an SSH login occurred.
- `producer_inactive`, `permission_denied`, `stale`, `degraded`, or `unsupported` must remain explicit. Do not enable SSH, perform a login, restart a service, widen journal/config permissions, or edit authentication policy solely to turn the row green.
- For an L4 target, `linux-ssh` must resolve to exactly `applicable` or `not_applicable`; an applicable row must be enabled, fresh, and healthy. `unknown` and `unsupported` cannot be skipped by the strict gate.

Public validation uses only the hand-authored aggregate fixture `synthetic-linux-ssh-evidence-cases.json`. Real inventory, journal records, hostnames, service output, configuration, and validation captures remain private and outside the repository.
