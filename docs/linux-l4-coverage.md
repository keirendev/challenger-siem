# Linux L4 full-target coverage

Status: implementation available for controlled deployment; private Linux VM validation, soak, and performance evidence have not yet passed

Linux L4 is Challenger SIEM's highest defined Linux coverage level. It extends the healthy L1/L2 journal baseline and approval-gated L3 process, network, and host-behaviour sources with two mandatory assurance sources and each applicable role-specific journal pack. The journal remains system-only by default; the optional all-accessible-local scope is a separately reviewed, plan-bound input that grants no new access. L4 is deliberately strict: it is a reviewed high-value-host target, not a default installation mode or a promise that every possible Linux telemetry source is collected.

The implementation remains passive and read-only. It does not install or configure Linux Audit Framework rules, load eBPF programs, enable application logging, change firewall or authentication policy, alter kernel or mandatory-access-control settings, or add privileges to make a source appear healthy. Missing prerequisites remain visible coverage gaps.

## Current implementation

An L4-capable agent reports these mandatory L4 sources:

| Source ID | Kind | Purpose | Healthy boundary |
| --- | --- | --- | --- |
| `linux-policy-posture-drift` | `inventory_diff` | Compare a bounded, fixed security-posture observation with the exact operator-approved baseline | The L4 plan and baseline hashes match, the latest complete scan matches the approved baseline, and no gap, denial, truncation, or queue failure is active |
| `linux-agent-performance-slo` | `agent_health` | Evaluate bounded rolling process CPU, RSS, and write-rate evidence plus queue health | The rolling window is complete, every implemented required counter is available, process thresholds and queue-health checks pass, and no active pressure/collection gap exists |

Six L4 journal packs reuse the existing physical systemd-journal reader and cursor:

| Source ID | Declared role | Scope |
| --- | --- | --- |
| `linux-role-web` | `web_server` | Exact `nginx`, `apache2`, `httpd`, or `caddy` identifier/service-unit evidence |
| `linux-role-database` | `database_server` | Exact PostgreSQL, MySQL, or MariaDB identifier/service-unit evidence (`postgres`, `postgresql`, `mysqld`, `mysql`, `mariadb`, `mariadbd`) |
| `linux-role-dns` | `dns_server` | Exact `named`, `bind9`, `unbound`, `pdns`, or `powerdns` identifier/service-unit evidence |
| `linux-role-file-server` | `file_server` | Exact Samba/NFS identifier/service-unit evidence (`smbd`, `nmbd`, `samba`, `nfsd`, `nfs-server`, `rpc-mountd`, `rpc.mountd`) |
| `linux-role-container` | `container_host` | Exact `docker`, `dockerd`, `containerd`, `crio`, `cri-o`, or `podman` identifier/service-unit evidence |
| `linux-role-identity` | `identity_server` | Exact `sssd`, `krb5kdc`, `slapd`, `ipa`, or `dirsrv` identifier/service-unit evidence |

These packs add classification, source health, and detection context; they do not create new file readers, application audit plugins, paths, commands, cursors, privileges, or producer settings. A match requires an exact identifier, an exact `<identity>.service` unit, or an `<identity>@...` template unit from the fixed table. Classification does not mine arbitrary message text to guess a role source. The agent persists the last successful shared-journal read and uses that observation for quiet declared-role health only when independent system-journal visibility is verified; heartbeat generation time and user-only read success are not substitutes. When no matching role event occurred, canonical event-family state remains `not_observed` so health is not confused with activity.

If one structured record matches both an approved declared-role family and an L2 family such as service lifecycle or PAM login, the L4 role classification is the single queued primary event so applicable role evidence is not starved. The record retains at most one bounded secondary L2 source/family in `linux.secondary_source_id` and `linux.secondary_event_family`; journal state uses it to update the L2 source's observed family/time, and the server accepts only a fixed catalog-valid pair from a known L4 role source when preserving the corresponding existing L2 detection predicate. It does not enqueue a duplicate event, create separate evidence, or introduce a payload-based role detection. Role message/command-line payload redaction still applies to the primary envelope.

Canonical mandatory families are `policy_baseline`, `policy_drift`, `policy_restored`, `policy_sample`, and `policy_gap` for posture, and `slo_sample`, `slo_breach`, `slo_recovery`, and `slo_gap` for performance. Role families are `web_service`/`web_security`; `database_service`/`database_authentication`/`database_security`; `dns_service`/`dns_security`; `file_service`/`file_authentication`/`file_security`; `container_service`/`container_lifecycle`/`container_security`; and `identity_service`/`identity_authentication`/`identity_security`.

`general_server` and `workstation` are supported declarations with no specialized role pack. Existing `ssh_server` and `bastion` declarations continue to make the L2 `linux-ssh` source applicable. A host may declare more than one role; every corresponding applicable source must then pass.

Linux Audit Framework remains the explicit optional `unsupported` catalog entry. Audit, eBPF, broad file-integrity monitoring, packet capture, and unrestricted application-log ingestion are not hidden prerequisites for L4 and are not enabled by this implementation.

## Strict L4 calculation

A Linux host reaches L4 only when all of the following are true at the same assessment time:

1. Every mandatory applicable L1 and L2 source is healthy.
2. All three mandatory passive L3 sources are enabled with their exact approved plan and are healthy.
3. `linux-policy-posture-drift` and `linux-agent-performance-slo` are enabled with their exact L4 approval and are healthy.
4. At least one supported role is explicitly declared and every declared role resolves. Empty or unknown role declarations block L4.
5. All six L4 role rows are present and resolve to `applicable` or `not_applicable`; every applicable role-specific L2/L4 source is enabled, fresh, and healthy.
6. There is no active source gap, permission denial, stale observation, pressure/throttle state, poison or acknowledgement failure relevant to a mandatory/applicable source.
7. No mandatory or applicable source is being satisfied by a coverage exception.

This last rule is intentionally stricter than lower levels. An approved exception remains useful for recording and explaining a gap, but a host with an exception cannot claim full-target L4 coverage. `not_applicable` is valid only for a role pack whose role was explicitly resolved as absent; it resolves the matrix but never counts as L4 evidence, cannot stand in for the two mandatory sources, and cannot erase an unresolved role.

Policy-posture and role-journal observations become stale after two hours; the rolling performance row becomes stale after five minutes. An observation more than five minutes in the future degrades. These server-enforced freshness rules prevent a stopped collector or old SLO window from retaining L4.

Optional unsupported sources, including the current Linux Audit Framework catalog entry, remain visible but do not independently block L4. Their status must not be summarized as collected coverage.

## Role declaration and resolution

Roles are operator declarations in `Agent:Journal:DeclaredRoles`; the agent never infers or enables a server role from an installed package, process, listener, inventory item, or one journal message. Supported values are:

- `general_server`
- `workstation`
- `ssh_server`
- `bastion`
- `web_server`
- `database_server`
- `dns_server`
- `file_server`
- `container_host`
- `identity_server`

Declarations remain bounded, unique, lowercase identifiers. Before L4 activation, preflight resolves the complete set and lists the resulting applicable and not-applicable source rows. An empty set means `host_role_not_declared`; an unknown identifier means `host_role_unsupported`. Both states are visible and block L4 rather than being treated as general-purpose coverage.

A current nonempty declaration is authoritative. If a role is removed through a newly approved plan, persisted historical observations from that role cannot keep its row applicable after restart; the row resolves from the current declaration.

Use `general_server` or `workstation` only after reviewing that no specialized pack applies. These declarations resolve the six specialized role rows; they do not waive either mandatory L4 source or any of the five fixed posture inputs. If the VM later acquires a new role, update the declaration, generate a new plan, review a new posture baseline where required, and repeat validation. A prior approval does not authorize the expanded role.

## Exact plan and posture-baseline workflow

The two mandatory L4 collectors are disabled by default under `Agent:L4Telemetry`; structured role classification is selected only by `Journal.TargetCoverageLevel=L4` with known declared roles. Full activation requires that target/role configuration and both `ApprovedPlanHash` and `ApprovedBaselineHash` match the current non-policy-mutating preflight:

1. Publish/copy the portable bundle and create a separate private mode-0600 real configuration with the intended L4 target/roles, reviewed `IncludeAccessibleUserJournals` value, `L4Telemetry.Enabled=false`, and both L4 approval hashes unset. Complete the separate passive-L3 preflight/approval first: `PassiveTelemetry.Enabled=true`, its bounds valid, and its exact plan hash matching are L4 activation-readiness prerequisites. A fresh VM must already have the reviewed non-root `challenger-siem` passwd entry (UID not 0), matching primary group, an exact nologin/false shell, and a shadow password locked with `!` or `*`; real-host install verifies these as root before creating paths. Python 3 and identity lookup tools are target plan prerequisites, and root-triggered L4 preflight uses `runuser`. The operator must also verify the intended existing journal visibility. All-accessible-local scope means only local journals already readable by that identity and may expose high-sensitivity user-service text; it does not authorize a new privilege. The installer does not create/correct the identity, install those tools, or join journal groups/change ACLs. Review the lifecycle plan, then install/start this L4-disabled configuration only through the separately approved lifecycle window; passive-L3 enablement is its own approved collection action. The L4 posture preflight intentionally waits for the installed private state directory and steady-state identity; a pre-install payload cannot complete the fixed `/opt` executable and `/etc` configuration portion of `linux_agent_integrity`, and the helper does not probe as root to fake it.
2. From the installed target, run the bundled `./linux-agent.sh plan --config <installed-private-mode-0600-config>`. It invokes the installed payload's `--l4-telemetry-plan` as the locked `challenger-siem` service identity with a clean environment, so baseline readability matches steady state. Alternate-root, missing-identity, missing-binary/state-directory, unwritable-state, or unsafe-config cases remain explicit blockers rather than broadening identity or access.
3. Review the product version, declared-role resolution, effective journal scope, independent system visibility, the five fixed posture inputs (`linux_agent_integrity`, `linux_firewall`, `linux_mandatory_access_control`, `linux_secure_boot`, and `linux_ssh`), collection cadence and limits, queue priority, privacy boundary, proposed host changes, rollback, plan hash, and candidate baseline hash. Store the full output only in ignored/private evidence.
4. Investigate unexpected candidate posture before approval. Do not approve a baseline merely to remove a coverage warning.
5. Copy only the reviewed candidate hash into `ApprovedBaselineHash`, keep `Enabled=false` and `ApprovedPlanHash` unset, then rerun the same installed preflight. The plan hash changes because it binds the approved baseline hash.
6. Review that second, baseline-bound plan, copy its exact hash into `ApprovedPlanHash`, and set `Enabled=true` in the protected staged configuration. `upgrade` may stage that configuration/binary/unit without starting or restarting the service. Obtain separate explicit restart approval before activating it; staging alone is not L4 enablement.
7. On startup, the collector must match both approvals before it emits healthy evidence. A missing, corrupt, changed, denied, partial, or mismatched baseline cannot be silently adopted.
8. Subsequent complete observations compare with the approved baseline. Drift remains visible until posture returns to the approved state or an operator intentionally reviews and approves a new baseline through this two-pass workflow.
9. Changing roles, plan-bound limits, fixed inputs, collector version, queue-priority relationships, or approved posture invalidates the applicable hash and requires review again.

The L4 preflight changes no policy, L4 state, queue, configuration, or collected telemetry. Because the published agent is a .NET single-file executable, its runtime may populate only `/var/lib/challenger-siem-agent/.dotnet-bundle` under the already installed private state directory. Treat that bounded product-owned cache write as part of the preflight and do not describe the operation as literally zero-write.

Both approval values use the exact lowercase form `sha256:` followed by 64 hexadecimal characters. The plan binds target/journal state including `system_only` versus `all_accessible_local` scope, heartbeat cadence, the baseline hash, sorted roles, passive enablement/approval and queue relationships, inventory cadence/deadline/budget, all other plan-bound L4 fields except its activation switch and self-referential hash, fixed observations, rolling thresholds/inputs, collector version, and exclusions. Changing scope invalidates both the prerequisite passive-L3 approval and the L4 plan approval. Enabled configuration additionally requires the journal reader and enforces SLO interval + scan timeout + heartbeat at no more than 270 seconds and posture interval + inventory timeout + heartbeat at no more than 6,900 seconds, preserving reporting headroom inside the five-minute/two-hour server freshness boundaries.

### Preflight readiness fields and blocker codes

The JSON preflight reports `plan_hash`, `candidate_baseline_hash`, `candidate_baseline_complete`, `candidate_baseline_states`, `candidate_baseline_blockers`, `activation_ready`, `activation_blockers`, `enabled`, `approval_hash_matches`, `baseline_hash_matches`, `declared_roles`, `applicable_role_sources`, `not_applicable_role_sources`, `policy_snapshot_types`, and bounded privilege/change/privacy/limits/rollback descriptions. Keep the complete document and both hashes private.

`activation_ready` is deliberately independent of `enabled`: it is true exactly when the preflight has no activation blocker. In particular, it can be true while the L4 candidate remains disabled, which lets the operator approve and stage `Enabled=true` without first running L4 collection. It verifies passive-L3 configuration/approval but not its runtime health or private soak; strict server L4 still requires all three passive sources healthy. Do not activate unless `activation_ready=true`, `activation_blockers` is empty, `candidate_baseline_complete=true`, and both match flags are true on the second, baseline-bound pass.

Exact activation blocker values are:

| Code | Meaning |
| --- | --- |
| `l4_telemetry_bounds_invalid` | One or more base/relational L4 field bounds is invalid. |
| `journal_bounds_invalid` | The journal poll/input/queue/target/role configuration is invalid. |
| `passive_telemetry_disabled` | Mandatory passive L3 process/network/behaviour collection is not enabled. |
| `passive_telemetry_bounds_invalid` | A passive-L3 base/relational field or queue-priority bound is invalid. |
| `passive_telemetry_approval_hash_mismatch` | Passive-L3 approval is absent, invalid, or does not equal its current plan hash. |
| `heartbeat_interval_invalid` | Heartbeat cadence is not positive. |
| `slo_freshness_budget_exceeded` | SLO sample + scan timeout + heartbeat exceeds 270 seconds. |
| `policy_freshness_budget_exceeded` | Posture interval + inventory timeout + heartbeat exceeds 6,900 seconds. |
| `journal_target_not_l4` | Journal target is not exactly L4. |
| `journal_disabled` | The one journal reader is disabled. |
| `declared_roles_missing` | No role was declared. |
| `declared_role_unsupported` | At least one declaration is outside the fixed supported set. |
| `candidate_baseline_incomplete` | One or more fixed posture snapshots is not complete. |
| `approved_baseline_hash_missing_or_invalid` | Baseline approval is empty or not exact lowercase `sha256:` + 64 hex. |
| `approved_baseline_hash_mismatch` | The valid approval does not match the current candidate. |
| `approved_plan_hash_missing_or_invalid` | Plan approval is empty or not in the exact hash format. |
| `approved_plan_hash_mismatch` | The valid approval does not match the current baseline-bound plan. |

`candidate_baseline_states` maps each fixed snapshot type to `missing`, `invalid_contract`, or `<state>:<error_code>`. `candidate_baseline_blockers` contains only incomplete entries and uses the following bounded formats:

| Blocker value | Completeness rule |
| --- | --- |
| `snapshot_missing` | The fixed snapshot type was not present. |
| `snapshot_invalid_contract` | Items or summary was absent. |
| `snapshot_truncated:<error_code>` | The fixed snapshot was truncated. |
| `snapshot_<state>:<error_code>` | Top-level state was neither `success` nor `not_applicable`. |
| `agent_integrity_components_incomplete:config=<state>,executable=<state>,config_item=<present\|missing>,executable_item=<present\|missing>` | Both child states must be `success`, with exact `agent_integrity` items named `configuration` and `executable` present. |
| `mandatory_access_control_providers_incomplete:apparmor=<state>,selinux=<state>` | Both child states must be explicit `success`, `unavailable`, or `not_applicable`, and at least one `success` provider must have its matching `mandatory_access_control` item present. Denied, timeout, malformed, unknown, or two unobserved alternatives block. |

Combined child states are normalized to `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, `malformed`, or `unknown`. These codes explain readiness without printing raw posture values. They are diagnostic blockers, not instructions to install/enable a provider or widen access.

The first complete runtime observation is baseline establishment evidence, not automatic approval. Each fixed snapshot must report `success` or an explicit, reviewed `not_applicable`; the latter state is included in the fingerprint rather than treated as collected control evidence. The combined integrity and MAC snapshots must also pass the child rules above, so a healthy top-level summary cannot hide a missing installed executable/configuration or a denied/malformed alternative MAC provider. Missing, unavailable, denied, timed-out, malformed, partial, or truncated evidence cannot assert deletion, restoration, or no drift. Event sequence ranges are reserved in the private state before queue insertion, collected position advances only after the whole range is durably queued, and interrupted reservations become explicit non-reused gaps. Acknowledged position advances only through a contiguous range of accepted/duplicate server acknowledgements.

An explicit server rejection is not acknowledgement. The agent may durably abandon and poison only the immediately next contiguous rejected sequence after earlier accepted/abandoned outcomes; it increments dropped/gap state and keeps the L4 source non-healthy. A rejection that would jump over an unseen outcome remains queued and raises a non-contiguous error. The subsequently emitted recovery-gap sequence must be durably acknowledged before the active gap clears; current collection still determines source status, and poison/drop health remains visible. This prevents either rejected-first or accepted-first batch ordering from deadlocking or silently skipping evidence.

Minimal VM images commonly expose incomplete posture—for example denied/missing firewall visibility or absent/malformed `sshd`, `mokutil`, or mandatory-access-control provider observations. Only an explicit collector-returned `not_applicable` is eligible for reviewed fingerprinting. An operator cannot relabel absent, denied, unavailable, or malformed evidence to make the baseline complete, and the agent does not install a package, enable a service, broaden permission, or change policy to clear the blocker.

Relevant fields are documented in [Agent configuration format](agent-config.md#linux-l4-fields). The fixed state file is `/var/lib/challenger-siem-agent/l4-telemetry-state.json`. Cleanup after disablement may remove only this pack-owned state file when explicitly requested; it does not alter the approved host posture, shared queue, journal state, credentials, or server evidence.

## Rolling performance SLO evidence

The performance source is an online guardrail, not a substitute for a rollout benchmark. It evaluates a bounded rolling window at the configured sample cadence and reports warm-up, unavailable metrics, breaches, pressure, gaps, and recovery explicitly. A sample represents the interval from its prior endpoint. Health requires both the calculated number of complete interval samples and endpoint-inclusive elapsed coverage of at least the full configured window; merely reaching the sample count early cannot pass warm-up. The implemented rolling checks are:

- average agent CPU below 2%;
- p95 agent CPU below 5%;
- RSS below 250 MiB;
- average process writes below 1 MiB/s.

Managed memory is emitted only as bounded context (`maximum_managed_memory_bytes`) alongside `covered_window_seconds`; it is not an L4 pass/fail threshold. Queue health also requires zero poison depth, an explicit zero dropped-event total, exact `normal` pressure, and either an empty queue with no oldest-age value or a non-empty queue whose oldest item is no older than the larger of five minutes or twice the configured maximum backoff. Unknown required queue metrics fail closed. The coverage specification additionally requires that no individual collector sustain more than 10% CPU for over 60 seconds; the current rolling source does not measure per-collector CPU, so that criterion remains a private benchmark/soak gate and must not be inferred from a healthy source row.

A zero value is used only when measured. Unsupported or unavailable counters remain unknown and prevent healthy L4 evidence. A new agent start, plan change, insufficient rolling window, counter reset, or observation discontinuity returns a non-healthy warm-up/gap state rather than reusing old evidence. Optional L4 work pauses before mandatory L1/L2 collection under queue or resource pressure.

Private validation must still measure idle, steady state, burst, server outage/queue growth, reconnect/drain, restart, role workload, per-collector CPU, and optional-collector windows over the required canary period. When all-accessible-local scope is selected it must also verify existing-identity access, independent system visibility, scope-transition/cursor recovery, sensitive-data exposure, volume, and rollback to system-only. The heartbeat/source row proves only the current implemented rolling state; it does not prove that the VM passed those broader scenarios.

## Deployment and validation state

The implementation and synthetic test surface can be deployment-ready without claiming that L4 has passed on a real host. At the time of this document, the operator-provided Linux VM canary has not been run. Therefore:

- do not describe L4 as a default or production-ready rollout;
- do not infer L4 success from unit tests, one healthy heartbeat, or a short idle window;
- retain all VM plans, baseline observations, telemetry, API responses, resource samples, screenshots, logs, and benchmark output only under ignored local or approved runtime paths; and
- publish only synthetic fixtures and aggregate pass/fail/blocked conclusions.

Follow [Linux local-host rollout validation](linux-local-host-validation.md#l4-private-vm-canary) after the VM is available. L1's 24-hour and L1+L2's seven-day gates still apply; L3 and L4 require their own reviewed approval, workload, recovery, privacy, performance, and rollback evidence. Any secret/excluded-data collection, unauthorized mutation, host impact, silent loss, persistent gap, uncontrolled growth, false-healthy state, or SLO breach is an immediate stop/rollback condition.

## Explicit non-goals

L4 does not authorize or implement:

- audit rule installation or audit daemon reconfiguration;
- eBPF programs, kernel modules, packet capture, or payload collection;
- enabling role-application logging or changing its retention;
- broad or recursive file-content/integrity scanning;
- process environment, memory, secret-store, browser/session, shell-input, or credential collection;
- arbitrary commands, executable paths, log paths, or operator-provided parser expressions;
- automatic remediation, posture mutation, service restart, or privilege expansion; or
- a public claim based on private raw evidence.

Those boundaries remain authoritative even when a missing source prevents L4.
