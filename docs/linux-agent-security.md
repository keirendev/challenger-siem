# Linux agent security and privacy design

Status: bounded read-only L1-L2 with default system-only and opt-in all-accessible-local journal scopes, approval-gated L3 snapshots, and approval-gated L4 posture/SLO/role-journal sources implemented; private L4 VM validation remains outstanding and audit/eBPF/broad file collectors remain deferred
Specification version: 0.1
Primary audience: security reviewers, Linux agent engineers, packagers, operators

## Purpose and governing principles

This document defines the threat model, least-privilege boundary, privacy controls, and change-approval model for the Linux agent described in [linux-host-coverage-spec.md](linux-host-coverage-spec.md). The bounded inventory controls, passive L1 journal reader with a system-only default and explicit all-accessible-local option, opt-in L2 structured normalization, explicit-opt-in L3 self-integrity/procfs packs, and separately approval-gated L4 policy-posture, rolling-SLO, and declared-role journal sources are implemented; audit, eBPF, broad/live file collectors, and application-log file readers remain deferred. The [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) keeps audit/eBPF deferred, the [passive telemetry contract](linux-passive-telemetry.md) defines polling limits, and [Linux L4 full-target coverage](linux-l4-coverage.md) defines the strict approval/validation boundary. This document does not authorize deployment or host changes.

The design follows the existing Windows/public-repository baseline: authenticate agents separately from operators, use HTTPS outside development, protect endpoint credentials, keep queues/state restricted, never log secrets, bound raw telemetry, report collection gaps, and keep real telemetry and local evidence out of git. Linux support must not weaken those controls merely to obtain broader visibility.

Principles:

1. passive observation before host mutation;
2. minimum privileges per collector, not unrestricted root for convenience;
3. minimum necessary telemetry, with explicit prohibited content;
4. fail visibly and safely rather than silently broadening access;
5. independently bounded collectors and durable delivery;
6. plan, explicit approval, verified application, and reversible rollback for every optional host change.

## Threat model

### Protected assets

- per-agent enrollment/transport credentials and server trust configuration;
- agent executable, packages, configuration, source manifests, queue, checkpoints, and logs;
- host telemetry and identity metadata in memory, on disk, and in transit;
- source integrity, event ordering/position, and source-health status;
- host availability and existing audit, firewall, authentication, kernel, service, and security policy.

### Adversaries and failures

The design must account for an unprivileged local user reading or injecting telemetry; a compromised service producing malicious or oversized records; a network attacker intercepting/replaying traffic; a malicious or compromised server response; accidental operator misconfiguration; resource exhaustion; log rotation/truncation; package or update tampering; and a privileged attacker stopping, replacing, or deleting the agent and source data.

A user with unrestricted root or kernel control can suppress or forge host observations. The agent must report detectable service/config/source changes and heartbeat gaps, but must not claim tamper-proof visibility against that adversary.

### Security objectives

- authenticate the server and agent, protect transport confidentiality/integrity, and prevent cross-agent identity claims;
- prevent telemetry input from becoming code execution, path traversal, privilege escalation, or unbounded resource use;
- prevent intentional collection of prohibited sources and known secret-bearing fields, and redact recognized common credential forms before queueing;
- preserve deterministic event identity, durable checkpoints, and explicit loss/gap metadata;
- make privilege, configuration, package, and collector changes attributable and reviewable;
- avoid disrupting host workloads or reducing existing security controls.

## Least-privilege architecture

The preferred future architecture separates a low-privilege core from narrowly privileged source access:

| Component | Default boundary | Permitted responsibility |
| --- | --- | --- |
| Core agent | Dedicated locked service account, no login shell, no reusable password, restrictive umask | Normalize already-readable records, redact, queue, send, heartbeat |
| Source adapters | Same account where group/ACL read access suffices; otherwise narrowly isolated helper | Read only declared journal/files/status interfaces; return bounded records |
| Optional privileged helper | Absent by default; fixed audited operations only after approval | Open an approved protected source or attach an approved advanced collector; no shell or arbitrary path/command API |
| Installer/upgrader | Temporary administrative execution with reviewed plan | Verify package and pre-existing locked identity, create product directories/unit, set exact permissions; relinquish privileges after completion |

Requirements for future implementation:

- Do not run the whole steady-state agent as root when a dedicated identity plus narrowly scoped groups, ACLs, capabilities, or helpers can satisfy the approved source manifest.
- Treat membership in groups such as `systemd-journal` or `adm` as privileged access and list its effective data scope in plan output.
- Linux capabilities must be individually justified and attached only to the component that needs them. Never grant a broad capability set, privileged container mode, host PID namespace, arbitrary `/proc`, or unrestricted host filesystem access by default.
- Privileged helpers must use a fixed protocol, caller authentication, allowlisted operations and paths, bounded inputs/outputs, timeouts, and secret-safe audit logs. They must not invoke a shell or accept arbitrary commands.
- Configuration must not select arbitrary files through untrusted server instructions. Source manifests and remote configuration must be authenticated, schema-validated, locally policy-constrained, and versioned.
- Agent directories must be root-owned where needed and inaccessible to unrelated users. The service identity receives only the minimum read/write access: read approved sources/config, write its private queue/state/runtime logs, and no write access to source logs or security policy.
- Queue databases, checkpoints, config, credentials, and diagnostic logs require restrictive ownership/modes and symlink-safe, atomic file handling. Secrets must use an OS-appropriate protected credential mechanism; plaintext command-line arguments and environment-value dumps are forbidden.
- Package/update artifacts must be signed and verified before privileged installation. Downgrades and unexpected publisher/config changes must be explicit operator actions.
- systemd hardening (or init-system equivalent) should deny privilege escalation, restrict namespaces/filesystems/devices/syscalls, isolate temporary paths, and bound CPU/memory/tasks/files, subject to validation against required collectors.

## Implemented L1/L2 journal controls

One collector uses systemd's existing machine-readable journal interface through fixed `/usr/bin/journalctl` or `/bin/journalctl` candidates. It launches directly without a shell, clears the environment except fixed locale values, uses fixed bounded arguments/field projection, caps records per poll, captures only a bounded stable error classification, and terminates the process tree on cancellation. `IncludeAccessibleUserJournals=false` supplies the fixed `--system` selector. When explicitly true, the reader supplies neither `--system` nor `--user`, so `journalctl` selects every local journal file already readable by the service identity; a separate bounded system-only probe independently gates mandatory system visibility. Configuration cannot select an executable, arbitrary arguments, a journal file/directory, namespace, remote source, command, helper, or fallback source. L2 and the six L4 role packs change classification only; they add no reader, source path, privilege, producer configuration, audit collector, eBPF, or file-integrity watch. Role classification uses fixed structured identifier/unit fields, not new message-regex inference. On a role/L2 collision the role event wins as the single privacy-redacted queued envelope, while one bounded secondary source/family label updates L2 health evidence without duplicating payload/event storage. Quiet role, login/session, tamper, and kernel-security freshness comes from the persisted last successful shared-journal read only when system visibility is verified, never the current heartbeat timestamp; canonical families remain `not_observed` until matching evidence exists.

The service identity receives no new capability or group membership from installation or scope selection. All-accessible-local means accessible under existing permissions, not every user's journal. If the system journal is unreadable, health reports denied, missing, or error even if a user-journal read succeeds; the agent does not retry as root, broaden ACLs, mutate a group, or read alternate files. Operators must assess the expanded data scope before independently granting `systemd-journal` or `adm` membership.

Journal JSON is untrusted and bounded before parsing. The normalizer requires cursor, boot ID, and real-time timestamp; allowlists journal/process/PAM/user/remote/result/action/unit/package/module fields; replaces control text and binary/non-text values; caps command lines, fields, messages, and raw JSON; and redacts common credential-shaped assignments in every retained string before queue insertion. Structured fields always override message-derived evidence. Supplemental parsers inspect at most 4,096 message characters with fixed 50 ms regex timeouts or bounded token counts; ambiguous text stays L1 without invented enrichment. Redaction/truncation paths are explicit. Malformed/oversized/missing-identity input creates a health gap without raw diagnostics. Deterministic event identity plus queue uniqueness bounds replay.

Each event commits to the private Agent.Core SQLite queue before the collected cursor is atomically persisted. Accepted/duplicate acknowledgement is persisted before queue deletion. Invalid/vacuumed cursor recovery starts a bounded read from available records while preserving a gap; pressure pauses collection rather than deleting unacknowledged rows. Logical L2 and L4 role families share that physical cursor and cannot bypass its ordering. Source health exposes requirement/applicability, prerequisite/event-family state, permission, unsupported/degraded/stale/gap, malformed/binary, duplicate/reorder, throttle, config, collector version, lag, and collected/acknowledged positions without payload content. A successful journal read may establish quiet role, login/session, tamper, or kernel-security source health while leaving each activity family `not_observed`; it does not create recent detection evidence. Exceptions remain server-approved rather than agent-asserted, and no exception satisfies strict L4.

## Implemented inventory controls

The inventory collector is a read-only, fixed catalog rather than a general host scanner. Every operation declares exact executable path candidates and arguments or one exact file path, accepted exit codes, a 5-20 second timeout, a 16 or 64 KiB command/content cap (or a 64 MiB streaming hash cap for the fixed executable), and cancellation. Processes run without a shell, inherit no environment, receive only fixed locale/PATH values, and are terminated as a process tree on timeout, cancellation, or output truncation. File access uses no-follow opens, accepts only regular single-link files, rejects symbolic links and special files, and reads only within the catalogued byte/time cap.

The parser boundary emits bounded allowlisted fields rather than raw command/file output. It excludes stdout/stderr, arbitrary paths and file contents, account descriptions/home directories/shells, group membership, addresses, command lines, firewall rules, repository configuration/content, and unapproved SSH directives. Source failures become stable secret-safe codes and one of `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`; truncation is explicit.

Collection runs as a non-overlapping service independently of heartbeat, durable queue drain, and future passive work. The one-hour default interval has a five-minute enforced minimum and a default 30-second startup delay. A default 120-second collection deadline, 20-snapshot maximum, 200-item-per-snapshot maximum, and 256 KiB default serialized budget constrain host and transport impact.

The agent observes high-level package/update, network listener, firewall, SSH, mandatory-access-control, Secure Boot, and agent-file posture without changing them. It does not refresh repositories or alter packages, services, audit/firewall/authentication/kernel/MAC policy, Secure Boot, ownership, or modes. The agent-integrity snapshot reports regular-file, numeric owner, and mode observations for the fixed configuration and executable paths plus a bounded SHA-256 fingerprint of the non-secret executable. The credential-bearing configuration is never read or hashed for inventory. The executable fingerprint supports change review but is not trusted attestation and cannot provide tamper-proof guarantees against root or kernel control.

## Implemented L3 self-integrity snapshot controls

The `linux-agent-self-integrity-snapshot` source is disabled by default and cannot be enabled by installation, enrollment, `TargetCoverageLevel`, or missing coverage. It runs only when `Agent:SelfIntegrity:Enabled=true` and `ApprovedPlanHash` exactly matches the non-mutating plan hash for the built-in allowlist and limits. The preflight plan reports platform support, exact allowlist entries, missing/denied/type/oversize findings, privacy/resource impact, sequencing/loss/pressure behavior, and rollback without changing files, permissions, groups, capabilities, packages, services, audit, firewall, authentication, kernel, MAC policy, or journal retention.

The allowlist is literal and agent-owned: the published Linux agent executable and systemd unit receive no-follow regular-file metadata plus bounded streaming SHA-256; the credential-bearing `agentsettings.json` receives metadata only; `/etc/challenger-siem-agent/` and `/var/lib/challenger-siem-agent/` receive directory owner/group/mode/type metadata only. There is no recursion, arbitrary path configuration, symlink following, hard-link acceptance for hashed files, device/FIFO/socket handling, secret-store access, package database hashing, browser/profile/history access, or file-content emission. Denied, missing, unsupported type, oversize, timeout, and pressure conditions become source health or bounded `agent_health` records, not permission to broaden access.

Self-integrity emits additive v1 `agent_health` events with deterministic sequence checkpoints and explicit `added`, `changed`, `deleted`, `unreadable`, `gap`, `drop`, and `sample` states. Raw payloads contain metadata buckets and digests only; the configuration file is never content-read or hashed. Events are queued before collected sequence advances, acknowledged sequence advances only for accepted/duplicate server acknowledgement, and pressure pauses this optional L3 source before journal L1/L2, heartbeat, inventory, or queue drain. Clean disable may remove only `SelfIntegrity.StatePath`; monitored files and host policy are never touched.

## Implemented L3 passive procfs controls

The process/network/behaviour pack is also disabled by default and requires an exact approval hash over its built-in sources and limits. It reads only fixed procfs files and uses no shell, configurable path, native dependency, kernel program, audit rule, packet socket, unrelated process file-descriptor target, or host-policy mutation. Ordinary permission failures are reported; they are never corrected by adding root, capabilities, groups, ACLs, or a privileged helper.

Process collection excludes `environ`, memory, maps, stacks, arbitrary syscall data, and unrestricted files. Command lines are byte/character bounded and passed through shared common credential-pattern sanitation before any durable state or event write. Recognized URI user information, credential assignments/switches, authorization fragments, invalid text, and controls are redacted or omitted; remaining command text is still high-sensitivity telemetry and is never asserted to be secret-free. Network collection parses fixed TCP/UDP tables only and excludes packet/application payloads, DNS contents, Unix-socket paths, and unrelated FD targets. Host behaviour uses aggregate counters only.

Polling evidence must not be presented as exact exec/exit/connect/close telemetry. Initial observations are baselines; subsequent `observed`, `disappeared`, and `changed` events carry deterministic sequence identity. Partial/truncated/deadline scans cannot create disappearance claims. Queue pressure, event caps, malformed state, and permission gaps remain explicit in source health, and this L3 pack pauses itself at a lower queue threshold so L1/L2 journal collection can continue.

Private pack state is bounded and mode `0600`. Events are queued before collected sequence advances, and acknowledged sequence advances only for accepted/duplicate server acknowledgement. Disable/cleanup may remove only the pack-owned state when explicitly requested; it cannot delete the shared queue, journal state, agent credentials, server telemetry, or host data sources.

## Implemented L4 posture, SLO, and role controls

`Agent:L4Telemetry` is disabled by default. It cannot be enabled by enrollment, a server target-level query, missing coverage, or a role declaration alone. Install it disabled before posture preflight so the candidate observation uses the steady-state identity and private state boundary. Collection starts only when the separately approved passive pack is enabled/valid, the journal reader is enabled at `Journal.TargetCoverageLevel=L4`, roles are non-empty/known, `Enabled=true`, `ApprovedPlanHash` matches the exact non-policy-mutating L4 plan, and `ApprovedBaselineHash` matches the reviewed posture baseline. The plan binds fixed sources, roles, heartbeat/collector cadence, deadlines, queue priority, the bounded 7-500 event cap, state path, version, privacy impact, and rollback. Changing a bound value invalidates approval instead of silently broadening collection. The preflight may populate only the product-owned `.dotnet-bundle` runtime cache under the installed private state directory; it does not write L4 state, queue data, configuration, telemetry, or host policy.

`linux-policy-posture-drift` compares only its built-in bounded posture observations. The approved baseline is distinct from mutable current state: a first scan, restart, missing state file, or changed host cannot approve itself. A required snapshot is complete only in `success` or explicit `not_applicable` state; `not_applicable` is fingerprinted and reviewed rather than treated as collected control evidence. The combined integrity input additionally requires both successful child observations and exact configuration/executable items. The combined MAC input requires explicit valid AppArmor/SELinux alternative states and at least one matching successfully observed provider item; a healthy combined summary cannot hide a denied or malformed child. Missing, unavailable, denied, partial, truncated, timed-out, malformed, mismatched, or corrupt observations remain non-healthy and cannot assert deletion, restoration, or no drift. Raw command/file output, credentials, arbitrary content, and unrestricted paths are not retained. Drift evidence is high-sensitivity endpoint metadata and follows the same durable sequence/acknowledgement ordering as other advanced events.

`linux-agent-performance-slo` samples bounded process and queue/runtime counters at the configured cadence. Complete interval samples must span the full endpoint-inclusive configured window before health is possible. Warm-up, unavailable counters, counter reset, discontinuity, pressure, gap, or threshold breach remains non-healthy. Zero is reported only when measured; maximum managed memory and covered seconds are context rather than thresholds. The current implementation's rolling source is an online release guardrail, not proof of the broader host-class and per-collector benchmark matrix; the private VM canary remains mandatory before any rollout claim.

Declared-role sources reuse the existing journal input and sanitization boundary. They recognize only fixed structured identifier/unit evidence for declared `web_server`, `database_server`, `dns_server`, `file_server`, `container_host`, and `identity_server` roles. They never discover roles by scanning software, open application log files, enable producer logging, or accept configurable parser expressions. `general_server`, `workstation`, `ssh_server`, and `bastion` remain explicit supported declarations without these six specialized sources. Empty or unknown declarations block L4 rather than expanding observation.

The L4 state file is fixed at `/var/lib/challenger-siem-agent/l4-telemetry-state.json`, bounded, private, atomically replaced, and symlink-safe. Cleanup may remove only this file after explicit disablement. L4 pressure behavior yields to L1/L2 collection, heartbeat, and durable queue delivery. The full contract, strict no-exception calculation, and private evidence boundary are in [Linux L4 full-target coverage](linux-l4-coverage.md).

## Collection and privacy boundary

Permitted telemetry is the security metadata defined by the coverage specification: bounded event metadata, identity/process/network/file metadata needed for approved detections, security-control status, and agent/source health. Every collector needs a field inventory, purpose, sensitivity classification, retention expectation, and redaction tests.

Collectors explicitly exclude direct access to, or deliberate retention of, the following prohibited sources and known secret-bearing fields:

- credentials, passwords, tokens, cookies, connection strings, and authorization headers;
- secret stores, credential caches, keyrings/wallets, private keys, and private certificate material;
- browser profiles and browser/session stores;
- environment-value dumps;
- keystrokes, terminal input, clipboard contents, and screen capture;
- packet payloads or full packet capture;
- unrestricted file-content collection.

The exclusion applies to normalized fields, raw source records, diagnostics, errors, benchmarks, and support bundles. Raw data is never an exception for a prohibited source or known secret-bearing field. Collectors must use allowlisted fields where practical, redact recognized common credential forms before queue insertion, cap record/field/batch sizes, mark truncation, and discard prohibited fields. No diagnostic mode may silently disable these protections.

Command lines, source messages, paths, usernames, hostnames, addresses, and role/application logs can contain arbitrary sensitive or credential-like values that no pattern sanitizer can guarantee it will recognize. The all-accessible-local journal scope increases that exposure because user-service/session stdout and stderr may contain application text, command lines, paths, and identities. Retaining these approved fields is not permission to target credentials: they remain high-sensitivity telemetry, require restricted access and retention, and must be dropped or the collector disabled if prohibited-content collection is suspected. Future access control and redaction must be enforced server-side as well as at display. Operators must be able to restore system-only scope without making source health falsely appear healthy for detections that require broader evidence.

## Host-policy mutation boundary

**No installer or collector may mutate audit, firewall, authentication, kernel, service, or security policy by default.** This includes audit rules/backlog settings, nftables/iptables/firewalld configuration, PAM/SSH settings, sysctl/kernel parameters, kernel modules or eBPF settings, SELinux/AppArmor policy, log-retention settings, service configuration, file audit watches, and security-control enablement.

Default install may create only package files, private state/runtime directories, and its own service definition after showing the install plan. The reviewed service identity must already have the exact non-root `challenger-siem` passwd entry (UID not 0) and primary group, an allowlisted nologin/false shell, and a shadow password locked with `!` or `*`; real-host mutation verifies the full boundary as root before creating paths. Installer/upgrader does not create/correct the identity, join journal groups, or change ACLs. It must not enable unrelated facilities or weaken a control to gain access. Enabling the broader journal scope is an approved configuration and agent-restart action, not approval to expand permissions or producer logging. Passive/L4 plan hashes bind the effective scope, and preflight reports missing sources and the exact resulting coverage gap.

Any optional change requires all of the following:

1. **Plan output before mutation:** stable plan ID/config hash; detected platform; exact files, commands, units, groups, capabilities, rules, or settings affected; current and proposed state; security/privacy/resource impact; restart/reload impact; expected telemetry; validation; and exact rollback.
2. **Explicit operator approval:** interactive or policy-authorized approval bound to that exact plan. Installation, enrollment, or requesting a coverage level is not approval. Changed host state invalidates approval and requires a new plan.
3. **Narrow application:** apply only approved operations, validate preconditions again, use atomic writes where possible, preserve no secret-bearing backups in tracked or world-readable locations, and stop on partial failure.
4. **Post-change verification:** verify effective policy, source availability, host/service health, agent SLOs, and that no unrelated state changed. Emit only secret-safe change metadata.
5. **Rollback:** provide and test bounded rollback before rollout. Rollback restores the recorded prior state rather than a generic default and verifies the result.

Changes to authentication, firewall, kernel, or mandatory access-control policy warrant separate high-risk approval and can never be bundled into routine agent upgrade. A future central control plane may propose plans but must not bypass host/operator policy. An L4 plan/baseline approval authorizes observation only and is never approval to make posture match the baseline. Optional audit, eBPF, and broader file-integrity ideas remain bound by the [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) and require a later reviewed implementation before any collection or host change exists.

## Input, transport, and storage controls

- Production traffic uses HTTPS with modern TLS and verified server identity. Enrollment credentials are temporary/revocable; per-agent credentials are unique, protected at rest, rotated deliberately, and never logged.
- Server responses, remote configuration, and acknowledgements are untrusted input until authenticated and validated. Normal queue deletion covers only accepted/duplicate IDs. An explicit rejected L4 sequence may move to poison only after its immediately preceding sequence outcome is durable; the agent records dropped/gap/error state and never skips an unseen outcome to unblock the queue.
- Journal fields, syslog lines, filenames, application logs, and kernel/audit records are untrusted. Parsers must be memory/time bounded and robust to malformed encoding, control characters, oversized values, and record floods.
- File readers must defend against symlink/hard-link replacement, device/FIFO/socket paths, path escape, permission changes, truncation, and rotation races. Only declared regular files or approved source APIs are read.
- Local IPC must authenticate peers, use restrictive socket permissions, and frame/cap messages. Network listeners are not enabled by default.
- Queue/state storage must be bounded and corruption-aware. Resource pressure follows the priority and explicit-gap behavior in the coverage specification; it must never trigger broader permissions or silent data capture.
- Logs and health events contain error classes/codes and bounded metadata, not raw secret-bearing records, headers, credentials, connection details, process command output, or environment values. Observability values use null/unknown for unsupported metrics and explicit zero only when measured.

## Security verification gates

Before any further Linux event or advanced collector release, review must include (L1/L2 provide synthetic checks for applicable parsing, structured precedence, cursor, replay, pressure, coverage-state, and privacy items but do not claim host-soak completion):

- package signature/provenance and install/upgrade/uninstall permission tests;
- service sandbox and effective privilege/capability inspection;
- filesystem ownership/mode, symlink/race, local IPC, and credential-storage tests;
- malformed/oversized/flooded input and parser fuzz testing;
- redaction and prohibited-content tests using wholly synthetic canaries;
- TLS identity, enrollment, token isolation/rotation, replay, and acknowledgement tests;
- queue corruption, disk exhaustion, source rotation/truncation, reboot, and rollback tests;
- the private 24-hour L1, seven-day L1+L2, and separately approved L3/L4 VM canaries plus all resource SLO measurements specified in the coverage document;
- confirmation that install and collection did not mutate audit, firewall, authentication, kernel, service, or security policy outside an explicitly approved plan.

Immediate rollback is mandatory for suspected secret/prohibited-content collection, unauthorized mutation, privilege expansion, package verification failure, host instability, queue corruption/silent loss, uncontrolled resource use, or an SLO breach not corrected by bounded throttling. Disable the offending collector or remove the agent according to the reviewed plan, verify host policy and permissions, revoke credentials when compromise is possible, and retain only sanitized diagnostics in approved ignored/runtime locations. The [Linux local-host validation runbook](linux-local-host-validation.md) provides the private evidence layout, aggregate result template, recovery drill gates, and blocked-status wording for live soaks.

## Public repository and evidence safety

Only minimal, hand-authored synthetic fixtures with fake hosts, users, IDs, documentation-only addresses, commands, and messages belong in this public repository. Fixture filenames below a `fixtures/` directory use the `synthetic-` prefix (except `README.md`); recommended canaries include `SYNTHETIC-LINUX-01` and `synthetic-user`. Never derive fixtures by sanitizing real records, and never commit or attach real journal/syslog/audit output, inventory, benchmark output, generated settings, queues/state, credentials, logs, captures, traces, screenshots, dumps, or host-policy snapshots—even with a synthetic filename.

Packaged agents use restrictive OS-owned locations outside a source checkout: configuration/credentials under `/etc/challenger-siem-agent`, durable queue/state under `/var/lib/challenger-siem-agent`, the executable under `/opt/challenger-siem-agent`, and the service definition under `/etc/systemd/system`. Transient files and bounded diagnostics, if added, must remain under appropriate `/run`, `/var/log`, or system-journal boundaries and require review. Developer and lab evidence belongs only under ignored `.local/`; safety tooling must not traverse or mutate that evidence. Run `./scripts/validate-repository-safety.sh` to check indexed filenames before publication.

This is at least as strict as the [Windows specification's security and raw-payload rules](windows-host-full-coverage-spec.md#16-security-and-privacy-requirements) and the [documentation public-data rules](index.md#public-data-rules-for-docs-and-screenshots). Further implementation must preserve the existing additive generic `/api/v1/agents/inventory` and v1 schema compatibility and update this design when its threat or privilege boundary changes.
