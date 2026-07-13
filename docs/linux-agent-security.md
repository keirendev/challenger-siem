# Linux agent security and privacy design

Status: planned design; no Linux agent or installer is implemented
Specification version: 0.1
Primary audience: security reviewers, Linux agent engineers, packagers, operators

## Purpose and governing principles

This document defines the threat model, least-privilege boundary, privacy controls, and change-approval model for the future Linux agent described in [linux-host-coverage-spec.md](linux-host-coverage-spec.md). It does not authorize deployment or host changes.

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
- prevent secret and prohibited-content collection before durable queueing;
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
| Installer/upgrader | Temporary administrative execution with reviewed plan | Verify package, create identity/directories/unit, set exact permissions; relinquish privileges after completion |

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

## Collection and privacy boundary

Permitted telemetry is the security metadata defined by the coverage specification: bounded event metadata, identity/process/network/file metadata needed for approved detections, security-control status, and agent/source health. Every collector needs a field inventory, purpose, sensitivity classification, retention expectation, and redaction tests.

Full coverage explicitly excludes collection or retention of:

- credentials, passwords, tokens, cookies, connection strings, and authorization headers;
- secret stores, credential caches, keyrings/wallets, private keys, and private certificate material;
- browser profiles and browser/session stores;
- environment-value dumps;
- keystrokes, terminal input, clipboard contents, and screen capture;
- packet payloads or full packet capture;
- unrestricted file-content collection.

The exclusion applies to normalized fields, raw source records, diagnostics, errors, benchmarks, and support bundles. Raw data is never an exception. Collectors must use allowlisted fields where practical, redact before queue insertion, cap record/field/batch sizes, mark truncation, and discard prohibited fields. No diagnostic mode may silently disable these protections.

Command lines, source messages, paths, usernames, hostnames, addresses, and role/application logs can contain sensitive values. Future access control and redaction must be enforced server-side as well as at display. Operators must be able to disable sensitive optional fields without making source health falsely appear healthy for detections that require them.

## Host-policy mutation boundary

**No installer or collector may mutate audit, firewall, authentication, kernel, service, or security policy by default.** This includes audit rules/backlog settings, nftables/iptables/firewalld configuration, PAM/SSH settings, sysctl/kernel parameters, kernel modules or eBPF settings, SELinux/AppArmor policy, log-retention settings, service configuration, file audit watches, and security-control enablement.

Default install may create only the approved agent identity, package files, private state/runtime directories, and its own service definition after showing the install plan. It must not enable unrelated facilities or weaken a control to gain access. Passive preflight reports missing sources and the exact resulting coverage gap.

Any optional change requires all of the following:

1. **Plan output before mutation:** stable plan ID/config hash; detected platform; exact files, commands, units, groups, capabilities, rules, or settings affected; current and proposed state; security/privacy/resource impact; restart/reload impact; expected telemetry; validation; and exact rollback.
2. **Explicit operator approval:** interactive or policy-authorized approval bound to that exact plan. Installation, enrollment, or requesting a coverage level is not approval. Changed host state invalidates approval and requires a new plan.
3. **Narrow application:** apply only approved operations, validate preconditions again, use atomic writes where possible, preserve no secret-bearing backups in tracked or world-readable locations, and stop on partial failure.
4. **Post-change verification:** verify effective policy, source availability, host/service health, agent SLOs, and that no unrelated state changed. Emit only secret-safe change metadata.
5. **Rollback:** provide and test bounded rollback before rollout. Rollback restores the recorded prior state rather than a generic default and verifies the result.

Changes to authentication, firewall, kernel, or mandatory access-control policy warrant separate high-risk approval and can never be bundled into routine agent upgrade. A future central control plane may propose plans but must not bypass host/operator policy.

## Input, transport, and storage controls

- Production traffic uses HTTPS with modern TLS and verified server identity. Enrollment credentials are temporary/revocable; per-agent credentials are unique, protected at rest, rotated deliberately, and never logged.
- Server responses, remote configuration, and acknowledgements are untrusted input until authenticated and validated. An agent deletes queue entries only for accepted/duplicate IDs in a valid response.
- Journal fields, syslog lines, filenames, application logs, and kernel/audit records are untrusted. Parsers must be memory/time bounded and robust to malformed encoding, control characters, oversized values, and record floods.
- File readers must defend against symlink/hard-link replacement, device/FIFO/socket paths, path escape, permission changes, truncation, and rotation races. Only declared regular files or approved source APIs are read.
- Local IPC must authenticate peers, use restrictive socket permissions, and frame/cap messages. Network listeners are not enabled by default.
- Queue/state storage must be bounded and corruption-aware. Resource pressure follows the priority and explicit-gap behavior in the coverage specification; it must never trigger broader permissions or silent data capture.
- Logs and health events contain error classes/codes and bounded metadata, not raw secret-bearing records, headers, credentials, or environment values.

## Security verification gates

Before any Linux collector release, review must include:

- package signature/provenance and install/upgrade/uninstall permission tests;
- service sandbox and effective privilege/capability inspection;
- filesystem ownership/mode, symlink/race, local IPC, and credential-storage tests;
- malformed/oversized/flooded input and parser fuzz testing;
- redaction and prohibited-content tests using wholly synthetic canaries;
- TLS identity, enrollment, token isolation/rotation, replay, and acknowledgement tests;
- queue corruption, disk exhaustion, source rotation/truncation, reboot, and rollback tests;
- 24-hour L1 and seven-day L1+L2 soaks and all resource SLO measurements specified in the coverage document;
- confirmation that install and collection did not mutate audit, firewall, authentication, kernel, service, or security policy outside an explicitly approved plan.

Immediate rollback is mandatory for suspected secret/prohibited-content collection, unauthorized mutation, privilege expansion, package verification failure, host instability, queue corruption/silent loss, uncontrolled resource use, or an SLO breach not corrected by bounded throttling. Disable the offending collector or remove the agent according to the reviewed plan, verify host policy and permissions, revoke credentials when compromise is possible, and retain only sanitized diagnostics in approved ignored/runtime locations.

## Public repository and evidence safety

Only minimal, hand-authored synthetic fixtures with fake hosts, users, IDs, documentation-only addresses, commands, and messages belong in this public repository. Fixture filenames below a `fixtures/` directory use the `synthetic-` prefix (except `README.md`); recommended canaries include `SYNTHETIC-LINUX-01` and `synthetic-user`. Never derive fixtures by sanitizing real records, and never commit or attach real journal/syslog/audit output, inventory, benchmark output, generated settings, queues/state, credentials, logs, captures, traces, screenshots, dumps, or host-policy snapshots—even with a synthetic filename.

Future packaged agents must use restrictive OS-owned locations outside a source checkout: configuration/credentials under an appropriate `/etc` path, durable queue/state under `/var/lib`, transient files under `/run`, and bounded diagnostics under `/var/log` or the system journal. Exact product paths and permissions are an implementation decision requiring review. Developer and lab evidence belongs only under ignored `.local/`; safety tooling must not traverse or mutate that evidence. Run `./scripts/validate-repository-safety.sh` to check indexed filenames before publication.

This is at least as strict as the [Windows specification's security and raw-payload rules](windows-host-full-coverage-spec.md#16-security-and-privacy-requirements) and the [documentation public-data rules](index.md#public-data-rules-for-docs-and-screenshots). Future implementation must preserve versioned API/schema compatibility and update this design when its threat or privilege boundary changes.
