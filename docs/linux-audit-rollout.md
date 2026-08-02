# Linux audit visibility rollout

This runbook adds observation only. It does not block, kill, quarantine, change
firewall policy, make audit rules immutable, or run the Challenger SIEM agent as
root. The shipping configuration remains disabled. Apply the stages only to an
authorized host after a disposable-VM pass with matching kernel, audit, systemd, and
architecture characteristics.

## Trust boundaries

| Component | Identity and privilege | Reads | Emits or writes |
| --- | --- | --- | --- |
| Main agent | `challenger-siem`; no capabilities; existing hardened sandbox | its already readable journal scope and fixed procfs inputs | private queue/state and authenticated SIEM telemetry |
| auditd/kernel producer | host root/kernel boundary | kernel audit records and reviewed policy | host audit log/journal according to host retention policy |
| Audit health sampler | root one-shot; bounding set contains only `CAP_AUDIT_CONTROL`; hardened service | fixed `auditctl -s` status only | one schema-fixed numeric journal message per minute through a short-lived `systemd-cat` sender retained for one second so journald can attach trusted unit/executable metadata |

The health sampler does not read audit records or logs. The main agent never invokes
audit control tools. Audit rules and auditd lifecycle remain explicit host-policy
operations, independent of agent install/upgrade.

The native `systemd-journald-audit.socket` must already be active or be enabled for a
planned boot before parsing is enabled. Auditd alone can consume and persist records
without making them visible to the journal reader. Do not claim healthy transport
until a synthetic canary proves `_TRANSPORT=audit` visibility as the service identity.
Starting the socket after journald is active can be refused; do not force a journald
restart on a live host merely to complete this rollout. Enabling the socket also
persists raw kernel audit records in the system journal, where existing journal-reader
group members can access them. The agent drops arguments and other excluded content
before its own state/queue, but it cannot retroactively sanitize journald or auditd
storage; review local access and retention before activation.

## Privacy and coverage boundary

The router accepts either the legacy embedded audit identity or systemd's trusted
`_AUDIT_ID`/`_AUDIT_TYPE_NAME` fields. It retains bounded numeric identities, executable, parent/process ID,
result, syscall, rule key, up to eight watched paths, and selected authentication,
MAC, integrity, and policy fields. It discards raw audit messages, `EXECVE` argument
records, `PROCTITLE`, TTY input, environment values, and unknown fields before durable
queueing. Paths, executable names, account names, and the broader journal stream are
still high-sensitivity metadata; access and retention must remain restricted.

The foundation policy observes writes/attribute changes to selected identity,
privilege, persistence, SSH, package-policy, kernel-policy, audit-policy, and
Challenger files plus module/kexec control syscalls. The optional execution policy
observes exec metadata only for attributable root and UID 1000+ login sessions. It
does not retain command arguments and does not cover every daemon/kernel-thread exec.
No connect/bind/open/read/write blanket syscall rules are supplied because their
volume and privacy cost are not justified for this host canary. Procfs socket-owner
attribution can therefore remain partial across UID boundaries.

## Baseline and stop gates

Before every material stage, record only aggregate values in a private ignored
location: service state/PID/security properties, queue/WAL sizes and depth, delivery
health, audit status/rules, disk free space, `/proc/pressure/{cpu,memory,io}`, blocked
task count, `/proc/<agent>/io`, cgroup CPU/memory/tasks, and a short `vmstat` sample.
Do not copy live journals, audit logs, credentials, command lines, or queue contents
into repository evidence.

Stop and roll back the latest stage when any of these occur:

- audit `lost` increases, backlog remains at or above 80%, or auditd/rule loading fails;
- agent/API delivery continuity fails, queue grows unexpectedly, or a source gap is
  hidden instead of reported;
- blocked tasks or IO PSI become sustained, free storage approaches the host limit,
  agent writes exceed the reviewed baseline materially, or CPU/memory limits regress;
- the main agent gains UID 0, any capability, extra journal/file permission, or a
  weaker sandbox;
- prohibited content or uncontrolled event volume is suspected.

Rollback never deletes `queue.sqlite`, its WAL/SHM files, journal checkpoints,
audit-router state, audit logs, or SIEM telemetry.

## Stages

1. **Disposable VM.** Install the candidate agent disabled, validate its service
   identity/capabilities, install the health script/unit/timer, start auditd, and load
   only `70-challenger-siem-foundation.rules`. Confirm `_TRANSPORT=audit` and trusted
   health records reach the same configured reader, synthetic file changes normalize
   without arguments, restart/replay produces no duplicate, and `auditctl --signal
   stop` plus removal of the managed rules is a viable rollback. Then repeat with the
   optional execution rules under a bounded synthetic workload.
2. **Host foundation canary.** Re-baseline. Preserve the prior auditd/rules/config and
   agent config/binary in a private root-only rollback location. Install auditd only
   if already present as a package or through the approved package manager. Install
   only paths that exist from `70-challenger-siem-foundation.rules`; never add `-D` or
   `-e 2`. Load/verify rules, enable the health timer, then enable agent v2 with its
   exact new plan hash and one controlled agent-only restart.
3. **Observe foundation.** Use one-, five-, and fifteen-minute windows. Require audit
   lost=0, bounded backlog, fresh healthy SIEM audit source, continuous delivery,
   stable queue/WAL, no sustained PSI/blocked tasks, and acceptable CPU/memory/write
   deltas. Generate one harmless temporary test file only in a separately approved
   disposable watched path; otherwise use naturally occurring evidence.
4. **Execution canary.** Only after the foundation gate passes, add
   `71-challenger-siem-session-exec.rules`. Observe the same gates at one, five,
   fifteen, and sixty minutes. Session-attributed exec volume must remain below queue
   and storage budgets, including while delivery is unavailable and private audit
   assembly state grows. Remove these exact four rules first if volume or privacy is
   unacceptable; foundation coverage can remain. A failed execution canary is a hard
   defer gate, not permission to raise storage limits or weaken synchronous durability.
5. **Sustain and expand deliberately.** Review daily event rates, audit loss/backlog,
   queue growth, write amplification, false positives, retention, and source-health
   gaps before any longer soak. New file paths or syscalls require a new reviewed
   policy and canary; never infer literal complete visibility.

## Rollback

1. Disable audit parsing in the protected agent configuration (or restore its prior
   exact config and plan hash) and restart only the agent if required. This suppresses
   new audit content before it can fall through generic L1.
2. Remove the optional execution rules with their exact `auditctl -d` equivalents and
   verify `auditctl -l`. Do not use `-D` on a live host. If necessary, remove each
   managed foundation watch with its exact `-W` form and each syscall rule with its
   exact `-d` form, then restore the recorded prior backlog/failure values. Remove the
   persistent managed files only after the effective rules are verified.
3. Disable the health timer. Use the audit package's supported `auditctl --signal
   stop` path only when the reviewed rollback calls for returning auditd to its prior
   inactive state; verify kernel status and unit state. Do not force-kill it.
4. Restore only recorded prior unit/package enablement state. Preserve audit logs and
   all agent runtime data. Confirm the main agent remains healthy and its journal
   scope/coverage report reflects the resulting audit gap rather than claiming health.

Audit rules without immutable mode can be reloaded without reboot. Distribution
packaging may refuse a generic `systemctl stop auditd`; the VM gate must validate the
supported signal-based stop and enablement rollback before host activation.

## Remaining blind spots

Polling can miss short-lived processes and sockets. Cross-UID `/proc/<pid>/exe` and
file-descriptor access remains constrained for the unprivileged agent, so socket-to-
process attribution can be partial. The staged audit rules improve attributable exec
and parent/executable evidence but do not capture command arguments, kernel threads,
every daemon exec, packets, encrypted payloads, in-memory-only activity, firmware,
or activity occurring while the audit/journal/agent path is gapped. Root or kernel
compromise can tamper with every local observer. Health and gap reporting make these
limits explicit; they do not turn them into complete coverage.
