# Linux agent

The .NET 8 Linux agent is a first-class endpoint service built on the same `Agent.Core` durable SQLite queue, acknowledgement, retry metadata, deterministic serialization, configuration hashing, and v1 transport used by the Windows agent. It enrolls through `/api/v1/agents/register`, stores the resulting credential in its mode-0600 configuration, sends heartbeats, passively collects bounded L1 system-journal records, uploads bounded host and security-posture inventory, and drains already-durable queued events gradually.

The implemented journal source covers kernel, boot, systemd service, authentication, and core-system records available to the dedicated service identity. Linux audit and non-journal file sources remain planned. Inventory snapshots remain current-state observations and do not substitute for journal source health.

## Supported capability

- Linux on x86-64 or ARM64 with systemd and a .NET 8 published application payload.
- Dedicated locked `challenger-siem` service identity created by the operator or package manager before installation.
- HTTPS server URL only. Configuration: `/etc/challenger-siem-agent/agentsettings.json` (dedicated identity, 0600, writable only within its private configuration directory so enrollment can persist the credential). Queue/state: `/var/lib/challenger-siem-agent` (0700). Binary: `/opt/challenger-siem-agent`. Unit: `/etc/systemd/system/challenger-siem-agent.service`.
- Enrollment, heartbeat, passive L1 journal collection, durable queue delivery, and read-only inventory upload through the existing v1 agent APIs.
- Fixed direct `/usr/bin/journalctl` or `/bin/journalctl` execution with machine-readable JSON, an allowlisted field projection, no shell, and no configurable executable, arguments, source path, or fallback reader.
- No Linux capability, audit/firewall/authentication/kernel/MAC-policy mutation, source-group enrollment, privileged helper, or arbitrary command/path collection interface.

The unit passes only the configuration path, never a credential. It denies privilege escalation, capabilities, home/device/kernel/control-group access, write access outside private state, and limits memory/tasks and restart bursts.

## Passive L1 system-journal collection

The single stable source `linux-journal-l1` reads the system journal in bounded polls. After startup it resumes with the last durably collected opaque journald cursor. Each accepted record is normalized and committed to the Agent.Core SQLite queue before the atomically written state file advances `collected_checkpoint`. A server accepted/duplicate acknowledgement is persisted as `acknowledged_checkpoint` before the corresponding queue row is deleted. A crash at any boundary can replay a deterministic ID, but cannot make a cursor claim data that was never durable.

The reader requests JSON from a fixed `journalctl` path and projects only cursor, real-time timestamp, boot ID, transport, unit, identifier, facility, priority, message ID, PID, UID, and message. It classifies records into `kernel`, `boot`, `service`, `authentication`, or `system`; it does not execute a shell or accept remote/configured commands or paths. Event IDs use the existing server-validated `sha256_uuid` recipe over `agent_id`, `source_id`, and `checkpoint.cursor`.

Input records default to a 128 KiB pre-parse ceiling. Retained fields are capped at 2,048 characters, cursor at 1,024, message at 20,000, and compact raw JSON at the v1 65,536-byte ceiling. Control text is replaced, non-text/binary fields become `<binary-or-nontext>`, and common secret-shaped assignments are replaced before enqueue. `data_handling` lists every truncated/redacted field and reports original/retained size without reproducing removed values.

The heartbeat manifest declares source kind, namespace, checkpoint kind, parser/config/version, prerequisites, event families, and validation scenarios. Health separately reports latest event and lag, collected and acknowledged cursors, collector/config/version state, permission and throttle state, stable errors, gap state, and bounded duplicate/reordered/malformed counters. Empty, unavailable, denied, invalid-cursor, rotation, vacuum, malformed/binary, reorder, and pressure states are never inferred as healthy. On invalid cursor the next bounded poll re-establishes a cursor from available records while retaining a gap marker. Rotation with continuity remains healthy; an observed rotation/vacuum discontinuity remains a gap.

Queue depth at `QueuePauseDepth` pauses source reads without deleting queued events. Poll and batch limits bound collection rate; heartbeat and drain services remain independent. Operators should fix access or capacity rather than grant root or weaken journal policy. Membership in `systemd-journal`/`adm`, if chosen by an operator, expands readable data and is not added by the installer.

## Bounded inventory snapshots

Each collection produces these snapshot categories:

- `linux_host_identity` for allowlisted operating-system and kernel identity fields;
- `linux_users` and `linux_groups` for names and numeric IDs only;
- `linux_services`, `linux_units`, and `linux_timers` for bounded systemd state, or `not_applicable` on a detected non-systemd host;
- `linux_packages` and `linux_available_updates` for package names and versions without repository configuration or content;
- `linux_interfaces` and `linux_listeners` for interface state and listening protocol/port only;
- `linux_mounts` for filesystem-type counts without mount paths;
- `linux_firewall` for high-level nftables, firewalld, or UFW state without rules;
- `linux_ssh` for allowlisted values observed directly in the primary configuration for `PermitRootLogin`, `PasswordAuthentication`, and `PubkeyAuthentication` before the first `Match` block, without SSH configuration text;
- `linux_mandatory_access_control` for AppArmor and SELinux state;
- `linux_secure_boot` when the fixed provider is available; and
- `linux_agent_integrity` for observable regular-file, owner-ID, and mode posture of the fixed agent configuration and executable paths.

Every snapshot reports exactly one collection state in `summary.state`: `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`. It also reports a stable error code, item count, and explicit truncation marker. Missing tools, files, permissions, applicability, malformed output, and deadlines are therefore not represented as healthy or silently absent.

The agent emits at most 20 snapshots and 200 items per snapshot. The default serialized batch budget is 256 KiB, configurable only from 64 KiB through 512 KiB; deterministic trimming marks both snapshot and payload-budget truncation. Source command output is capped at 16 or 64 KiB according to the fixed catalog, command timeouts are 5, 10, or 20 seconds, file operations time out after 5 seconds, and the default whole-collection deadline is 120 seconds (allowed range 10-300 seconds).

## Schedule and configuration

Inventory runs in its own non-overlapping hosted service, independently of heartbeat, durable queue drain, and future passive collection. Commands are requested at below-normal process priority where the operating system permits. A slow or failed inventory cycle does not block the heartbeat/queue worker.

`Agent.InventoryIntervalSeconds` defaults to one hour (`3600`) and has an enforced minimum of five minutes (`300`). `Agent.Inventory.StartupDelaySeconds` defaults to 30 seconds and may be set from 0 through 300 seconds, allowing enrollment and the primary transport worker to start first. Relevant defaults are:

```json
{
  "Agent": {
    "InventoryIntervalSeconds": 3600,
    "Inventory": {
      "StartupDelaySeconds": 30,
      "CollectionTimeoutSeconds": 120,
      "MaxSerializedBytes": 262144
    },
    "Journal": {
      "Enabled": true,
      "PollIntervalSeconds": 5,
      "MaxRecordsPerPoll": 500,
      "MaxInputRecordBytes": 131072,
      "QueuePauseDepth": 100000
    }
  }
}
```

Inventory is a periodic current-state upload rather than durable passive telemetry. If an upload fails, the next scheduled collection provides a fresh bounded snapshot; heartbeat, journal collection, and queued-event recovery continue on separate paths. Journal bounds are enforced as follows: poll interval 1-300 seconds, batch 1-5,000 records, input record 4-256 KiB, and pressure pause depth 100-1,000,000 events.

## Read-only source policy

The collector catalog fixes every executable path candidate, argument list, exact file path, accepted exit code, timeout, and output cap. Commands are launched directly without a shell, with a cleared environment and only fixed locale/PATH values. Timed-out, cancelled, or output-capped commands are terminated as a process tree. File reads accept only catalogued regular, single-link files, reject symbolic links and special files, use no-follow access, and cap bytes before parsing. Caller cancellation and the whole-collection deadline flow through every operation.

Parsers serialize only bounded allowlisted fields. They exclude raw stdout/stderr, arbitrary file contents and paths, account descriptions/home directories/shells, group membership, IP addresses, process details, command lines, firewall rules, repository configuration/content, and unapproved SSH directives. Errors and logs contain stable types/codes rather than source output.

Collection is strictly observational: it does not install tools, refresh package metadata, alter services, audit policy, firewall rules, SSH settings, kernel state, AppArmor/SELinux policy, Secure Boot, file ownership, or file modes. The `linux_agent_integrity` category reports observable ownership/mode for both fixed agent files plus a bounded SHA-256 fingerprint of the non-secret executable. This fingerprint supports change review but are not trusted attestation and are not tamper-proof against a privileged or kernel-level adversary; heartbeat gaps, fingerprint changes, and permission drift remain review signals rather than proof of integrity.

## Safe lifecycle

First publish the app into a private local directory and create a mode-0600 configuration from the synthetic example. Never put real settings in the repository.

```bash
./scripts/linux-agent.sh plan
./scripts/linux-agent.sh install --payload <private-publish-dir> --config <private-mode-0600-config>
./scripts/linux-agent.sh upgrade --payload <private-publish-dir> --config <private-mode-0600-config>
./scripts/linux-agent.sh validate
./scripts/linux-agent.sh uninstall
```

`plan` is read-only. Every mutating mode completes platform/init/architecture/privilege/payload/config/identity preflights before creating a path. Install and uninstall touch only the four declared project paths. Uninstall intentionally retains the service identity because account removal can affect operator-managed ownership. No secret is printed. Sandbox `--root` and `--no-service-control` options exist for CI lifecycle tests and must not be used as deployment shortcuts.

## Server and contract boundary

Journal records use the existing additive `linux_journal` v1 envelope and the existing `/api/v1/ingest/events` persistence, deduplication, and portable search path. Source manifests and health use the additive portable heartbeat shape. Linux snapshots continue to use the generic `POST /api/v1/agents/inventory` payload. No `/api/v2`, schema replacement, or incompatible Windows behavior is introduced. Server-side Linux coverage overlays beyond the reported source row remain future work.

## Validation and recovery

Run `dotnet test tests/LinuxAgent.Tests/LinuxAgent.Tests.csproj`, `dotnet test Challenger.Siem.sln`, `./scripts/validate-contracts.sh`, and `./scripts/validate-repository-safety.sh`. The tracked tests use only hand-authored synthetic records and cover cursor restart, queue-before-checkpoint, acknowledgement, outage/replay, deterministic deduplication, rotation/vacuum/invalid cursor, denied/empty/malformed/binary input, duplicate/reorder, pressure, and a bounded 5,000-record benchmark. That benchmark is a regression guard, not a host CPU/write measurement or a 24-hour soak claim.

On a separately approved disposable systemd host, operators may later inspect source health and service restrictions while keeping raw output under `.local/`. This release did not perform or claim the required private 24-hour canary soak. Stop rollout on credential exposure, unauthorized host mutation, queue corruption, silent loss, host impact, or resource-bound breach. Uninstall project-owned files, revoke the agent credential, and retain only sanitized aggregate findings.
