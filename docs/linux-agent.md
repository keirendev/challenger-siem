# Linux agent

The .NET 8 Linux agent is a first-class endpoint service built on the same `Agent.Core` durable SQLite queue, acknowledgement, retry metadata, deterministic serialization, configuration hashing, and `/api/v1` transport as the Windows agent. It enrolls, heartbeats, passively reads the systemd journal through one cursor, uploads bounded host/security-posture inventory, and drains only already-durable queued events.

The default journal target remains **L1**. Operators may set the bounded target to **L2** for an approved canary; default L2 rollout remains blocked on the private seven-day L1+L2 soak. This implementation does not perform or claim that soak.

## Supported capability and safety boundary

- Linux x86-64 or ARM64 with systemd and a .NET 8 published payload.
- Dedicated locked `challenger-siem` identity; no root steady state, capability grant, privileged helper, or installer-added group membership.
- HTTPS server URL only. Configuration: `/etc/challenger-siem-agent/agentsettings.json` (0600). Queue/state: `/var/lib/challenger-siem-agent` (0700). Binary: `/opt/challenger-siem-agent`. Unit: `/etc/systemd/system/challenger-siem-agent.service`.
- Fixed direct `/usr/bin/journalctl` or `/bin/journalctl` machine-readable invocation, with no shell, configurable executable/arguments/path, alternate file reader, or fallback collector.
- No audit collector or audit-policy change, eBPF, file-integrity monitoring, firewall/authentication/kernel/MAC-policy mutation, source-group enrollment, or general command/path interface. The [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) is a design decision only and does not enable those collectors.

## One durable journal path

`linux-journal-l1` remains the physical L1 source and owns the one opaque journald cursor. L2 does not create another reader or checkpoint path. When L2 is selected, the same normalized record is assigned to a stable logical security source after structured classification. Every event is committed to the Agent.Core queue before `collected_checkpoint` advances; accepted/duplicate acknowledgement is persisted before deletion and before `acknowledged_checkpoint` advances.

Rotation, vacuum, invalid cursors, permission loss, malformed input, reordering, duplicates, empty startup, and queue pressure remain explicit. All applicable journald logical sources report the shared physical cursor plus their own last-observed event-family time/evidence. A crash can replay a deterministic ID but cannot claim a cursor that was not durably queued.

## L1 and L2 source catalog

| Stable source ID | Level | Requirement | Event families | Default/applicability |
| --- | --- | --- | --- | --- |
| `linux-journal-l1` | L1 | mandatory | boot, system, application/service baseline | enabled by default |
| `linux-login-session` | L2 | mandatory | login, session | applicable when L2 is selected |
| `linux-ssh` | L2 | role-specific | SSH authentication/session | applicable for declared `ssh_server`/`bastion`, not applicable for other declared roles, unknown when no role is declared |
| `linux-sudo-su` | L2 | mandatory | `sudo`, `su` | applicable when L2 is selected |
| `linux-cron-timers` | L2 | mandatory | cron, systemd timers | applicable when L2 is selected |
| `linux-package-management` | L2 | mandatory | install, update, remove | applicable when L2 is selected |
| `linux-firewall` | L2 | optional | allow/deny/policy change | unknown until already-enabled firewall journal evidence is observed |
| `linux-kernel-security` | L2 | mandatory | kernel security, security modules, kernel modules | applicable when L2 is selected |
| `linux-service-change` | L2 | mandatory | service start/stop/reload/failure | applicable when L2 is selected |
| `linux-agent-log-tamper` | L2 | mandatory | agent/log tamper | applicable when L2 is selected |
| `linux-audit-framework` | L2 | optional | audit | explicitly `unsupported`; no audit collector or enablement is included |

Every manifest includes platform/source kind/namespace, coverage level, checkpoint kind, `mandatory`/`optional`/`role_specific` requirement, applicable roles, prerequisites, event families, validation scenarios, parser/source-pack identity, privacy level, and applicability/reason. Corresponding health includes bounded prerequisite and event-family state maps.

## Structured normalization

The reader projects only fixed journal fields. In addition to cursor/time/boot/transport/unit/identifier/facility/priority/message identity, the L2 projection allowlists process (`_PID`, `_UID`, `_COMM`, `_EXE`, `_CMDLINE`), PAM/user, remote address/port/protocol, result/action, unit, package, and module metadata.

Structured values always win. A bounded vendor/message parser examines at most the first 4,096 characters and uses fixed 50 ms regex timeouts or bounded token parsing only when structured evidence is missing. It recognizes narrow SSH/PAM, sudo/su, cron, package-manager, UFW/nftables, kernel/MAC/module, systemd service, journald, and agent patterns. Ambiguous text remains on the L1 source with no invented action, outcome, user, address, package, or process enrichment.

Classified events consistently use:

- category/action/outcome and severity (`audit_success`/`audit_failure` only when authentication/authorization outcome evidence exists);
- bounded flattened and portable `user`, `process`, and `network` concepts;
- service/unit, scheduler task, package, and kernel-module fields when present;
- `linux.event_family`, evidence mode, boot ID, transport, and source-pack labels; and
- deterministic `sha256_uuid` IDs over `agent_id`, logical `source_id`, and cursor.

Invalid IPs/ports, absent identities, and ambiguous messages do not create normalized fields. Command lines and all retained strings pass through control-text replacement, bounds, and secret-shaped assignment redaction before queueing.

## Input, privacy, and pressure bounds

Input records default to a 128 KiB pre-parse ceiling. Cursor is capped at 1,024 characters, message at 20,000, command line at 4,096, other retained fields at 2,048, and compact raw JSON at the portable-v1 65,536-byte ceiling. Non-text values become `<binary-or-nontext>`. `data_handling` lists every redacted/truncated field and original/retained sizes without reproducing removed values.

Polling defaults to 500 records every five seconds. Bounds are 1-300 seconds, 1-5,000 records, 4-256 KiB input records, and a pressure pause depth of 100-1,000,000 queued events. At the pause depth, journal reads stop without deleting unacknowledged events; heartbeat and transport remain independent.

## Health and coverage semantics

Portable health status supports `healthy`, `missing`, `disabled`, `stale`, `degraded`, `permission_denied`, `unsupported`, `error`, `not_applicable`, and `excepted`. The server applies exceptions; portable heartbeat validation rejects agent-reported `excepted`, while source-health responses may expose it only from an active server-side coverage exception.

- `permission_denied` means the fixed source could not be read; the agent does not retry as root or change groups/ACLs.
- `degraded` represents pressure, unresolved optional/role applicability, or a mandatory L2 family whose producer evidence has not yet been observed; it is distinct from stale data.
- `unsupported` is explicit collector/platform capability absence, currently used for Linux Audit Framework.
- `not_applicable` requires a declared role/platform reason.
- `stale` covers age/discontinuity conditions; cursor gaps remain errors where appropriate.
- prerequisite states and event-family states distinguish satisfied/observed, not observed, missing, disabled, stale, degraded, denied, unsupported, not applicable, excepted, and unknown.

Mandatory applicable sources determine the current level. Optional sources do not lower the level; an applicable role-specific source becomes mandatory for that role. `excepted` and `not_applicable` are covered only when explicitly represented, while `unsupported`, denied, stale, degraded, disabled, and missing mandatory sources do not satisfy a level.

## Configuration

Relevant defaults:

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
      "TargetCoverageLevel": "L1",
      "DeclaredRoles": [],
      "PollIntervalSeconds": 5,
      "MaxRecordsPerPoll": 500,
      "MaxInputRecordBytes": 131072,
      "QueuePauseDepth": 100000
    }
  }
}
```

`TargetCoverageLevel` accepts only `L1` or `L2`. `DeclaredRoles` accepts at most 16 bounded lowercase/number/underscore/hyphen role identifiers. An empty role list preserves `unknown` role-specific applicability rather than guessing. Use `L2` only in an approved canary; it does not grant permission to change a producer or host policy.

## Bounded inventory snapshots

The independent inventory service emits up to 20 snapshots, 200 items per snapshot, and a default 256 KiB serialized batch. Categories cover host identity, users/groups, services/units/timers, packages/updates, interfaces/listeners, mounts, firewall, SSH, MAC state, Secure Boot, and observable agent file posture. Every snapshot reports `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`; the server maps these states without treating mere presence as healthy.

The fixed catalog uses exact executable candidates/arguments/files, no shell, a cleared environment, process-tree cancellation, time/output caps, and no-follow regular-file reads. It excludes raw output, arbitrary file content/path scans, account descriptions, group membership, addresses, command lines, firewall rules, repository contents, and unapproved SSH directives. Inventory remains current-state evidence, not a substitute for event-source health.

## Safe lifecycle

Publish privately and create a mode-0600 configuration from the synthetic example; never put a real token/settings file in the repository.

```bash
./scripts/linux-agent.sh plan
./scripts/linux-agent.sh install --payload <private-publish-dir> --config <private-mode-0600-config>
./scripts/linux-agent.sh upgrade --payload <private-publish-dir> --config <private-mode-0600-config>
./scripts/linux-agent.sh validate
./scripts/linux-agent.sh uninstall
```

`plan` is read-only. Mutating modes preflight platform/init/architecture/privilege/payload/config/identity before creating paths and touch only declared product paths. Uninstall retains the service identity. Sandbox `--root`/`--no-service-control` options are CI aids, not deployment shortcuts.

## API, validation, and rollout gate

Events continue through additive `source=linux_journal` portable-v1 envelopes and `/api/v1/ingest/events`; heartbeat uses additive manifest/health fields; inventory uses the existing generic endpoint. Server source-health and telemetry-coverage APIs overlay the Linux catalog, count recent portable events by `source_id`, and expose platform/requirement/applicability/evidence metadata. No `/api/v2` or incompatible Windows behavior is introduced.

Run:

```bash
dotnet test tests/LinuxAgent.Tests/LinuxAgent.Tests.csproj
dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

Tracked tests are hand-authored synthetic data only. They cover every catalog family with positive/negative evidence, structured-field precedence, ambiguity, malformed/binary/control/secret/oversized input, source catalog/health states, cursor/replay/pressure, normalized portable contract behavior, and 5,000-record L1/L2 throughput/allocation guards. Those unit benchmarks are regression checks, not host CPU/RSS/write measurements.

The private seven-day L1+L2 canary, distribution/systemd matrix, outage/rotation/restart windows, and resource/disruption SLOs remain an outstanding rollout gate. Do not claim default L2 readiness from unit tests. Optional L3 audit/eBPF/file-integrity ideas are separately gated by the [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md); only a future snapshot-based agent self-integrity design candidate is selected, and it is not implemented here. Stop rollout on secret/excluded-data collection, unauthorized mutation, host impact, queue corruption, silent loss, persistent gaps, or SLO breach; keep all live evidence under ignored `.local/` or approved OS runtime paths.
