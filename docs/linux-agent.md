# Linux agent

The .NET 8 Linux agent is a first-class endpoint service built on the same `Agent.Core` durable SQLite queue, acknowledgement, retry metadata, deterministic serialization, configuration hashing, and `/api/v1` transport as the Windows agent. It enrolls, heartbeats, passively reads the systemd journal through one cursor, uploads bounded host/security-posture inventory, and drains only already-durable queued events.

The default journal target remains **L1** and the default physical scope remains **system-only**. `Journal.IncludeAccessibleUserJournals=true` is a separate disabled-by-default expansion to all local journals already readable by the service identity. `Journal.TargetCoverageLevel` can select L1-L4 expectations, but higher values do not enable independent advanced collectors or grant approval. Default L2 rollout remains blocked on the private seven-day L1+L2 soak. L3 self-integrity/procfs and L4 policy-posture/rolling-SLO capabilities are implemented but disabled by default and require separate exact approvals. Six role-specific L4 families reuse the one journal reader for explicitly declared server roles. The implementation is available for controlled deployment, but no private L4 VM soak is claimed.

## Supported capability and safety boundary

- Linux x86-64 or ARM64 with systemd and the matching self-contained `linux-x64` or `linux-arm64` payload produced by the tracked publish helper.
- Target-side Python 3 for the bundled lifecycle `plan` helper, plus `getent`/`id` for identity validation and `runuser` for root-triggered installed L4 preflight. They are external prerequisites, not bundled or installed by the agent; Python is not required by the steady-state self-contained service.
- Pre-existing non-root `challenger-siem` passwd entry (UID must not be 0) with an existing matching `challenger-siem` primary group, shell exactly `/usr/sbin/nologin`, `/sbin/nologin`, or `/bin/false`, and a shadow password field locked with `!` or `*`. Real-host install verifies this as root before creating paths. There is no root steady state, capability grant, privileged helper, or installer-added group membership.
- HTTPS server URL only. Configuration: `/etc/challenger-siem-agent/agentsettings.json` (0600). Queue/state: `/var/lib/challenger-siem-agent` (0700). Binary: `/opt/challenger-siem-agent`. Unit: `/etc/systemd/system/challenger-siem-agent.service`.
- Fixed direct `/usr/bin/journalctl` or `/bin/journalctl` machine-readable invocation, with no shell, configurable executable, arbitrary arguments/path, alternate file reader, or fallback collector. The one Boolean scope choice maps only to fixed `system_only` or `all_accessible_local` argument sets.
- No audit collector or audit-policy change, eBPF, broad/live file-integrity monitoring, firewall/authentication/kernel/MAC-policy mutation, source-group enrollment, or general command/path interface. L3 implementations are limited to explicit-plan-hash snapshot sources. L4 adds an exact-plan/baseline posture comparison, bounded rolling agent SLOs, and structured role-journal classification only. These features create no watches or kernel programs, open no application log files, and change no host policy.

## One durable journal path

`linux-journal-l1` remains the physical L1 source and owns the one opaque journald cursor. By default the reader supplies `--system`. With `IncludeAccessibleUserJournals=true` it supplies neither `--system` nor `--user`, selecting all local journal files `journalctl` can already read as the service identity; a separate bounded system-only probe still gates mandatory system visibility. This does not guarantee access to every user's journal and introduces no remote journal, namespace, directory, privilege, group, or ACL selection. L2 and the six role-specific L4 packs do not create another reader or checkpoint path. The same normalized record is assigned to one stable primary logical source after structured classification. When an approved role record also matches an L2 family, the role source is primary and bounded `linux.secondary_source_id`/`linux.secondary_event_family` labels preserve L2 source-health and existing-rule evidence without queueing a duplicate event. Every event is committed to the Agent.Core queue before `collected_checkpoint` advances; accepted/duplicate acknowledgement is persisted before deletion and before `acknowledged_checkpoint` advances.

Rotation, vacuum, invalid cursors, permission loss, malformed input, reordering, duplicates, empty startup, queue pressure, and scope transitions remain explicit. Expanding or contracting scope preserves the durable cursor and starts observing newly accessible records after that position; it does not backfill older user-journal entries. If the selected scope rejects the cursor, the agent persists the gap and scope, durably clears only the collected cursor while retaining acknowledgement state, and resumes through the bounded history window. All applicable journald logical sources report the shared physical cursor plus their own last-observed event-family time/evidence. A crash can replay a deterministic ID but cannot claim a cursor that was not durably queued.

## Linux source catalog

| Stable source ID | Level | Requirement | Event families | Default/applicability |
| --- | --- | --- | --- | --- |
| `linux-journal-l1` | L1 | mandatory | boot, system, application/service baseline | enabled by default |
| `linux-login-session` | L2 | mandatory | login, session | applicable when L2 is selected |
| `linux-ssh` | L2 | role-specific | SSH authentication/session | applicable for declared `ssh_server`/`bastion`, not applicable for other declared roles, unknown when no role is declared |
| `linux-sudo-su` | L2 | mandatory | `sudo`, `su` | applicable when L2 is selected |
| `linux-cron-timers` | L2 | mandatory | cron, systemd timers | applicable when L2 is selected |
| `linux-package-management` | L2 | mandatory when supported | install, update, remove | applicability comes from bounded dpkg/rpm/pacman inventory or a matching record; quiet supported producers remain degraded until journal visibility is proved |
| `linux-firewall` | L2 | optional | allow/deny/policy change | unknown until already-enabled firewall journal evidence is observed |
| `linux-kernel-security` | L2 | mandatory | kernel security, security modules, kernel modules | applicable when L2 is selected; current system-journal visibility establishes source freshness independently of rare family activity |
| `linux-service-change` | L2 | mandatory | service start/stop/reload/failure | applicable when L2 is selected |
| `linux-agent-log-tamper` | L2 | mandatory | agent/log tamper | applicable when L2 is selected |
| `linux-audit-framework` | L2 | optional | audit | explicitly `unsupported`; no audit collector or enablement is included |
| `linux-agent-self-integrity-snapshot` | L3 | optional | agent-owned binary/unit/config/directory metadata snapshot | disabled by default; requires explicit self-integrity approval hash |
| `linux-process-snapshot-diff` | L3 | mandatory for an L3 target | process baseline/observed/disappeared/changed polling evidence | disabled by default; requires passive-telemetry approval hash |
| `linux-network-socket-snapshot-diff` | L3 | mandatory for an L3 target | socket/listener baseline/observed/disappeared/changed polling evidence | disabled by default; requires passive-telemetry approval hash |
| `linux-host-behaviour-metrics` | L3 | mandatory for an L3 target | coalesced host resource and pressure samples | disabled by default; requires passive-telemetry approval hash |
| `linux-policy-posture-drift` | L4 | mandatory | approved posture baseline/sample/drift/restoration evidence | disabled by default; requires matching L4 plan and baseline hashes |
| `linux-agent-performance-slo` | L4 | mandatory | rolling agent performance and delivery SLO evidence | disabled by default; warm-up/unavailable/breach states do not satisfy L4 |
| `linux-role-web` | L4 | role-specific | structured web-service journal family | applicable to declared `web_server` |
| `linux-role-database` | L4 | role-specific | structured database-service journal family | applicable to declared `database_server` |
| `linux-role-dns` | L4 | role-specific | structured DNS-service journal family | applicable to declared `dns_server` |
| `linux-role-file-server` | L4 | role-specific | structured file-service journal family | applicable to declared `file_server` |
| `linux-role-container` | L4 | role-specific | structured runtime/orchestrator journal family | applicable to declared `container_host` |
| `linux-role-identity` | L4 | role-specific | structured identity-service journal family | applicable to declared `identity_server` |

Every manifest includes platform/source kind/namespace, coverage level, checkpoint kind, `mandatory`/`optional`/`role_specific` requirement, applicable roles, prerequisites, event families, validation scenarios, parser/source-pack identity, privacy level, and applicability/reason. Corresponding health includes bounded prerequisite and event-family state maps.

The exact package producer matrix and supported, quiet, unsupported, missing, and malformed state transitions are documented in [Linux package-management evidence](linux-package-management-evidence.md). Inventory resolves whether an in-scope package backend exists; it does not turn event absence into proof of journal visibility.

## Passive L3 process, network, and behaviour pack

The procfs pack is independent of the journal reader and self-integrity scan. It starts only when enabled with its matching plan hash and pauses itself at a lower shared-queue pressure threshold so L1/L2 journal collection and transport can continue.

Process scans use fixed procfs identity/status files, establish a bounded non-alerting initial baseline, and then emit polling differences. PID plus process start ticks prevents PID reuse from merging identities. Network scans parse fixed TCP/UDP procfs tables, establish the same non-alerting baseline boundary, and emit later socket/listener snapshot differences without packet contents or unrelated file-descriptor traversal. Host samples coalesce fixed aggregate CPU, memory, pressure, load, disk, and interface counters. Incomplete scans report partial/gap health and cannot assert disappearances.

All three sources use durable sequence checkpoints and the existing v1 queue/acknowledgement flow. Command lines and other sensitive text are bounded, control-cleaned, and filtered for common credential-bearing forms before queueing; they remain restricted telemetry rather than being treated as provably secret-free. Process environments, memory, packet payloads, secret stores, browser data, and arbitrary file content are never read. See [Linux passive process, network, and behaviour telemetry](linux-passive-telemetry.md) for the exact operational contract.

## Approval-gated L4 pack

`Agent:L4Telemetry` adds the mandatory `linux-policy-posture-drift` and `linux-agent-performance-slo` sources. The pack starts only when passive telemetry is enabled with its valid exact approval, `Enabled=true`, and the current L4 preflight's `ApprovedPlanHash` and `ApprovedBaselineHash` both match. Passive activation is separately approval-gated and all three sources must still become healthy for server L4. A first scan is not implicit baseline approval. Partial, denied, timed-out, mismatched, corrupt, or pressure-limited observation cannot assert no drift or make the source healthy.

L4 reserves sequence ranges before queue insertion and advances collected/acknowledged state only at the documented durable boundaries. A server rejection can abandon only the next contiguous sequence, moves that row to poison with explicit dropped/gap health, and requires acknowledged recovery evidence; it cannot jump over an unseen queued outcome.

The posture source uses fixed bounded inputs and deterministic sequence events. The performance source evaluates currently implemented process CPU, RSS, process-write, and queue/delivery evidence over a bounded rolling window. It cannot become healthy until complete interval samples span the full endpoint-inclusive configured time window. Maximum managed memory and covered seconds are bounded context only. Warm-up and unavailable counters remain explicit. The broader documented per-collector and host-class benchmark matrix remains a private VM validation gate rather than being inferred from this rolling source.

Supported role declarations are `general_server`, `workstation`, `ssh_server`, `bastion`, `web_server`, `database_server`, `dns_server`, `file_server`, `container_host`, and `identity_server`. Empty or unknown declarations block L4. The six specialized role sources classify only fixed structured journal identifier/unit evidence; no application file reader or new regex/message inference is added. Successful journal reads can keep a quiet applicable role source healthy while `event_family_statuses` truthfully remains `not_observed`.

L4 is strict: all mandatory L1-L4 sources and all applicable role-specific sources must be healthy. Server-side exceptions document gaps but do not satisfy L4. The optional L3 self-integrity source and optional unsupported audit source do not become mandatory merely because L4 is requested. See [Linux L4 full-target coverage](linux-l4-coverage.md).

## Structured normalization

The reader projects only fixed journal fields in either scope. In addition to cursor/time/boot/transport/system-or-user-unit/identifier/facility/priority/message identity, the L2 projection allowlists process (`_PID`, `_UID`, `_COMM`, `_EXE`, `_CMDLINE`), PAM/user, remote address/port/protocol, result/action, unit, package, and module metadata.

Structured values always win. A bounded vendor/message parser examines at most the first 4,096 characters and uses fixed 50 ms regex timeouts or bounded token parsing only when structured evidence is missing. It recognizes narrow SSH/PAM, sudo/su, cron, apt/dpkg/dnf/yum/rpm/PackageKit/pacman package changes (including ALPM-prefixed records), UFW/nftables, kernel/MAC/module, systemd service, journald, and agent patterns. An interactive package-manager command line is not classified as a package change, and the agent does not read package-manager log files. L4 role classification is stricter: it uses only fixed structured identifier/unit evidence and does not add role-specific message parsing. Ambiguous text remains on the L1 source with no invented action, outcome, user, address, package, process, or role enrichment.

Classified events consistently use:

- category/action/outcome and severity (`audit_success`/`audit_failure` only when authentication/authorization outcome evidence exists);
- bounded flattened and portable `user`, `process`, and `network` concepts;
- service/unit, scheduler task, package, and kernel-module fields when present;
- `linux.event_family`, evidence mode, boot ID, transport, and source-pack labels; and
- deterministic `sha256_uuid` IDs over `agent_id`, logical `source_id`, and cursor.

Invalid IPs/ports, absent identities, and ambiguous messages do not create normalized fields. Command lines and all retained strings pass through control-text replacement, bounds, and secret-shaped assignment redaction before queueing.

## Input, privacy, and pressure bounds

Input records default to a 128 KiB pre-parse ceiling. Cursor is capped at 1,024 characters, message at 20,000, command line at 4,096, other retained fields at 2,048, and compact raw JSON at the portable-v1 65,536-byte ceiling. Non-text values become `<binary-or-nontext>`. `data_handling` lists every redacted/truncated field and original/retained sizes without reproducing removed values. The broader scope may expose user-service/session stdout or stderr, command lines, paths, identities, and arbitrary application text. These remain high-sensitivity endpoint data; sanitation is defensive and cannot prove an arbitrary journal message contains no secret.

Polling defaults to 500 records every five seconds. Bounds are 1-300 seconds, 1-5,000 records, 4-256 KiB input records, and a pressure pause depth of 100-1,000,000 queued events. At the pause depth, journal reads stop without deleting unacknowledged events; heartbeat and transport remain independent.

## Health and coverage semantics

Portable health status supports `healthy`, `missing`, `disabled`, `stale`, `degraded`, `permission_denied`, `unsupported`, `error`, `not_applicable`, and `excepted`. The server applies exceptions; portable heartbeat validation rejects agent-reported `excepted`, while source-health responses may expose it only from an active server-side coverage exception.

- `permission_denied` means the fixed source could not be read; the agent does not retry as root or change groups/ACLs.
- `degraded` represents pressure, unresolved optional/role applicability, or a mandatory L2 family whose producer evidence has not yet been observed; it is distinct from stale data.
- `unsupported` is explicit collector/platform capability absence, currently used for Linux Audit Framework.
- `not_applicable` requires a declared role/platform reason.
- `stale` covers age/discontinuity conditions; cursor gaps remain errors where appropriate.
- prerequisite states and event-family states distinguish satisfied/observed, not observed, missing, disabled, stale, degraded, denied, unsupported, not applicable, excepted, and unknown.

Mandatory applicable sources determine the current level. Optional sources do not lower the level; an applicable role-specific source becomes mandatory for that role. Lower-level assessments can account for server-approved exceptions, but strict L4 requires `healthy` for every mandatory/applicable source and accepts no exception as full coverage. `not_applicable` requires resolved role evidence; `unsupported`, denied, stale, degraded, disabled, missing, unresolved-role, and excepted mandatory/applicable sources do not satisfy L4.

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
    "SelfIntegrity": {
      "Enabled": false,
      "ApprovedPlanHash": "",
      "StartupDelaySeconds": 60,
      "IntervalSeconds": 3600,
      "ScanTimeoutSeconds": 30,
      "QueuePauseDepth": 100000,
      "MaxEventsPerScan": 20,
      "CleanupStateOnDisable": false,
      "StatePath": "/var/lib/challenger-siem-agent/self-integrity-state.json"
    },
    "PassiveTelemetry": {
      "Enabled": false,
      "ApprovedPlanHash": "",
      "StartupDelaySeconds": 30,
      "ProcessPollIntervalSeconds": 15,
      "NetworkPollIntervalSeconds": 15,
      "HostMetricsIntervalSeconds": 60,
      "ScanTimeoutSeconds": 5,
      "QueuePauseDepth": 50000,
      "MaxProcessesPerScan": 4096,
      "MaxSocketsPerScan": 8192,
      "MaxEventsPerScan": 500,
      "MaxProcessReadBytesPerScan": 16777216,
      "MaxNetworkReadBytesPerScan": 4194304,
      "MaxCommandLineBytes": 4096,
      "MaxRawEventBytes": 16384,
      "CleanupStateOnDisable": false,
      "StatePath": "/var/lib/challenger-siem-agent/passive-telemetry-state.json"
    },
    "L4Telemetry": {
      "Enabled": false,
      "ApprovedPlanHash": "",
      "ApprovedBaselineHash": "",
      "StartupDelaySeconds": 60,
      "PostureIntervalSeconds": 3600,
      "SloSampleIntervalSeconds": 60,
      "SloWindowMinutes": 15,
      "ScanTimeoutSeconds": 10,
      "QueuePauseDepth": 25000,
      "MaxEventsPerScan": 100,
      "CleanupStateOnDisable": false,
      "StatePath": "/var/lib/challenger-siem-agent/l4-telemetry-state.json"
    },
    "Journal": {
      "Enabled": true,
      "IncludeAccessibleUserJournals": false,
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

`IncludeAccessibleUserJournals=false` maps to `system_only`; `true` maps to `all_accessible_local`. The broader scope is independent of `TargetCoverageLevel`, requires explicit privacy/volume review, invalidates the passive-L3 and L4 plan hashes, and takes effect only after the installed service restarts. Roll back by restoring `false`, regenerating any enabled approval hashes, and using another approved agent-only restart. `TargetCoverageLevel` accepts `L1` through `L4`. It selects the expected catalog and enables structured role classification at L4; it does not enable self-integrity, passive procfs, or L4 posture/SLO collection. `DeclaredRoles` accepts at most 16 bounded lowercase/number/underscore/hyphen identifiers. L4 requires at least one role and accepts only the ten documented values; empty/unknown roles fail configuration rather than being guessed. Use L2/L3/L4 only through their separate approved canary paths; no target, role, or scope value grants permission to change a producer or host policy.

`SelfIntegrity.Enabled` remains `false` unless an operator separately approves the exact self-integrity preflight plan and sets `ApprovedPlanHash` to the matching `sha256:` plan hash. Installation, enrollment, or requested coverage level does not enable it. The fixed allowlist is limited to `/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent` (metadata plus SHA-256 capped at 64 MiB), `/etc/systemd/system/challenger-siem-agent.service` (metadata plus SHA-256 capped at 256 KiB), `/etc/challenger-siem-agent/agentsettings.json` (metadata only; no hash/content), `/etc/challenger-siem-agent/` (directory metadata only), and `/var/lib/challenger-siem-agent/` (directory metadata only). Symlinks, hard-link surprises, devices, FIFOs, sockets, arbitrary paths, recursive scans, and secret values are rejected. Disable cleanup removes only `SelfIntegrity.StatePath` when `CleanupStateOnDisable=true`; it never touches monitored files or host policy.

`PassiveTelemetry.Enabled` also remains `false` until its separate `ApprovedPlanHash` matches the fixed sources and configured limits. The process/network defaults poll every 15 seconds, host metrics every 60 seconds, and pause at 50,000 queued events before the journal's default threshold. Bounds reject intervals, deadlines, item/event counts, command-line/raw sizes, and read budgets outside the supported range. Production validation accepts only the product-owned `PassiveTelemetry.StatePath` shown above; optional cleanup removes only that fixed-path, symlink-rejecting regular state file. No process, socket, host policy, shared queue, or server telemetry is changed.

`L4Telemetry.Enabled` remains `false` until the journal is enabled at `Journal.TargetCoverageLevel=L4` and both its plan and candidate posture baseline are reviewed and copied as the exact `ApprovedPlanHash` and `ApprovedBaselineHash`. The default posture interval is one hour; the SLO sampler uses a 60-second cadence and 15-minute rolling window. L4 pauses at 25,000 queued events, before the passive L3 and journal thresholds. Bounds accept posture intervals of 300-3,600 seconds that are no shorter than `InventoryIntervalSeconds`, SLO intervals of 30-240 seconds, windows of 10-60 minutes, deadlines of 1-30 seconds, queue thresholds of 100-1,000,000, and 7-500 events per scan. The L4 threshold cannot exceed the passive threshold, the event cap cannot exceed its threshold, and both intervals must exceed the deadline. When enabled, SLO interval + scan timeout + heartbeat must be at most 270 seconds, while posture interval + inventory collection timeout + heartbeat must be at most 6,900 seconds. These end-to-end collection/reporting relations leave at least 30 seconds inside the server's five-minute SLO boundary and five minutes inside its two-hour policy boundary; a delayed/failed observation still becomes stale or non-healthy. Production state is restricted to the exact path shown above. See [Agent configuration format](agent-config.md#linux-l4-fields) and [Linux L4 full-target coverage](linux-l4-coverage.md).

## Bounded inventory snapshots

The independent inventory service emits up to 20 snapshots, 200 items per snapshot, and a default 256 KiB serialized batch. Categories cover host identity, users/groups, services/units/timers, packages/updates, interfaces/listeners, mounts, firewall, SSH, MAC state, Secure Boot, and observable agent file posture. Package inventory supports fixed dpkg, rpm, and pacman queries; available-update inventory supports fixed apt, cache-only dnf, and pacman queries. Pacman uses only `-Q` and `-Qu`, and its silent exit-1 empty-update result is accepted only when stderr is also empty. Every snapshot reports `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`; the server maps these states without treating mere presence as healthy.

The fixed catalog uses exact executable candidates/arguments/files, no shell, a cleared environment, process-tree cancellation, time/output caps, and no-follow regular-file reads. It excludes raw output, arbitrary file content/path scans, account descriptions, group membership, addresses, command lines, firewall rules, repository contents, and unapproved SSH directives. Inventory remains current-state evidence, not a substitute for event-source health.

## Safe lifecycle

Publish the portable installer bundle for the target architecture, keep the generated directory private/ignored, and transfer it through an operator-approved private channel. The helper rejects symlink/non-empty output so stale or credential-bearing files cannot enter the transfer bundle, enforces output mode 0700, and allows repository-local output only below ignored `dist/` or `.local/`. It produces the required self-contained, compressed single-file executable, rejects output over the fixed 64 MiB installer/self-integrity cap, and places the lifecycle helper, systemd unit, and a placeholder-only synthetic configuration reference beside it. Create a separate private mode-0600 real configuration; the bundled synthetic reference is not deployable credentials. A fresh target must already have the separately reviewed locked `challenger-siem` identity. The installer refuses to create it, add journal groups, or change journal permissions. Review the plan's effective journal scope and high-sensitivity boundary before installation or upgrade. Never put the bundle, a real token, real settings, or collected journal data in the repository.

```bash
./scripts/publish-linux-agent.sh linux-x64 <private-publish-dir>
# Or for an ARM64 target:
./scripts/publish-linux-agent.sh linux-arm64 <private-publish-dir>
# On the authorized target, from the copied private bundle:
./linux-agent.sh plan --payload . --config <separate-private-mode-0600-config>
# After approval, install with L4 disabled:
./linux-agent.sh install --payload . --config <separate-private-mode-0600-config>
# Then generate the L4 candidate baseline as the installed identity:
./linux-agent.sh plan --config /etc/challenger-siem-agent/agentsettings.json
# This stages reviewed files without restart; activation needs separate approval:
./linux-agent.sh upgrade --payload . --config <separate-private-mode-0600-config>
./linux-agent.sh validate
./linux-agent.sh uninstall
```

The lifecycle plan changes no installation path or host policy. The L4 posture preflight runs only after disabled installation, as the `challenger-siem` service identity with a clean environment and its owned private state directory as the working directory; missing identity/binary/private writable state, insufficient existing journal visibility, an unsafe config, or alternate-root cases report a blocker instead of probing as root or widening access. A pre-install payload also cannot complete `linux_agent_integrity` for the fixed installed binary/configuration paths. The .NET single-file runtime may populate only `/var/lib/challenger-siem-agent/.dotnet-bundle`; it does not change L4 state, the queue, configuration, collected telemetry, or host policy. Keep all host-specific output private. Mutating modes preflight platform/init/architecture/privilege/payload/config/identity before creating paths and touch only declared product paths. Transferred executable/configuration/unit inputs must be bounded regular files, and existing product targets must have their expected type; symlinks are rejected before any directory is created. The bundled helper accepts the adjacent unit when repository packaging paths are absent. An upgrade may explicitly reuse the installed mode-0600 configuration, which is validated and preserved in place rather than copied onto itself. The installed unit directs bundle extraction into the same private state cache instead of a shared temporary location. `upgrade` stages the new executable, unit, and configuration without starting or restarting the service and prints that separate restart approval is required to activate them. Uninstall retains the service identity. Sandbox `--root`/`--no-service-control` options are CI aids, not deployment shortcuts.

## API, validation, and rollout gate

Events continue through additive portable-v1 envelopes using `source=linux_journal`, `inventory_diff`, or `agent_health` as applicable and `/api/v1/ingest/events`; heartbeat uses additive manifest/health fields; inventory uses the existing generic endpoint. Heartbeats also report bounded resource/queue observability where available: RSS/managed memory, nullable CPU, queue bytes/depth/oldest age, pressure state, send/backoff/recovery timestamps, poison counters, and explicit drop zero when no local shedding occurred. Per-source health reports observed time, rate, lag/silence, gap counts, permission-denied/recovery timestamps, transition state, `configured_journal_scope`, independently verified `system_journal_visibility`, and `scope_transition` without raw journal data. Server source-health and telemetry-coverage APIs overlay the Linux catalog, count recent portable events by `source_id`, and expose platform/requirement/applicability/evidence metadata. Scope expansion improves what the existing classifier can observe but cannot itself satisfy an unobserved package, sudo, or other event family. The mandatory `linux-agent-log-tamper` and `linux-kernel-security` rows are intentionally quiet event-driven sources: their tamper or kernel/security-module families retain independent observed/not-observed evidence and do not require artificial activity. A successful bounded system-journal observation within the two-hour source-health window, with satisfied source-specific prerequisites and no active permission, gap, clear, or bookmark condition, is `healthy` even when matching events are absent or old; an expired observation is `stale`, while unavailable or degraded prerequisites and an implausibly future observation remain non-healthy. A quiet kernel observation establishes visibility only; it does not satisfy a detection's recent kernel-event requirement. Permission denial and active continuity failures remain explicit higher-priority states. Server-side [Linux detections](linux-detections.md) consume only accepted v1 events and current source-health prerequisites; degraded prerequisites lower confidence or suppress evaluation rather than implying safety. No `/api/v2` or incompatible Windows behavior is introduced.

Run:

```bash
dotnet test tests/LinuxAgent.Tests/LinuxAgent.Tests.csproj
dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

Tracked tests are hand-authored synthetic data only. They cover every catalog family with positive/negative evidence, structured-field precedence, ambiguity, malformed/binary/control/secret/oversized input, source catalog/health states, cursor/replay/pressure, normalized portable contract behavior, and 5,000-record L1/L2 throughput/allocation guards. Those unit benchmarks are regression checks, not host CPU/RSS/write measurements.

The private seven-day L1+L2 canary, distribution/systemd matrix, outage/rotation/restart windows, L3 soak, L4 VM canary, and resource/disruption SLO evidence remain outstanding rollout gates. Use the [Linux local-host validation runbook](linux-local-host-validation.md) for non-policy-mutating preflight, private evidence handling, staged L1-L4 procedures, recovery drills, rollback, and sanitized aggregate reporting. Do not claim default L2/L3/L4 readiness from unit tests or a short healthy rolling window. Optional audit/eBPF/broad-file-integrity ideas remain deferred by the [Linux L3 telemetry ADR](linux-l3-telemetry-adr.md). Stop rollout on secret/excluded-data collection, unauthorized mutation, host impact, queue corruption, silent loss, persistent gaps, false-healthy posture, or SLO breach; keep all live evidence under ignored `.local/` or approved OS runtime paths.
