# Agent configuration format

Agent configuration file: `agentsettings.json`. Windows fields are documented first; Linux-specific journal coverage fields follow below.

The file should be stored in a protected Windows directory, for example:

```text
C:\ProgramData\ChallengerSIEM\Agent\agentsettings.json
```

Permissions should be restricted to Administrators and SYSTEM.

## Example

```json
{
  "Agent": {
    "AgentId": "win11-test-001",
    "ServerBaseUrl": "https://siem.example.local",
    "ApiToken": "",
    "ProtectedApiToken": "dpapi:stored-after-registration-on-windows",
    "Enrollment": {
      "Enabled": false,
      "EnrollmentToken": "only-used-for-first-run-enrollment",
      "MachineGuid": null
    },
    "Channels": [
      "Security",
      "System",
      "Application"
    ],
    "OptionalChannels": [
      "Windows PowerShell",
      "Microsoft-Windows-PowerShell/Operational",
      "Microsoft-Windows-Windows Defender/Operational",
      "Microsoft-Windows-TaskScheduler/Operational",
      "Microsoft-Windows-WMI-Activity/Operational",
      "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
      "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
      "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
      "Microsoft-Windows-WinRM/Operational",
      "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      "Microsoft-Windows-GroupPolicy/Operational",
      "Microsoft-Windows-CodeIntegrity/Operational",
      "Microsoft-Windows-AppLocker/EXE and DLL",
      "Microsoft-Windows-AppLocker/MSI and Script",
      "Microsoft-Windows-AppLocker/Packaged app-Execution",
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "StartAtEndWhenNoState": true,
    "PollIntervalSeconds": 10,
    "HeartbeatIntervalSeconds": 60,
    "InventoryIntervalSeconds": 3600,
    "Batching": {
      "MaxEvents": 100,
      "MaxIntervalSeconds": 10
    },
    "Queue": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\queue.sqlite",
      "MaxSizeMb": 512,
      "MaxSendAttempts": 10,
      "MaxBackoffSeconds": 300,
      "WarningSizePercent": 80
    },
    "State": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\state.json"
    },
    "Sysmon": {
      "ConfigPath": "C:\\ProgramData\\ChallengerSIEM\\Agent\\sysmon\\challenger-siem-sysmon-l3.xml",
      "ProfileVersion": "challenger-siem-l3-2026.07.06"
    }
  }
}
```

The agent also accepts the same fields at the JSON root for simple deployments. If both root fields and an `Agent` section are present, the `Agent` section wins.

## Enrollment modes

Existing lab deployments can continue to provide a per-agent `ApiToken` directly. A fresh endpoint can instead set `ApiToken` and `ProtectedApiToken` to empty strings and provide `Enrollment.EnrollmentToken`. On startup the agent calls `POST /api/v1/agents/register`, receives a per-agent API token, persists it to the configured `agentsettings.json` as `ProtectedApiToken` using Windows DPAPI machine protection, clears the enrollment token in that file, and uses the decrypted API token for ingest and heartbeat requests.

Never place enrollment or per-agent tokens in committed examples. Use ignored local files or protected Windows paths only. `ProtectedApiToken` values are host-bound and must still be treated as secret local configuration.

## Queue reliability fields

- `Queue.MaxSizeMb` caps the SQLite queue file and drives reported `max_size_bytes`/used-percent health.
- `Queue.WarningSizePercent` emits operator-visible warnings before the cap and maps to the `warning` pressure state; 85%, 95%, and full map to higher queue-pressure states.
- `Queue.MaxSendAttempts` controls when repeatedly failing events are moved to the local `poison_events` table so future events can continue draining; poison depth and cumulative local poison count are reported without payloads.
- `Queue.MaxBackoffSeconds` caps per-event retry backoff; send/backoff/recovery timestamps are nullable when unknown and zero is reported only for measured zero values.
- `InventoryIntervalSeconds` controls how often the agent sends bounded inventory/audit-policy snapshots. The agent sends one snapshot batch soon after startup, then repeats at this interval.

## Sysmon profile fields

- `Sysmon.ConfigPath` points at the versioned approved Sysmon profile copy. When present, the agent includes its SHA-256 hash on the Sysmon source-health row.
- `Sysmon.ProfileVersion` is an operator-visible source version for the active approved profile, for example `challenger-siem-l3-2026.07.06`.

## Channel position state

MVP state can use `channel + record_id` tracking:

```json
{
  "Security": 123456,
  "System": 44551,
  "Application": 9981
}
```

Windows Event Log bookmarks can replace or supplement this later.

## Linux journal coverage fields

The Linux agent uses the same top-level `Agent` section but has a platform-specific fixed source configuration; see [`examples/synthetic-linux-agent-config.json`](../examples/synthetic-linux-agent-config.json). Its journal block is:

```json
{
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
```

`IncludeAccessibleUserJournals=false` is the default `system_only` scope. Setting it to `true` selects `all_accessible_local`: the same fixed reader omits the fixed `--system` selector and can therefore consume system and user journals already readable by the non-root service identity. It does not add `--user`, accept arbitrary arguments/paths/namespaces, read remote journals, grant root, join groups, change ACLs, or change journal retention or producers. The agent independently probes system-journal visibility so a successful user-journal read cannot make mandatory L1 evidence healthy. Scope changes preserve the durable cursor and do not backfill older records; an invalid cursor is persisted as a gap, durably reset, and recovered through the existing bounded history window. Applying a scope change to an installed running agent requires a separately approved agent restart. Source health reports `configured_journal_scope`, `system_journal_visibility`, and `scope_transition` without payload content.

`TargetCoverageLevel` accepts `L1` through `L4`; `L1` remains the default until the staged private rollout gates pass. Selecting L3/L4 changes expected source and role classification but does not enable or approve independent advanced collectors. `DeclaredRoles` accepts at most 16 unique lowercase/number/underscore/hyphen identifiers and affects role-specific source applicability. L4 requires one or more roles and accepts only `general_server`, `workstation`, `ssh_server`, `bastion`, `web_server`, `database_server`, `dns_server`, `file_server`, `container_host`, and `identity_server`. It does not enable services, grant access, select paths/commands, or approve coverage exceptions. An empty or unknown role fails L4 configuration rather than being guessed. The fixed Linux source catalog and normalization behavior are documented in [linux-agent.md](linux-agent.md).

## Linux passive L3 fields

The process/network/behaviour pack is independent of the journal target and is disabled until an operator reviews its preflight and supplies the matching plan hash:

```json
{
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
  }
}
```

Changing any plan-bound field changes the required `sha256:` approval hash. It binds every `PassiveTelemetry` field above except the activation switch `Enabled` and the self-referential `ApprovedPlanHash`; it also binds `Queue.MaxSizeMb`, `Queue.WarningSizePercent`, `Journal.QueuePauseDepth`, `Journal.MaxRecordsPerPoll`, `Journal.MaxInputRecordBytes`, and the effective journal scope because those values define the passive pack's priority and reviewed collection boundary. `Enabled=true` with an absent or mismatched hash reports disabled/approval-mismatch health and does not collect. The procfs paths are built in, and production validation accepts only the exact product-owned `StatePath` shown above; configuration cannot add arbitrary filesystem paths, commands, packet capture, process memory/environment reads, or broader privileges. `CleanupStateOnDisable=true` may remove only that fixed-path, symlink-rejecting regular state file after disablement. See [Linux passive process, network, and behaviour telemetry](linux-passive-telemetry.md).

The supported passive-plan bounds are deliberately relational as well as per-field: startup delay is 0–300 seconds; process/network intervals are 5–300 seconds and at least twice the 1–30 second scan timeout; the 10–3600 second metrics interval must exceed that timeout. Queue pause depth is 100–1,000,000 events, `MaxEventsPerScan` is 1–5,000 and cannot exceed that passive threshold, and the passive threshold cannot exceed `Journal.QueuePauseDepth`. Linux queue validation accepts `MaxSizeMb` 1–1,048,576, `MaxSendAttempts` 1–1,000, `MaxBackoffSeconds` 1–86,400, and `WarningSizePercent` 1–95; journal plan inputs retain their normal 1–5,000 record and 4–256 KiB input bounds. The conservatively estimated maximum passive batch must fit below the queue warning limit after reserving the estimated bytes for one maximum journal poll, even when the queue is empty. Process/socket caps are 1–4,096 and 1–8,192. Process and network read budgets are 1–64 MiB and 256 KiB–16 MiB; command-line and raw-event bounds are 256–4,096 and 4–32 KiB. Both the lifecycle plan helper and the agent reject a configuration outside these bounds before collection. The helper accepts case-insensitive native JSON values but intentionally rejects string-coerced primitives; when environment overrides affect any plan-bound passive, queue, or journal value, the published binary's plan output is authoritative.

## Linux L4 fields

The Linux L4 pack has an independent approval from L3, but activation also requires `Journal.TargetCoverageLevel=L4`. Install it disabled first, then keep it disabled until the exact non-policy-mutating installed preflight and candidate posture baseline are reviewed. The .NET single-file runtime may populate only its private `/var/lib/challenger-siem-agent/.dotnet-bundle` cache during preflight; L4 state, queue, configuration, telemetry, and host policy remain unchanged:

```json
{
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
  }
}
```

- `Enabled` activates L4 work only when `Journal.Enabled=true`, `Journal.TargetCoverageLevel=L4`, declared roles are non-empty/known, passive telemetry is enabled with valid bounds and its exact separate approval, both L4 approvals match, and the enabled-only reporting-headroom relations below pass. A missing prerequisite fails configuration or reports non-healthy approval state; it must not silently collect or adopt a baseline.
- `ApprovedBaselineHash` is the exact lowercase `sha256:` plus 64-hex candidate over the fixed `linux_agent_integrity`, `linux_firewall`, `linux_mandatory_access_control`, `linux_secure_boot`, and `linux_ssh` bounded inventory snapshots. Each must be `success` or explicitly `not_applicable`; denied, unavailable, timeout, malformed, missing, or truncated evidence makes the candidate incomplete. Integrity additionally requires successful configuration and executable children with both exact items present. MAC requires explicit valid AppArmor/SELinux alternative states and at least one successfully observed provider item. The collector emits signatures and bounded state/blocker codes, not raw inventory values.
- `ApprovedPlanHash` uses the same exact lowercase hash format. It binds target/journal state including the effective journal scope, heartbeat cadence, the baseline hash, sorted declared roles, passive enablement/approval and queue relationship, inventory cadence/deadline/budget, every other plan-bound L4 field except the activation switch and self-referential plan hash, fixed posture types, rolling-SLO inputs/thresholds, collector version, role input boundary, and exclusions. Set the baseline hash first, regenerate the plan, and then approve that resulting plan hash. Changing `IncludeAccessibleUserJournals` invalidates both the passive-L3 and L4 plan approvals.
- The default rolling SLO uses 60-second process samples over 15 minutes. Each complete sample covers the interval from its prior endpoint, and health requires both the required interval-sample count and at least the full endpoint-inclusive configured elapsed window. It evaluates measured average/p95 process CPU, maximum RSS, average `/proc/self/io` write rate, and bounded queue poison/drop/pressure/oldest-age health. Maximum managed memory and covered seconds are emitted context, not pass/fail thresholds; the separate private benchmark remains responsible for per-collector and host-class evidence not measured by this source.
- The L4 queue threshold must not exceed `PassiveTelemetry.QueuePauseDepth`, so L4 yields before passive L3 and the journal. It never authorizes dropping acknowledged-state safeguards or deleting unacknowledged rows.
- The fixed state path is the only accepted production path. `CleanupStateOnDisable=true` may remove only this bounded, symlink-rejecting L4 state after disablement; it cannot remove inventory, the shared queue, journal/L3 state, credentials, or server events.

Supported base bounds are: startup 0–300 seconds; posture interval 300–3,600 seconds and no shorter than `InventoryIntervalSeconds`; SLO interval 30–240 seconds; SLO window 10–60 minutes; scan timeout 1–30 seconds and shorter than both intervals; queue threshold 100–1,000,000 and no higher than the passive threshold; and 7–500 events per scan, no higher than the L4 queue threshold. When L4 is enabled, the SLO interval plus scan timeout plus `HeartbeatIntervalSeconds` must be at most 270 seconds, and the posture interval plus `Inventory.CollectionTimeoutSeconds` plus heartbeat interval must be at most 6,900 seconds. Those end-to-end collection/reporting relations leave at least 30 seconds inside the server's five-minute SLO boundary and five minutes inside its two-hour policy boundary. Delayed or failed observations still become stale/non-healthy. Any invalid value prevents agent startup rather than being clamped silently.

The preflight contains host-specific posture signatures and belongs only in protected local evidence. Do not commit or publish generated settings, plan/baseline output, real roles, resource samples, or state. See [Linux L4 full-target coverage](linux-l4-coverage.md) and [Linux local-host rollout validation](linux-local-host-validation.md#l4-private-vm-canary).

Before staging `Enabled=true`, require the installed second-pass preflight to report `activation_ready=true`, an empty `activation_blockers` list, `candidate_baseline_complete=true`, and both approval match flags true while `enabled=false`. This readiness also requires passive-L3 enabled/valid/exactly approved; it does not replace runtime passive-source health or soak evidence. The exact readiness fields and bounded blocker vocabulary are documented in [Linux L4 full-target coverage](linux-l4-coverage.md#preflight-readiness-fields-and-blocker-codes).
