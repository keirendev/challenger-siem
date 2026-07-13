# Windows agent MVP

Project: `agent/WindowsAgent`

## Current capabilities

- Runs as a .NET 8 Worker Service and can be hosted as a Windows Service.
- Reads configured Windows Event Log channels using the Windows Event Log API.
- Starts at the end of each channel by default when no state exists, preventing a first-run flood of historical events.
- Normalizes records into the v1 `EventEnvelope` contract with source-specific category/action/entity metadata for Security, System, Application, PowerShell, Defender, Task Scheduler, WMI, RDP, WinRM, Firewall, Group Policy, Code Integrity, AppLocker/WDAC, and Sysmon source groups.
- Uses deterministic event IDs based on agent/channel/record/provider/event ID for server-side deduplication.
- Persists channel position state to JSON.
- Persists unsent events to a local SQLite queue before forwarding.
- Supports first-run enrollment with `POST /api/v1/agents/register` and persists the returned per-agent token.
- Sends batches to `POST /api/v1/ingest/events`.
- Deletes queued events only after server acknowledgement, using event-id acknowledgement arrays when present.
- Sends heartbeat data to `POST /api/v1/agents/heartbeat`, including current host timezone metadata, configuration hash, queue SLO metrics, source manifest, source-health probes, and tamper-check summary fields.
- Supports DPAPI-protected persisted API tokens for first-run enrollment on Windows.
- Retries with bounded exponential backoff when collection or forwarding fails.
- Quarantines repeatedly failing queued events in a local `poison_events` table so later events can continue draining.
- Reports bounded host timezone metadata on registration, heartbeat, inventory snapshots, source-health rows, and event envelopes. `event_time` remains UTC; the event-specific `host_timezone.utc_offset_minutes` lets the server/web console render host-local time across daylight-saving boundaries.

## Build

The project targets `net8.0-windows` and enables Windows targeting so it can be compiled from this Linux development host:

```bash
dotnet build agent/WindowsAgent/WindowsAgent.csproj
```

Publish a standalone Windows executable from a machine with the .NET SDK:

```bash
./scripts/publish-windows-agent.sh
```

Output:

```text
dist/windows-agent-win-x64/WindowsAgent.exe
```

This is a self-contained single-file executable for `win-x64`. It does not need `WindowsAgent.dll` or a .NET runtime install on the Windows host. It still needs `agentsettings.json` next to `WindowsAgent.exe`, under `C:\ProgramData\ChallengerSIEM\Agent`, or equivalent environment variables.

Running and validating real event collection requires Windows. The agent treats `EventRecord.TimeCreated` values with `DateTimeKind.Unspecified` as endpoint-local time before converting to UTC, avoiding server-timezone interpretation.

## Install on Windows

The supported workflow is `scripts/install-windows-agent.ps1`, which can plan, install, upgrade, repair, validate, and uninstall the service while preserving existing config, queue, and state by default.

Preview without changing the host:

```powershell
.\scripts\install-windows-agent.ps1 -Mode plan -TargetLevel L3
```

Install from an elevated PowerShell session after publishing:

```powershell
.\scripts\install-windows-agent.ps1 -Mode install -PublishPath .\dist\windows-agent-win-x64
```

Upgrade or repair without silently restarting a running service:

```powershell
.\scripts\install-windows-agent.ps1 -Mode upgrade -PublishPath .\dist\windows-agent-win-x64 -RestartService
.\scripts\install-windows-agent.ps1 -Mode validate -TargetLevel L3
```

The workflow creates:

- service: `ChallengerSiemAgent` with display name `Challenger SIEM Agent`
- default MVP service account: LocalSystem
- install directory: `C:\Program Files\ChallengerSIEM\Agent`
- protected data/config directory: `C:\ProgramData\ChallengerSIEM\Agent`
- template config: `C:\ProgramData\ChallengerSIEM\Agent\agentsettings.json`
- optional Sysmon profile copy: `C:\ProgramData\ChallengerSIEM\Agent\sysmon\challenger-siem-sysmon-l3.xml`

The install and data directories are ACL-restricted to `BUILTIN\\Administrators` and `NT AUTHORITY\\SYSTEM`. LocalSystem is the MVP default because it can run as a service and read the protected `Security` event log on standard Windows installations. If a custom service account is used later, grant only the specific Windows Event Log permissions it needs and validate Security-log access explicitly.

Edit the config with either the registered `AgentId` and `ApiToken` or a first-run enrollment token, then start the service:

```powershell
Start-Service ChallengerSiemAgent
```

Uninstall through the same workflow while preserving queued data and state:

```powershell
.\scripts\install-windows-agent.ps1 -Mode uninstall
```

Remove queued data and state too only in a disposable lab after explicit approval:

```powershell
.\scripts\install-windows-agent.ps1 -Mode uninstall -RemoveData
```

See [Windows agent installer workflow](windows-agent-installer.md) for guarded prerequisite configuration and Sysmon management.

## Configuration

The agent reads configuration from:

1. bundled/default `appsettings.json` when present
2. `agentsettings.json` next to `WindowsAgent.exe`
3. `CHALLENGER_SIEM_AGENT_CONFIG` if set, otherwise `C:\ProgramData\ChallengerSIEM\Agent\agentsettings.json`
4. environment variables prefixed with `CHALLENGER_SIEM_AGENT_`

The external `agentsettings.json` can either use an `Agent` section or the same fields at the root.

Required fields:

- `AgentId`
- `ServerBaseUrl`
- `ApiToken`, `ProtectedApiToken`, **or** `Enrollment.EnrollmentToken`
- at least one channel in `Channels`

For the current lab server binding, set:

```json
"ServerBaseUrl": "http://192.168.122.1:4444"
```

A ready-to-edit example is available at `examples/windows-agentsettings-192.168.122.1-4444.json`.

Do not log or commit `ApiToken`, `ProtectedApiToken`, or `Enrollment.EnrollmentToken`.

### First-run enrollment

To enroll from the endpoint, leave `ApiToken` blank and set:

```json
"Enrollment": {
  "Enabled": true,
  "EnrollmentToken": "<temporary-enrollment-token>",
  "MachineGuid": null
}
```

On successful registration the agent stores the returned per-agent token as DPAPI-protected `ProtectedApiToken` in the configured `agentsettings.json`, clears the enrollment token in that file, and continues with normal ingest/heartbeat authentication. Existing lab configs that already contain `ApiToken` continue to work and skip enrollment.

## State and queue files

Default paths:

```text
C:\ProgramData\ChallengerSIEM\Agent\state.json
C:\ProgramData\ChallengerSIEM\Agent\queue.sqlite
```

These files should be protected to Administrators and SYSTEM when installed. Use this read-only helper on Windows to summarize ACLs and Security-log read access without changing service state:

```powershell
.\scripts\test-windows-agent-acls.ps1
```

## Windows validation notes

- Required channels are `Security`, `System`, and `Application`. Security access depends on the service account; LocalSystem is expected to work in the MVP lab.
- Optional L2/L3 channels are represented in the source manifest and report `missing`/`error` source-health status when unavailable or unreadable.
- Default `StartAtEndWhenNoState: true` prevents a first-run flood. For bounded lab collection tests, set it to `false` only in ignored temporary configs.
- The safety runbook avoids reboots, firewall/authentication changes, event-log clearing, and deleting operator data. If a service uninstall must be demonstrated, use a disposable lab and explicit operator approval; the default uninstall script preserves data unless `-RemoveData` is supplied.


## Reliability implementation boundary

The Windows process uses `Agent.Core` for its queue, transport, serialization, deterministic IDs, configuration hashing, acknowledgement handling, and retry schedule. Windows-only collection, secret protection, checkpoint path selection, and service integration remain in `WindowsAgent`; there is no second queue or transport path. Queue records survive process restart, duplicate enqueue is suppressed by agent/event identity, and only explicitly accepted or duplicate acknowledgements are deleted after partial responses.
