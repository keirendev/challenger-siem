# Windows agent MVP

Project: `agent/WindowsAgent`

## Current capabilities

- Runs as a .NET 8 Worker Service and can be hosted as a Windows Service.
- Reads configured Windows Event Log channels using the Windows Event Log API.
- Starts at the end of each channel by default when no state exists, preventing a first-run flood of historical events.
- Normalizes records into the v1 `EventEnvelope` contract.
- Uses deterministic event IDs based on agent/channel/record/provider/event ID for server-side deduplication.
- Persists channel position state to JSON.
- Persists unsent events to a local SQLite queue before forwarding.
- Sends batches to `POST /api/v1/ingest/events`.
- Deletes queued events only after server acknowledgement.
- Sends heartbeat data to `POST /api/v1/agents/heartbeat`.
- Retries with exponential backoff when collection or forwarding fails.

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

Running and validating real event collection requires Windows.

## Install on Windows

Run from an elevated PowerShell session after publishing:

```powershell
.\scripts\install-windows-agent.ps1 -PublishPath .\dist\windows-agent-win-x64
```

The script creates:

- service: `ChallengerSiemAgent`
- install directory: `C:\Program Files\ChallengerSIEM\Agent`
- protected data/config directory: `C:\ProgramData\ChallengerSIEM\Agent`
- template config: `C:\ProgramData\ChallengerSIEM\Agent\agentsettings.json`

Edit the config with the registered `AgentId` and `ApiToken`, then start the service:

```powershell
Start-Service ChallengerSiemAgent
```

Uninstall while preserving queued data and state:

```powershell
.\scripts\uninstall-windows-agent.ps1
```

Remove queued data and state too:

```powershell
.\scripts\uninstall-windows-agent.ps1 -RemoveData
```

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
- `ApiToken`
- at least one channel in `Channels`

For the current lab server binding, set:

```json
"ServerBaseUrl": "http://192.168.122.1:4444"
```

A ready-to-edit example is available at `examples/windows-agentsettings-192.168.122.1-4444.json`.

Do not log or commit `ApiToken`.

## State and queue files

Default paths:

```text
C:\ProgramData\ChallengerSIEM\Agent\state.json
C:\ProgramData\ChallengerSIEM\Agent\queue.sqlite
```

These files should be protected to Administrators and SYSTEM when installed.

## Next Windows validation tasks

- Verify permissions required for reading `Security` channel.
- Validate service install/start/stop behavior.
- Confirm rendered messages are available on target hosts.
- Confirm optional channels are skipped cleanly when missing.
