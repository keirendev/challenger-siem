# Agent configuration format

Windows agent configuration file: `agentsettings.json`.

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
      "Microsoft-Windows-WinRM/Operational",
      "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      "Microsoft-Windows-GroupPolicy/Operational",
      "Microsoft-Windows-CodeIntegrity/Operational",
      "Microsoft-Windows-AppLocker/EXE and DLL",
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "StartAtEndWhenNoState": true,
    "PollIntervalSeconds": 10,
    "HeartbeatIntervalSeconds": 60,
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
    }
  }
}
```

The agent also accepts the same fields at the JSON root for simple deployments. If both root fields and an `Agent` section are present, the `Agent` section wins.

## Enrollment modes

Existing lab deployments can continue to provide a per-agent `ApiToken` directly. A fresh endpoint can instead set `ApiToken` and `ProtectedApiToken` to empty strings and provide `Enrollment.EnrollmentToken`. On startup the agent calls `POST /api/v1/agents/register`, receives a per-agent API token, persists it to the configured `agentsettings.json` as `ProtectedApiToken` using Windows DPAPI machine protection, clears the enrollment token in that file, and uses the decrypted API token for ingest and heartbeat requests.

Never place enrollment or per-agent tokens in committed examples. Use ignored local files or protected Windows paths only. `ProtectedApiToken` values are host-bound and must still be treated as secret local configuration.

## Queue reliability fields

- `Queue.MaxSizeMb` caps the SQLite queue file.
- `Queue.WarningSizePercent` emits operator-visible warnings before the cap.
- `Queue.MaxSendAttempts` controls when repeatedly failing events are moved to the local `poison_events` table so future events can continue draining.
- `Queue.MaxBackoffSeconds` caps per-event retry backoff.

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
