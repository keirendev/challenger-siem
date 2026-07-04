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
    "ApiToken": "stored-after-registration",
    "Channels": [
      "Security",
      "System",
      "Application"
    ],
    "OptionalChannels": [
      "Windows PowerShell",
      "Microsoft-Windows-PowerShell/Operational",
      "Microsoft-Windows-Sysmon/Operational",
      "Microsoft-Windows-Windows Defender/Operational"
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
      "MaxSizeMb": 512
    },
    "State": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\state.json"
    }
  }
}
```

The agent also accepts the same fields at the JSON root for simple deployments.

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
