# L2 Windows validation runbook

Use only authorized lab hosts. Do not clear event logs, reboot, uninstall services, or change firewall/auth settings without operator approval.

## Preconditions

- API listening on the host at `http://0.0.0.0:4444`.
- Windows lab VM can reach `http://192.168.122.1:4444/health`.
- Temporary agent uses a unique agent ID and paths under `C:\Temp\ChallengerSIEM\issue-<n>\`.
- Configure `Channels` to at least `Security`, `System`, and `Application`; include L2 optional channels when present.

## Steps

1. Apply/validate database schema locally.
2. Start the API with `./scripts/run-server-4444.sh` and capture output under ignored `.local/`.
3. Prepare Windows agent files with `./scripts/prepare-windows-agent-files.sh`.
4. Adjust ignored generated config for bounded validation: low poll/heartbeat intervals, small batches, unique queue/state paths.
5. Copy `WindowsAgent.exe` and `agentsettings.json` to the VM temporary directory.
6. Run the agent long enough to emit at least one heartbeat and bounded System-channel events.
7. Stop only that temporary process if it is still running.
8. Query `/api/v1/source-health?agent_id=<id>&target_level=L2`, `/api/v1/telemetry-coverage?agent_id=<id>&target_level=L2&lookback_hours=24`, and `/api/v1/events?agent_id=<id>&limit=10` with the review token.

## Evidence

Record only bounded, sanitized evidence in `.local/resolve-issues/`: API health, VM health check, temporary process status, aggregate recent event count, source-health status counts, inventory/audit-policy status counts, detection prerequisite status counts, and command names. Do not commit raw event JSON, generated settings, logs, screenshots, or traces.

## Pass criteria

- API health is reachable locally and from the VM.
- Heartbeat is accepted and source-health shows one row per expected L2 source, with unavailable sources marked `missing`, `not_applicable`, or `excepted` rather than silently absent.
- Telemetry coverage reports a defined lookback, recent normalized event counts, source-health row counts, inventory/audit-policy status, and detection prerequisite status for the unique test agent.
- Events or heartbeat evidence exist for the unique test agent, or the telemetry coverage response explains why recent events are unavailable.
- No secrets or raw telemetry are staged or printed in public output.
