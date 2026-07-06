# Architecture

## Goal

Build a custom SIEM pipeline focused first on Windows endpoints.

```text
Windows Endpoint
  -> Custom Windows Agent
  -> HTTPS Log Ingestion Server
  -> PostgreSQL Event Storage
  -> Search / Review API
  -> Web Review Console
```

## MVP scope

- Windows endpoints only.
- Custom C#/.NET Windows service agent.
- Custom ASP.NET Core ingestion, review API, and server-hosted web console.
- PostgreSQL storage with structured columns plus JSONB raw event data.
- No Docker and no proprietary SIEM/logging products.

## Server flow

```text
Agent registration
  -> validate enrollment token
  -> create/update agent record
  -> issue per-agent API token

Event ingestion
  -> validate per-agent bearer token
  -> validate batch and event schema
  -> deduplicate by agent_id + event_id
  -> assign server ingest_time
  -> store structured fields and raw JSON

Search/review API
  -> validate review API token
  -> apply filters
  -> return normalized event envelopes

Web review console
  -> validate review token on login
  -> issue HTTP-only operator session cookie
  -> query PostgreSQL-backed repositories
  -> render dashboard, agent inventory, event search, event detail, and about pages
```

## Agent flow

```text
Read Windows Event Log record
  -> normalize to v1 EventEnvelope
  -> persist to local queue before send
  -> send queued events in batches
  -> delete only after server acknowledgement
  -> update channel position/bookmark after durable queue write
```

## Initial Windows channels

Required for agent MVP:

- `Security`
- `System`
- `Application`

Default optional L2/L3 source manifest channels:

- `Windows PowerShell`
- `Microsoft-Windows-PowerShell/Operational`
- `Microsoft-Windows-Windows Defender/Operational`
- `Microsoft-Windows-TaskScheduler/Operational`
- `Microsoft-Windows-WMI-Activity/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`
- `Microsoft-Windows-WinRM/Operational`
- `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`
- `Microsoft-Windows-GroupPolicy/Operational`
- `Microsoft-Windows-CodeIntegrity/Operational`
- `Microsoft-Windows-AppLocker/EXE and DLL`
- `Microsoft-Windows-AppLocker/MSI and Script`
- `Microsoft-Windows-AppLocker/Packaged app-Execution`
- `Microsoft-Windows-Sysmon/Operational`

## Reliability decisions

- Server deduplication is based on `(agent_id, event_id)`.
- Agent must maintain local channel position state.
- Agent must maintain a durable local queue.
- Server ingest time is generated server-side and does not trust client-provided ingest timestamps.

## Security decisions

- HTTPS is required outside local development.
- Registration uses an enrollment token.
- Registration returns a per-agent API token.
- Agent API tokens are stored hashed server-side.
- Review/search API uses a separate review token for the MVP.
- Web review login uses the same review token and stores only an HTTP-only session cookie in the browser.
- Secrets must not be logged or committed.
