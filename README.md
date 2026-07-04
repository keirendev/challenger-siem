# Challenger SIEM

Custom SIEM capability focused first on Windows endpoints.

The MVP is custom-built from open-source components only. Docker is intentionally not used.

## v0.1 goal

1. A Windows endpoint agent normalizes Windows Event Log records.
2. The agent buffers events locally and sends batches over HTTPS.
3. The ASP.NET Core ingestion API validates, deduplicates, and stores events in PostgreSQL.
4. A basic review API can query recent events by host, agent, channel, event ID, time range, or keyword.

## Repository layout

```text
agent/WindowsAgent/     Windows endpoint agent
server/Siem.Api/        ASP.NET Core ingestion/search API
shared/Contracts/       Versioned C# API contracts
contracts/v1/           JSON schema contracts for external clients
docs/                   Architecture, API, schema, auth, and agent config docs
.pi/                    Project-local Pi prompts, skills, and WinRM helper
AGENTS.md               Coding-agent project guidance
VERSION                 Project version source of truth
CHANGELOG.md            Release notes and operator-visible changes
```

## Build

```bash
dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln
./scripts/publish-windows-agent.sh
```

Standalone Windows agent output:

```text
dist/windows-agent-win-x64/WindowsAgent.exe
```

## Current lab run target

Authorized WinRM validation VM: `192.168.122.240`.

Run the server on this machine for Windows agents:

```bash
./scripts/run-server-4444.sh
```

Agent `ServerBaseUrl` for the Windows host:

```text
http://192.168.122.1:4444
```

Prepare copy-ready Windows agent files, including a registered `agentsettings.json`:

```bash
./scripts/prepare-windows-agent-files.sh http://127.0.0.1:4444 http://192.168.122.1:4444 win11-test-001 WIN11-TEST "Windows 11"
```

Copy both files from `dist/windows-agent-copy/` to the Windows host and run `./WindowsAgent.exe`.

## Versioning

Project version is managed in `VERSION` and can be checked with:

```bash
./scripts/current-version.sh
```

See `docs/versioning.md` for the version bump and changelog workflow.

## Current build target

The first practical target was the server MVP:

- receive a fake Windows event JSON batch
- authenticate the agent using a per-agent token
- store events in PostgreSQL with JSONB raw payloads
- return stored events from `GET /api/v1/events`

See:

- `docs/architecture.md`
- `docs/api.md`
- `docs/schema.md`
- `docs/auth.md`
- `docs/agent.md`
- `docs/dependencies.md`
- `docs/development.md`
- `docs/milestones.md`
- `docs/versioning.md`
- `server/Siem.Api/Database/001_initial.sql`
- `examples/agent-registration.json`
- `examples/fake-event-batch.json`
