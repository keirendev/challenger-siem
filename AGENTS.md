# challenger-siem agent instructions

Project purpose: build a custom SIEM capability focused first on Windows endpoints.

## Scope

- Build a custom Windows endpoint agent and server-side ingestion/storage capability.
- Initial target architecture:
  - Windows endpoint agent
  - HTTPS ingestion API
  - PostgreSQL-backed event storage
  - Basic event search/review API
  - Detection logic later
- Initial log sources:
  - Windows Security
  - System
  - Application
  - Windows PowerShell
  - Microsoft-Windows-PowerShell/Operational
  - Microsoft-Windows-Sysmon/Operational when present
  - Microsoft-Windows-Windows Defender/Operational when present

## Repository boundaries

- Do not rely on any outside projects or resources on this host.
- Do not inspect, copy, import, or adapt code/config/docs from sibling directories or unrelated local repositories.
- Keep all project work inside this repository unless the operator explicitly says otherwise.
- Prefer creating project-local docs, contracts, code, and tests over referencing local external material.

## Implementation guidance

- Prefer C#/.NET for the Windows agent and ASP.NET Core for the server unless requirements change.
- Prefer PostgreSQL for server event storage, with structured searchable columns plus raw JSON payload storage.
- Design shared contracts carefully: event envelope, batch ingest request, registration request, heartbeat request, and server acknowledgements.
- Treat reliability as core functionality:
  - local disk queue on the agent
  - retry with backoff
  - deduplication on the server
  - tracked event positions/bookmarks per channel
- Treat security as core functionality:
  - HTTPS only
  - enrollment token for initial MVP
  - per-agent token after registration
  - no secret logging
  - protected local config paths on Windows

## Development workflow

- Start with small, testable milestones.
- Document design decisions in project-local docs before broad implementation.
- Keep schemas and API contracts versioned.
- Add tests for parsing, normalization, queue behavior, API validation, and database writes.
- Keep MVP simple: first prove fake event ingestion and storage, then one real Windows Event Log channel, then expand.

## Version management

- Follow `docs/versioning.md` for every project change set.
- Use `VERSION` as the project version source of truth; check it with `./scripts/current-version.sh`.
- When code, API, schema, configuration, packaging, or operator-visible behavior changes require a SemVer bump, update `VERSION` and `CHANGELOG.md` in the same change set.
- For docs-only, tests-only, or no-artifact refactors, explicitly report that no version bump was needed.
- Treat API/schema contract versions separately from the project release version; create a new route/schema version for incompatible contract changes.
- Do not update generated `dist/`, `bin/`, or `obj/` artifacts unless the operator explicitly asks for release artifacts.

## Windows lab access via WinRM

- Project-local Pi WinRM support lives in `.pi/extensions/winrm.ts` and `.pi/skills/winrm/`.
- Current operator-authorized local lab VM: `192.168.122.240`.
- When validating agent-to-server flows from that VM, the Windows agent must target this host machine at `http://192.168.122.1:4444`.
- Use WinRM only for operator-authorized Windows lab hosts related to this project.
- Do not scan, brute-force, bypass authentication, or run commands against unknown systems.
- Keep WinRM credentials in `.local/winrm.env`, environment variables, or another ignored local file. Never commit or print passwords, API tokens, or full agent settings containing secrets.
- Prefer the `winrm` Pi tool when active; otherwise use `python3 .pi/skills/winrm/scripts/winrm.py ...` from the repository root.
- Ask before rebooting hosts, changing firewall/authentication settings, uninstalling services, deleting data, or clearing event logs.

## Initial MVP target

1. Server receives a fake Windows event over HTTPS.
2. Server validates and stores it.
3. Server can return it via a basic query endpoint.
4. Agent reads one Windows Event Log channel.
5. Agent sends normalized events in batches.
6. Agent buffers and retries when the server is unavailable.
