# Challenger SIEM

Challenger SIEM is a custom, no-Docker SIEM prototype supporting Windows endpoints and a Linux service foundation. It pairs C# endpoint agents with an ASP.NET Core ingestion/review API, PostgreSQL storage, and a server-hosted web review console.

## Current capabilities

- Windows Event Log collection with local agent queueing, retries, channel position state, heartbeat/source-health reporting, and host timezone metadata for review displays.
- Linux endpoint service with enrollment, heartbeat, durable queue delivery, and bounded read-only host/security-posture inventory snapshots; passive Linux event collection remains planned.
- Windows agent installer workflow with plan/install/upgrade/repair/validate/uninstall modes, guarded prerequisite configuration, and a versioned Sysmon L3 profile.
- Agent registration with an enrollment token and per-agent API token authentication.
- PostgreSQL-backed event storage with structured search columns, JSONB raw payloads, server-side deduplication, source-health, inventory, alerts/detections foundations, investigation graphs, and `soc-agent` persistence.
- Authenticated `/api/v1` review APIs for events, agents/source health, telemetry coverage validation, inventory, alerts, detection rules, investigation graphs, platform capabilities, and `soc-agent`.
- Review-token-protected web console for dashboard review, agent inventory, host coverage/source health with telemetry completeness and detection prerequisite status, event search/detail, alert skeletons, investigation graphs, the live `soc-agent` workspace, audit-policy snapshots, and system/about status.
- Synthetic smoke-test and Windows lab validation scripts that keep secrets and collected data out of the public repository.

## Architecture

```text
Windows endpoint -> WindowsAgent.exe --\
                                      -> HTTPS/HTTP-in-lab ingestion API
Linux endpoint   -> Linux agent -----/  -> PostgreSQL storage
                                         -> Review API + web console + soc-agent workspace
```

See [docs/architecture.md](docs/architecture.md) and the [documentation index](docs/index.md) for the full design.

## Public repository safety

This repository is public. Do not commit tokens, passwords, connection strings, private keys, real agent settings, raw endpoint telemetry, Windows Event Log exports, queue/state databases, captures, dumps, screenshots with real host/user data, or local coding-agent files. Use synthetic examples and keep local validation artifacts under ignored `.local/` paths.

## Quickstart without Docker

Prerequisites: .NET SDK, PostgreSQL, Bash-compatible shell for helper scripts, and a private local environment file such as `.local/dev.env` containing `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ReviewToken`.

```bash
./scripts/apply-schema.sh

dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln

./scripts/smoke-test-server.sh
./scripts/smoke-test-web.sh
```

For accumulated disposable test data, start with the dry-run scoped cleanup or fresh-start reset reports. Execute modes require explicit confirmation phrases and are only for operator-owned local test environments:

```bash
./scripts/cleanup-synthetic-data.sh
./scripts/reset-test-environment.sh
```

Run the API and web console locally with the lifecycle helper:

```bash
./scripts/platform.sh start
./scripts/platform.sh status
# when finished:
./scripts/platform.sh stop
```

For a foreground run, use `ASPNETCORE_URLS=http://127.0.0.1:5081 dotnet run --project server/Siem.Api --no-launch-profile`. Open `http://127.0.0.1:5081/login` and sign in with the configured `Auth__ReviewToken`.

## Windows agent lab path

Build/publish the standalone Windows agent:

```bash
./scripts/publish-windows-agent.sh
```

For the authorized local WinRM validation VM, start the API on this host and prepare copy-ready agent files:

```bash
./scripts/run-server-4444.sh
./scripts/prepare-windows-agent-files.sh \
  http://127.0.0.1:4444 \
  http://192.168.122.1:4444 \
  demo-agent-001 DEMO-WIN11 "Windows 11"
```

Copy `dist/windows-agent-copy/WindowsAgent.exe`, the generated `agentsettings.json`, and the optional `dist/windows-agent-copy/Sysmon/` profile directory to the Windows host together. The generated settings file contains an API token; do not print or commit it.

## Repository layout

```text
agent/WindowsAgent/     Windows endpoint agent
agent/LinuxAgent/       Linux endpoint service foundation
server/Siem.Api/        ASP.NET Core ingestion/search API and Razor Pages console
shared/Contracts/       Versioned C# API contracts
contracts/v1/           JSON Schema contracts for external clients
docs/                   Versioned wiki/operator/developer documentation
examples/               Minimal synthetic API examples
scripts/                Local build, schema, smoke, and agent packaging helpers
VERSION                 Project version source of truth
CHANGELOG.md            Release notes and operator-visible changes
```

## Documentation index

Start with [docs/index.md](docs/index.md). Key pages:

- [Operator guide](docs/operators.md)
- [Challenger family alignment](docs/challenger-family-alignment.md)
- [Architecture](docs/architecture.md)
- [API contract v1](docs/api.md) and [schema design](docs/schema.md)
- [Windows agent](docs/agent.md), [installer workflow](docs/windows-agent-installer.md), and [agent configuration](docs/agent-config.md)
- [Linux agent](docs/linux-agent.md), [host coverage specification](docs/linux-host-coverage-spec.md), and [security/privacy design](docs/linux-agent-security.md)
- [Authentication](docs/auth.md) and [TLS deployment](docs/tls.md)
- [Web review console](docs/web.md) and [sanitized screenshot demo](docs/web-console-demo.md)
- [soc-agent](docs/soc-agent.md)
- [Runbooks](docs/runbooks.md) and [troubleshooting](docs/troubleshooting.md)
- [Contributor guide](docs/contributors.md), [development](docs/development.md), and [versioning](docs/versioning.md)

## Versioning

Check the current version with:

```bash
./scripts/current-version.sh
```

`VERSION` drives .NET assembly metadata and local helper defaults. Follow [docs/versioning.md](docs/versioning.md) and update [CHANGELOG.md](CHANGELOG.md) for notable operator-visible changes.
