# Local development without Docker

This project intentionally does not use Docker for the MVP.

## Prerequisites

- .NET 8 SDK
- PostgreSQL 16 or newer, installed directly on the host or on a dedicated database server

## Create the development database

Example Linux commands using local PostgreSQL administration tools:

```bash
sudo -u postgres createuser --pwprompt siem
sudo -u postgres createdb --owner siem challenger_siem
psql "host=localhost port=5432 dbname=challenger_siem user=siem password=<password>" \
  --file server/Siem.Api/Database/001_initial.sql
```

## Configure secrets via environment variables

Do not commit real tokens or passwords.

```bash
export ConnectionStrings__SiemDatabase='Host=localhost;Port=5432;Database=challenger_siem;Username=siem;Password=<password>'
export Auth__EnrollmentToken='<long-random-enrollment-token>'
export Auth__ReviewToken='<long-random-review-token>'
```

## Project version

The project version source of truth is `VERSION`:

```bash
./scripts/current-version.sh
```

Follow `docs/versioning.md` when a change needs a version bump or changelog entry.

## Build and test

```bash
dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln
```

The Windows agent targets `net8.0-windows` and is configured to compile on this Linux development host. Running real event collection still requires Windows.

## Run the API

Default local development:

```bash
dotnet run --project server/Siem.Api
```

Current lab binding for Windows agents:

```bash
./scripts/run-server-4444.sh
```

This binds the API to `http://0.0.0.0:4444`. Windows agents on the libvirt/NAT host network should use:

```text
http://192.168.122.1:4444
```

Prepare copy-ready Windows agent files, including a registered API token in `agentsettings.json`:

```bash
./scripts/prepare-windows-agent-files.sh http://127.0.0.1:4444 http://192.168.122.1:4444 win11-test-001 WIN11-TEST "Windows 11"
```

Copy both files from `dist/windows-agent-copy/` to the Windows host and run `./WindowsAgent.exe` from that folder.

Use HTTPS for all non-local production testing. For local ASP.NET Core development, trust the development certificate if needed:

```bash
dotnet dev-certs https --trust
```

## Optional WinRM lab access

Current authorized local lab topology:

- Windows VM for WinRM/E2E validation: `192.168.122.240`
- API callback URL from the VM to this host: `http://192.168.122.1:4444`

Pi/coding-agent local files such as `.pi/` and `AGENTS.md` are intentionally ignored and are not versioned project artifacts. If the operator provides local WinRM helper tooling, it should read credentials from environment variables or ignored files. Copy the example env file and fill in lab-only values:

```bash
mkdir -p .local
cp examples/winrm.env.example .local/winrm.env
$EDITOR .local/winrm.env
```

Test connectivity only with operator-authorized local tooling, without printing secrets. Use WinRM only against authorized lab hosts, and do not commit `.local/winrm.env`.

## Smoke test with fake data

After creating `.local/dev.env` or exporting the required environment variables, run:

```bash
./scripts/smoke-test-server.sh
```

The script starts the API on local HTTP in `Development`, registers the example agent, ingests `examples/fake-event-batch.json`, queries it back, and writes temporary responses/logs under `.local/`.

Manual equivalent:

```bash
curl -k https://localhost:5001/api/v1/agents/register \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @examples/agent-registration.json

curl -k https://localhost:5001/api/v1/ingest/events \
  -H "Authorization: Bearer <api-token-from-registration>" \
  -H 'Content-Type: application/json' \
  --data @examples/fake-event-batch.json

curl -k 'https://localhost:5001/api/v1/events?windows_event_id=4625' \
  -H "Authorization: Bearer $Auth__ReviewToken"
```
