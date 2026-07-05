# Local development without Docker

This project intentionally does not use Docker for the MVP. Start with the [documentation index](index.md) for the wiki-style map of operator, API, agent, web-console, and release docs.

## Prerequisites

- .NET 8 SDK
- PostgreSQL 16 or newer, installed directly on the host or on a dedicated database server

## Create the development database

Example Linux commands using local PostgreSQL administration tools:

```bash
sudo -u postgres createuser --pwprompt siem
sudo -u postgres createdb --owner siem challenger_siem
cat > .local/dev.env <<'EOF'
ConnectionStrings__SiemDatabase='Host=localhost;Port=5432;Database=challenger_siem;Username=siem;Password=<password>'
Auth__EnrollmentToken='<long-random-enrollment-token>'
Auth__ReviewToken='<long-random-review-token>'
EOF

./scripts/apply-schema.sh
./scripts/validate-schema.sh
```

To reset a disposable local lab database, drop and recreate the database with PostgreSQL admin tools, then rerun the two schema scripts. Do not run destructive reset commands against shared or client databases.

## Configure secrets via environment variables

Do not commit real tokens or passwords. The API validates these required settings at startup and fails with key names only if any are missing or blank:

- `ConnectionStrings__SiemDatabase`
- `Auth__EnrollmentToken`
- `Auth__ReviewToken`

For shell-only runs you can export them directly:

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

PostgreSQL-backed integration tests are opt-in so contributors do not need Docker or a shared test database. Set one of these ignored/local environment variables to run them:

```bash
export CHALLENGER_SIEM_TEST_DATABASE='Host=localhost;Port=5432;Database=challenger_siem_tests;Username=siem;Password=<password>'
# or
export ConnectionStrings__SiemTestDatabase='Host=localhost;Port=5432;Database=challenger_siem_tests;Username=siem;Password=<password>'
```

When absent, the integration tests report a skip reason and unit/web-auth tests still run.

## Run the API and web review console

Default local development:

```bash
dotnet run --project server/Siem.Api
```

The web review console is hosted by the API process at the API base URL. Open the base URL in a browser and log in with `Auth__ReviewToken`. The login creates an HTTP-only same-origin cookie and does not store the review token in browser local storage.

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

## Documentation and PR checklist

Before opening a pull request, review the [documentation-maintenance checklist](contributors.md#documentation-maintenance-checklist). Update README/wiki/operator docs, API/schema docs, web-console screenshots, changelog, and versioning metadata in the same change set when behavior or public workflows change.

For web-app related changes, run browser E2E against the real app and update [web-console-demo.md](web-console-demo.md) if visible pages, routes, filters, or screenshots change.

## Smoke test with fake data

After creating `.local/dev.env` or exporting the required environment variables, run:

```bash
./scripts/smoke-test-server.sh
```

The script starts the API on local HTTP in `Development`, registers the example agent, ingests `examples/fake-event-batch.json`, queries it back, and writes temporary responses/logs under `.local/`. After it has ingested data, you can also start the API normally and use the web console to review the same events. Set `SIEM_SMOKE_CLEANUP=1` to remove only that documented example agent data after a successful smoke run.

To smoke-test the web console against seeded SIEM data without Docker, run:

```bash
./scripts/smoke-test-web.sh
```

It starts the API, registers a synthetic agent, ingests a synthetic event, logs into the web console with `Auth__ReviewToken`, creates a synthetic `soc-agent` chat tied to that agent, and verifies the dashboard, agent inventory, event search, event detail, investigation graphs, and `soc-agent` pages. Temporary HTML and API responses remain under `.local/`. Set `SIEM_WEB_SMOKE_CLEANUP=1` to remove only the per-run `web-smoke-*` agent data and its agent-linked `soc-agent` chat history after a successful smoke run.

To inspect or clean accumulated synthetic records without running a smoke test, use the guarded cleanup script. Dry-run is the default and prints only aggregate table counts, including dependent `soc_agent_*` and investigation-graph rows selected by a target agent or explicit synthetic selector:

```bash
./scripts/cleanup-synthetic-data.sh
./scripts/cleanup-synthetic-data.sh --no-defaults --agent-id web-smoke-12345
```

For contextless synthetic `soc-agent` chats or standalone synthetic graphs, prefer exact IDs or tight synthetic title prefixes such as `--soc-agent-session-id`, `--soc-agent-title-prefix`, `--graph-id`, or `--graph-title-prefix`.

Execute mode requires an explicit confirmation phrase:

```bash
./scripts/cleanup-synthetic-data.sh --execute --confirm DELETE-SYNTHETIC-DATA
```

Do not use broad selectors or run cleanup against shared/client databases. Prefer exact `--agent-id` values for manual validation records.

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
