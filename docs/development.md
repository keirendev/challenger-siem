# Development

Requirements: Linux, .NET 8 SDK, PostgreSQL client/server, Bash, and Python 3 for repository validation scripts. Node.js/npm is required only to build or test the optional traffic interface.

Keep all secrets and runtime telemetry under ignored `.local/` paths. A typical local environment defines `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ServiceToken` in `.local/dev.env`.

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

Kernel-network or lifecycle changes also require the native and isolated lifecycle gates:

```bash
make -C agent/KernelNetwork/Native test
./tests/kernel-network-lifecycle/run.sh
bash -n scripts/*.sh tests/*/run.sh packaging/linux/challenger-siem-audit-health
```

Use `./scripts/current-version.sh` to verify the release identity from `VERSION`. Generated native, UI, publish, bundle, and validation outputs remain ignored and must not be committed.

Frontend validation is explicit so ordinary backend builds do not require Node.js:

```bash
cd web/Siem.Ui
npm ci
npm test
npm run build
```

The generated build is written to the ignored `server/Siem.Api/wwwroot/ui/` directory. See [Network geography UI](network-geography-ui.md) for private local configuration and the combined launcher.

The launcher uses the `ConnectionStrings__SiemDatabase` currently loaded in the environment. For live local review, that must be the same database used by the active writable backend; no runtime discovery or agent-queue fallback occurs. Use `TrafficMap__ReadOnlyDatabase=true` only for a separate loopback viewer, never for the process receiving agent telemetry or serving audited MCP workflows.

The schema requires an empty database. Tests and examples must use synthetic hostnames, users, addresses, IDs, and payloads. The only browser surface is the optional read-only traffic interface; do not add an embedded model client, user-account/session system, or non-Linux endpoint project.
