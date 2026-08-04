# Release readiness

- [x] `VERSION` and `CHANGELOG.md` agree.
- [x] `dotnet build Challenger.Siem.sln --no-restore` and the available `dotnet test Challenger.Siem.sln --no-restore` suites pass on Linux; the latest 2.8.1 window reports its 15 environment-gated PostgreSQL skips separately rather than treating them as executed.
- [x] JSON Schemas and synthetic v2 fixtures pass `./scripts/validate-contracts.sh`.
- [x] A disposable empty PostgreSQL database passes apply and validation scripts.
- [x] Service-token REST and MCP reject missing or invalid credentials.
- [x] Agent registration, heartbeat, ingest, query, and retry behavior use synthetic data only.
- [x] The optional browser interface is read-only, locally configured, self-hosted, and has no embedded model provider, OAuth flow, user/session schema, persistent browser credential store, or non-Linux endpoint artifact.
- [x] Repository safety validation and `git status --short --ignored` show no private data or generated outputs staged.

Sanitized results from the current validation window are recorded in [End-to-end validation](end-to-end-validation.md). Version 2.8.1 passed the repository build, available solution tests, contracts, repository-safety, shell, native-parser, and kernel-lifecycle gates. The PostgreSQL schema and repository SQL are unchanged; the last disposable-database gate remains the applicable database evidence because no disposable database was configured for the latest window. The exact single-host agent-only canary passed its initial 30-minute acceptance and one additional complete healthy L4 rolling window with the native helper unchanged. Its dated 24-hour read-only soak is in progress, and seven-day or materially different host/source gates remain explicitly outstanding.
