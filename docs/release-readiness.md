# Release readiness

- [x] `VERSION` and `CHANGELOG.md` agree.
- [x] `dotnet build Challenger.Siem.sln` and `dotnet test Challenger.Siem.sln` pass on Linux.
- [x] JSON Schemas and synthetic v2 fixtures pass `./scripts/validate-contracts.sh`.
- [x] A disposable empty PostgreSQL database passes apply and validation scripts.
- [x] Service-token REST and MCP reject missing or invalid credentials.
- [x] Agent registration, heartbeat, ingest, query, and retry behavior use synthetic data only.
- [x] No browser application, embedded model provider, OAuth flow, user/session schema, or non-Linux endpoint artifact is present.
- [x] Repository safety validation and `git status --short --ignored` show no private data or generated outputs staged.

Sanitized results from the current validation window are recorded in [End-to-end validation](end-to-end-validation.md). The bounded repository, exact 2.2.0 disposable-VM artifact gate, PostgreSQL/schema gate, and protected-host rollout/recovery gate passed. The initial L4 window completed and honestly reported rollout-window write pressure; post-validation recovery plus the 24-hour/seven-day stability, resource, and noise soaks remain explicitly outstanding and are not implied by these checks.
