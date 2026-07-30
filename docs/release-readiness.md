# Release readiness

- [ ] `VERSION` and `CHANGELOG.md` agree.
- [ ] `dotnet build Challenger.Siem.sln` and `dotnet test Challenger.Siem.sln` pass on Linux.
- [ ] JSON Schemas and synthetic v2 fixtures pass `./scripts/validate-contracts.sh`.
- [ ] A disposable empty PostgreSQL database passes apply and validation scripts.
- [ ] Service-token REST and MCP reject missing or invalid credentials.
- [ ] Agent registration, heartbeat, ingest, query, and retry behavior use synthetic data only.
- [ ] No browser application, embedded model provider, OAuth flow, user/session schema, or non-Linux endpoint artifact is present.
- [ ] Repository safety validation and `git status --short --ignored` show no private data or generated outputs staged.
