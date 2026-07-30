# Development

Requirements: Linux, .NET 8 SDK, PostgreSQL client/server, Bash, and Python 3 for repository validation scripts.

Keep all secrets and runtime telemetry under ignored `.local/` paths. A typical local environment defines `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ServiceToken` in `.local/dev.env`.

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
dotnet build Challenger.Siem.sln
dotnet test Challenger.Siem.sln
./scripts/validate-contracts.sh
./scripts/validate-repository-safety.sh
```

The schema requires an empty database. Tests and examples must use synthetic hostnames, users, addresses, IDs, and payloads. Do not add a browser application, embedded model client, or non-Linux endpoint project.
