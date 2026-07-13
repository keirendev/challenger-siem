# Dependencies and ownership policy

The project should remain open-source and custom-built.

## Policy

- Do not use Docker or container-only workflows for the MVP.
- Do not depend on proprietary SIEM, EDR, log pipeline, or hosted search products.
- Prefer custom application code for ingestion, normalization, buffering, deduplication, and search APIs.
- Third-party dependencies must be open-source and documented here before use.
- Do not copy code or configuration from unrelated local repositories.

## Approved MVP components

| Component | Purpose | License / status |
| --- | --- | --- |
| .NET 8 SDK/runtime | Windows agent and API runtime | MIT, open-source |
| ASP.NET Core | HTTPS API server and Razor Pages web review console | MIT, open-source |
| PostgreSQL | Server event storage | PostgreSQL License, open-source |
| Npgsql | .NET PostgreSQL driver | PostgreSQL License, open-source |
| Microsoft.Data.Sqlite | Agent local queue driver | MIT, open-source |
| SQLite | Agent local queue storage engine | Public domain / open-source ecosystem |
| Microsoft.Extensions.Hosting | Agent worker runtime | MIT, open-source |
| Microsoft.Extensions.Hosting.WindowsServices | Windows Service hosting integration | MIT, open-source |
| Microsoft.Extensions.Http | Typed HTTP client support | MIT, open-source |
| System.Diagnostics.EventLog | Windows Event Log reader APIs | MIT, open-source |
| xUnit.net | Unit test framework | Apache 2.0, open-source |
| Microsoft.NET.Test.Sdk | .NET test runner integration | MIT, open-source |
| Microsoft.AspNetCore.Mvc.Testing | ASP.NET Core web auth/session tests | MIT, open-source |
| JsonSchema.Net | Deterministic draft 2020-12 contract-schema and golden-fixture validation in tests | MIT, open-source |

## Optional project tooling

| Component | Purpose | License / status |
| --- | --- | --- |
| pypsrp | Optional local WinRM helper support for authorized Windows lab validation | MIT, open-source |

## Not in scope for MVP

- Docker / Compose-based development or deployment.
- Proprietary SaaS ingestion, analytics, or alerting platforms.
- OpenSearch, Elasticsearch, ClickHouse, or object storage until the custom PostgreSQL-backed MVP is proven.

## Linux agent runtime

The Linux agent targets .NET 8 and uses the existing Agent.Core SQLite/HTTP reliability dependencies plus the official `Microsoft.Extensions.Hosting.Systemd` integration. systemd is the supported init boundary for this foundation. No audit, eBPF, firewall, kernel-module, privileged-helper, or host-policy package is installed.
