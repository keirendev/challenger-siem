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

The Linux agent targets .NET 8 and uses the existing Agent.Core SQLite/HTTP reliability dependencies plus the official `Microsoft.Extensions.Hosting.Systemd` integration. systemd is the supported init and L1/L2 journal boundary. One collector directly invokes the host's existing `journalctl` machine-readable JSON interface at a fixed approved path and performs L2 classification with .NET library code only; this introduces no NuGet/native library, vendored code, package installation, or additional license. `journalctl` is part of systemd (LGPL-2.1-or-later; individual files retain their SPDX notices) and is an external host prerequisite, not redistributed code. No audit, eBPF, firewall, kernel-module, file-integrity, privileged-helper, or host-policy package is installed or enabled.

## Evaluated Linux L3 telemetry components

The [optional Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) evaluates audit, narrowly scoped eBPF, and allowlisted file-integrity approaches. This documentation-only spike adds **no runtime dependency**, package, collector, kernel object, audit rule, fanotify/inotify watch, IMA policy, or host-policy mutation.

| Component or facility | Evaluated purpose | License / dependency decision |
| --- | --- | --- |
| Linux Audit Framework / auditd / audit journal | Future read-only normalization of host-owned audit telemetry when already enabled | Deferred. Treat as an external host facility. Do not bundle or install audit userspace. Upstream audit-userspace repository declares GPL-2.0; any future linking, vendoring, or redistribution requires separate legal/release review. |
| Linux audit rules / watches | Future syscall/file audit coverage | Deferred. Rule/backlog/failure/loginuid settings are host security policy, not an agent dependency. No rules are installed or managed. |
| libbpf / BPF CO-RE | Future eBPF process/network metadata collector | Deferred. libbpf is dual licensed BSD-2-Clause or LGPL-2.1 and depends on libelf/zlib; BPF object builds require Clang/LLVM and kernel BTF compatibility. No native library or BPF object is added. |
| BCC or runtime BPF compilation toolchains | Alternative eBPF implementation path | Rejected for endpoint runtime use because it would add a compiler/kernel-header runtime surface and broader supply-chain burden. |
| fanotify / inotify | Future file-change hints or live monitoring | Deferred for broad use. Direct kernel APIs do not require a third-party library, but live watches add overflow/interference semantics and are not enabled. |
| Linux IMA/EVM | Future measurement-policy integration on hosts that already operate it | Deferred. Kernel/boot/policy configuration is host security policy; no IMA policy or template setting is installed or required. |
| Snapshot-based agent self-integrity | Selected future design candidate for exact agent-owned paths | Adopted as design only. Intended to reuse existing .NET file APIs and Agent.Core transport if implemented; no new dependency is approved by this spike. |
