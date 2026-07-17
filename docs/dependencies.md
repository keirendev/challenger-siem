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
| ModelContextProtocol.AspNetCore 1.4.1 | Stateless Streamable HTTP MCP server, tool/resource/prompt discovery, and ASP.NET Core authorization integration | Apache-2.0, open-source official .NET MCP SDK; direct dependency owned by the server project |
| JsonSchema.Net | Deterministic draft 2020-12 contract-schema and golden-fixture validation in tests | MIT, open-source |
| Microsoft.Playwright for .NET | Real-application browser release gates for Razor Pages, accessibility, security, and performance validation | Apache 2.0 Playwright project / Microsoft NuGet package; browser binaries are installed explicitly under ignored `.local/release-gates/ms-playwright/` and are not redistributed. |
| Python 3 | Target-side parsing and hashing for the reviewed Linux lifecycle `plan` helper only | Python Software Foundation License; external prerequisite, not bundled or used by the steady-state self-contained agent service. |

## Optional project tooling

| Component | Purpose | License / status |
| --- | --- | --- |
| pypsrp | Optional local WinRM helper support for authorized Windows lab validation | MIT, open-source |

## Optional soc-agent provider runtime

| Component | Purpose | License / status |
| --- | --- | --- |
| OpenAI Codex CLI (`codex app-server`) | Official token-free ChatGPT account status and device-code login/refresh control for the optional external `soc-agent` provider | Apache-2.0, official OpenAI CLI; operator-installed external runtime, not vendored or redistributed by Challenger SIEM. |

`SocAgent:CodexAppServer` is enabled by default so the integration is available, while the overall `soc-agent` provider remains local and external calls remain disabled until explicitly configured. The server resolves `codex` from an operator-configured executable path, the service `PATH`, or the service account's `~/.local/bin/codex`; that executable may legitimately be a symlink into the official package tree under `~/.codex/packages`. The process still receives an isolated `.local/soc-agent/codex` `CODEX_HOME` and a forced file credential store there. Global Codex credential/configuration state such as `~/.codex/auth.json` or `config.toml`, and all Pi state, are not credential sources. No credentials are migrated into the isolated state directory, so an administrator must complete a fresh SIEM-managed login. This broker is currently supported only when the SIEM API runs on a non-Windows host with enforceable owner-only file modes; Windows endpoint collection is unaffected, while a Windows-hosted API fails this optional provider path closed pending owner-only DACL enforcement.

## Frontend architecture decision

The [frontend architecture ADR](frontend-architecture-adr.md) selects enhanced ASP.NET Core/Razor Pages as the only active web-console architecture for high-density search and timeline work. No TypeScript frontend, npm package manager, lockfile, bundler, client router, external component library, CDN, analytics script, font service, or generated static build output is approved by this spike.

The release-gate browser suite uses Microsoft.Playwright from .NET tests only; it does not create a Node/TypeScript application toolchain. Install browser binaries with `./scripts/release-gates.sh install-browsers`, which places runtime artifacts under ignored `.local/release-gates/`. See [release-gates.md](release-gates.md) for license/supply-chain ownership, invocation, budgets, and cleanup.

TypeScript ecosystem candidates such as TypeScript, Vite, React, Svelte, and table-virtualization/component packages were stopped at preflight because they did not demonstrate a material measurable benefit over the existing Razor path after accounting for auth/session/CSRF/CSP design, server-side protected-field authorization, build/release complexity, testing, and supply-chain ownership. Reconsidering a separate frontend requires a new ADR with passing gates, a dependency/license inventory, synthetic measurements, and complete removal of rejected prototype artifacts.

## Not in scope for MVP

- Docker / Compose-based development or deployment.
- Proprietary SaaS ingestion, analytics, or alerting platforms.
- A separate TypeScript frontend or JavaScript build pipeline for the SIEM console until a future ADR demonstrates a material benefit and passes the security/accessibility/dependency gates.
- OpenSearch, Elasticsearch, ClickHouse, or object storage until the custom PostgreSQL-backed MVP is proven.

## Linux agent runtime

The Linux agent targets .NET 8 and uses the existing Agent.Core SQLite/HTTP reliability dependencies plus the official `Microsoft.Extensions.Hosting.Systemd` integration. The published endpoint binary is self-contained, so the target does not need a separately installed .NET runtime. systemd is the supported init and journal boundary. The bundled lifecycle `plan` helper currently requires target-side Python 3 for bounded configuration parsing and deterministic plan hashing; identity checks use the host's `getent`/`id`, and root-triggered installed L4 preflight uses `runuser`. Install/steady-state collection does not import Python code, and the bundle installs none of these host tools. One collector directly invokes the host's existing `journalctl` machine-readable JSON interface at a fixed approved path, selects only one of two fixed local scopes, independently probes system visibility in the broader scope, and performs L2 plus structured L4 role classification with .NET library code only; this introduces no NuGet/native library, vendored code, package installation, privilege, or additional license. `journalctl` is part of systemd (LGPL-2.1-or-later; individual files retain their SPDX notices) and is an external host prerequisite, not redistributed code. L4 posture uses existing sanitized inventory/cryptographic APIs; rolling SLO sampling uses existing process APIs and fixed `/proc/self/io`. No audit, eBPF, firewall, kernel-module, file-integrity, application-log-reader, privileged-helper, or host-policy package is installed or enabled.

## Evaluated Linux L3 telemetry components

The [optional Linux L3 telemetry ADR](linux-l3-telemetry-adr.md) evaluates audit, narrowly scoped eBPF, allowlisted file integrity, and bounded procfs snapshots. Challenger SIEM implements disabled-by-default explicit-opt-in snapshot collectors for agent self-integrity and passive process/socket/host-behaviour evidence. These implementations add **no third-party runtime dependency**, package, kernel object, audit rule, fanotify/inotify watch, IMA policy, broad/live file monitor, or host-policy mutation.

| Component or facility | Evaluated purpose | License / dependency decision |
| --- | --- | --- |
| Linux Audit Framework / auditd / audit journal | Future read-only normalization of host-owned audit telemetry when already enabled | Deferred. Treat as an external host facility. Do not bundle or install audit userspace. Upstream audit-userspace repository declares GPL-2.0; any future linking, vendoring, or redistribution requires separate legal/release review. |
| Linux audit rules / watches | Future syscall/file audit coverage | Deferred. Rule/backlog/failure/loginuid settings are host security policy, not an agent dependency. No rules are installed or managed. |
| libbpf / BPF CO-RE | Future eBPF process/network metadata collector | Deferred. libbpf is dual licensed BSD-2-Clause or LGPL-2.1 and depends on libelf/zlib; BPF object builds require Clang/LLVM and kernel BTF compatibility. No native library or BPF object is added. |
| BCC or runtime BPF compilation toolchains | Alternative eBPF implementation path | Rejected for endpoint runtime use because it would add a compiler/kernel-header runtime surface and broader supply-chain burden. |
| fanotify / inotify | Future file-change hints or live monitoring | Deferred for broad use. Direct kernel APIs do not require a third-party library, but live watches add overflow/interference semantics and are not enabled. |
| Linux IMA/EVM | Future measurement-policy integration on hosts that already operate it | Deferred. Kernel/boot/policy configuration is host security policy; no IMA policy or template setting is installed or required. |
| Snapshot-based agent self-integrity | Exact agent-owned binary, service-unit, configuration metadata, and state/config directory snapshots | Implemented as a disabled-by-default explicit opt-in source using existing .NET file APIs and Agent.Core transport. It adds no new dependency and does not collect file contents or secret values. |
| Procfs process/socket/resource snapshots | Polling-honest process and TCP/UDP socket differences plus aggregate host-behaviour samples | Implemented as an approval-gated source using existing .NET APIs and fixed procfs files. It adds no native dependency, `AF_NETLINK`, kernel program, capability, packet capture, or host-policy change. |
| Linux L4 posture/SLO/role sources | Approved sanitized-inventory fingerprints, rolling process counters, and structured role journal families | Implemented with existing .NET, Agent.Core, inventory, and journal facilities. No new package, native library, application audit plugin, log reader, privilege, or policy change is added. |
