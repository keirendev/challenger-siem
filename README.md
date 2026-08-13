# Challenger SIEM

Challenger SIEM is a Linux-only security telemetry backend. It collects Linux endpoint telemetry, stores searchable events in PostgreSQL, evaluates built-in Linux detections, and exposes bounded REST and read-only MCP interfaces for coding agents such as Codex.

An optional, disabled-by-default local interface at `/ui/traffic` maps retained network socket and separately labeled kernel-flow observations. It adds no user-account, cookie, OAuth, browser-session, or browser-token system. Its two bounded read-only geography routes accept implied authentication only for direct loopback requests; a deployment-supplied service bearer still protects all other review and administration APIs and MCP, while enrollment and per-agent credentials protect endpoint ingestion.

## Components

- `agent/LinuxAgent`: .NET Linux collector with a durable local queue, retry, checkpoints, inventory, and source health.
- `server/Siem.Api`: ASP.NET Core ingestion, search, alerts, cases, graphs, coverage, inventory, detections, retention, REST, and stateless Streamable HTTP MCP.
- `shared/Contracts`: Linux-only v2 request and response contracts.
- `contracts/v2`: JSON Schemas for the public v2 boundary.
- `web/Siem.Ui`: optional React/TypeScript traffic-geography interface, built into the service's ignored static-output directory.
- `server/Siem.Api/Database/001_linux_v2.sql`: fresh-install PostgreSQL schema.

## Optional traffic map

The local map turns retained `linux-network-socket-snapshot-diff` and optional `linux-network-flow-summary` events into a searchable geographic view of remote IP peers. It provides all-retained, 1-hour, 24-hour, 7-day, 30-day, and custom time ranges; metadata filters; an observation timeline; destination summaries; a map and sortable table; destination details; and bounded drill-down to the newest matching events. Credential-free filter state can be shared as a deep link.

Snapshot evidence can miss short-lived sockets and does not measure packets, bytes, or direction. The separately approved Linux x86_64 kernel source adds no-payload cgroup flow summaries with direction and aggregate packet/SKB-byte deltas; these are not wire-accurate accounting. Geolocation is approximate and may identify a provider, CDN, VPN, proxy, or anycast location rather than a physical server. Cited process/IP correlation is available through `/api/v2/network/activity` and `siem_search_network_activity`; `siem_investigate_process_activity` adds a bounded process-instance workflow with lineage, privilege/change context, and source-health qualifications.

The interface can run in the normal backend process or as a dedicated loopback viewer with PostgreSQL transactions forced read-only. A dedicated viewer must use the exact database receiving the live agent's telemetry; it does not read the agent's local queue or collect from the host. Local MMDB enrichment is recommended so country—and optionally city/region/coordinates/ASN—can be resolved synchronously without disclosing destination IPs to an API. Obtain and keep those databases separately outside the checkout. Open the dashboard directly on `localhost` or `127.0.0.1`; it neither requests nor stores the service bearer. See the [traffic-map operator guide](docs/network-geography-ui.md) for the exact loopback trust boundary, configuration, data-source checks, privacy boundaries, and troubleshooting.

## Quick start

Create an empty PostgreSQL database, keep credentials in an ignored local environment file, then run:

```bash
./scripts/apply-schema.sh
dotnet run --project server/Siem.Api
```

Required configuration keys are `ConnectionStrings__SiemDatabase`, `Auth__EnrollmentToken`, and `Auth__ServiceToken`. Production traffic must use HTTPS.

The REST API is under `/api/v2`; MCP is exposed at `/mcp`. To enable the local traffic interface, follow [Network geography UI](docs/network-geography-ui.md). See [documentation](docs/index.md), [single-user deployment](docs/deployment-single-user.md), [coverage](docs/coverage-matrix.md), [API](docs/api.md), [authentication](docs/auth.md), and [MCP](docs/mcp.md).
