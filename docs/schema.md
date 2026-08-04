# Database and contracts

`contracts/v2/` and `Challenger.Siem.Contracts.V2` define the Linux-only public boundary. Event sources are `linux_journal`, `linux_audit`, `inventory_diff`, and `agent_health`; every event declares `platform=linux`, a stable `source_id`, a checkpoint, deterministic deduplication metadata, and data-handling metadata. `asset-inventory.schema.json` defines both legacy unpaged snapshots and the additive bounded generation/page summary contract. `telemetry-coverage.schema.json` includes additive liveness-monitor, retention-scheduler, and per-agent history-readiness fields.

The PostgreSQL schema is [001_linux_v2.sql](../server/Siem.Api/Database/001_linux_v2.sql). It includes agents, events, heartbeats, source health, inventory, detections, alerts, cases, graphs, saved searches, audit, and retention metadata. Inventory paging metadata stays in the existing bounded summary JSON object; releases through 2.6.0 add no columns or migration. The schema deliberately contains no endpoint fields or tables for other operating systems, browser UI state, embedded chat sessions, OAuth, user accounts, or login sessions.

The optional traffic map reads existing event/source-health rows and does not add PostgreSQL state. Its separate private SQLite cache is an implementation detail, not a public schema: it stores only normalized IP location/ASN/status/provider/timestamp fields and UTC-day quota counts. It contains no raw provider response, event payload, browser credential, or UI session state.

Apply it only to an empty database with `./scripts/apply-schema.sh`; verify with `./scripts/validate-schema.sh`. Back up 1.x data separately if it must be retained. Version 2 does not transform an existing schema.
