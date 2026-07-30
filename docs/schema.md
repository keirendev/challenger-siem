# Database and contracts

`contracts/v2/` and `Challenger.Siem.Contracts.V2` define the Linux-only public boundary. Event sources are `linux_journal`, `linux_audit`, `inventory_diff`, and `agent_health`; every event declares `platform=linux`, a stable `source_id`, a checkpoint, deterministic deduplication metadata, and data-handling metadata.

The PostgreSQL schema is [001_linux_v2.sql](../server/Siem.Api/Database/001_linux_v2.sql). It includes agents, events, heartbeats, source health, inventory, detections, alerts, cases, graphs, saved searches, audit, and retention metadata. It deliberately contains no endpoint fields or tables for other operating systems, browser UI state, embedded chat sessions, OAuth, user accounts, or login sessions.

Apply it only to an empty database with `./scripts/apply-schema.sh`; verify with `./scripts/validate-schema.sh`. Back up 1.x data separately if it must be retained. Version 2 does not transform an existing schema.
