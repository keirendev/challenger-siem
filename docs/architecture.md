# Architecture

The Linux agent collects approved journal, audit, inventory, health, and opt-in higher-tier sources. It normalizes events into the v2 envelope, persists them in a local SQLite queue, and sends bounded HTTPS batches. The server validates identity and deduplication metadata before writing PostgreSQL.

The ASP.NET Core service owns registration, ingestion, search, coverage, inventory, detections, alerts, cases, investigation graphs, administrative settings, and managed retention. It serves JSON only. Human or agent-driven review happens through `/api/v2` or the read-only `/mcp` Streamable HTTP endpoint.

MCP runs in the same process and reads the same repositories. It cannot mutate SIEM state, execute host commands, call model providers, or make outbound AI requests. REST remains the versioned automation and mutation boundary.

Version 2 requires a fresh database. The schema installer refuses databases with existing public tables; there is no 1.x in-place migration path.
