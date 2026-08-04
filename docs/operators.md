# Operations

Provision the service on Linux behind HTTPS and connect it to a dedicated PostgreSQL database. Provide enrollment and service credentials through a secret manager or ignored environment configuration. Rotate them outside the application and restart the service after updating configuration.

Use REST, a read-only MCP client, or the optional local traffic interface for review. Monitor `/health`, agent last-seen times, queue pressure, source health, storage accounting, retention runs, ingestion errors, security audit events, and—when enabled—geolocation cache/quota/provider degradation. Use explicit confirmation fields on sensitive REST mutations.

For process/IP correlation, prefer `GET /api/v2/network/activity` or `siem_search_network_activity`; both return retained event citations and separate `snapshot_diff` from `kernel_flow`. MCP geography is cache-only by design. Enabling kernel flow collection is a separate signed privileged-source lifecycle, never part of routine install or an API request; follow [Linux kernel network flow telemetry](linux-kernel-network.md).

## Traffic-map checks

- Confirm the map is using the intended backend database by comparing **Retained evidence** with recent authenticated event/source-health results. A viewer does not read the agent queue or discover the backend database automatically.
- Check **All retained** before investigating an empty preset. Presets use telemetry `event_time` in UTC; delayed delivery does not make an older event part of the last 24 hours.
- Keep agents pointed at the normal writable service. A `TrafficMap__ReadOnlyDatabase=true` process is a dedicated loopback viewer and rejects mutating `/api/v2` traffic.
- Distinguish no matching socket evidence from unresolved enrichment. Provider-disabled, pending, excluded, failed, and quota-limited peers can still be searchable in the table.
- Treat result truncation, source-health gaps, and partial process attribution as evidence limitations. Narrow filters rather than extrapolating from bounded rows.
- Keep the bearer, connection string, cache database, API responses, screenshots, and live telemetry in private ignored storage. Reloading the page intentionally clears its in-memory bearer.

Version 2 is a fresh deployment. Export or archive any 1.x data according to local retention requirements, then provision an empty v2 database. Never point `apply-schema.sh` at a populated database. Start with the [single-user deployment guide](deployment-single-user.md), review [coverage](coverage-matrix.md), and validate risky lifecycle/permission/recovery work in the [disposable VM](virtual-machine-validation.md) first.
