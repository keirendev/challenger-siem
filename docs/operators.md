# Operations

Provision the service on Linux behind HTTPS and connect it to a dedicated PostgreSQL database. Provide enrollment and service credentials through a secret manager or ignored environment configuration. Rotate them outside the application and restart the service after updating configuration.

Use REST, a read-only MCP client, or the optional local traffic interface for review. Monitor `/health`, agent last-seen times, queue pressure, source health, storage accounting, retention runs, ingestion errors, security audit events, and—when enabled—geolocation cache/quota/provider degradation. Use explicit confirmation fields on sensitive REST mutations.

Version 2 is a fresh deployment. Export or archive any 1.x data according to local retention requirements, then provision an empty v2 database. Never point `apply-schema.sh` at a populated database. Start with the [single-user deployment guide](deployment-single-user.md), review [coverage](coverage-matrix.md), and validate risky lifecycle/permission/recovery work in the [disposable VM](virtual-machine-validation.md) first.
