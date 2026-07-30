# Operations

Provision the service on Linux behind HTTPS and connect it to a dedicated PostgreSQL database. Provide enrollment and service credentials through a secret manager or ignored environment configuration. Rotate them outside the application and restart the service after updating configuration.

Use REST or a read-only MCP client for review. Monitor `/health`, agent last-seen times, queue pressure, source health, storage accounting, retention runs, ingestion errors, and security audit events. Use explicit confirmation fields on sensitive REST mutations.

Version 2 is a fresh deployment. Export or archive any 1.x data according to local retention requirements, then provision an empty v2 database. Never point `apply-schema.sh` at a populated database.
