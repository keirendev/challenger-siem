# TLS

Production REST, agent ingest, and MCP traffic must use HTTPS. Terminate TLS in Kestrel or an approved reverse proxy, use a certificate trusted by Linux endpoints and MCP clients, and disable plaintext access outside isolated development.

Certificate private keys, trust bundles with private material, passwords, and deployment topology belong in secret-managed or ignored paths. Verify certificate expiry, hostname matching, chain trust, and rotation in deployment monitoring.
