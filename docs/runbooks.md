# Runbooks

## Start and verify

1. Load ignored environment configuration containing database, enrollment, and service credentials.
2. Apply the schema to a new empty database with `./scripts/apply-schema.sh`.
3. Validate with `./scripts/validate-schema.sh`.
4. Start `dotnet run --project server/Siem.Api` behind HTTPS.
5. Verify `/health`, then use `./scripts/register-agent.sh` for a synthetic Linux registration.

## Investigate

Use service-authenticated REST or read-only MCP to review events, source health, coverage, alerts, cases, inventory, detections, and graphs. Preserve exact event IDs and time bounds. Treat missing or stale sources as visibility gaps. Use REST confirmation fields for mutations; MCP cannot mutate state.

## Retention

Review storage accounting and perform a dry run before executing managed retention. Manual execution requires the exact `CONFIRM RETENTION DELETE` confirmation and is security-audited. The allowlist is limited to events, heartbeat history, inventory snapshots, and ingestion errors. Current source state, alerts/evidence, cases, graphs, detection metadata, audit, and agents are protected.

## Incident safety

The SIEM does not execute endpoint response commands. Reboots, service changes, firewall/authentication changes, package changes, and data deletion require a separate authorized host procedure. Keep all real evidence under ignored local or approved runtime paths.
