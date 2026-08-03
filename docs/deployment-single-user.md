# Single-user Linux deployment

This deployment shape is one operator, one Linux SIEM service, one dedicated PostgreSQL database, and one or more Linux endpoint agents. It has no browser application or user-account system. Review uses authenticated REST or read-only MCP.

## 1. Prepare the service

1. Provision an empty PostgreSQL database and a least-privilege application database identity. Version 2 refuses a populated database and has no 1.x in-place migration.
2. Generate three separate secret values: `Auth__EnrollmentToken`, `Auth__ServiceToken`, and the PostgreSQL credential. Store them in a secret manager or an ignored mode-restricted environment file; never put them in `appsettings.json`, shell history, URLs, or Git.
3. Set `ConnectionStrings__SiemDatabase`, apply `./scripts/apply-schema.sh`, and verify with `./scripts/validate-schema.sh`.
4. Run `dotnet run --project server/Siem.Api` for local evaluation or publish the service through the normal .NET deployment workflow. Terminate trusted HTTPS in Kestrel or an approved reverse proxy before accepting non-loopback traffic.
5. Verify `/health`, then make one small service-authenticated `/api/v2/platform/capabilities` request. Do not print the bearer or response records into public logs.

Use a dedicated database backup policy. Monitor API health, database capacity, failed ingestion, security audit records, retention state, agent last-seen, queue pressure, source health, and coverage gaps.

## 2. Prepare the Linux agent

1. Build a private standalone bundle under ignored storage:

   ```bash
   ./scripts/publish-linux-agent.sh linux-x64 .local/linux-agent-bundle
   ```

   Use `linux-arm64` only for an ARM64 endpoint. Keep generated bundles and every real configuration out of Git.
2. Create a private mode-0600 configuration from the synthetic example. Use the HTTPS server URL, a synthetic/operator-chosen agent ID, and either the enrollment token for first registration or a per-agent token. Keep L3/L4 disabled for the first rollout.
3. Ensure the target already has a reviewed locked, non-root `challenger-siem` identity with matching primary group and a non-login shell. Identity creation or any journal group/ACL change is a separate host-administration decision; the installer does not broaden it.
4. From the copied bundle, review the non-mutating plan:

   ```bash
   ./linux-agent.sh plan --payload . --config /private/path/agentsettings.json
   ```

5. Before stopping or removing an existing agent, verify the exact target backend exposes authenticated `/api/v2` registration and ingestion routes. A successful generic `/health` response is insufficient because a 1.x service can be healthy while every 2.x route is absent. Keep the current agent running until this compatibility gate passes.
6. After reviewing affected product paths, service lifecycle, rollback, and current journal visibility, perform the separately approved install. The lifecycle helper writes only the declared product executable, configuration, private state, and systemd unit. Installation enables/starts the product service; an upgrade stages without restart.
7. Run `./linux-agent.sh validate`, then review heartbeat, queue, source-health, and coverage through REST/MCP. Do not grant root, capabilities, groups, ACLs, audit rules, firewall logging, or broader journal access merely to clear a gap. The sole supported exception is the explicit `CrossUserExecutableVisibility=true` workflow: review its separate plan, stage the fixed one-capability profile, VM-validate it, and use `process-visibility-validate` after the separately approved agent restart.

### Moving a 1.x installation to 2.x

Version 2 is a coordinated agent/server cutover, not an in-place database upgrade. Provision the 2.x service against a fresh empty PostgreSQL database, validate its authenticated `/api/v2` routes, generate new enrollment/service credentials, and retain or archive the 1.x database under a separately reviewed policy. Prefer a parallel v2 service during validation. Only after the new service accepts a synthetic registration/ingestion cycle should an endpoint switch its server URL and credentials or replace its working 1.x agent. Preserve the old binary, configuration, queue/state, unit/drop-ins, and trust material in a private rollback archive before the switch.

If the 2.x agent starts but receives missing-route responses, stop it before an unbounded backlog develops, preserve its durable queue privately, and restore the prior agent and state. Do not feed v2 queue records to a v1 agent or claim a VM-only v2 result proves compatibility with a separate v1 deployment.

After the switched endpoint proves fresh heartbeat, inventory, source health, event persistence, detections/evidence, authenticated REST, read-only MCP, audit rows, queue drain, and stable service state, stop the 1.x writer before placing its database into retained read-only service. Verify zero old-database sessions, set `default_transaction_read_only` for both the old database and former application role, and verify the setting through a new least-privilege connection. Keep the old dump, runtime, configuration, TLS material, agent archive, and disabled service definition private for the observation window. Re-enabling v1 is a rollback operation: stop v2 writers first and explicitly reverse the old database/role read-only settings before starting the old writer.

## 3. Safe defaults

- L1 system journal enabled; `IncludeAccessibleUserJournals=false`.
- L2 is an explicit canary target after L1 passes.
- Self-integrity, passive procfs telemetry, and L4 remain disabled until their exact plans/hashes and private validation gates are approved.
- Managed retention defaults to a 30-day target, 100 GiB hard ceiling, and dry-run manual invocation. Manual deletion additionally requires `confirm_impact: "CONFIRM RETENTION DELETE"`.
- MCP is read-only. Use explicit REST only for reviewed mutations.

## 4. First validation

Follow [VM validation](virtual-machine-validation.md) before testing install/uninstall, service recovery, reboot durability, pressure, permission, audit, firewall, or authentication scenarios. Follow [Linux local-host validation](linux-local-host-validation.md) for a protected endpoint. Store real configurations, credentials, telemetry, API responses, logs, queues, databases, and screenshots only in ignored/private evidence.
