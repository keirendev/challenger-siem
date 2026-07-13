# Linux agent

The .NET 8 Linux agent is a first-class endpoint service built on the same `Agent.Core` durable SQLite queue, acknowledgement, retry metadata, deterministic serialization, configuration hashing, and v1 transport used by the Windows agent. It enrolls through `/api/v1/agents/register`, stores the resulting credential in its mode-0600 configuration, sends heartbeats, uploads bounded host and security-posture inventory, and drains already-durable queued events gradually.

Passive journal and audit event collection remains planned. An empty source manifest is therefore an explicit foundation state, not a claim of L1 event coverage. Inventory snapshots provide current-state observations; they do not change server coverage calculations or prove that passive telemetry sources are healthy.

## Supported capability

- Linux on x86-64 or ARM64 with systemd and a .NET 8 published application payload.
- Dedicated locked `challenger-siem` service identity created by the operator or package manager before installation.
- HTTPS server URL only. Configuration: `/etc/challenger-siem-agent/agentsettings.json` (0600). Queue/state: `/var/lib/challenger-siem-agent` (0700). Binary: `/opt/challenger-siem-agent`. Unit: `/etc/systemd/system/challenger-siem-agent.service`.
- Enrollment, heartbeat, durable queue delivery, and read-only inventory upload through the existing v1 agent APIs.
- No Linux capability, audit/firewall/authentication/kernel/MAC-policy mutation, source-group enrollment, privileged helper, or arbitrary command/path collection interface.

The unit passes only the configuration path, never a credential. It denies privilege escalation, capabilities, home/device/kernel/control-group access, write access outside private state, and limits memory/tasks and restart bursts.

## Bounded inventory snapshots

Each collection produces these snapshot categories:

- `linux_host_identity` for allowlisted operating-system and kernel identity fields;
- `linux_users` and `linux_groups` for names and numeric IDs only;
- `linux_services` and `linux_timers` for bounded systemd unit state, or `not_applicable` on a detected non-systemd host;
- `linux_packages` and `linux_available_updates` for package names and versions without repository configuration or content;
- `linux_interfaces` and `linux_listeners` for interface state and listening protocol/port only;
- `linux_mounts` for filesystem-type counts without mount paths;
- `linux_firewall` for high-level nftables, firewalld, or UFW state without rules;
- `linux_ssh` for the allowlisted effective values of `PermitRootLogin`, `PasswordAuthentication`, and `PubkeyAuthentication` before the first `Match` block, without SSH configuration text;
- `linux_mandatory_access_control` for AppArmor and SELinux state;
- `linux_secure_boot` when the fixed provider is available; and
- `linux_agent_integrity` for observable regular-file, owner-ID, and mode posture of the fixed agent configuration and executable paths.

Every snapshot reports exactly one collection state in `summary.state`: `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, or `malformed`. It also reports a stable error code, item count, and explicit truncation marker. Missing tools, files, permissions, applicability, malformed output, and deadlines are therefore not represented as healthy or silently absent.

The agent emits at most 20 snapshots and 200 items per snapshot. The default serialized batch budget is 256 KiB, configurable only from 64 KiB through 512 KiB; deterministic trimming marks both snapshot and payload-budget truncation. Source command output is capped at 16 or 64 KiB according to the fixed catalog, command timeouts are 5, 10, or 20 seconds, file operations time out after 5 seconds, and the default whole-collection deadline is 120 seconds (allowed range 10-300 seconds).

## Schedule and configuration

Inventory runs in its own non-overlapping hosted service, independently of heartbeat, durable queue drain, and future passive collection. Commands are requested at below-normal process priority where the operating system permits. A slow or failed inventory cycle does not block the heartbeat/queue worker.

`Agent.InventoryIntervalSeconds` defaults to one hour (`3600`) and has an enforced minimum of five minutes (`300`). `Agent.Inventory.StartupDelaySeconds` defaults to 30 seconds and may be set from 0 through 300 seconds, allowing enrollment and the primary transport worker to start first. Relevant defaults are:

```json
{
  "Agent": {
    "InventoryIntervalSeconds": 3600,
    "Inventory": {
      "StartupDelaySeconds": 30,
      "CollectionTimeoutSeconds": 120,
      "MaxSerializedBytes": 262144
    }
  }
}
```

Inventory is a periodic current-state upload rather than durable passive telemetry. If an upload fails, the next scheduled collection provides a fresh bounded snapshot; heartbeat and queued-event recovery continue on their separate path.

## Read-only source policy

The collector catalog fixes every executable path candidate, argument list, exact file path, accepted exit code, timeout, and output cap. Commands are launched directly without a shell, with a cleared environment and only fixed locale/PATH values. Timed-out, cancelled, or output-capped commands are terminated as a process tree. File reads accept only catalogued regular, single-link files, reject symbolic links and special files, use no-follow access, and cap bytes before parsing. Caller cancellation and the whole-collection deadline flow through every operation.

Parsers serialize only bounded allowlisted fields. They exclude raw stdout/stderr, arbitrary file contents and paths, account descriptions/home directories/shells, group membership, IP addresses, process details, command lines, firewall rules, repository configuration/content, and unapproved SSH directives. Errors and logs contain stable types/codes rather than source output.

Collection is strictly observational: it does not install tools, refresh package metadata, alter services, audit policy, firewall rules, SSH settings, kernel state, AppArmor/SELinux policy, Secure Boot, file ownership, or file modes. The `linux_agent_integrity` category reports observable file metadata only. It is not cryptographic attestation, does not currently hash files, and is not tamper-proof against a privileged or kernel-level adversary; heartbeat gaps and permission drift remain review signals rather than proof of integrity.

## Safe lifecycle

First publish the app into a private local directory and create a mode-0600 configuration from the synthetic example. Never put real settings in the repository.

```bash
./scripts/linux-agent.sh plan
./scripts/linux-agent.sh install --payload <private-publish-dir> --config <private-mode-0600-config>
./scripts/linux-agent.sh upgrade --payload <private-publish-dir> --config <private-mode-0600-config>
./scripts/linux-agent.sh validate
./scripts/linux-agent.sh uninstall
```

`plan` is read-only. Every mutating mode completes platform/init/architecture/privilege/payload/config/identity preflights before creating a path. Install and uninstall touch only the four declared project paths. Uninstall intentionally retains the service identity because account removal can affect operator-managed ownership. No secret is printed. Sandbox `--root` and `--no-service-control` options exist for CI lifecycle tests and must not be used as deployment shortcuts.

## Server and contract boundary

Linux snapshots use the existing additive generic `POST /api/v1/agents/inventory` payload and existing v1 snapshot/item fields. The same generic records remain available through `GET /api/v1/inventory`; no `/api/v2`, schema replacement, or incompatible Windows inventory behavior is introduced. This agent capability does not add Linux-specific server coverage evaluation or claim Linux event persistence/search coverage.

## Validation and recovery

Run `dotnet test Challenger.Siem.sln` and `./scripts/validate-repository-safety.sh`. On a specifically approved disposable systemd host, inspect `systemctl show` for the documented identity, capability, restart, memory, and filesystem restrictions; keep raw output under `.local/`. Stop rollout on credential exposure, unauthorized host mutation, queue corruption, host impact, or resource-bound breach. Uninstall the project-owned files, revoke the agent credential, and retain only sanitized aggregate findings.
