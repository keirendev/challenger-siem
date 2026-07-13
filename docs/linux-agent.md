# Linux agent foundation

The .NET 8 Linux agent is a first-class endpoint service built on the same `Agent.Core` durable SQLite queue, acknowledgement, retry metadata, deterministic serialization, configuration hashing, and v1 transport used by the Windows agent. It enrolls through `/api/v1/agents/register`, stores the resulting credential in its mode-0600 configuration, sends heartbeats and bounded host inventory, and drains already-durable queued events gradually. Passive journal collection is delivered separately; an empty source manifest is therefore an explicit foundation state, not a claim of L1 coverage.

## Supported foundation

- Linux on x86-64 or ARM64 with systemd and .NET 8 published application payload.
- Dedicated locked `challenger-siem` service identity created by the operator or package manager before installation.
- HTTPS server URL only. Configuration: `/etc/challenger-siem-agent/agentsettings.json` (0600). Queue/state: `/var/lib/challenger-siem-agent` (0700). Binary: `/opt/challenger-siem-agent`. Unit: `/etc/systemd/system/challenger-siem-agent.service`.
- No Linux capability, audit/firewall/authentication/kernel/MAC-policy mutation, source-group enrollment, or privileged helper.

The unit passes only the configuration path, never a credential. It denies privilege escalation, capabilities, home/device/kernel/control-group access, write access outside private state, and limits memory/tasks and restart bursts.

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

## Validation and recovery

Run `dotnet test Challenger.Siem.sln` and `./scripts/validate-repository-safety.sh`. On a specifically approved disposable systemd host, inspect `systemctl show` for the documented identity, capability, restart, memory, and filesystem restrictions; keep raw output under `.local/`. Stop rollout on credential exposure, unauthorized host mutation, queue corruption, host impact, or resource-bound breach. Uninstall the project-owned files, revoke the agent credential, and retain only sanitized aggregate findings.
