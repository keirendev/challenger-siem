# Disposable Linux VM validation

Use a disposable libvirt/KVM guest before any test that can affect service startup, permissions, capabilities, audit, firewall, authentication, networking, packages, disk pressure, queue recovery, installation, removal, or reboot durability. The guest must be visible/manageable in virt-manager and contain only synthetic data and VM-only credentials.

## Read-only host preflight

Before creating a guest, verify without changing the host:

- `/dev/kvm`, `virsh`, QEMU, `virt-install`, and virt-manager already exist and are usable;
- an existing active isolated/NAT network and storage pool have adequate capacity;
- current available memory, swap pressure, CPU/load, free storage, and active guest allocation leave conservative headroom;
- the exact domain and volume names do not exist;
- no package install, host service enable/restart, network definition/change, firewall change, or permission expansion is needed.

If any prerequisite is missing, stop and request operator approval for the exact host change. Do not stop or resize an existing guest to make room.

## Provisioning plan

Record privately before creation:

- exact synthetic domain and volume names;
- supported distribution/image URL, official checksum source, and verified digest;
- vCPU, memory, sparse disk, network, graphics/serial console, and autostart settings;
- exact created files/libvirt objects;
- start/pressure stop gates;
- recovery and exact teardown procedure.

A conservative personal-lab starting point is 1 vCPU, 1.5–2 GiB RAM, and a sparse 16 GiB qcow2 disk, but use the host baseline rather than treating those values as permission. Prefer an official generic cloud image, a newly generated VM-only SSH key, the existing NAT network, virtio devices, serial console plus virt-manager graphics, and autostart disabled. Store downloads, keys, known-host entries, and raw validation evidence only under `.local/` or an approved private store.

## Baseline and snapshots

1. Boot the guest and verify the expected distribution, systemd health, free disk, memory, VM-only access, and absence of private host data.
2. Gracefully shut down the guest.
3. Create an offline snapshot named `clean-baseline` before SIEM installation.
4. Start the guest and verify boot/readiness once.
5. Shut it down between bounded test windows when the host is resource-constrained.

Before each risky scenario, create a named checkpoint derived from `clean-baseline`. Revert after the scenario and verify boot, network, authentication, filesystem, and systemd health. A guest reboot is permitted; a current-host reboot is not.

## Validation sequence

1. Publish a private agent bundle and create a synthetic private configuration.
2. Run the lifecycle plan; confirm exact paths, identity, service, permissions, base empty capabilities, no policy mutation, and rollback. If the candidate explicitly selects cross-user executable visibility, separately run its process-visibility plan and validate the one-capability profile, syscall deny list, effective runtime capability, >=80% readability, privacy boundary, and drop-in removal/restart rollback.
3. Install with L3/L4 disabled; validate service start, enrollment, heartbeat, inventory, L1 queue/checkpoint/acknowledgement, and source health.
4. Reboot the guest; verify service recovery, queue durability, checkpoint continuity, and no boot/network/authentication regression.
5. Exercise API/database outage and recovery without changing host networking; verify bounded retry, no deletion before acknowledgement, deduplication, and drain.
6. Use synthetic records for malformed, oversized, prompt-injection, and detection scenarios. Do not inject real credentials or host telemetry.
7. Test bounded queue/disk pressure through a controlled guest-only method with an explicit stop threshold; never fill the host filesystem.
8. Test uninstall and rollback; verify only product-owned guest files/service state are affected and the dedicated identity is retained unless a separately approved procedure says otherwise.
9. Revert to `clean-baseline` before optional L2/L3/L4 or permission/audit/firewall experiments. Each optional source requires its own plan and approval.

### 2.2.0 candidate gate

Use synthetic journal records and the disposable guest only. Do not inspect, enable, or
modify the guest audit producer. Validate the API and agent candidates as one exact
artifact set:

1. restart-always recovery while confirming intentional `systemctl stop` remains
   stopped; server liveness timing, deterministic outage alert, and heartbeat recovery;
2. API outage, bounded queue growth, replay/deduplication, and recovery to a drained
   queue;
3. multi-page inventory delivery/retry, server-derived completeness, page-loss
   degradation, direct procfs/sysfs interfaces, and L4 fingerprint stability;
4. process visibility ratios, PID reuse, deleted/memfd/temporary markers, capability
   decoding, socket descriptor/owner caps and partial attribution, and bounded whole-
   device pressure diagnostics;
5. passive/self-integrity/L4 plan invalidation and reapproval, plus boot/session,
   timer-inventory, sustained-pressure, and directory-signature detection behavior;
6. `Agent:Audit:Enabled=false`, `FacilityDeclaration=undeclared`, audit/lifecycle plan
   output, and synthetic trusted audit transport proving pre-L1 interception with no raw
   content in queue, logs, health, state, poison, REST, or MCP;
7. private WAL corruption/mode/restart/pressure/poison/recovery bounds using synthetic
   state only; privacy-router failure must stop before L1;
8. retention execution dry-run before enabling the hourly scheduler; then verify the
   30-day/100-GiB scheduler status fields; and
9. artifact/config rollback, service health inside five minutes, and preservation of
   credentials, queue, checkpoints, TLS, sandboxing, and unrelated drop-ins.

## Recovery and teardown

Recovery order is virt-manager/serial console, graceful shutdown, snapshot revert, and recreation from the verified base image. Do not change the host firewall, libvirt network, authentication, packages, or boot configuration to recover a guest.

For teardown, first resolve and verify the exact synthetic domain, its state, disks, snapshots, and the exact pool volume. Gracefully shut it down, undefine only that domain with its snapshot/managed state as applicable, delete only its exact volume, and remove only its ignored VM-specific image/key/evidence directory. Never use a broad path, glob, home directory, workspace root, pool directory, or unresolved variable as a deletion target. Record whether recovery remains possible after teardown.

## 2026-07-30 aggregate result

- A small Debian 13 guest passed clean boot, offline snapshot, restart, install, enrollment, inventory, heartbeat, L1 collection, queue/checkpoint acknowledgement, service restart, guest reboot, API outage plus reboot, bounded queue pressure, recovery, uninstall, post-uninstall reboot, and snapshot-revert verification.
- Initial collection without extra privilege correctly reported journal permission denial. The synthetic identity was then added only to the guest's existing `systemd-journal` group; no ACL, journal configuration, capability, audit, firewall, or authentication policy was changed. L1 became healthy only after the prerequisite was effective.
- A stopped API left PostgreSQL unchanged while the durable queue grew across a guest reboot. Recovery drained to zero and delivered three fixed outage records exactly once each.
- With an 8 MiB test limit, the queue stopped within one event of the bound, left ample guest and host free space, then reused freed pages and delivered 600 fixed pressure records exactly once each. The normal 512 MiB configuration was restored before lifecycle removal.
- VM-backed MCP returned bounded, read-only, untrusted-evidence envelopes and correctly reported L1 attained with L2 missing. No permission-denied, degraded, or error source was hidden.
- A later exact-2.0.2 full-tier campaign exercised all nine L2 journal families, all four L3 self-integrity/passive sources, and reviewed L4 posture/performance plus one declared web-role source. L4 activation passed only after the two-step baseline/plan approvals and its mandatory post-reboot ten-minute rolling window; undeclared roles stayed not applicable and Audit Framework stayed unsupported.
- The full-tier campaign delivered real guest process, listener, package, firewall, kernel, scheduler, service, privilege, tamper, posture, SLO, and role evidence through HTTPS, PostgreSQL, detections, alert evidence, REST, MCP, and Codex. A stopped API plus guest reboot retained a 1,021-row queue, recovered to zero with no poison rows, and stored the three fixed outage records under three distinct IDs.
- The VM campaign used the matching 2.0.2 `/api/v2` service. It proves candidate behavior against that service, not compatibility with a separate 1.x deployment; protected-host replacement therefore requires an authenticated v2 route check before the working agent is removed.
- The campaign exposed and closed two release blockers: non-UEFI `mokutil` output was read from the wrong stream, and a nullable PostgreSQL detection-evidence parameter was untyped. Both gained regressions; the exact updated agent/server candidate was rerun through the affected live path.
- Uninstall removed only product-owned paths and unit state, retained the locked non-login identity, and allowed a healthy guest reboot. The guest-only journal membership and disposable CA were removed. Reverting the pre-agent snapshot then proved the identity, CA, service, and product paths absent; SSH and systemd remained healthy.
- The guest definition, exact disk, and recovery snapshots remain available for later approved soak/canary work, with autostart disabled. The guest is powered off.

## 2026-08-01 2.2.0 aggregate result

- The exact 2.2.0 API/agent set passed restart-always recovery, API outage and queue replay, deterministic heartbeat-loss timing/recovery, inventory paging and filtering, procfs/sysfs interfaces, process visibility, bounded socket ownership, per-device disk diagnostics, passive/self-integrity/L4 approval invalidation, retention dry run/scheduler exposure, rollback, and the audit-disabled resource/SLO matrix.
- Audit remained disabled and undeclared. The router reported valid attestation/private state, synthetic trusted audit transport was intercepted before L1, and no audit package, rule, service, privilege, group, ACL, journal, firewall, authentication, or kernel change occurred.
- Two dependency-injection constructor ambiguities and a lifecycle candidate-selection error were found and fixed before protected-host activation. Later host recovery regressions for accepted recovery prefixes, stale completed acknowledgements, and per-source backed-off queue ordering were republished and exact-hash/startup checked in the same powered-off-on-exit guest.
- The final exact candidate ran under the packaged `Restart=always` unit with audit disabled, then the guest shut down cleanly. Long-duration evidence remains a protected-host follow-up, not a VM-unit-test inference.

## 2026-08-03 2.4.0 process-visibility aggregate result

- The exact private 2.4.0 candidate was staged with L4 disabled and newly bound passive/self-integrity approvals. The separate process-visibility plan and fixed systemd drop-in were reviewed before an agent-only restart.
- The running guest agent remained a dedicated non-root process with only effective `CAP_SYS_PTRACE`; `CAP_SYS_ADMIN` was absent, `NoNewPrivileges` and the existing service sandbox remained active, and a direct ptrace invocation was stopped by the fixed syscall filter.
- Cross-user executable and command-line readability both exceeded the 80% source-health threshold. A deliberately invalid-text command line was omitted as bounded partial enrichment while the process source remained healthy, with zero core malformed records and aggregate-only diagnostic output.
- The exact rollback removed only the product-owned drop-in and used an agent-only restart. The effective capability disappeared and the process source returned to an honest degraded state below the executable threshold; queue, credentials, and collector history were preserved.
- The guest was shut down gracefully, reverted to its offline pre-test snapshot, and left powered off with autostart disabled. Synthetic registration was disabled without deleting retained validation evidence.

## 2026-08-04 2.8.1 validation boundary

- The 2.8.1 repository build, focused/full available .NET suites, contract validation, repository-safety validation, shell checks, native parser tests, and isolated kernel lifecycle tests passed. The latest window skipped the environment-gated PostgreSQL tests because no disposable database was configured; the patch changes no PostgreSQL schema or repository SQL.
- A separate new disposable-VM run was not performed for the agent receive/persist patch. The prior signed-helper VM evidence remains valid for the unchanged native helper, protocol, event schema, capabilities, and detach behavior, but it does not by itself validate the changed managed-agent path.
- Because this project is explicitly developed and used on one designated host, the operator accepted same-host agent-only validation for this deployment. The initial 30-minute window plus one additional complete healthy L4 rolling window passed with the helper unchanged; a dated 24-hour read-only soak is now in progress. This exception is deployment-specific and is not evidence for a different host class or general protected-host rollout.
