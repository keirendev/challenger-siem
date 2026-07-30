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
2. Run the lifecycle plan; confirm exact paths, identity, service, permissions, no capabilities, no policy mutation, and rollback.
3. Install with L3/L4 disabled; validate service start, enrollment, heartbeat, inventory, L1 queue/checkpoint/acknowledgement, and source health.
4. Reboot the guest; verify service recovery, queue durability, checkpoint continuity, and no boot/network/authentication regression.
5. Exercise API/database outage and recovery without changing host networking; verify bounded retry, no deletion before acknowledgement, deduplication, and drain.
6. Use synthetic records for malformed, oversized, prompt-injection, and detection scenarios. Do not inject real credentials or host telemetry.
7. Test bounded queue/disk pressure through a controlled guest-only method with an explicit stop threshold; never fill the host filesystem.
8. Test uninstall and rollback; verify only product-owned guest files/service state are affected and the dedicated identity is retained unless a separately approved procedure says otherwise.
9. Revert to `clean-baseline` before optional L2/L3/L4 or permission/audit/firewall experiments. Each optional source requires its own plan and approval.

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
