# Issue 190 implementation plan

## Context and requirements

Deliver the dependency-ordered Linux service foundation from epic #184 after the cross-platform contracts, storage, and Agent.Core work. Acceptance means: a hardened explicit-identity/capability-free systemd service; mode-0600 secret storage with no unit/log argument disclosure; read-only planning; project-path-only lifecycle operations; enrollment, heartbeat, inventory, durable restart-safe queue and bounded recovery drain; and clear preflight failure before writes.

## Implementation

1. Add a .NET 8 Linux worker that consumes the active Agent.Core queue/transport/acknowledgement/config-hash path rather than cloning reliability code.
2. Bind and validate HTTPS configuration, enroll with v1, atomically persist the returned token at mode 0600, record non-secret state, initialize the durable queue, heartbeat, inventory, and bounded queue drain.
3. Add a capability-free, dedicated-user systemd unit with restart/resource/filesystem/kernel/device hardening.
4. Add deterministic plan/install/upgrade/validate/uninstall shell workflows. Complete all unsupported-platform, architecture, init, privilege, payload, config-mode, and identity preflights before mutation. Limit removal to product-owned paths and make plan non-mutating.
5. Add synthetic configuration, unit and Linux sandbox lifecycle/plan tests, operator docs/runbooks and documentation index updates.

## Validation and acceptance mapping

Build/test the complete solution; run repository safety checks; test read-only plan snapshots, mode 0600, secret-free unit, sandbox install/validate/uninstall ownership boundaries, unsupported preflight behavior, inventory bounds, and existing Agent.Core reliability regressions. Local live systemd validation is optional and requires explicit host-mutation approval, so CI-compatible sandbox tests are the default. Inspect ignored/staged status and candidate filenames before publication.

## Version/config/docs impact

This is a backward-compatible new agent capability: bump MINOR from 0.23.0 to 0.24.0 and update `CHANGELOG.md`. Preserve `/api/v1` and `contracts/v1` unchanged. Linux configuration is a new platform-specific shape; no migration or compatibility path is introduced. Update capability/security status, README/index/operator/runbook/troubleshooting/dependency guidance.

## Risks, assumptions, cleanup

Systemd sandbox directives can vary by distribution; preflight intentionally limits support to systemd x86-64/ARM64 and live validation remains a rollout gate. The operator/package manager supplies the locked identity and verified publish payload; package signing is outside this source-layout installer. L1 collectors are deliberately not claimed by this foundation. Remove temporary outputs, never publish generated binaries/settings/evidence, retain no backup paths, and remove the isolated worktree/branch after merge.
