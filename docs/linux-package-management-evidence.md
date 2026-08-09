# Linux package-change evidence

Package visibility has two complementary L2 sources. `linux-package-inventory-diff` is the mandatory detection source for current agents. `linux-package-management` is supplemental direct journal evidence. During an API-first rolling upgrade, the server continues to accept the exact pre-2.9 manifest in which the journal source is mandatory; once an agent reports the inventory-diff source, the current mandatory-diff/supplemental-journal shape is enforced.

## Inventory-difference source

`linux-package-inventory-diff` reuses only the complete `linux_packages` inventory already collected through the fixed dpkg, RPM, or pacman commands. It adds no reader, command, path, privilege, package operation, or host-policy change. Its private baseline is stored as `package-inventory-diff-state.json` under the existing agent state directory with mode 0600.

The first complete observation establishes a non-alerting baseline. Later complete observations compare stable package identity and version and emit deterministic `install`, `update`, and `remove` evidence with a sequence checkpoint. The event time is the inventory observation end, and raw metadata records the observation start/end. `outcome=unknown`; the evidence does not claim exact operation time, actor, command, intent, or authorization.

An observation emits at most 200 events. When more changes exist, the final retained event is an explicit gap with the omitted count. The new complete baseline is committed only after every event for the observation is durably queued. A failed or interrupted enqueue leaves the prior baseline intact, abandons the reserved sequence range on recovery, and reports a gap; queue, WAL, checkpoint, and prior baseline state are never deleted or rewritten to recover.

Partial, truncated, denied, timed-out, malformed, oversized, or duplicate-identity inventories do not replace the last valid baseline. They degrade the source and emit one transition gap when possible. The next complete observation emits recovery evidence and compares against the last valid baseline. A complete observation with no changes advances the observation boundary without manufacturing a change event.

## Supplemental direct journal source

`linux-package-management` retains the existing bounded journald classifier. A matching direct event requires an install/update/remove action and a package name from the fixed structured fields or bounded producer-specific message forms. An interactive package-manager command line, available-update row, package presence, or sudo command alone is not a package-change event.

For each complete inventory interval, the agent correlates process-local direct journal observations by exact normalized action and package name. If an inventory change has no matching journal record, the journal source becomes degraded with `package_record_change_unobserved`, while the mandatory inventory-diff source still supplies detection evidence. A later fully matched or change-free interval clears the active journal gap; the cumulative missed-change count remains visible. Restart discards this correlation cache so historical activity cannot be claimed as directly observed.

| Package family | Fixed inventory evidence | Accepted journal identifiers |
| --- | --- | --- |
| Debian | `dpkg-query -W -f=...` | `apt`, `apt-get`, `dpkg` |
| RPM | `rpm -qa --qf ...` | `dnf`, `yum`, `rpm` |
| Arch | `pacman -Q` | `pacman` |
| PackageKit | An in-scope dpkg/RPM/pacman backend | `packagekit`, `packagekitd` |

Known out-of-scope producers remain explicit `unsupported`; absent, denied, malformed, and timed-out inventory remain distinct health states. Event absence is never evidence that no package activity occurred.

## Detection semantics

`package.change.linux` version 2 accepts either canonical package source and preserves the existing package/action suppression keys. Inventory baselines, recovery markers, and gaps are non-alerting. A directly matching event is still evaluated when health is degraded, but confidence is lowered when the source has an active gap or unavailable prerequisite.

Validation uses only hand-authored synthetic package names and versions. It never modifies the validating host's installed packages.
