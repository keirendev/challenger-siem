# Linux package-management evidence

`linux-package-management` separates producer applicability from journal visibility. A host can be quiet, an in-scope producer can be present without emitting a supported record, or the host can use an out-of-scope producer. Event absence alone cannot distinguish those cases. The agent therefore uses bounded read-only package inventory to resolve applicability and retains `degraded` visibility until a matching journal record proves that the event family is observable.

## Supported producer and evidence matrix

| Package family | Bounded inventory applicability evidence | Accepted journal producer identifier | Accepted event evidence |
| --- | --- | --- | --- |
| Debian family | fixed `dpkg-query -W -f=...` installed-package listing | `apt`, `apt-get`, `dpkg` | structured `ACTION` plus `PACKAGE_NAME` or `PACKAGE`; otherwise a bounded leading install/update/remove message form |
| RPM family | fixed `rpm -qa --qf ...` installed-package listing | `dnf`, `yum`, `rpm` | the same structured fields or bounded leading message form |
| PackageKit | resolved through an in-scope dpkg, RPM, or pacman backend; PackageKit alone does not establish inventory applicability | `packagekit`, `packagekitd` | the same structured fields or bounded leading message form |
| Arch family | fixed `pacman -Q` installed-package listing | `pacman` | the same structured fields or a bounded leading `[ALPM]` install/update/remove form |

The journal producer is the normalized lower-case first non-empty value of `SYSLOG_IDENTIFIER` or `_COMM`. Structured `ACTION`, `RESULT`, `PACKAGE_NAME`, and `PACKAGE` values take precedence. Message fallback examines at most 4,096 characters with a fixed 50 ms regex timeout. A package action and bounded package name are both required. An interactive package-manager command line, an available-update inventory row, or package presence alone is never classified as a package-change event.

Known out-of-scope distribution families are reported only after every fixed in-scope inventory probe is unavailable: Alpine/Wolfi (`apk`), Gentoo (`portage`), NixOS (`nix`), Solus (`eopkg`), and Void (`xbps`). Other absent in-scope probes remain `missing`, not `unsupported`, because distribution identity alone is not enough to invent a producer.

## Deterministic health states

`systemd_journal_readable` continues to report the physical journal prerequisite independently. The table below defines the package-specific applicability, `package_manager_journal_visibility` prerequisite, and all three event-family states.

| Evidence case | Applicability | Source status | Package visibility prerequisite | `package_install`, `package_update`, `package_remove` |
| --- | --- | --- | --- | --- |
| Supported producer and matching record observed | `applicable` | follows physical journal health; normally `healthy` | `satisfied` | each family is independently `observed` or `not_observed` |
| Supported producer, successful journal reads, no matching record | `applicable` | `degraded` with `package_manager_journal_visibility_unverified` | `unknown` | `not_observed` |
| Known out-of-scope producer | `unsupported` | `unsupported` | `unsupported` | `unsupported` |
| No supported producer evidence | `unknown` | `degraded` | `missing` | `not_observed` |
| Malformed package inventory | `unknown` | `degraded` | `degraded` | `not_observed` |
| Package inventory permission denial | `unknown` | `degraded` unless the physical journal has a stronger failure | `permission_denied` | `not_observed` |
| Package inventory timeout | `unknown` | `degraded` unless the physical journal has a stronger failure | `stale` | `not_observed` |

A genuine matching journal record is stronger evidence than a stale or contradictory inventory observation: it makes the source applicable and satisfies journal visibility. Permission loss, cursor gaps, throttling, and other physical-journal failures still take precedence and cannot be hidden by inventory or an older package event.

The `linux_packages` snapshot adds only aggregate `package_manager_evidence`, `package_manager_producer`, and `package_manager_reason` values. It does not add mutating package operations, read package-manager log files, quote raw command output, or generate install, update, or removal activity. Validation uses hand-authored synthetic fixtures and aggregate assertions only.
