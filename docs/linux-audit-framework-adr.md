# ADR: read-only Linux Audit Framework collector boundary

Status: reviewed and accepted design/security/privacy boundary; implementation, live access, and rollout are not authorized
Date: 2026-07-19
Scope: a future optional `linux-audit-framework` source

Approval record: independent contract, reliability, and privacy review found no
content blocker on 2026-07-19. Maintainer acceptance of issue #241 and the merge that
carries this ADR are the explicit design and security/privacy approval. They do not
approve an implementation issue, collector code, live reads, deployment, host change,
or rollout.

## Decision

Challenger SIEM may consider one future audit collector only: a disabled-by-default,
read-only logical source over Linux Audit Framework records that an operator-owned
systemd journal already stores and that the existing non-root agent identity can
already read. The collector would extend the existing fixed system-journal reader;
it would not add a second audit reader or checkpoint.

The first implementation boundary supports exactly one producer/interface pair. It
also requires a journal router in front of the existing generic L1 normalizer. That
router must inspect trusted journal metadata and intercept every
`_TRANSPORT=audit` entry before the generic normalizer can retain `MESSAGE`,
`_CMDLINE`, or other generic journal fields. The current implementation has no such
router and can retain audit-transport entries as high-sensitivity L1 journal data;
therefore this prerequisite is not satisfied by the present agent.

| Producer | Read interface | Decision |
| --- | --- | --- |
| Linux kernel Audit Framework records already persisted by the local systemd journal with trusted `_TRANSPORT=audit` metadata | The agent's existing fixed absolute-path `journalctl --system` JSON stream, `IncludeAccessibleUserJournals=false`, and durable physical journal cursor | Design supported, but not implemented or enabled; the broader all-accessible-local scope is not an audit-source interface in the first milestone |
| `/var/log/audit/audit.log`, rotated audit files, stdin, pipes, arbitrary paths, syslog text, remote journal namespaces, or exported journal files | Direct file or operator-selected input | Unsupported |
| Audit netlink, audit multicast, auditd dispatcher/plugin sockets, `audisp`, `auplugin`, or `libaudit`/`libauparse` callbacks | Socket, plugin, or native-library reader | Unsupported for the first milestone |
| Any producer that requires package installation, service enablement/reload, rule or backlog changes, a capability grant, group/ACL change, or permission widening | Mutating prerequisite workflow | Prohibited |

The source remains the current visible optional `unsupported` catalog entry until a
separate implementation proposal passes the review and rollout gates below. This ADR
does not authorize code, live audit reads, deployment, package/service changes,
audit-policy changes, capability grants, permission changes, or production rollout.

This deliberately narrow choice reuses one journal access process, physical cursor,
queue, transport, redaction, and source-health boundary. It adds a logical router and
an audit-group write-ahead state machine; it does not add a second reader. It also
avoids making the agent an audit daemon, auditd plugin, policy owner, or privileged
netlink client. Linux capabilities distinguish read access (`CAP_AUDIT_READ`) from
audit control, but the first milestone does not request or consume either capability.

## Preconditions and applicability

A future implementation must add an exact-plan approval independent of requested
coverage level. The approved plan binds the source ID, interface name, fixed limits,
privacy contract, agent configuration hash, and an explicit operator declaration
that a local journal-backed audit facility already exists.

The declaration is applicability evidence, not permission to configure the host.
The collector must not infer audit applicability from distribution name, package
files, service names, an empty journal interval, or ordinary syslog text.

| Condition | Applicability | Health | Required detail and operator meaning |
| --- | --- | --- | --- |
| Collector is absent from the binary, platform is not Linux/systemd, or the declared interface is not `systemd_journal_audit_v1` | `unsupported` | `unsupported` | Current capability boundary; optional and informational |
| Collector exists but is not enabled or its exact plan is not approved | `unknown` | `disabled` | The shared journal read continues for L1, but the router discards audit-transport entries without audit parsing and records only bounded suppression counts |
| Operator explicitly declares that no applicable audit facility exists | `not_applicable` | `not_applicable` | No scan or package/service inference overrides the declaration |
| Operator declares a facility exists but also declares its audit production disabled | `applicable` | `disabled` | The agent does not enable it |
| Enabled/applicable declared facility is supported and the fixed system journal is readable | `applicable` | `healthy` or a runtime fault state below | A successful bounded journal observation may be healthy-but-quiet |
| Enabled/applicable declared facility exists, but the service identity receives journal access denial | `applicable` | `permission_denied` | No root retry, capability, group, ACL, mode, or ownership change |
| Enabled/applicable agent-owned router/group state receives access denial or fails validation | `applicable` | `error` | Journal permission was not denied; fail closed and do not relabel an internal state fault |
| Audit-shaped text lacks trusted journal transport metadata | unchanged | unchanged for audit; record stays on its existing source | Untrusted text cannot impersonate the audit source |

A healthy-but-quiet source requires all of the following: a matching exact approval;
an explicit plan-bound declaration of interface `systemd_journal_audit_v1`; successful
current reads from the mandatory system journal; a successful physical journal
observation no more than two hours old; durable router/group state; and no active
cursor, assembly, suppression, or drop gap. Merely reading the journal is insufficient:
the running binary must attest that audit transport is routed before generic L1.
Seeing a trusted audit-transport entry upgrades family evidence from `not_observed`
to `observed`, but is not required for quiet health. It does not require generating
audit activity, and event-dependent detection prerequisites remain unsatisfied while
quiet.

The first implementation must retain the existing v1 catalog and envelope contract,
not silently migrate it: optional requirement, source kind `linux_audit`, namespace
`linux.audit`, sequence checkpoint, `high_sensitivity` privacy, event source
`linux_audit`, and disabled-by-default behavior. A manifest migration would require a
separate contract proposal. The implementation may replace the current `unsupported`
parser and applicability reason only after review. Its prerequisites are:

- `collector_implementation_available`;
- `systemd_journal_audit_interface_supported`;
- `operator_existing_audit_facility_declared`;
- `systemd_journal_readable`;
- `audit_transport_routed_before_l1` (attested even while quiet; an observed trusted
  audit record is separate family evidence, not the routing prerequisite); and
- `durable_audit_assembly_state_available`.

The router owns every trusted audit-transport entry regardless of source enablement.
It must never pass one to the generic L1 normalizer. When the audit logical source is
unsupported, disabled, not applicable, or unapproved, the router performs no audit
field parsing: it durably finalizes the physical entry as locally suppressed and
increments bounded type-free counts. This prevents raw audit text from leaking into
L1 without claiming that the current, unimplemented router already provides that
property.

The privacy router must still intercept trusted audit transport if the separately
configured generic reader uses the broader all-accessible-local scope, but that scope
cannot satisfy audit applicability or health in this milestone. An enabled audit
source with that scope is `unsupported`; system-only configuration is an exact-plan
input. A future scope expansion requires separate privacy and cursor review.

## Startup, steady state, shutdown, and recovery

### Startup

1. Load and validate only the protected agent configuration and local agent-owned
   state. Reject unknown interfaces, limits, and plan hashes before opening the
   journal.
2. Reuse the existing fixed journal executable and system-only visibility probe.
   Do not call `auditctl`, `ausearch`, `aureport`, `systemctl`, `service`, package
   tools, or auditd control/plugin interfaces.
3. Load the physical collected and finalized journal cursors, boot ID, bounded
   router write-ahead log (WAL), next audit sequence, pending groups, cumulative
   counters, and any active gap. Reject symlinks, unexpected file types,
   ownership/mode failures, incompatible state versions, and oversized state.
4. Resume after the last durably collected physical journal cursor and replay the WAL
   first. A corrupt or invalid cursor is a gap; startup never silently jumps to the
   tail and claims continuous coverage. A state access denial is `error`, not
   `permission_denied`.

### Record grouping and checkpointing

Linux audit events can contain interleaved records. Records are grouped only when
their strict `msg=audit(seconds.millis:serial)` identity matches within one boot.
Malformed, negative, overflowing, or conflicting identities never merge.

One router owns the single physical journal stream. For every entry, its WAL records
exactly one of these dispositions before the physical collected cursor may advance:

| Disposition | When used | Finality and continuity |
| --- | --- | --- |
| `l1_queued` | Non-audit entry produced a generic L1 row | Final after accepted/duplicate acknowledgement; an existing bounded permanent rejection becomes `l1_poison_gap` |
| `audit_pending` | Valid trusted audit record joined a bounded compound group | Not final until replaced atomically by `audit_queued` or an audit terminal-gap disposition |
| `audit_queued` | Completed/partial allowlisted group produced a row with a durably reserved sequence | Final after accepted/duplicate acknowledgement |
| `audit_contract_filtered` | Valid trusted audit record type is intentionally outside the reviewed allowlist | Locally final without a coverage gap; increments only bounded unsupported-type counters |
| `audit_suppressed` | Logical audit source is unsupported, disabled, not applicable, or unapproved | Locally final without audit parsing; increments only bounded type-free suppression counters |
| `audit_input_gap` | Enabled-source JSON/message is oversized, malformed, has invalid/conflicting identity, or violates a field/record bound before a trustworthy event can be queued | Locally final only after a durable gap ID, reason code, and count are committed; no raw input is retained |
| `audit_pressure_gap` | Rate limit, audit row limit, assembly/WAL pressure, pending eviction, or audit queue insertion failure prevents admission | Locally final only with durable gap/drop counters; repeated adjacent drops coalesce into one bounded physical range |
| `audit_disabled_pending_gap` | Disablement finds a pending group | The group is not queued after disable; it is durably finalized as a local partial/drop gap, then later entries use `audit_suppressed` |
| `audit_poison_gap` | Server permanently rejects a queued audit row and the existing queue commits it to poison | Final after poison row, reason code, affected sequence, and audit gap are durable; it never counts as accepted coverage |
| `l1_poison_gap` | Existing L1 row is permanently rejected | The implementation must add a router callback from the existing queue poison result, durably record an L1 gap, and make the physical disposition final without calling it an accepted acknowledgement |

The WAL privately retains bounded physical cursor anchors and queued row/sequence
references. Audit envelopes expose only the existing sequence checkpoint. A separate
private physical **finalized** cursor advances contiguously when each earlier
disposition reaches the final state above. It is not exposed as an audit or L1 server
acknowledgement. Public logical-source acknowledged checkpoints continue to advance
only for accepted/duplicate rows. This distinction prevents a filtered, dropped, or
poisoned audit record from being presented as acknowledged coverage while still
allowing the router to reclaim state.

Each WAL mutation atomically persists the disposition, first/last physical cursor,
bounded row ID or audit sequence when applicable, counters, and new collected/finalized
cursor. Later per-entry acknowledgements may arrive out of order, but compaction and
the finalized cursor advance only through a contiguous final prefix. A pending group
or unacknowledged row blocks that private watermark while later entries may advance
the collected cursor only within the hard WAL limits. Queue deletion happens only
after the accepted/duplicate or poison result and its WAL transition are durably
committed. Contiguous terminal dispositions are compacted into a range holding only
first/last cursors, counts by fixed reason code, and the gap ID; raw data is never in
the WAL.

Audit sequences are monotonically reserved in durable state before an audit row is
queued. The event checkpoint is that sequence. A crash replays the same WAL group,
reserved sequence, normalized raw object, and event identity, so accepted/duplicate
server acknowledgement cannot become a second logical event. No physical cursor is
an audit event-identity input.

A group completes on an explicit end marker, a strictly later serial after the
bounded completion window, or the fixed age/record boundary. Timeout completion is
marked partial unless the record type is defined as single-record. Interleaving is
never reordered across different identities merely to make an event appear complete.

`EOE` is the only explicit end marker and is never retained as an event field. At a
boundary, a group containing exactly one record may be complete rather than partial
only for these single-record candidates: the listed authentication/session types;
`AVC`, `USER_AVC`, `SELINUX_ERR`, `MAC_STATUS`, `MAC_POLICY_LOAD`; the listed
audit-policy-tamper types; and the listed integrity types. Any group containing
`SYSCALL`, `EXECVE`, `PROCTITLE`, `SOCKADDR`, or `PATH`, more than one record, an
unknown type, or a conflicting identity is compound/partial unless `EOE` closed it.
Single-record candidacy does not cause immediate queueing: the same five-second/500-
physical-record boundary still allows interleaved records to arrive. Synthetic tests
must cover every candidate plus late `EOE` and compound promotion.

Enablement is generation-bound and begins strictly after the router's current durably
**collected** physical cursor at the configuration cutover; it does not wait for the
finalized cursor and does not backfill older audit records. Disablement stops audit
parsing, uses `audit_disabled_pending_gap` for every pending group, and suppresses
later trusted audit entries. Already queued rows retain their original generation and
normal accepted/duplicate/poison disposition. Neither transition regresses a cursor
or deletes an unacknowledged row.

### Rotation, restart, loss, and recovery

Journal vacuum/rotation, invalid cursors, boot changes, pending-group eviction,
malformed group identities, input/normalization/rate-limit drops, state corruption,
and queue rejection create explicit gap counters and an active `gap_id`. Cumulative
history is monotonic; recovery never resets it to zero.

An active gap clears only after:

1. the original fault is absent;
2. a complete bounded audit group, or a bounded audit source-health recovery row for
   a quiet source, is durably queued after the fault;
3. that exact recovery row receives accepted/duplicate acknowledgement; and
4. the audit acknowledged sequence, private physical finalized cursor, collected
   cursor, WAL, and pending groups are again internally consistent.

The quiet recovery row is an ordinary v1-valid `EventEnvelope`, not the unacknowledged
heartbeat source-health object. It uses `platform=linux`, `source=linux_audit`, the
canonical `linux-audit-framework` source ID, sequence checkpoint, event code
`audit_source_recovery`, information severity, and the same six-input deduplication
recipe defined below. Its message is exactly
`Linux audit source continuity recovered without collecting audit activity.`;
agent ID and hostname use the existing bounded enrolled-agent values, and every other
common envelope field follows the current portable-v1 defaults. Its compact canonical
`raw` object contains exactly schema
version, `record_kind=source_health_recovery`, hashed gap ID, fixed reason code,
`content_collected=false`, `routed_interface=systemd_journal_audit_v1`, and observation
time. It contains no audit record, cursor, producer text, path, identity, or event
field. Its normalized shape is exactly `category=source_health`, `action=recovered`,
and `outcome=success`, with all process/user/network/file/label concepts absent.
`data_handling.raw_size_bytes` equals compact UTF-8 serialization size,
`redaction_applied=false`, `truncation_applied=false`, and both field-path arrays are
empty. At most one such row may be outstanding per gap.

Server validation, coverage, and detections must treat
`audit_source_recovery` as source-health evidence only: it never marks an audit event
family `observed`, never satisfies a recent-audit-event prerequisite, and is excluded
from audit activity detections. Accepted/duplicate acknowledgement may clear the
named gap; rejection becomes `audit_poison_gap`. This is additive within v1 because
the existing Linux-audit source kind, sequence checkpoint, event-code field, compact
raw object, data-handling metadata, and deterministic recipe already support the
shape. Synthetic contract validation of the exact envelope is an implementation
gate.

Until then, the source remains `degraded`, `permission_denied`, `stale`, or `error`
as appropriate. Unrecoverable missing records are not backfilled or described as
complete. The web/API retain the cumulative gap/drop counters after current health
recovers.

### Shutdown and removal

Graceful shutdown stops reading the shared journal, bounds group finalization,
persists WAL, pending groups, sequences, and positions atomically, and leaves queued
rows intact. It does not signal or stop auditd or journald. Upgrade preserves
protected configuration, queue, physical checkpoints, WAL, sequences, and pending
groups. Disablement uses the explicit cutover behavior above without altering the
producer. Uninstall may remove only agent-owned audit state through the existing
guarded lifecycle after queue disposition; there is no host audit state to restore.

## Source-health state machine

| State | Entry condition | Exit/recovery condition |
| --- | --- | --- |
| `unsupported` | Implementation/platform/interface is absent or unsupported | A separately approved compatible implementation is installed; no runtime guess changes this state |
| `disabled` | Feature or producer declaration is disabled, or exact approval is absent | Matching explicit approval and an already-configured facility declaration |
| `permission_denied` | The fixed system-journal read returns an access-denied class error | A later successful journal read followed by acknowledged recovery; no automatic permission change |
| `stale` | The age of the last successful physical journal observation is greater than two hours; exactly two hours remains current to match the existing shared comparator | A successful current observation followed by acknowledged recovery when a gap was active |
| `degraded` | Active cursor/assembly/rate/drop/pressure gap, incomplete group, or routing-attestation/declaration mismatch | Fault absent plus the acknowledged recovery sequence above |
| `error` | Agent-owned state denial/corruption, internal invariant, parser, or queue failure not represented by a more specific state | Successful bounded retry and acknowledged recovery; repeated error detail is type-only and secret-free |
| `healthy` | Every prerequisite including `systemd_journal_audit_v1` router attestation is satisfied, the last physical journal observation is no more than two hours old, and no active gap exists | Any fault transition above |
| `healthy` with quiet detail | Same as healthy, with zero allowlisted audit families observed in the current bounded window | A matching event changes family evidence to `observed`; quiet itself is not a fault |

The future implementation uses this exact precedence. An inability to inspect trusted
transport metadata or guarantee interception before L1 is a router-integrity `error`
and stops the shared reader before the next generic normalization; it overrides every
logical audit state because privacy cannot be asserted. With the classifier intact,
an unsupported interface remains `unsupported`, and an unapproved/disabled or
explicitly not-applicable audit source remains `disabled`/`not_applicable`; journal
faults are still visible on mandatory L1. For an enabled applicable source, durable
audit-state denial/corruption is `error`, then system-journal access denial is
`permission_denied`, then the exact stale/gap states apply.

An audit-only WAL/assembly-state failure does not pass trusted audit entries to L1 and
does not silently stop mandatory collection. While the transport classifier and the
existing shared L1 checkpoint remain sound, the router enters stateless fail-closed
suppression for audit transport, reports audit `error`, and continues non-audit L1.
Recovery creates a durable `audit_state_discontinuity` gap before audit parsing
resumes, because suppressed counts during an inaccessible state interval cannot be
claimed complete. Failure of the shared physical checkpoint or shared queue is not
audit-only: the reader pauses under the existing mandatory L1 error contract.

Implementation must add this source to the server's successful-journal-observation
freshness mapping with the exact two-hour threshold. Until that server and agent work
ships together, a heartbeat cannot claim the quiet-health semantics in this ADR.

Unknown record types do not by themselves make the source unhealthy. They increment a
bounded aggregate `unsupported_record_type_count`. A malformed allowlisted record,
group eviction, or any record dropped after the collector accepted responsibility for
it creates a degraded coverage gap.

## Normalization and privacy contract

Only trusted `_TRANSPORT=audit` entries with a valid audit identity enter the audit
parser. The parser treats every field and message byte as hostile input, uses no shell,
performs bounded numeric/token decoding, and does not use unrestricted regular
expressions. Structured values win over message fallbacks.

### Allowlisted record families

| Normalized family | Accepted audit record types | Retained purpose |
| --- | --- | --- |
| `authentication_session` | `USER_AUTH`, `USER_ACCT`, `USER_LOGIN`, `USER_START`, `USER_END`, `CRED_ACQ`, `CRED_DISP` | Bounded subject/session/result evidence |
| `authorization_syscall` | `SYSCALL`, with associated `SOCKADDR` or `PATH` only when tied to the same accepted event | Architecture/syscall/result and bounded object/network metadata |
| `process_execution` | `SYSCALL` plus `EXECVE` or `PROCTITLE` presence | Execution occurrence and executable metadata; argument/proctitle payloads are discarded |
| `mandatory_access_control` | `AVC`, `USER_AVC`, `SELINUX_ERR`, `MAC_STATUS`, `MAC_POLICY_LOAD` | Bounded decision, policy, subject/object labels, and result |
| `audit_policy_tamper` | `CONFIG_CHANGE`, `FEATURE_CHANGE`, `DAEMON_START`, `DAEMON_END`, `DAEMON_ABORT`, `DAEMON_CONFIG` | Audit facility lifecycle/configuration evidence already produced by the host |
| `integrity` | `INTEGRITY_RULE`, `INTEGRITY_DATA`, `INTEGRITY_METADATA`, `INTEGRITY_STATUS`, `INTEGRITY_HASH`, `INTEGRITY_PCR` | Bounded integrity decision/status metadata; no file content |

Everything else remains counted aggregate capability evidence and is not queued as a
normalized audit event until a later reviewed allowlist revision. `TTY`, `USER_TTY`,
`USER_CMD`, raw `EXECVE` arguments, and raw `PROCTITLE` are explicitly excluded even
when they accompany an otherwise accepted event.

### Retained fields and exact cardinality

The normalized `raw` object contains only event time, audit serial, boot ID, family,
the sorted record-type set, result, and the bounded allowlisted values below. It does
not contain a journal cursor, journal envelope, original `MESSAGE`, or original audit
record. Numeric IDs remain canonical; name resolution is not performed.

| Value | Exact retained limit |
| --- | --- |
| Unique audit record types | 16 per compound event; sorted, each type at most 32 ASCII characters |
| Compound input records | 64 total; duplicate fields use first syntactically valid value and increment bounded duplicate counters |
| Boot ID | Exactly 32 ASCII hexadecimal digits, normalized to lowercase |
| PATH records | 8, ordered by validated numeric `item`; each keeps `item`, `nametype`, device, inode, mode, and sanitized path only |
| PATH `nametype` | 1–32 uppercase ASCII bytes matching `[A-Z_]+`; unknown valid tokens remain bounded data, not executable behavior |
| Account/name and audit rule key | 128 UTF-8 bytes each after control cleaning; truncation never splits a scalar |
| Executable and each sanitized path | 512 UTF-8 bytes each after control cleaning; truncation never splits a scalar |
| Terminal class | 64 UTF-8 bytes |
| Remote address | 128 ASCII bytes; port is unsigned 16-bit `0..65535` |
| Service and action | 64 UTF-8 bytes each |
| MAC subject/object labels | 2 labels, 256 UTF-8 bytes each |
| MAC class | 64 UTF-8 bytes |
| MAC permissions | 16 unique sorted values, 32 ASCII bytes each |
| PID and PPID | Signed 32-bit decimal; PID `1..2147483647`, PPID `0..2147483647` |
| UID, GID, AUID, and session ID | Unsigned 32-bit decimal `0..4294967295`; the all-ones unset value remains numeric and is not name-resolved |
| Audit identity | Seconds are decimal `0..253402300799`, the maximum representable Unix second for v1 `DateTimeOffset`; milliseconds are `0..999`; serial is unsigned 64-bit decimal; each input must round-trip canonically |
| PATH item, inode, device, and mode | Item is unsigned 32-bit; inode is unsigned 64-bit; device is a fixed `major:minor` pair of unsigned 32-bit hexadecimal values; mode is either the exact unknown sentinel `00` or a leading-zero 6–7-byte octal token matching `0[0-7]{5,6}` with value at most `0177777`, retaining file-type bits such as `0100644` |
| Architecture and syscall | Architecture is exactly 8 ASCII hexadecimal digits; syscall is unsigned 32-bit decimal |
| Result | One of the fixed normalized tokens `success`, `failure`, or `unknown` |
| Envelope metadata | Existing maximum of 64 entries; any metadata list uses the existing maximum of 32 items |

Excess values are not retained. The event carries bounded `partial`, `truncated`,
`input_record_count`, `retained_record_count`, `duplicate_field_count`, and per-limit
drop counters; field paths, not discarded values, identify truncation. A 65th record,
ninth PATH, 17th type or permission, third label, invalid number, or conflicting
duplicate cannot silently look complete. First-valid-wins is deterministic across the
physical input order.

The following are always discarded before durable queueing: syscall argument words
`a0`-`a3`, complete command lines, `EXECVE` argument values, `PROCTITLE` payload,
environment variables, TTY/keystroke content, arbitrary `msg` text after allowlisted
fields are extracted, DNS payloads, packet payloads, socket raw bytes, file contents,
secret stores, authentication material, and unknown vendor fields. No raw audit record
or raw compound event is retained in event data, logs, source health, poison rows,
public fixtures, screenshots, or issue/PR text.

Retained text is UTF-8/control-cleaned, secret-assignment redacted, and truncated at
the exact encoded-byte limits above without splitting a Unicode scalar. Paths and
labels remain high-sensitivity telemetry and
follow the existing operator-role redaction and retention policy. High-sensitivity
audit access must be visible in operator audit logs; exports remain confirmation-gated
and subject to the existing spreadsheet-injection and protected-field rules.

### Deduplication

Every queued audit activity or recovery event uses the existing supported
`sha256_uuid` recipe, in this exact order:
`agent_id`, `source_id`, `checkpoint.sequence`, `event_code`, `event_time`, and
`raw_sha256`. For activity rows, `event_code` is the normalized audit family and
`event_time` is validated audit identity time. For the one recovery shape,
`event_code=audit_source_recovery` and `event_time` is its observation time; it is not
an audit family. `raw_sha256` is recomputed over the applicable compact canonical
`raw` object. The durable sequence reservation makes crash replay stable. Boot ID,
audit serial, type set, retained field values, partial flags, and bounded counters
affect an activity ID only through `raw_sha256`; raw text and private physical cursors
are never inputs. Any future identity recipe change requires a v1 contract migration
rather than undocumented fields.

## Fixed resource and reliability budgets

The implementation proposal may lower these ceilings but may not raise them without
re-review:

| Budget | Maximum |
| --- | --- |
| Effective audit journal JSON input | `min(Journal.MaxInputRecordBytes, 131072)` bytes; the general journal option remains configurable from 4 to 256 KiB |
| Audit `MESSAGE` examined | 65,536 bytes; larger audit input is rejected before field parsing and creates a gap rather than being partially trusted |
| Records per compound audit event | 64 |
| Retained pending state per group | 64 KiB |
| Simultaneous pending groups | 128 |
| Total audit assembly state | 8 MiB across all pending groups, retained fields, indices, and counters; the per-group limit is included, not additive |
| Router WAL | 16,384 length-prefixed binary records and 64 MiB on disk, whichever is reached first; each cursor anchor is at most 1,024 printable ASCII bytes and each encoded record at most 4,096 bytes, leaving at least 2,048 bytes for disposition, row/sequence reference, counters, reason, and gap ID when both cursors are maximal |
| Group completion age | 5 seconds or 500 subsequent physical records, whichever comes first |
| Compact normalized `raw` object | 32 KiB, below the existing 65,536-byte portable-source hard ceiling |
| Audit events admitted | Token bucket of 100/second sustained with capacity 500 |
| Audit events per transport batch | `min(existing transport batch ceiling, 100)` audit rows |
| Mandatory L1 row reserve | `min(Journal.QueuePauseDepth, max(100, ceil(Journal.QueuePauseDepth / 4)))` |
| Audit-specific durable rows | `min(10000, floor(max(0, Journal.QueuePauseDepth - mandatory_l1_reserve) / 10))` |
| Incremental average/p95 CPU | below 0.25% / 1% in the private matrix |
| Incremental RSS | below 32 MiB |
| Incremental average disk writes | below 128 KiB/s |

The private SLO matrix uses one-second process/resource samples after a 30-minute
warm-up. Average CPU, p95 CPU, RSS, and average disk-write gates apply to a 60-minute
quiet run and a separate 60-minute representative run of one 2-KiB normalized audit
event per second, both compared with the same binary/configuration with the logical
source disabled. The 100-events/second admission ceiling is a separate 15-minute
stress/boundedness test: it must respect rate, memory, queue, WAL, gap, and mandatory-
L1 priority limits but is not claimed to meet the representative average disk-write
SLO. The proposal must lower admission or event-size limits if boundedness cannot be
maintained.

An exact plan is invalid when the formula yields zero audit rows. Audit admission
stops before generic journal admission: when the audit row cap is reached, total queue
depth reaches `Journal.QueuePauseDepth - mandatory_l1_reserve`, or the WAL reaches 75%
of either hard limit, new trusted audit entries use `audit_pressure_gap` and adjacent
terminal dispositions coalesce. The router continues admitting non-audit L1 rows into
the reserved headroom. It first compacts final WAL prefixes and terminal ranges, then
finalizes the oldest incomplete audit groups as explicit pressure gaps; it never
deletes an unacknowledged queued row.

If compaction and audit pressure finalization still cannot make room below the
16,384-record/64-MiB hard WAL boundary, the reader stops before consuming the next
physical entry, leaves the collected cursor unchanged, and reports
`journal_router_wal_full` on both the audit row and mandatory shared-journal health.
This visible fail-closed stop is preferable to losing ordering or leaking audit text.
If the shared queue reaches its existing mandatory journal pause threshold, the same
physical reader pauses under the existing L1 contract. Heartbeat, acknowledgement,
and transport work retain priority throughout.

On an audit storm, the collector also applies its token bucket and input/group limits,
increments exact drop/gap counters, and emits one coalesced bounded source-health
transition. It never changes audit rules, kernel backlog/rate/failure settings,
journal retention, or auditd disk policy to hide pressure.

Poison handling follows the existing bounded queue contract. A server rejection may
move only the rejected audit row to poison with an `audit_poison_gap` transition. It
may make that physical disposition final, but never advances the public audit
acknowledged sequence, never skips an unseen sequence, and never recursively queues
raw rejected data.

## Threat model and least privilege

- **Privilege:** steady state remains the existing non-root service identity with no
  ambient or file capabilities. A denial is evidence, not an installation task.
- **Host policy:** the agent never executes audit/journal service control, rule,
  backlog, rate, failure, enable/lock, loginuid, retention, rotation, or package
  commands. It never writes audit configuration or producer paths.
- **Symlink/replacement:** only the existing validated journal executable and
  agent-owned no-follow state paths are opened. No operator path is accepted. State
  replacement, hard links, non-regular files, and ownership/mode mismatch fail closed.
- **Namespace/container:** the source represents only the local system journal visible
  to the service. It does not traverse host mounts, container namespaces, remote
  journals, or `/proc/*/root`. A containerized or non-systemd environment is
  unsupported unless a later design names a distinct interface.
- **Confused deputy:** configuration cannot add arguments, paths, filters, commands,
  record types, or output destinations. API/web requests cannot cause endpoint audit
  reads or host mutations.
- **Untrusted records:** strict lengths, counts, numeric ranges, token grammar, record
  allowlists, fixed completion rules, and deterministic duplicate handling protect
  parser memory and CPU. Invalid input never reaches a shell or dynamic code path.
- **Dependency boundary:** the first milestone adds no audit-userspace library or
  endpoint package. Any future native dependency needs separate license, provenance,
  signing, and release review.

## Operator and API presentation

The existing `/api/v1` manifest, source-health, telemetry-coverage, event search, and
web detail surfaces are sufficient; no incompatible contract is designed. Stable
details expose only bounded codes/counters, never raw records.

| Presentation | Guidance |
| --- | --- |
| `unsupported` | Optional capability is unavailable in this collector/platform. No host action is requested. |
| `disabled` | Collector or existing facility declaration is disabled. Enable only through a separately approved exact plan; the product will not enable host auditing. |
| `permission_denied` | The declared existing journal-backed facility is not readable by the service identity. Keep the source disabled or use a separately reviewed host-access change; the agent will not widen access. |
| `stale` | Current journal observation is unavailable. Review agent/journal health without generating audit activity or changing retention. |
| `degraded` | A bounded gap, partial group, drop, or pressure condition exists. Review counters and continuity; do not interpret missing events as clean evidence. |
| `error` | A bounded parser/state/queue failure occurred. Review type-only diagnostics and the approved rollback path. |
| healthy but quiet | The declared interface is readable and continuous, but no allowlisted family was observed. No activity generation is required; event-dependent detections remain unsatisfied. |

Because the source remains optional, absent/unsupported/disabled states stay visible
and filterable but do not lower achieved coverage. If a later role or policy makes the
source applicable/mandatory, every non-healthy state remains fail-closed and cannot
satisfy strict coverage or detection readiness.

## Synthetic verification contract

All public tests use hand-authored records with synthetic identities, times, cursors,
and paths. No live audit access, host output, raw telemetry, or copied audit example is
allowed. A future implementation PR must include:

1. **Producer/interface fixtures:** trusted journal transport intercepted before L1;
   proof that audit sentinels never reach generic L1; type-free durable suppression
   while unsupported, disabled, not applicable, or unapproved; spoofed audit text on
   another transport remaining ordinary L1; unsupported platform/interface;
   undeclared, explicitly absent, quiet, journal-access-denied, and agent-state-denied
   cases; and explicit `systemd_journal_audit_v1` routing attestation.
2. **Grouping fixtures:** simple event, interleaved compound events, duplicate records,
   missing end marker, out-of-order records, malformed/overflowing serial/time, 64/65
   record boundary, timeout, pending-map pressure, eviction, and restart with a pending
   group.
3. **Checkpoint fixtures:** interleaved L1, pending audit, queued audit, and suppressed
   dispositions; pending groups blocking the acknowledged but not collected cursor;
   crash before state persist, after pending-state persist, after sequence reservation,
   after queue commit, and after accepted/duplicate acknowledgement; cursor
   invalidation, rotation/vacuum, boot change, stable replay, enable-without-backfill,
   disable-with-pending-group, every contract-filter/input-gap/pressure-gap/poison
   disposition, out-of-order row acknowledgement, contiguous finalized-prefix
   compaction, and acknowledged recovery.
4. **Privacy fixtures:** every allowed field, every excluded command/environment/TTY/
   raw-message field, secret-shaped assignments, invalid UTF-8, controls, oversized
   strings, path truncation, exact 32-hex boot ID, bounded `nametype`, unknown `00`
   mode, ordinary seven-digit `0100644`/`0100755` modes, duplicate keys, and unknown
   record types. Assertions must
   prove excluded sentinel values are absent from event, log, health, state, and poison
   serialization.
5. **Health fixtures:** `unsupported`, journal-only `permission_denied`, `disabled`,
   exactly-two-hour-current boundary and first value greater than two hours becoming
   `stale`, agent-state-denial `error`, `degraded`, healthy
   observed, attested healthy quiet, unattested quiet, active gap, pressure/drop, and
   recovery only after downstream acknowledgement. The exact
   `audit_source_recovery` envelope must pass v1 validation while remaining excluded
   from event-family observation, coverage readiness, and detections.
6. **Performance fixtures:** sustained ceiling, burst, oversized input, group fan-out,
   server outage, queue pressure, poison, reconnect/drain, and long quiet periods. Tests
   assert the fixed memory/rate/queue/WAL bounds, maximum 1,024-byte first/last cursor
   anchors plus maximum metadata fitting one 4,096-byte record, 75% audit cutoff,
   zero-budget plan rejection, mandatory-L1 reserve, terminal-range compaction, and
   hard-stop behavior.
7. **Mutation-negative fixtures:** a fake process/file/capability/service adapter must
   fail any executable, path, argument, write, signal, capability, group, ACL, package,
   or service operation outside the existing journal/state allowlist. The published
   lifecycle plan and upgrade diff must show no audit-related mutation.
   Router-integrity failure must stop before L1; audit-state-only failure must suppress
   audit transport while allowing bounded non-audit L1 progress and then create a
   durable state-discontinuity gap on recovery.
8. **API/web fixtures:** optional unsupported remains informational; applicable faults
   remain explicit; healthy quiet does not fabricate observed event families; raw
   records and excluded fields never render or serialize.

Repository safety, contract, unit, integration, publish, lifecycle-plan, and private
Linux canary gates must all pass before rollout. Public assertions remain aggregate
only.

## Compatibility matrix and rollout gates

The implementation review must name and test each supported architecture,
distribution, systemd version, journal storage mode, audit producer version, kernel,
boot/rotation behavior, and bare-metal/VM boundary. Containers and non-systemd hosts
start unsupported. No support claim may be inferred from CachyOS or one canary alone.

Rollout order is:

1. design approval and security/privacy review;
2. a separately approved implementation issue and threat-model review;
3. synthetic contract/unit/integration evidence;
4. self-contained artifact lifecycle `plan` proving zero audit/host-policy mutation;
5. private read-only canary on an operator-owned host whose audit facility and access
   already exist, with no production host data copied into public artifacts;
6. outage, rotation, restart, pressure, malformed-input, acknowledgement-recovery,
   rollback, and resource-SLO exercises;
7. a bounded disabled-by-default release; and
8. a separate operator decision for any wider rollout.

Canary rollback criteria include any host-policy diff, privilege change, producer
impact, audit/journal loss increase, unexplained cursor/serial gap, excluded-field
retention, unbounded memory/CPU/disk/queue growth, mandatory-source starvation,
incorrect recovery, or lifecycle/state corruption. Rollback disables the logical
source and removes only agent-owned source state after queue disposition; it never
changes or restarts the host audit facility.

## Lifecycle non-mutation proof obligations

An implementation is not reviewable unless its generated plan and tests demonstrate
all of the following:

- no calls to `auditctl`, `augenrules`, `ausearch`, `aureport`, auditd plugins,
  `systemctl`, `service`, package managers, `setcap`, user/group tools, ACL/mode/owner
  mutation, sysctl, kernel-module, reboot, or firewall tooling;
- no writes below `/etc/audit*`, `/var/log/audit*`, systemd journal paths, package
  paths, unit files, or kernel/sysctl paths;
- no added service capabilities, supplementary groups, privileged helper, socket,
  mount, device, or path access;
- no change to audit enable/lock/rules/backlog/rate/failure/loginuid, auditd/journald
  configuration, retention, rotation, ownership, or permissions; and
- the only new mutable data is bounded, no-follow, agent-owned state under the
  existing private state directory and ordinary durable queue rows.

## Decision consequences

The design provides an implementable passive boundary without overstating coverage or
turning collection into host policy management. It intentionally gives up direct
audit-log/netlink coverage, non-systemd support, arbitrary producer compatibility,
and automatic prerequisite remediation. Those are separate security decisions, not
fallbacks.

No implementation issue is created by this ADR. A maintainer must first record
explicit design and security/privacy approval, then deliberately authorize a separate
implementation milestone. Until that happens, `linux-audit-framework` remains
`unsupported` and no live audit validation is appropriate.

## Primary references

- Linux audit userspace architecture and event grouping:
  <https://github.com/linux-audit/audit-userspace>
- Linux capabilities, including the separate audit read/control capabilities:
  <https://man7.org/linux/man-pages/man7/capabilities.7.html>
- Audit control, status, backlog, loss, and lock semantics:
  <https://man7.org/linux/man-pages/man8/auditctl.8.html>
- Audit rule and performance semantics:
  <https://man7.org/linux/man-pages/man7/audit.rules.7.html>
- auditd rotation, disk-pressure, and daemon configuration semantics:
  <https://man7.org/linux/man-pages/man5/auditd.conf.5.html>
- systemd journal audit and storage behavior:
  <https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html>
- journal cursor, structured-output, and access behavior:
  <https://www.freedesktop.org/software/systemd/man/latest/journalctl.html>
