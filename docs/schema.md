# Schema and contract design

## Additive v1 cross-platform contract

The versioned JSON Schemas remain under `contracts/v1/`. Version 1 preserves the original Windows JSON shapes while adding conditional cross-platform fields. Existing Windows registration, heartbeat, ingest, search, and source-health documents do not need to send any new property.

The C# models are under `shared/Contracts/`. `WindowsCoverageLevel` remains the C# type name for source compatibility with existing clients; its serialized `L0`-`L4` values can also describe new source manifests. No `/api/v2` or `contracts/v2/` contract is introduced.

Run deterministic schema, fixture, serialization, and runtime-validation checks with:

```bash
./scripts/validate-contracts.sh
```

Tracked fixtures under `tests/ContractFixtures/v1/` are minimal synthetic records only.

## Event envelope

Versioned schema: `contracts/v1/event-envelope.schema.json`.

Fields required for every event:

- `event_id` - non-empty client-generated UUID used with `agent_id` for server deduplication.
- `agent_id` - endpoint agent identifier.
- `hostname` - endpoint hostname at collection time.
- `source` - source kind.
- `event_time` - RFC 3339 timestamp with an offset; default/minimum timestamps are invalid. UTC is canonical after normalization.
- `severity` - one of the exact lowercase values `verbose`, `information`, `warning`, `error`, `critical`, `audit_success`, or `audit_failure`. Additive-source schema and runtime validation use ordinal matching; the legacy Windows Event Log runtime retains its existing case-insensitive acceptance.
- `message` - rendered or synthesized message, at most 20,000 characters.
- `raw` - a JSON object; for additive portable sources its compact UTF-8 serialization is at most 65,536 bytes. Legacy Windows Event Log v1 events retain their original unbounded schema allowance.

Source kinds are:

| `source` | Platform | Conditional identity |
| --- | --- | --- |
| `windows_event_log` | Windows | Existing `channel`, `provider`, `windows_event_id`, and `record_id` remain required. Optional `platform`, when present, is `windows`. |
| `linux_journal` | Linux | `platform=linux`, stable `source_id`, checkpoint, deduplication metadata, data-handling metadata, and at least one of `event_code`, `facility`, or `unit`. Windows-only identity fields must be omitted. |
| `linux_audit` | Linux | Linux identity metadata plus `event_code`. Windows-only identity fields must be omitted. |
| `inventory_diff` | Windows or Linux | Explicit platform, portable identity metadata, and `event_code`. Windows Event Log identity fields must be omitted. |
| `agent_health` | Windows or Linux | Explicit platform, portable identity metadata, and `event_code`. Windows Event Log identity fields must be omitted. |

`event_code` is a bounded platform-native symbolic code. `facility` and `unit` carry bounded journal facility and service/unit identity. They are never populated with fake Windows IDs.

### Source checkpoints

`checkpoint` carries a bounded opaque `cursor`, a non-negative `sequence`, or both, with optional event/recorded timestamps. Cursors are compared as opaque exact strings. Sequences are source-local monotonically increasing integers; they are not globally comparable.

Source-health reports can carry both:

- `collected_checkpoint` - highest position durably placed in the local queue;
- `acknowledged_checkpoint` - highest position acknowledged as accepted or duplicate by the server.

An acknowledged sequence cannot be ahead of the collected sequence. Collectors must queue before advancing the collected checkpoint, and agents must not advance the acknowledged checkpoint or delete a queued record until an ingest acknowledgement covers that event. A difference between the two positions is visible backlog, not successful coverage.

### Deterministic deduplication

Every additive portable-source event requires `deduplication.algorithm=sha256_uuid` and an ordered `inputs` list. Inputs use these exact field paths:

- `agent_id`
- `source_id`
- `checkpoint.cursor`
- `checkpoint.sequence`
- `event_code`
- `event_time`
- `raw_sha256`

`agent_id` and `source_id` are always included. Every cursor/sequence named as an input must exist, and each checkpoint value present on an additive-source event must be included. `raw_sha256`, when selected, is a 64-character lowercase hexadecimal digest and must be present in the metadata.

For `sha256_uuid`, resolve inputs in declared order, represent integers as invariant base-10 and timestamps in UTC as exactly `yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'`, join the values with U+001F, hash the UTF-8 bytes with SHA-256, use the first 16 digest bytes in network byte order, set RFC 4122 variant bits and the version-5 nibble, and format those bytes as a lowercase UUID. `raw_sha256` is recomputed over the compact UTF-8 serialization of `raw`; neither that declared digest nor `event_id` is trusted. Runtime and deterministic contract validation reject either mismatch. The server's stable uniqueness key remains `(agent_id, event_id)`.

Legacy Windows Event Log events retain their existing deterministic event-ID inputs and semantics. They are not required to add `deduplication` metadata.

### Redaction, truncation, and raw bounds

Every additive portable-source event requires `data_handling`; all limits in this subsection are conditional on an additive source and do not narrow a legacy Windows Event Log envelope:

- `raw_size_bytes` exactly reports the compact UTF-8 serialization size of `raw` and cannot exceed 65,536;
- `redaction_applied` is true exactly when `redacted_fields` is non-empty;
- `truncation_applied` is true exactly when `truncated_fields` is non-empty;
- truncation requires `original_size_bytes` greater than the retained raw size;
- field lists contain unique bounded field paths.

Redaction and truncation happen before durable queueing. The metadata describes removed or shortened fields; it must not reproduce the removed sensitive value. The JSON Schema carries `x-maxUtf8Bytes: 65536` and `x-rawSizeMatches: /raw`; the deterministic contract validator and API runtime enforce exact raw byte size, original/retained size ordering, and the byte ceiling because JSON Schema has no standard cross-object UTF-8 size keyword. The deterministic validator also applies the runtime checkpoint-ordering and event-ID recipe checks, so `validate-contracts.sh` cannot certify a structurally valid but contradictory document.

### Structured normalized concepts

The existing flattened normalized fields remain unchanged. Additive optional `normalized.process`, `normalized.user`, `normalized.network`, and `normalized.file` objects provide bounded platform-neutral concepts:

- process: PID, parent PID, executable, and command line;
- user: name, platform identifier, and realm;
- network: source/destination IP and numeric port plus protocol;
- file: path, operation, and lowercase SHA-256.

`entities` retains its existing v1 limit of 100 entries. For additive portable-source events, entity identity strings must be non-empty and `labels` is limited to 64 entries with bounded keys and values. Legacy Windows Event Log labels retain their original v1 shape and sizes.

## Registration, heartbeat, source manifest, and source health

Registration and heartbeat add optional `platform` (`windows` or `linux`) and platform-neutral `host_id`. Legacy Windows requests can omit both. Linux requests require both and do not need to fabricate `machine_guid`.

A legacy source-manifest or source-health item can retain its original required `channel` shape. Event envelopes continue to call their discriminator `source`; `source_kind` exists only on manifest and health entries, matching the C# models. Portable heartbeat input cannot report the server-owned `excepted` state; the heartbeat schema and runtime reject it, while server source-health responses may use `excepted` only after applying an active coverage exception. New explicitly typed items add:

- `platform` and `source_kind`;
- stable `source_id` plus `source_namespace` for identity;
- optional `facility` and `unit`;
- `applicability` (`applicable`, `not_applicable`, `unknown`, or `unsupported`) and a required reason for the latter three states;
- manifest `checkpoint_kind` (`cursor`, `sequence`, or `cursor_and_sequence`);
- source-health `collected_checkpoint` and `acknowledged_checkpoint`.

Linux journal/audit kinds require `platform=linux`. Platform-neutral inventory-diff and agent-health kinds accept explicit `platform=windows` or `platform=linux`; source kind never implies platform for those records. All four additive portable kinds omit `channel` and Windows record-ID ranges. Health remains explicit through `healthy`, `missing`, `disabled`, `stale`, additive `degraded`, `permission_denied`, and `unsupported`, plus `error`, `not_applicable`, and `excepted`. Typed non-applicable and unsupported sources pair matching applicability/status values and require a reason. Optional additive `requirement` (`mandatory`, `optional`, `role_specific`), `applicable_roles`, and bounded prerequisite/event-family status maps carry Linux coverage semantics without becoming requirements for old valid v1 documents.

A portable typed `source_id` is stable and unique per agent and source configuration. It occurs at most once in each heartbeat manifest and health array; every portable manifest entry matches exactly one health entry. The pair/top-level heartbeat agree on platform, kind, namespace, facility, unit, applicability/reason, requirement, applicable roles, and evidence-map keys. Checkpoint shapes match `checkpoint_kind`. Portable heartbeats require `host_id`; Linux entries require top-level `platform=linux`, while Windows neutral entries require `platform=windows`.

Source manifests and source-health arrays retain their existing limit of 100 entries per heartbeat. Existing prerequisite/event-family/validation lists retain their original 32-item and 128-character limits, including legacy empty-string validity; typed portable list items must additionally be non-empty. Portable source-health `details` is limited to 32 bounded key/value entries, while untyped Windows `details` retains its original unrestricted map sizes. Linux heartbeat CPU, timestamp, resource, and tamper-string bounds are conditional and do not reject a previously valid Windows heartbeat. When `queue_metrics` is present on a Linux heartbeat, `max_size_mb` and `warning_size_percent` are required and range-validated; legacy and portable-source Windows queue-metrics objects retain the existing optional-field shape, including empty and partial objects. Additive queue/resource/source observability fields are nullable when unknown and explicitly zero only when measured; string states use bounded enums and timestamps must not be defaults. JSON Schema annotations `x-uniquePortableBy` and `x-crossSourceIdentity` identify the non-standard cross-entry rules; deterministic contract validation and API runtime enforce them.

## Storage boundary

Numbered migrations under `server/Siem.Api/Database/` apply in lexical order. `002_multiplatform_events.sql` upgrades the original Windows table in place: existing rows and `(agent_id, event_id)` deduplication are preserved, Windows identity columns become conditionally required, and portable platform/source/checkpoint/deduplication/data-handling fields are stored without fabricated Windows IDs. `003_portable_source_health.sql` makes legacy `channel` nullable for portable rows and stores platform/source identity, applicability, and checkpoints. `004_operator_rbac.sql` creates operator identity/session/security-audit tables. `005_linux_l2_source_coverage.sql` additively persists registered platform/host identity, Linux requirement/applicable-role/prerequisite/event-family metadata, and the expanded health-state constraint. `006_health_observability.sql` stores additive resource metrics on heartbeats and bounded timestamped source observability columns for silence, rates, gaps, transitions, poison, and drops. `007_managed_retention.sql` adds managed-retention run summaries and removed-event reference markers so alert evidence can report when underlying telemetry was removed by policy. `008_linux_detection_execution.sql` additively extends Linux detection metadata and execution indexes. `009_search_saved_queries.sql` adds owner/versioned saved event searches plus index-supported mature search predicates for provider/facility/unit, severity/outcome, process command, service/file/registry/network pivots, normalized entity containment, and detection evidence joins. `011_alert_triage_cases.sql` additively extends alerts with ownership/lifecycle/disposition/concurrency columns and creates case, relationship, evidence, note, and append-only activity tables. `012_detections_dashboards_admin.sql` additively adds detection-rule management/history, saved dashboard layouts, source review settings, and allowlisted server configuration settings for safe admin mutations. Reapplying all migrations is supported.

Portable v1 events ingest, deduplicate, persist, and search through the same `/api/v1` paths as Windows events. The Linux self-integrity snapshot uses the existing platform-neutral `agent_health` source with `platform=linux`, `source_id=linux-agent-self-integrity-snapshot`, sequence checkpoints, deterministic `sha256_uuid` IDs, and bounded metadata/digest raw payloads; no new route or incompatible schema is introduced. Search accepts additive `source`, `platform`, `source_id`, `event_code`, provider/facility/unit, severity/outcome, detection, entity, network, service, process, file, registry, and normalized `package_name` filters with bounded cursor pagination and timeline aggregation. Authenticated `GET /api/v1/storage/accounting` reports exact live managed telemetry bytes, managed index allocation, PostgreSQL relation allocation, row count, threshold state, and retention lag for the allowlisted managed telemetry scope (`events`, `agent_heartbeats`, `asset_inventory_snapshots`, and `ingestion_errors`). Telemetry coverage responses add optional pressure, capacity, source-gap, throttle, and guidance fields derived from existing heartbeat/source-health columns without changing existing required v1 fields. `GET /api/v1/storage/retention/status` and `POST /api/v1/storage/retention/run` expose dry-run/execute cleanup guarded by PostgreSQL advisory locking and bounded transactions. Retention deletion never targets arbitrary schemas/files or protected records such as operators, sessions, agents, source-health current state, security audit, alerts/evidence, detections, investigation graphs, or `soc-agent` history.

## Database tables

Implemented in `server/Siem.Api/Database/001_initial.sql`.

### `agents`

Stores registered Windows/Linux endpoints, optional platform/host identity, hashed per-agent API tokens, lifecycle status, and optional current `host_timezone` metadata. `active` agents can authenticate and ingest; `disabled` agents are retired from default active views without deleting historical telemetry. Legacy Windows registrations may leave platform/host ID null.

### `events`

Stores conditional Windows or portable event identity, normalized fields, bounded portable checkpoint/deduplication/data-handling metadata, `raw_json`, and optional event-specific `host_timezone` as JSONB. The Linux L1 journal source uses `platform=linux`, `source=linux_journal`, stable `source_id`, opaque cursor checkpoint, and the v1 deterministic-ID recipe; no Windows identity columns are fabricated.

Current deduplication key:

```sql
unique (agent_id, event_id)
```

### `agent_heartbeats` and `source_health`

Store current heartbeat, source-manifest, source-health, resource, and queue observability data. Portable journal heartbeats carry source identity, requirement/applicable roles, applicability, prerequisite/event-family statuses, collected/acknowledged cursor, latest event/lag/silence/rate, stable error/gap/permission/transition flags, config/version, poison/drop counters, and bounded details while preserving existing Windows rows. Linux catalog evaluation distinguishes mandatory, optional, role-specific, stale, degraded, denied, unsupported, excepted, and not-applicable rows.

### Operator identity, session, and audit tables

Migration `004_operator_rbac.sql` additively creates `operators`, `operator_sessions`, and `security_audit_events`. Operators have a unique normalized username, one exact role, salted password hash, optional hashed API credential, enable/lockout state, and credential-change timestamps. Session rows store only a random handle hash plus absolute expiry/revocation state. Password or API-credential changes revoke active sessions.

Security audit rows are append-only: a PostgreSQL trigger rejects updates and deletes. Audit details are JSONB limited by application policy to action/outcome and non-secret identifiers; credentials, cookies, authorization headers, raw telemetry, and protected event fields are excluded.

### Managed retention tables

`managed_retention_runs` stores bounded status/details for dry-run and execute retention passes, including mode, status, trigger, cutoff, removed row counts, estimated removed bytes, category summaries, and managed/protected table lists. `managed_retention_removed_events` stores only event identifiers, event time, removal category, removal time, and run ID for events removed by policy; it does not store raw telemetry. Alert evidence joins this marker to expose `telemetry_retention_state` safely after underlying `events` rows are gone.

### Other tables

The current schema also includes asset inventory, coverage exceptions, detection rules, detection-rule management/history, saved dashboard layouts, source review settings, server configuration overrides, alerts/evidence, cases, investigation graphs, `soc_agent` records, and bounded ingestion errors. Migration `008_linux_detection_execution.sql` additively extends `detection_rules` with tactics, bounded correlation windows, suppression keys, false-positive notes, and response guidance, adds duplicate-safe alert-evidence indexing, and adds bounded Linux authentication-correlation indexes for server-side detection execution. Migration `011_alert_triage_cases.sql` keeps existing alerts compatible while adding `version`, owner, lifecycle timestamps, suppression reason/expiry, disposition, closure summary, and append-only `alert_activities`. It creates `cases`, `case_alerts`, `case_entities`, `case_graphs`, `case_evidence`, immutable `case_notes`, and append-only `case_activities` with bounded fields and indexes for owner/status/recent activity. Migration `012_detections_dashboards_admin.sql` stores detection-rule management metadata separately from built-in rule logic: effective enablement, lifecycle, synthetic validation status, tuning/suppression notes, optimistic settings version, and append-only management history. Alerts continue to persist `rule_id`, `rule_version`, and evidence event IDs without changing existing `/api/v1` response fields.

Alert and case evidence rows intentionally retain event identity (`agent_id`, `event_id`, event time, host timezone, and bounded summary) independent of underlying telemetry. Review queries join live `events` and `managed_retention_removed_events` to report `telemetry_retained`, `telemetry_removed_by_retention`, or `underlying_telemetry_missing`; missing telemetry is therefore explicit and does not erase the evidence reference.

## Core current indexes

Event indexes cover agent, hostname, event time, Windows identity, portable source/platform/source ID/event code, provider/facility/unit, severity/outcome, selected normalized network/process/service/file/registry fields, raw JSON, normalized JSON containment, detection evidence joins, and selected normalized fields. Additive package-name search uses a migration-managed `normalized_json->>'package_name'` expression index rather than a new column. Agent-platform and source-requirement indexes plus heartbeat, source-health, inventory, detection, alert, graph, saved-search, `soc_agent`, and ingestion-error indexes remain migration-managed.

## Applying and validating PostgreSQL

With PostgreSQL client tools installed and a private ignored connection configuration:

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
```

The apply script runs every numbered migration and fails on the first error. The validator checks portable columns plus operator/session/audit tables, columns, and indexes. Validate upgrades only on operator-owned empty or synthetic databases; keep plans and database output under ignored `.local/`.
