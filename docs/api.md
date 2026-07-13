# API contract v1

Base path: `/api/v1`.

All production traffic must use HTTPS. Operator routes use `Authorization: Bearer <operator-api-credential>` issued to a database-backed operator identity; endpoint-agent bearer credentials remain a completely separate domain. Role checks and sensitive-field policy are described in [auth.md](auth.md). The web console uses a revocable cookie session outside the `/api/v1` contract; see [web.md](web.md).

Version 1 has additive cross-platform contract fields. Every previously valid Windows registration, heartbeat, ingest, search, and source-health JSON shape keeps its original meaning and does not need to send the additions. The multi-platform PostgreSQL migration persists portable Linux events through the existing ingest/search path without introducing `/api/v2`.

Validate all v1 schemas plus synthetic legacy Windows and Linux golden fixtures with `./scripts/validate-contracts.sh`. The canonical conditions, bounds, checkpoint semantics, and deduplication recipe are documented in [schema.md](schema.md#additive-v1-cross-platform-contract).

## Register agent

```http
POST /api/v1/agents/register
X-Enrollment-Token: <enrollment-token>
Content-Type: application/json
```

Request:

```json
{
  "agent_id": "win11-test-001",
  "hostname": "WIN11-TEST",
  "machine_guid": "machine-guid",
  "os_version": "Windows 11 23H2",
  "agent_version": "0.1.0",
  "host_timezone": {
    "id": "Pacific Standard Time",
    "display_name": "(UTC-08:00) Pacific Time (US & Canada)",
    "base_utc_offset_minutes": -480,
    "utc_offset_minutes": -420,
    "is_daylight_saving_time": true
  }
}
```

Response:

```json
{
  "agent_id": "win11-test-001",
  "api_token": "per-agent-token",
  "registered_at": "2026-07-04T12:00:00Z"
}
```

Registration adds optional `platform` (`windows` or `linux`) and `host_id`. Legacy Windows requests may omit both and retain `machine_guid` semantics. A Linux contract document sets `platform=linux`, requires bounded `host_id`, and can omit `machine_guid`; it must not place a Linux identifier into the Windows-specific field.

## Ingest event batch

```http
POST /api/v1/ingest/events
Authorization: Bearer <per-agent-token>
Content-Type: application/json
```

Request:

```json
{
  "agent_id": "win11-test-001",
  "batch_id": "4c5e958b-7c8d-42e7-b060-75374c2fb2b1",
  "sent_at": "2026-07-04T12:00:00Z",
  "events": [
    {
      "event_id": "3af457f2-a61f-4f95-9da0-4697d00f76e7",
      "agent_id": "win11-test-001",
      "hostname": "WIN11-TEST",
      "source": "windows_event_log",
      "channel": "Security",
      "provider": "Microsoft-Windows-Security-Auditing",
      "windows_event_id": 4625,
      "record_id": 123456,
      "event_time": "2026-07-04T12:00:00Z",
      "host_timezone": {
        "id": "Pacific Standard Time",
        "display_name": "(UTC-08:00) Pacific Time (US & Canada)",
        "base_utc_offset_minutes": -480,
        "utc_offset_minutes": -420,
        "is_daylight_saving_time": true
      },
      "ingest_time": null,
      "severity": "information",
      "message": "An account failed to log on.",
      "normalized": {
        "category": "authentication",
        "action": "logon",
        "outcome": "failure",
        "target_user_name": "synthetic-user",
        "source_ip": "192.0.2.10",
        "entities": []
      },
      "raw": {
        "event_data": {}
      }
    }
  ]
}
```

Response:

```json
{
  "batch_id": "4c5e958b-7c8d-42e7-b060-75374c2fb2b1",
  "accepted": 1,
  "rejected": 0,
  "duplicates": 0,
  "accepted_event_ids": ["3af457f2-a61f-4f95-9da0-4697d00f76e7"],
  "duplicate_event_ids": [],
  "rejected_event_ids": []
}
```

The event-ID arrays are additive v1 response fields. Agents use them to delete only accepted or duplicate queue rows after acknowledgement. Older clients can continue to rely on the count fields. `event_time` accepts an RFC 3339 offset and remains canonical UTC after normalization for storage, filtering, correlation, and deduplication; default/minimum timestamps are invalid. Optional `host_timezone` metadata lets review clients display endpoint-local time.

`source=windows_event_log` retains the exact existing requirement for `channel`, `provider`, `windows_event_id`, and `record_id`. Additive source values are `linux_journal`, `linux_audit`, `inventory_diff`, and `agent_health`. Journal and audit are Linux-native and require `platform=linux`; inventory-diff and agent-health are platform-neutral and accept explicit `platform=windows` or `platform=linux`. Every additive source uses stable `source_id`, cursor and/or sequence `checkpoint`, explicit `sha256_uuid` deduplication inputs, and `data_handling`, and omits all four Windows Event Log identity fields. Audit, inventory-diff, and agent-health records require bounded `event_code`. Journal records require at least one of `event_code`, `facility`, or `unit`. Additive-source severity values use the exact lowercase v1 enumeration in both schema and runtime validation; legacy Windows Event Log runtime case-insensitive severity handling is unchanged.

For every additive portable source, the `raw` object has a hard 65,536-byte compact UTF-8 ceiling. `data_handling.raw_size_bytes` must match that compact serialization. Redaction/truncation booleans, bounded field-path arrays, and truncation original size are validated. When selected, `raw_sha256` must match the compact raw bytes, and every additive-source `event_id` must match its declared canonical `sha256_uuid` recipe; arbitrary IDs are rejected. Optional bounded `normalized.process`, `normalized.user`, `normalized.network`, and `normalized.file` objects coexist with all legacy flattened normalized fields. The new raw, label, and data-handling ceilings are conditional additive-source requirements: legacy Windows Event Log v1 envelopes retain the exact schema/runtime allowances they had before these additions. See [schema.md](schema.md#event-envelope) for the complete conditions and deterministic recipe.

Collectors queue an event durably before advancing `collected_checkpoint`. They advance `acknowledged_checkpoint` and delete queue data only after the response lists the event as accepted or duplicate. A checkpoint gap therefore remains visible backlog rather than implied complete coverage.

The Linux journal collector emits `source=linux_journal`, stable logical `source_id`, cursor checkpoints, and deterministic IDs over `agent_id`, `source_id`, and `checkpoint.cursor`. L1 uses `linux-journal-l1`; opt-in L2 uses stable IDs for login/session, SSH, sudo/su, cron/timers, package management, firewall, kernel/security modules, service changes, and agent/log tamper. Structured journal fields take precedence and bounded message parsing supplements only missing evidence. Category/action/outcome/severity plus bounded user/process/service/network/package fields are populated only when evidence exists. Message/raw content remains bounded and `data_handling` marks redaction/truncation.

Validation failures after successful agent authentication are persisted to `ingestion_errors` with bounded payload context that omits authorization headers, bearer tokens, rendered event messages, and raw event payloads. Contract-valid Windows and portable Linux/platform-neutral events use the same additive event table, deduplication boundary, and v1 ingest/search routes without fabricated Windows identity fields.

## Agent heartbeat

```http
POST /api/v1/agents/heartbeat
Authorization: Bearer <per-agent-token>
Content-Type: application/json
```

Request:

```json
{
  "agent_id": "win11-test-001",
  "hostname": "WIN11-TEST",
  "agent_version": "0.1.0",
  "os": "Windows 11",
  "last_event_time": "2026-07-04T12:00:00Z",
  "host_timezone": {
    "id": "Pacific Standard Time",
    "display_name": "(UTC-08:00) Pacific Time (US & Canada)",
    "base_utc_offset_minutes": -480,
    "utc_offset_minutes": -420,
    "is_daylight_saving_time": true
  },
  "queue_depth": 42,
  "cpu_percent": 1.5,
  "memory_mb": 90,
  "config_hash": "sha256-redacted-config-hash",
  "queue_metrics": {
    "queue_depth": 42,
    "poison_depth": 0,
    "oldest_queued_age_seconds": 120,
    "last_successful_send_time": "2026-07-04T12:00:00Z",
    "max_size_mb": 512,
    "warning_size_percent": 80
  },
  "source_manifest": [
    {
      "source_id": "sysmon-operational",
      "display_name": "Sysmon Operational",
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "coverage_level": "L3",
      "required": false,
      "source_pack": "windows-l3-sysmon",
      "parser_id": "sysmon",
      "prerequisites": ["sysmon_installed", "sysmon_approved_config"],
      "event_families": ["process", "network", "dns", "file", "registry", "tamper"],
      "validation_scenarios": ["sysmon_process_event", "sysmon_network_dns_event"],
      "privacy": "high_sensitivity",
      "installer_managed": true
    }
  ],
  "source_health": [
    {
      "source_id": "system",
      "display_name": "Windows System",
      "channel": "System",
      "coverage_level": "L1",
      "status": "healthy",
      "required": true,
      "enabled": true,
      "newest_record_id": 123456,
      "host_timezone": {
        "id": "Pacific Standard Time",
        "utc_offset_minutes": -420,
        "is_daylight_saving_time": true
      }
    }
  ]
}
```

Source status values are `healthy`, `missing`, `disabled`, `stale`, `degraded`, `permission_denied`, `unsupported`, `error`, `not_applicable`, and `excepted`. Coverage levels are `L0` through `L4`. Existing Windows manifest/health items retain required `channel`, record-ID semantics, and need not send any additive Linux metadata.

New typed source items add `platform`, `source_kind`, stable `source_id`, `source_namespace`, optional journal `facility`/`unit`, and `applicability` (`applicable`, `not_applicable`, `unknown`, or `unsupported`). Non-applicable/unknown/unsupported entries require a bounded reason. Additive optional `requirement` (`mandatory`, `optional`, or `role_specific`), `applicable_roles`, `prerequisite_statuses`, and `event_family_statuses` make Linux coverage explicit; evidence-state values are bounded enums. Linux-native kinds accept only `platform=linux`; platform-neutral inventory-diff and agent-health kinds accept Windows or Linux. Every portable manifest requires `checkpoint_kind`; applicable portable health entries require collected and acknowledged checkpoints and omit Windows identity fields.

Portable typed `source_id` values are scoped to one agent/source configuration and must be unique within each manifest and health array. Every portable manifest item has exactly one corresponding health item; the pair agrees on platform, kind, namespace, facility, unit, applicability/reason, requirement, and applicable roles; health evidence-map keys match the manifest prerequisites/families; and each checkpoint shape agrees with `checkpoint_kind`. The source platform must match the top-level heartbeat platform and `host_id` is required. Thus Windows can report neutral inventory/health sources without relabelling them as Linux, while a heartbeat containing a Linux source still requires top-level `platform=linux`. Arrays, maps, cross-entry relationships, and existing prerequisite/event-family/validation metadata are checked by deterministic schema tooling and runtime validation.

The Linux agent reports the physical `linux-journal-l1` pair plus the L2 catalog pairs, all backed by the same journal cursor. This agent never self-approves `excepted`; active server-side coverage exceptions apply that state during coverage evaluation. L2 is disabled while `TargetCoverageLevel=L1`; SSH role applicability uses bounded declared roles, firewall remains optional/unknown until observed, and Linux Audit Framework is explicitly unsupported. Bounded `details` retain collector/gap/permission/throttle/config/counter state, while first-class fields carry requirements, applicability, prerequisites, and event-family evidence. Empty, denied, stale, degraded, unsupported, invalid/vacuumed cursor, rotation, malformed/binary, reorder, and pressure conditions remain distinguishable.

Heartbeat also adds optional `platform` and `host_id` with the registration conditions. Linux heartbeats enforce the new CPU, queue, timestamp, and tamper-value bounds; every typed portable source entry enforces source-metadata and details-map bounds. If a Linux heartbeat supplies `queue_metrics`, both `max_size_mb` and `warning_size_percent` are required and range-validated. Untyped legacy Windows heartbeats retain the pre-existing v1 limits, including empty or partial `queue_metrics`, unrestricted string sizes in `details` and tamper fields, and no upper bound on reported CPU percentage. `host_timezone` remains optional and bounded; for heartbeat it describes the endpoint's current timezone, while source-health/event rows use the offset associated with the reported event time where available.

## Agent inventory upload

```http
POST /api/v1/agents/inventory
Authorization: Bearer <per-agent-token>
Content-Type: application/json
```

Agents send bounded inventory and audit-policy snapshots independently of raw event batches. Snapshot payloads include `agent_id`, `hostname`, `snapshot_type`, `collected_at`, optional `host_timezone`, bounded `items`, and summary counts/statuses. The server validates that every snapshot `agent_id` matches the authenticated batch agent and stores the snapshots for `/api/v1/inventory`, `/api/v1/telemetry-coverage`, `/audit-policy`, and host coverage review.

The Linux agent uses this existing generic additive endpoint for up to 20 current-state snapshots and 200 items per snapshot, with a default agent-side serialized payload budget of 256 KiB. Its implemented types are `linux_host_identity`, `linux_users`, `linux_groups`, `linux_services`, `linux_units`, `linux_timers`, `linux_packages`, `linux_available_updates`, `linux_interfaces`, `linux_listeners`, `linux_mounts`, `linux_firewall`, `linux_ssh`, `linux_mandatory_access_control`, `linux_secure_boot`, and `linux_agent_integrity`. Linux snapshot summaries use the exact `state` values `success`, `unavailable`, `not_applicable`, `permission_denied`, `timeout`, and `malformed`, plus stable `error_code`, `item_count`, and `truncated` metadata. Additive payload-budget truncation metadata may also be present.

This capability preserves the existing `/api/v1/agents/inventory` request, generic snapshot/item shapes, and all other v1 contracts; it adds no Linux-specific route or `/api/v2`. Linux telemetry coverage now maps inventory `state` values honestly, but inventory presence does not imply journal event coverage.

## Operator identity management

Admin-only `POST /api/v1/operators` creates an operator with `username`, `display_name`, one exact `role`, and a strong initial `password`. Authenticated operators can use `POST /api/v1/operators/me/password` to change their password after supplying the current password, and `POST /api/v1/operators/me/api-token/rotate` to receive a new API credential exactly once. Credential changes revoke active sessions. Unsafe API methods accept bearer authentication only, preventing cookie-based CSRF.

Initial bootstrap and locked-account recovery are deliberately not network APIs; use the local commands in [auth.md](auth.md).

## Search events

```http
GET /api/v1/events?windows_event_id=4625
Authorization: Bearer <operator-api-credential>
```

The database/search implementation returns persisted Windows and portable Linux events. Additive source, platform, source-ID, and event-code filters are available; facility, unit, and checkpoint remain event response fields rather than dedicated query filters.

Supported current filters:

- `hostname`
- `agent_id`
- `channel`
- `windows_event_id`
- `from` (UTC; offset-less `datetime-local` values from the web console are interpreted as UTC)
- `to` (UTC; offset-less `datetime-local` values from the web console are interpreted as UTC)
- `keyword`
- `category`
- `action`
- `user_name`
- `process_image`
- `source_ip`
- `destination_ip`
- `service_name`
- `file_path`
- `registry_key`
- `package_name` (additive normalized package filter)
- `limit` (maximum 500)

## Source health

```http
GET /api/v1/source-health?agent_id=win11-test-001&target_level=L2
Authorization: Bearer <operator-api-credential>
```

Returns persisted multi-platform source health plus calculated summaries. Existing Windows rows retain their original vocabulary and semantics. Typed rows expose platform/native identity, requirement/applicable roles, applicability, facility/unit, prerequisite/event-family states, and collected/acknowledged checkpoints. Agent-scoped requests overlay the canonical Windows or Linux catalog for `target_level`; expected but unreported sources are represented rather than hidden, active server exceptions become `excepted`, and summary counters separately report degraded, permission-denied, unsupported, excepted, and not-applicable rows.

## Telemetry coverage validation

```http
GET /api/v1/telemetry-coverage?agent_id=win11-test-001&target_level=L2&lookback_hours=24
Authorization: Bearer <operator-api-credential>
```

Returns a bounded operator validation summary for active Windows or Linux agents (or one `agent_id`) over a clamped 1-168 hour lookback. It includes platform-specific expected/reported source coverage, recent event counts by Windows channel or portable `source_id`, requirement/applicability/evidence metadata, explicit missing/stale/degraded/denied/unsupported reasons, source version/config hash, host timezone, platform-specific inventory state, alert/graph counts, and Windows detection prerequisites. Built-in detection rules remain Windows-focused, so Linux responses do not fabricate Windows prerequisite failures.

## Inventory

```http
GET /api/v1/inventory?agent_id=win11-test-001&snapshot_type=audit_policy
Authorization: Bearer <operator-api-credential>
```

Returns bounded generic asset inventory snapshots such as audit policy, security-control state, users/groups, services/drivers, scheduled tasks, installed software, patches/features, host identity, role detection, and the additive Linux snapshot types listed above. Existing Windows and generic v1 response shapes and meanings are preserved.

## Platform capabilities

```http
GET /api/v1/platform/capabilities
Authorization: Bearer <operator-api-credential>
```

Returns a bounded catalog of specification-gap foundation status and documentation links for authenticated operators. See `docs/spec-gap-foundations.md`.

## Investigation graphs

```http
GET /api/v1/graphs?status=active
POST /api/v1/graphs
GET /api/v1/graphs/<graph-id>
PUT /api/v1/graphs/<graph-id>
POST /api/v1/graphs/<graph-id>/archive
POST /api/v1/graphs/<graph-id>/nodes
POST /api/v1/graphs/<graph-id>/edges
POST /api/v1/graphs/<graph-id>/proposals
POST /api/v1/graphs/<graph-id>/proposals/<proposal-id>/apply
Authorization: Bearer <operator-api-credential>
```

Graph records contain bounded metadata (`title`, `description`, `owner`, `tags`, `version`), typed nodes, typed edges, and proposal artifacts. Node types include `agent`, `host`, `user`, `process`, `ip`, `domain`, `file`, `registry_key`, `service`, `event`, `alert`, `detection_rule`, `source_health`, `note`, and `custom`. Edge types include `observed_on`, `generated`, `parent_of`, `communicated_with`, `authenticated_as`, `touched_file`, `modified_registry`, `evidence_for`, `related_to`, and `annotates`.

Updates use `expected_version` for optimistic concurrency. `soc-agent` proposals are pending until an operator explicitly applies them; proposal application is audited and remains under the operator role/session model.

## soc-agent

Provider status:

```http
GET /api/v1/soc-agent/status
Authorization: Bearer <operator-api-credential>
```

Returns provider/model/auth state such as `local`, `disabled`, `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, `unsupported_subscription_oauth`, `scope_missing`, `connected`, `budget_limited`, `plan_limited`, `rate_limited`, `auth_failed`, or `provider_error`, plus a safe official setup/connect URL when applicable. When interactive subscription OAuth is enabled, `connect_url` may point at the local `/soc-agent/oauth/start` route, which requires an authenticated operator and redirects to an official provider authorization endpoint with state/PKCE. Subscription OAuth and delegated auth-file responses may include safe optional metadata such as `credential_source`, `expires_at`, `refresh_status`, `provider_path`, `auth_file_mode`, `setup_priority`, `scope_status`, and `entitlement_status`; Pi auth-file reuse is reported with values such as `auth_mode=pi_auth_json`, `provider_path=pi_auth_json_openai_codex`, and `refresh_status=pi_managed`. Responses never include provider secrets, raw auth-file contents, account identifiers, or full auth-file paths.

Backwards-compatible one-shot ask:

```http
POST /api/v1/soc-agent/ask
Authorization: Bearer <operator-api-credential>
Content-Type: application/json

{
  "question": "Summarize current coverage and alerts",
  "context_agent_id": "win11-test-001"
}
```

Chat sessions:

```http
GET /api/v1/soc-agent/sessions
POST /api/v1/soc-agent/sessions
GET /api/v1/soc-agent/sessions/<session-id>
DELETE /api/v1/soc-agent/sessions/<session-id>
POST /api/v1/soc-agent/sessions/<session-id>/messages
Authorization: Bearer <operator-api-credential>
Content-Type: application/json

{
  "message": "Summarize current coverage and alerts",
  "context_agent_id": "win11-test-001"
}
```

Returns bounded `soc-agent` chat sessions/messages with tool-run summaries and citations back to SIEM review pages. `DELETE /api/v1/soc-agent/sessions/<session-id>` is a backward-compatible management addition that removes the selected chat session and its `soc_agent_messages` rows through the database cascade, returns `404` when the session is already absent, and returns `409` with `status=run_active` while a live run is active for that session. Bounded one-shot `soc_agent_turns` audit rows are independent and retained. Delete responses are terse metadata only and do not echo message bodies. The default provider is `Local`; it does not send data to an external model provider and does not perform mutating actions. When `ChatGPT` subscription OAuth or `OpenAI` API-key/delegated bearer mode is explicitly configured with server-side credentials and external calls enabled, the server sends only bounded/redacted tool context to the configured ChatGPT Codex Responses or OpenAI Chat Completions endpoint and persists the bounded answer, tool summaries, citations, provider, and model. External provider setup must use server-side credentials or a supported delegated flow; browser clients never receive provider tokens.

Same-origin web live transport (outside `/api/v1`, authenticated by the existing operator session cookie rather than operator API credentials in URLs or browser storage):

```http
POST /soc-agent/live/runs
GET /soc-agent/live/runs/<run-id>/events?after=<sequence>
POST /soc-agent/live/runs/<run-id>/cancel
GET /soc-agent/live/sessions/<session-id>/active
```

`POST /soc-agent/live/runs` persists the operator message, starts or continues a bounded chat session, and returns `run_id`, `session`, `user_message`, `provider_status`, and `next_sequence`. The event stream is `text/event-stream` with monotonic `sequence` IDs plus typed events including `resume_snapshot`, `session_created`, `message_created`, `run_started`, `provider_status`, `tool_started`, `tool_finished`, `citation_added`, `content_delta`, `run_cancel_requested`, `run_error`, and `run_complete`. Reconnecting with `after=<sequence>` replays only newer retained events; refreshing the page can also query the active-run endpoint for the selected session. Cancellation requests stop the active turn through server-side cancellation and persist a bounded assistant cancellation message when interrupted.

## Alerts and detections

```http
GET /api/v1/alerts
GET /api/v1/alerts/<alert-id>
GET /api/v1/detections/rules
Authorization: Bearer <operator-api-credential>
```

The initial alert/detection APIs expose the storage and review skeleton plus built-in detection metadata. Mutating alert triage and rule activation remain future approved workflows.


## Managed event storage accounting

`GET /api/v1/storage/accounting` requires the operator API credential and returns PostgreSQL byte accounting for the managed `events` table and indexes plus row count and measurement time. Event search also accepts additive `source`, `platform`, `source_id`, and `event_code` query parameters. Existing v1 Windows filters and response shapes remain compatible.
