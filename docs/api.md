# API contract v1

Base path: `/api/v1`.

All production traffic must use HTTPS. The operator web review console is hosted by the same ASP.NET Core process outside the `/api/v1` API contract; see `docs/web.md`.

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

The event-ID arrays are additive v1 response fields. Agents use them to delete only accepted or duplicate queue rows after acknowledgement. Older clients can continue to rely on the count fields. `event_time` remains canonical UTC for storage, filtering, correlation, and deduplication; optional `host_timezone` metadata lets review clients display the endpoint's host-local time with the event-specific UTC offset, including daylight-saving boundaries.

Validation failures after successful agent authentication are also persisted to `ingestion_errors` with bounded payload context that omits authorization headers, bearer tokens, rendered event messages, and raw event payloads.

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

Source status values are `healthy`, `missing`, `disabled`, `stale`, `error`, `not_applicable`, and `excepted`. Coverage levels are `L0` through `L4`. Source-manifest entries also carry the additive installer/source matrix fields `prerequisites`, `event_families`, `validation_scenarios`, `privacy`, and `installer_managed` for operator validation and coverage reporting. `host_timezone` is optional and bounded; for heartbeat it describes the endpoint's current timezone, while source-health/event rows use the offset associated with the reported event time where available.

## Agent inventory upload

```http
POST /api/v1/agents/inventory
Authorization: Bearer <per-agent-token>
Content-Type: application/json
```

Agents send bounded inventory and audit-policy snapshots independently of raw event batches. Snapshot payloads include `agent_id`, `hostname`, `snapshot_type`, `collected_at`, optional `host_timezone`, bounded `items`, and summary counts/statuses. The server validates that every snapshot `agent_id` matches the authenticated batch agent and stores the snapshots for `/api/v1/inventory`, `/api/v1/telemetry-coverage`, `/audit-policy`, and host coverage review.

## Search events

```http
GET /api/v1/events?windows_event_id=4625
Authorization: Bearer <review-token>
```

Supported filters:

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
- `limit` (maximum 500)

## Source health

```http
GET /api/v1/source-health?agent_id=win11-test-001&target_level=L2
Authorization: Bearer <review-token>
```

Returns coverage summaries and per-source health rows populated from agent heartbeat data. Coverage summaries and source rows can include optional `host_timezone` metadata for host-local display. When `agent_id` is supplied, the response is overlaid with the canonical Windows source matrix for the requested `target_level` (`L2` by default), so expected but unreported sources appear as `missing` or `excepted` rows instead of disappearing from the operator view.

## Telemetry coverage validation

```http
GET /api/v1/telemetry-coverage?agent_id=win11-test-001&target_level=L2&lookback_hours=24
Authorization: Bearer <review-token>
```

Returns a bounded operator validation summary for active Windows agents (or one `agent_id`) over a clamped 1-168 hour lookback. The response includes sanitized aggregate counts, expected/reported source-health coverage, recent normalized event counts by source, missing/stale/error source reasons, additive source version/config-hash/details fields for profile-backed sources such as Sysmon, host timezone metadata when reported, inventory and audit-policy snapshot status, alert status counts, active graph counts, and per-rule detection prerequisite status. Status wording distinguishes `missing_prerequisites` or `unknown` telemetry validation from a confirmed detection miss.

## Inventory

```http
GET /api/v1/inventory?agent_id=win11-test-001&snapshot_type=audit_policy
Authorization: Bearer <review-token>
```

Returns bounded asset inventory snapshots such as audit policy, security-control state, users/groups, services/drivers, scheduled tasks, installed software, patches/features, host identity, and role detection.

## Platform capabilities

```http
GET /api/v1/platform/capabilities
Authorization: Bearer <review-token>
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
Authorization: Bearer <review-token>
```

Graph records contain bounded metadata (`title`, `description`, `owner`, `tags`, `version`), typed nodes, typed edges, and proposal artifacts. Node types include `agent`, `host`, `user`, `process`, `ip`, `domain`, `file`, `registry_key`, `service`, `event`, `alert`, `detection_rule`, `source_health`, `note`, and `custom`. Edge types include `observed_on`, `generated`, `parent_of`, `communicated_with`, `authenticated_as`, `touched_file`, `modified_registry`, `evidence_for`, `related_to`, and `annotates`.

Updates use `expected_version` for optimistic concurrency. `soc-agent` proposals are pending until an operator explicitly applies them; proposal application is audited and remains under the review-token/session model.

## soc-agent

Provider status:

```http
GET /api/v1/soc-agent/status
Authorization: Bearer <review-token>
```

Returns provider/model/auth state such as `local`, `disabled`, `provider_not_configured`, `auth_required`, `expired`, `refresh_failed`, `unsupported_delegated_auth`, `unsupported_subscription_oauth`, `scope_missing`, `connected`, `budget_limited`, `plan_limited`, `rate_limited`, `auth_failed`, or `provider_error`, plus a safe official setup/connect URL when applicable. When interactive subscription OAuth is enabled, `connect_url` may point at the local `/soc-agent/oauth/start` route, which requires an authenticated operator and redirects to an official provider authorization endpoint with state/PKCE. Subscription OAuth and delegated auth-file responses may include safe optional metadata such as `credential_source`, `expires_at`, `refresh_status`, `provider_path`, `auth_file_mode`, `setup_priority`, `scope_status`, and `entitlement_status`; Pi auth-file reuse is reported with values such as `auth_mode=pi_auth_json`, `provider_path=pi_auth_json_openai_codex`, and `refresh_status=pi_managed`. Responses never include provider secrets, raw auth-file contents, account identifiers, or full auth-file paths.

Backwards-compatible one-shot ask:

```http
POST /api/v1/soc-agent/ask
Authorization: Bearer <review-token>
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
Authorization: Bearer <review-token>
Content-Type: application/json

{
  "message": "Summarize current coverage and alerts",
  "context_agent_id": "win11-test-001"
}
```

Returns bounded `soc-agent` chat sessions/messages with tool-run summaries and citations back to SIEM review pages. `DELETE /api/v1/soc-agent/sessions/<session-id>` is a backward-compatible management addition that removes the selected chat session and its `soc_agent_messages` rows through the database cascade, returns `404` when the session is already absent, and returns `409` with `status=run_active` while a live run is active for that session. Bounded one-shot `soc_agent_turns` audit rows are independent and retained. Delete responses are terse metadata only and do not echo message bodies. The default provider is `Local`; it does not send data to an external model provider and does not perform mutating actions. When `ChatGPT` subscription OAuth or `OpenAI` API-key/delegated bearer mode is explicitly configured with server-side credentials and external calls enabled, the server sends only bounded/redacted tool context to the configured ChatGPT Codex Responses or OpenAI Chat Completions endpoint and persists the bounded answer, tool summaries, citations, provider, and model. External provider setup must use server-side credentials or a supported delegated flow; browser clients never receive provider tokens.

Same-origin web live transport (outside `/api/v1`, authenticated by the existing operator session cookie rather than review tokens in URLs or browser storage):

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
Authorization: Bearer <review-token>
```

The initial alert/detection APIs expose the storage and review skeleton plus built-in detection metadata. Mutating alert triage and rule activation remain future approved workflows.
