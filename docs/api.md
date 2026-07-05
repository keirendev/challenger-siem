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
  "agent_version": "0.1.0"
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

The event-ID arrays are additive v1 response fields. Agents use them to delete only accepted or duplicate queue rows after acknowledgement. Older clients can continue to rely on the count fields.

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
  "source_health": [
    {
      "source_id": "system",
      "display_name": "Windows System",
      "channel": "System",
      "coverage_level": "L1",
      "status": "healthy",
      "required": true,
      "enabled": true,
      "newest_record_id": 123456
    }
  ]
}
```

Source status values are `healthy`, `missing`, `disabled`, `stale`, `error`, `not_applicable`, and `excepted`. Coverage levels are `L0` through `L4`.

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
- `from`
- `to`
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
GET /api/v1/source-health?agent_id=win11-test-001
Authorization: Bearer <review-token>
```

Returns coverage summaries and per-source health rows populated from agent heartbeat data.

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
POST /api/v1/soc-agent/sessions/<session-id>/messages
Authorization: Bearer <review-token>
Content-Type: application/json

{
  "message": "Summarize current coverage and alerts",
  "context_agent_id": "win11-test-001"
}
```

Returns bounded `soc-agent` chat sessions/messages with tool-run summaries and citations back to SIEM review pages. The default provider is `Local`; it does not send data to an external model provider and does not perform mutating actions. When `ChatGPT` subscription OAuth or `OpenAI` API-key/delegated bearer mode is explicitly configured with server-side credentials and external calls enabled, the server sends only bounded/redacted tool context to the official Chat Completions endpoint and persists the bounded answer, tool summaries, citations, provider, and model. External provider setup must use official server-side credentials or a supported delegated flow; browser clients never receive provider tokens.

## Alerts and detections

```http
GET /api/v1/alerts
GET /api/v1/alerts/<alert-id>
GET /api/v1/detections/rules
Authorization: Bearer <review-token>
```

The initial alert/detection APIs expose the storage and review skeleton plus built-in detection metadata. Mutating alert triage and rule activation remain future approved workflows.
