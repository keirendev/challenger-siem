# Schema design

## Event envelope

Versioned schema: `contracts/v1/event-envelope.schema.json`.

Required structured fields:

- `event_id` - client-generated UUID for deduplication.
- `agent_id` - endpoint agent identifier.
- `hostname` - endpoint hostname at collection time.
- `source` - initial value: `windows_event_log`.
- `channel` - Windows Event Log channel.
- `provider` - Windows event provider.
- `windows_event_id` - Windows Event ID.
- `record_id` - Windows channel record ID.
- `event_time` - event timestamp from Windows.
- `severity` - normalized severity string.
- `message` - rendered or synthesized event message.
- `normalized` - optional normalized category/action/entity/search fields.
- `raw` - original parsed event payload.

`ingest_time` is set by the server when stored. Server storage extracts selected normalized fields such as category, action, user, process image, IPs, service, file path, and registry key into searchable columns while retaining `normalized_json` and `raw_json`.

## Database tables

Implemented in `server/Siem.Api/Database/001_initial.sql`.

### `agents`

Stores registered endpoints, hashed per-agent API tokens, and lifecycle status. `active` agents can authenticate and ingest; `disabled` agents are retired from default active views without deleting historical telemetry. Stale health is computed from `last_seen` rather than stored as a status.

### `events`

Stores normalized fields plus `raw_json` as JSONB.

Deduplication key:

```sql
unique (agent_id, event_id)
```

### `agent_heartbeats`

Stores heartbeat observations, queue SLO metrics, source manifest, source-health summaries, configuration hash, and tamper-check summaries.

### `source_health`

Stores the latest per-agent source-health row keyed by `(agent_id, source_id)`, including coverage level, status, required/enabled flags, record ranges, log-size metrics, stale/gap/clear indicators, source version/config hash, and bounded details.

### `coverage_exceptions`

Stores approved coverage exceptions for missing/not-applicable sources.

### `asset_inventory_snapshots`

Stores bounded inventory snapshots for host identity, network, users/groups, services/drivers, scheduled tasks/autoruns, installed software, patches/features, security-control state, audit policy, and Windows role detection.

### `detection_rules`

Stores detection rule metadata, source prerequisites, normalized field prerequisites, severity/confidence, ATT&CK tags, and enabled state.

### `soc_agent_turns`

Stores bounded backwards-compatible one-shot `soc-agent` question/answer metadata, provider/model, tool-run summaries, citations, and optional context identifiers. It must not store provider secrets or unbounded raw telemetry.

### `soc_agent_sessions` and `soc_agent_messages`

Store bounded chat workspace session metadata and message history, including role, redacted/bounded content, provider/model labels, tool-run summaries, citations, optional context identifiers, and timestamps. These tables must not store provider credentials, browser cookies, unofficial provider tokens, raw provider payloads, or unbounded endpoint telemetry.

### `alerts` and `alert_evidence`

Stores detection alert review skeleton data and links alerts to event evidence.

### `ingestion_errors`

Stores reviewable ingest validation failures after an agent has authenticated successfully. Rows include agent ID, batch ID, event ID when it can be safely identified, an error code/message, and bounded JSON context. The context intentionally omits authorization headers, bearer tokens, rendered event messages, and full raw event payloads.

Operators can inspect recent failures with a bounded query such as:

```sql
select error_time, agent_id, batch_id, event_id, error_code, error_message
from ingestion_errors
order by error_time desc
limit 25;
```

## Core indexes

- `events(agent_id)`
- `events(hostname)`
- `events(event_time desc)`
- `events(windows_event_id)`
- `events(channel)`
- `events(provider)`
- GIN index on `events(raw_json)`
- normalized event indexes for category, action, user, process image, and destination IP
- `agent_heartbeats(agent_id)` and `agent_heartbeats(heartbeat_time desc)`
- `source_health(agent_id)` and `source_health(status)`
- `asset_inventory_snapshots(agent_id, snapshot_type, collected_at desc)`
- `detection_rules(category)`
- `alerts(status)`, `alerts(agent_id)`, and `alerts(created_at desc)`
- `alert_evidence(alert_id)`
- `soc_agent_turns(created_at desc)` and `soc_agent_turns(context_agent_id)`
- `soc_agent_sessions(updated_at desc)` and `soc_agent_sessions(context_agent_id)`
- `soc_agent_messages(session_id, created_at asc, id asc)`
- `ingestion_errors(agent_id)` and `ingestion_errors(error_time desc)`

## Applying and validating the schema

No Docker workflow is required. With PostgreSQL client tools installed and `ConnectionStrings__SiemDatabase` set in an ignored `.local/dev.env`, run:

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
```

Both scripts accept an explicit connection string as their first argument, but do not echo it. The validation script checks required tables, the `(agent_id, event_id)` uniqueness constraint, and the key search/review indexes.
