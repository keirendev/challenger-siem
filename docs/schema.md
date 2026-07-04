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
- `raw` - original parsed event payload.

`ingest_time` is set by the server when stored.

## Database tables

Implemented in `server/Siem.Api/Database/001_initial.sql`.

### `agents`

Stores registered endpoints and hashed per-agent API tokens.

### `events`

Stores normalized fields plus `raw_json` as JSONB.

Deduplication key:

```sql
unique (agent_id, event_id)
```

### `agent_heartbeats`

Stores heartbeat observations and queue health metrics.

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
- `agent_heartbeats(agent_id)` and `agent_heartbeats(heartbeat_time desc)`
- `ingestion_errors(agent_id)` and `ingestion_errors(error_time desc)`

## Applying and validating the schema

No Docker workflow is required. With PostgreSQL client tools installed and `ConnectionStrings__SiemDatabase` set in an ignored `.local/dev.env`, run:

```bash
./scripts/apply-schema.sh
./scripts/validate-schema.sh
```

Both scripts accept an explicit connection string as their first argument, but do not echo it. The validation script checks required tables, the `(agent_id, event_id)` uniqueness constraint, and the key search/review indexes.
