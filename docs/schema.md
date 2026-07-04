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

Reserved for validation/storage errors that should be reviewed without dropping context.

## Core indexes

- `events(agent_id)`
- `events(hostname)`
- `events(event_time desc)`
- `events(windows_event_id)`
- `events(channel)`
- `events(provider)`
- GIN index on `events(raw_json)`
