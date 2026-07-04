# API contract v1

Base path: `/api/v1`.

All production traffic must use HTTPS.

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
  "duplicates": 0
}
```

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
  "memory_mb": 90
}
```

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
- `limit` (maximum 500)
