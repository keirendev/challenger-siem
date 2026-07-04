# Milestone tracker

## Phase 1: Design

- [x] Event schema: `contracts/v1/event-envelope.schema.json`, `shared/Contracts/EventEnvelope.cs`
- [x] API contract: `docs/api.md`, `contracts/v1/*.schema.json`
- [x] Database schema: `docs/schema.md`, `server/Siem.Api/Database/001_initial.sql`
- [x] Agent config format: `docs/agent-config.md`
- [x] Auth approach: `docs/auth.md`
- [x] Open-source/custom dependency policy: `docs/dependencies.md`

## Phase 2: Server MVP

- [x] ASP.NET Core API project scaffold: `server/Siem.Api`
- [x] PostgreSQL integration using open-source Npgsql
- [x] Agent registration endpoint
- [x] Event ingestion endpoint
- [x] Heartbeat endpoint
- [x] Basic event query endpoint
- [x] API validation unit tests
- [x] Build and run validation in an environment with .NET 8 SDK installed
- [x] PostgreSQL smoke test using `examples/fake-event-batch.json`

## Phase 3: Agent MVP

- [x] Windows Worker Service project scaffold: `agent/WindowsAgent`
- [x] Windows Service hosting integration
- [x] Config loading from protected-file path or environment
- [x] Reads configured Windows Event Log channels using Windows Event Log APIs
- [x] Normalizes Windows events to v1 envelopes
- [x] Deterministic event IDs for deduplication
- [x] Tracks last processed record ID per channel in JSON state
- [x] SQLite local queue before forwarding
- [x] Sends batches to the ingestion API
- [x] Sends heartbeat payloads
- [x] Build validation on the Linux development host
- [ ] Validate on a real Windows endpoint
- [x] Add Windows service install/uninstall script
- [ ] Confirm `Security` channel permissions and document required account rights

## Phase 4: Reliability

- [x] Durable SQLite local queue baseline
- [x] Delete queued events only after server acknowledgement
- [x] Exponential backoff on failed cycles
- [x] Server duplicate event handling
- [ ] Queue poison-event strategy for repeated validation failures
- [ ] Queue size monitoring and operator-visible warnings
- [ ] More granular batch acknowledgement handling

## Next action

Validate the agent on Windows, then add tests for queue/state behavior.
