# Contributing

Target Linux only. Prefer C#/.NET for agents and ASP.NET Core for the server; keep the optional read-only traffic UI isolated under `web/Siem.Ui` and frontend-independent from normal backend builds. Keep REST and contract changes versioned, preserve durable queue/checkpoint/deduplication guarantees, and add synthetic tests for validation, normalization, storage, detections, bounded UI reads, and MCP.

Never commit credentials, local configuration, collected telemetry, queue/state databases, logs, screenshots, captures, dumps, private evidence, generated binaries, or coding-agent state. Use fake hosts, users, addresses, tokens, and IDs in fixtures.

Before handoff run the proportionate build, tests, contract validation, schema validation on a disposable database when available, repository safety checks, and `git status --short --ignored`.
