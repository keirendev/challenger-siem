# Contributing

Target Linux only. Prefer C#/.NET for agents and ASP.NET Core for the headless server. Keep REST and contract changes versioned, preserve durable queue/checkpoint/deduplication guarantees, and add synthetic tests for validation, normalization, storage, detections, and bounded MCP reads.

Never commit credentials, local configuration, collected telemetry, queue/state databases, logs, screenshots, captures, dumps, private evidence, generated binaries, or coding-agent state. Use fake hosts, users, addresses, tokens, and IDs in fixtures.

Before handoff run the proportionate build, tests, contract validation, schema validation on a disposable database when available, repository safety checks, and `git status --short --ignored`.
