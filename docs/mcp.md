# MCP server and SIEM-agent integration

Challenger SIEM exposes a stateless [Model Context Protocol](https://modelcontextprotocol.io/) Streamable HTTP endpoint at `/mcp`. It is intended for an explicitly approved SIEM assistant or other operator-controlled MCP client that needs bounded, evidence-led access to the same environment data available through the review application.

The first MCP contract is deliberately read-only. It can review evidence, explain coverage gaps, advise on alert handling, and produce detection-tuning proposals. It cannot acknowledge or assign alerts, change cases or graphs, enable or edit detections, register or retire agents, change retention, modify configuration, run endpoint commands, or alter host state.

## Transport and authentication

- Endpoint: `https://<siem-server>/mcp`
- Transport: stateless Streamable HTTP
- Legacy HTTP+SSE transport: not enabled
- Authentication: `Authorization: Bearer <operator-api-credential>`
- Minimum role: `analyst`; `detection-engineer` and `admin` are also accepted
- Viewer credentials, browser session cookies, enrollment tokens, and per-agent credentials are rejected
- Endpoint inventory items are available only to `admin`; inventory summaries omit items by default
- HTTPS is required outside the documented loopback development exception
- Responses set `Cache-Control: no-store` and `Pragma: no-cache`

Create or rotate an operator API credential as described in [Authentication and operator authorization](auth.md#credential-and-session-security). It is displayed once. Put it directly into the MCP client's secret store or an ignored local environment/configuration file; never add it to source control, command history, screenshots, issue text, or tracked client configuration.

Example client configuration shape:

```json
{
  "mcpServers": {
    "challenger-siem": {
      "type": "http",
      "url": "https://siem.example.invalid/mcp",
      "headers": {
        "Authorization": "Bearer <operator-api-credential>"
      }
    }
  }
}
```

The exact configuration keys vary by MCP client. Use the client's secret-reference or environment-variable feature when available. The example hostname is reserved for documentation and the credential is a placeholder.

## Tools

Every tool is marked read-only, non-destructive, idempotent, and closed-world. List/search tools are bounded to at most 100 rows per call, nested source-health, case, and graph collections default to 50 and are capped at 100 records per collection, event lookback is bounded to 168 hours, and event search returns a cursor when more results are available.

| Tool | Purpose and important boundary |
| --- | --- |
| `siem_get_overview` | Aggregate agent, event, alert, and source-health posture for a 1-168 hour window; no raw events. |
| `siem_list_assets` | Filtered endpoint list with health, coverage, queue-pressure, and capacity metadata. |
| `siem_search_events` | Structured event search with bounded lookback, row limit, and cursor pagination; applies operator field policy. |
| `siem_get_event` | One event by agent ID and event UUID; non-admin raw data is omitted and sensitive fields are redacted. |
| `siem_get_timeline` | UTC event-count buckets for structured filters; aggregate only and capped at 500 buckets. |
| `siem_list_alerts` | Bounded alert list with role-based alert-field redaction. |
| `siem_get_alert` | One alert with evidence references, case links, and activity, subject to role policy. |
| `siem_list_cases` | Bounded investigation-case summaries. |
| `siem_get_case` | One case with existing links, notes, and activity; each nested collection defaults to 50 records and is capped at 100, with explicit truncation metadata. Analyst-authored text remains untrusted evidence. |
| `siem_list_detections` | Detection catalog and prerequisite/coverage state. |
| `siem_review_detection` | Catalog and bounded alert-outcome review plus advisory recommendations; always returns `proposal_only=true` and `applied=false`. |
| `siem_get_coverage` | One agent's telemetry, inventory, source, detection-prerequisite, alert, and investigation coverage assessment. |
| `siem_get_source_health` | One agent's source gaps, staleness, error, permission, and throttling state; summaries and sources each default to 50 records and are capped at 100, with per-collection returned counts and truncation metadata. |
| `siem_get_inventory` | Admin-only bounded inventory snapshots; items are opt-in and capped per snapshot. Server-held credentials are not included, while endpoint-supplied values remain sensitive and receive best-effort secret-pattern redaction. |
| `siem_list_graphs` | Bounded existing investigation-graph summaries; no proposal or graph mutation. |
| `siem_get_graph` | One existing bounded graph and its nodes, edges, and proposals as untrusted analyst evidence; each nested collection defaults to 50 records and is capped at 100, with per-collection returned counts and truncation metadata. |

Structured event search supports exact or bounded filters including agent, hostname, platform, source, channel, provider, event code, Windows event ID, severity, normalized category/action/outcome, detection rule, keyword, common user/process/network/service/file/registry fields, and normalized entity pivots. Clients should start narrowly, follow returned citations, and page deliberately rather than requesting broad environment dumps.

## Resources

Resources are JSON views backed by the same tools and authorization, redaction, bounds, and audit path:

| Resource URI | Name | Content |
| --- | --- | --- |
| `siem://environment/overview` | `siem_environment_overview` | 24-hour bounded aggregate posture. |
| `siem://events/{agentId}/{eventId}` | `siem_event` | One role-filtered event. |
| `siem://alerts/{alertId}` | `siem_alert` | One role-filtered alert. |
| `siem://cases/{caseId}` | `siem_case` | One existing investigation case. |
| `siem://detections/{ruleId}/{version}` | `siem_detection_review` | One 168-hour proposal-only detection review. |
| `siem://agents/{agentId}/coverage` | `siem_agent_coverage` | One agent's L2/24-hour coverage assessment. |
| `siem://agents/{agentId}/source-health` | `siem_agent_source_health` | One agent's L2 source-health view using the 50-record per-collection default. |
| `siem://graphs/{graphId}` | `siem_investigation_graph` | One existing investigation graph using the 50-record per-collection default. |

## Prompts

The server advertises four evidence-led prompt templates:

- `triage_alert(alertId)` starts from the alert, requires citations, separates facts from inference, checks telemetry gaps, and recommends operator-reviewed next steps.
- `investigate_asset(agentId, lookbackHours)` establishes source health and coverage before interpreting event or alert absence.
- `improve_detection(ruleId, version)` reviews prerequisites and alert outcomes and produces only a bounded proposal with test and rollback considerations.
- `review_coverage(agentId)` distinguishes missing, stale, degraded, denied, unsupported, excepted, and not-applicable source states.

Prompts do not grant capabilities. The MCP client still receives only the authenticated tools/resources above, and the server does not execute model recommendations or endpoint actions.

## Result, redaction, and trust model

Tool results use the `challenger-siem.mcp.v1` envelope. It includes generation time, result kind, data classification, redaction description, truncation state, row count, data, record citations, and warnings. Nested source-health, case, and graph results also include the applied per-collection limit plus accurate returned-record and truncation state for each named collection; the envelope warning names every collection that reached its bound. `read_only` and `untrusted_telemetry` are always true.

Collected event text, raw payloads, endpoint inventory, case notes, graph content, entity values, and analyst-authored fields are evidence, not instructions for the MCP client. A client should:

1. Establish source health and coverage before interpreting an absence of alerts or events.
2. Cite returned record identifiers and keep observed facts separate from inference.
3. Treat truncated counts as lower bounds and continue only with deliberate bounded calls.
4. Apply the least-privileged operator role and request admin inventory only when necessary.
5. Require human review before acting on alert, detection, investigation, or host recommendations.

Existing server-side role policy remains authoritative. Non-admin event reads omit raw payloads and redact protected account, command-line, path, registry, and network fields. Admin access may return more sensitive evidence and must be handled accordingly. MCP data tools do not return server-held credentials, connection strings, authorization headers, cookies, private configuration, or agent tokens. Endpoint-supplied inventory is untrusted: secret-named map values and high-confidence secret patterns are redacted, but operators must still treat the remaining admin-only inventory as restricted evidence.

## Auditing

Each data-returning tool call, including a resource read backed by a tool, writes a security-audit event named `mcp.tool.<tool-name>`. Audit metadata records outcome, safe target identifiers where applicable, row count, truncation, redaction, data classification, and a bounded reason code. It never records the operator credential, authorization header, query values, event messages, raw telemetry, inventory values, or other returned evidence.

Prompt discovery and rendering do not read SIEM telemetry. Subsequent tool/resource reads invoked by the client are audited normally.

## Validation

Use synthetic data and an isolated test database for protocol and authorization tests:

```bash
dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj
./scripts/validate-repository-safety.sh
./tests/repository-safety/run.sh
```

For an integration check, start the real server on an unused loopback port, connect an MCP inspector/client with a disposable analyst credential, and verify:

- unauthenticated, cookie-only, viewer, enrollment-token, and agent-token requests fail;
- analyst reads succeed but remain redacted and bounded;
- admin-only inventory fails for analyst and succeeds for a disposable admin credential;
- detection review is proposal-only and does not change the detection version or state;
- each tool/resource read creates a secret-safe security-audit row;
- no tracked file, terminal transcript, browser capture, or test artifact contains the credential or returned telemetry.

Keep protocol captures, responses, audit evidence, and temporary client configuration only under ignored `.local/` paths. Do not run broad queries against a real endpoint environment solely to demonstrate the integration.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `401` with `mcp_operator_bearer_required` | Send an operator API credential in an `Authorization: Bearer` header. A browser cookie or endpoint-agent token is not accepted. |
| `403` / authorization failure | Use an active analyst, detection-engineer, or admin operator; inventory item access requires admin. |
| HTTPS redirect or `https_required` | Use the deployed HTTPS URL. Restrict HTTP to the documented loopback development path. |
| Empty result | Confirm lookback and filters, then inspect source health and coverage; absence of telemetry is not proof of safety. |
| Truncated result | Narrow the filters or continue with the returned cursor/offset. Treat counts at a bound as lower bounds. |
| Invalid request | Check UUIDs, 1-168 hour lookbacks, row/item limits, cursor value, and maximum field lengths. |
| Client cannot discover resources/prompts | Confirm the client supports Streamable HTTP and current MCP resource/prompt discovery, and that it is connecting to the exact `/mcp` path. |

The MCP transport is additive and outside `/api/v1`; it does not change the versioned endpoint-agent or review API contracts. See [Architecture](architecture.md), [API contract v1](api.md), [Authentication](auth.md), and [Dependencies](dependencies.md) for the surrounding boundaries.
