# MCP integration

The service exposes stateless Streamable HTTP MCP at `/mcp`. Configure a client such as Codex with the server URL and a bearer token sourced from the environment. Use the same externally managed value configured as `Auth__ServiceToken`.

MCP provides bounded read-only tools and resources for overview, agents, events, timelines, alerts, cases, coverage, inventory, detections, and investigation graphs. Results include truncation and classification metadata. Tool calls are security-audited.

MCP cannot update alerts, cases, rules, agents, retention, server settings, hosts, or files. Use authenticated `/api/v2` REST calls for explicit mutations. The server contains no model client and makes no outbound model request.
