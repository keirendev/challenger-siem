# Sanitized web-console demo

This page is a public-safe visual guide to the web review console. Every screenshot and text wireframe referenced by this page must be generated from synthetic demo data, not from real endpoint telemetry. The mature console information architecture, target page map, accessibility requirements, and sanitized text wireframes live in [web.md](web.md).

## Screenshot and wireframe data contract

Tracked screenshots and documentation wireframes must satisfy all of these rules:

- Synthetic agent IDs, hostnames, users, graph titles, case IDs, alert IDs, messages, event IDs, IP addresses, and raw JSON only.
- Use fake examples such as `DEMO-WIN11`, `DEMO-LNX-02`, `synthetic-user`, `CASE-DEMO-0007`, `demo-alert-001`, and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- No operator API credentials, enrollment tokens, per-agent API tokens, connection strings, cookies, local browser profiles, shell history, private lab hostnames/users, real endpoint telemetry, event-log exports, raw customer/client data, provider credentials, auth-file paths, or generated agent settings.
- Browser page screenshots only; crop or capture the page viewport so browser chrome, bookmarks, extension icons, OS menu bars, local account names, local paths, window titles with private text, and desktop notifications are absent.
- Text wireframes must be hand-authored synthetic product examples. Do not paste real output and then sanitize it.
- Raw API responses, cookie jars, Playwright traces, videos, temporary screenshots, browser caches, and logs stay under ignored `.local/` paths.

The current gallery uses a synthetic agent similar to `issue-147-demo-agent` on `DEMO-WIN11` with a synthetic System event, source-health heartbeat, and investigation graph. Future gallery refreshes should align route captions with the page map in [web.md](web.md#current-route-map) while clearly labelling unimplemented IA wireframes as specification sketches rather than current UI.

## Gallery

### Login

The login page is captured with empty username and password fields so no operator identity or credential is visible.

![Operator login page with empty username and password fields](assets/web-console/login.png)

### Dashboard

The dashboard summarizes active/recent/stale/retired agents, queue observations, and recent ingest volume without listing hostnames.

![Dashboard metrics with synthetic development data](assets/web-console/dashboard.png)

### Agent inventory

The inventory screenshot is filtered to the synthetic demo agent so no unrelated hostnames appear.

![Agent inventory filtered to a synthetic demo agent](assets/web-console/agents.png)

### Host coverage and source health

The current screenshot uses the synthetic Windows matrix. The same page is now platform-aware and, for synthetic Linux agents, also shows requirement/applicability plus degraded, permission-denied, and unsupported source metrics without exposing telemetry.

![Host coverage detail for a synthetic demo agent](assets/web-console/agent-detail.png)

### Event search

Event search is filtered to the synthetic demo agent and unique marker.

![Event search results for a synthetic System event](assets/web-console/events.png)

### Event detail

The detail page shows normalized fields, entities, message text, and raw JSON that were all generated from a synthetic payload.

![Event detail page with synthetic normalized fields and raw JSON](assets/web-console/event-detail.png)

### Alerts

The alerts page currently demonstrates the alert review skeleton and empty-state behavior when no synthetic alerts match the selected filter.

![Alerts review skeleton with empty-state handling](assets/web-console/alerts.png)

### Investigation graphs

The graph list and detail screenshots use a synthetic operator-managed graph with demo nodes and an edge.

![Investigation graph list with synthetic graph](assets/web-console/graphs.png)

![Investigation graph detail with synthetic nodes and relationship](assets/web-console/graph-detail.png)

### soc-agent workspace

The `soc-agent` screenshot should show the widened live workspace layout with the provider status pill, a synthetic agent context, Recent chats controls, sanitized live tool activity, and only synthetic assistant Markdown/output if a chat response is visible. Do not use real prompts or responses in public screenshots.

![soc-agent workspace with local provider status and live tool activity](assets/web-console/soc-agent.png)

### Audit policy

The audit-policy page demonstrates empty-state handling when no synthetic audit snapshot has been reported.

![Audit policy drift empty-state page](assets/web-console/audit-policy.png)

### System/about

The about page shows version, contract version, environment, and database connectivity status without secret values.

![System about page with non-sensitive runtime status](assets/web-console/about.png)

## Regenerating screenshots safely

Use this process whenever web UI changes make the screenshots stale:

1. Start from a clean branch and confirm there are no unintended tracked changes.
2. Source private local configuration from `.local/dev.env`; never print it.
3. Start the real API/web app against a development database.
4. Seed only synthetic data through public API flows:
   - Register a synthetic agent with `X-Enrollment-Token`.
   - Ingest a synthetic event with the returned per-agent API token.
   - Send a synthetic heartbeat/source-health payload.
   - Create a synthetic graph through the review API.
5. Use Playwright or another headless browser to log in with a synthetic operator username/password, navigate the pages, and capture page screenshots. Keep raw traces/videos/temp captures under `.local/`.
6. Filter data-bearing pages by the synthetic agent ID or unique issue marker.
7. Inspect every selected PNG before staging or committing:
   - No token, cookie, connection string, API credential, enrollment token, per-agent token, provider credential, auth-file path, or generated agent setting.
   - No real hostname, username, IP address, event payload, browser profile, local path, lab telemetry, browser chrome, OS UI, desktop notification, extension icon, bookmark, or local account name.
   - Raw JSON, command lines, paths, account values, and network values are synthetic and minimal.
   - Redaction/omission labels match the role used for capture.
8. Save selected images under `docs/assets/web-console/` with stable descriptive names and update this page if routes, navigation labels, captions, or target IA wireframes change.
9. Run a local markdown link/image check and browser E2E validation for the affected web paths. For docs-only IA changes, run link/safety checks and record the design-review evidence instead of regenerating screenshots.

## Browser E2E coverage used for this gallery

The gallery was validated with a headless browser against the real redesigned app and covered:

- `/login` unauthenticated page and successful login redirect.
- Dashboard `/`.
- `/agents` filtered inventory and `/agents/detail` source-health detail.
- `/events` filtered search and `/events/detail`.
- `/alerts` alert skeleton.
- `/graphs` and `/graphs/detail` with a synthetic graph.
- `/soc-agent` live workspace, `/audit-policy`, and `/about`.
- Logout and unauthenticated redirect/denial behavior.
- Responsive-width smoke coverage, visible focus behavior, active navigation state, and lightweight CSS/page budget checks.

See [web.md](web.md) for page behavior and [contributors.md](contributors.md#documentation-maintenance-checklist) for the screenshot maintenance checklist.
