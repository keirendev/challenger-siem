# Web-console visual capture guide

This page defines the public-safe capture and validation contract for web-console visuals. The current console information architecture, page map, accessibility requirements, and text wireframes live in [web.md](web.md).

No screenshot gallery is claimed as current for version 1.6.0. The prior captures predate the refreshed navigation rail and security overview, so they were removed. Replacement screenshots may be published only after the current real application passes synthetic browser E2E and every selected image is inspected under the rules below. Until then, tests and [web.md](web.md) are the authoritative description of implemented behavior.

## Screenshot and wireframe data contract

Tracked screenshots and documentation wireframes must satisfy all of these rules:

- Synthetic agent IDs, hostnames, users, graph titles, case IDs, alert IDs, messages, event IDs, IP addresses, and raw JSON only.
- Use fake examples such as `DEMO-WIN11`, `DEMO-LNX-02`, `synthetic-user`, `CASE-DEMO-0007`, `demo-alert-001`, and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- No operator API credentials, enrollment tokens, per-agent API tokens, connection strings, cookies, local browser profiles, shell history, private lab hostnames/users, real endpoint telemetry, event-log exports, raw customer/client data, provider credentials, auth-file paths, or generated agent settings.
- Browser page screenshots only; crop or capture the page viewport so browser chrome, bookmarks, extension icons, OS menu bars, local account names, local paths, window titles with private text, and desktop notifications are absent.
- Text wireframes must be hand-authored synthetic product examples. Do not paste real output and then sanitize it.
- Raw API responses, cookie jars, Playwright traces, videos, temporary screenshots, browser caches, and logs stay under ignored `.local/` paths.

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
6. Filter data-bearing pages by a unique synthetic agent ID such as `demo-agent-001`.
7. Inspect every selected PNG before staging or committing:
   - No token, cookie, connection string, API credential, enrollment token, per-agent token, provider credential, auth-file path, or generated agent setting.
   - No real hostname, username, IP address, event payload, browser profile, local path, lab telemetry, browser chrome, OS UI, desktop notification, extension icon, bookmark, or local account name.
   - Raw JSON, command lines, paths, account values, and network values are synthetic and minimal.
   - Redaction/omission labels match the role used for capture.
8. Save selected images under `docs/assets/web-console/` with stable descriptive names and update this page if routes, navigation labels, captions, or target IA wireframes change.
9. Run a local markdown link/image check and browser E2E validation for the affected web paths. For docs-only IA changes, run link/safety checks and record the design-review evidence instead of regenerating screenshots.

## Required browser E2E coverage before publishing a gallery

Before adding current screenshots, validate the real application with a headless browser and cover:

- `/login` unauthenticated page and successful login redirect.
- Dashboard `/`.
- `/agents` filtered inventory and `/agents/detail` source-health detail.
- `/events` filtered search and `/events/detail`.
- `/alerts` alert skeleton.
- `/graphs` and `/graphs/detail` with a synthetic graph.
- `/soc-agent` live workspace, `/audit-policy`, and `/about`.
- Logout and unauthenticated redirect/denial behavior.
- Responsive-width smoke coverage, visible focus behavior, active/disabled role-aware navigation state, forbidden-state behavior, global event-search POST behavior, CSP-compatible owned JavaScript loading, and lightweight CSS/page budget checks.

Do not describe this gate as passed until the private synthetic run has completed. See [web.md](web.md) for page behavior and [contributors.md](contributors.md#documentation-maintenance-checklist) for the screenshot maintenance checklist.
