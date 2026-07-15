# ADR: Frontend architecture for high-density SIEM search and timelines

## Status

Accepted for the active product architecture.

## Context

Issue #201 asked for a measured frontend technology spike for high-density search and timeline workflows after the mature UX specification in [web.md](web.md). The existing console is hosted in the ASP.NET Core API process with Razor Pages, PostgreSQL-backed server-side search, database-backed operator sessions, antiforgery-protected forms, and server-enforced role redaction. The spike had to select exactly one active architecture, avoid a permanent parallel UI, and keep all synthetic benchmark/browser evidence local.

## Decision

Continue with an enhanced ASP.NET Core/Razor Pages frontend as the only active architecture for the SIEM console. Do not add a separate TypeScript frontend, JavaScript package manager, client router, build pipeline, lockfile, runtime analytics, CDN, or parallel UI tree for the current high-density search/timeline work.

The selected path is server-rendered Razor Pages with progressively enhanced, same-origin interactions only when a workflow proves that JavaScript adds measurable operator value. Search and timeline slices must keep bounded server-side pagination, request cancellation, role-aware field policy, CSRF-safe mutations, and CSP-compatible asset ownership in the ASP.NET Core application.

## Objective gates

A candidate architecture must pass every gate before weighted scoring can select it:

| Gate | Required outcome | Razor result | Separate TypeScript preflight result |
| --- | --- | --- | --- |
| Credential exposure | No enrollment token, per-agent token, operator API credential, password, provider token, raw auth file, cookie value, or connection string is delivered to JavaScript-readable storage, URLs, traces, screenshots, or docs. | Pass: browser credential remains the protected `HttpOnly`, `SameSite=Strict` session cookie. | No added evidence; a separate app would need a full BFF/session design before passing. |
| Authorization and protected fields | Protected event/alert/raw fields are filtered on the server before serialization or rendering; UI hiding is not a boundary. | Pass: `EventRepository.SearchEventsForOperatorAsync` strips sensitive filters and applies field policy. | No added evidence; an API-heavy client would increase serialized surface and review scope. |
| Build/deploy ownership | No unbounded toolchain, external network/CDN, analytics, generated build output, or runtime service is required for the console. | Pass: existing .NET build/deploy path. | Not justified: would add package manager, lockfile, bundler, and release ownership. |
| Accessibility and responsive behavior | Keyboard operation, visible focus, landmarks, labels, non-color status, and 320px+ reflow are planned and testable against current product pages. | Pass with current shell and page patterns; keep improving in Razor. | No material benefit without choosing and auditing a component system. |
| Performance boundary | Search/timeline views remain bounded, paginated, cancellable, and measured with synthetic data. | Pass: current event page uses bounded limit/offset and request cancellation. | No material benefit while the bottleneck is server filtering/storage rather than client rendering. |

Because the TypeScript path did not pass the preflight justification threshold, no TypeScript candidate was installed or built.

## Weighted scoring

Scores are 0 to the criterion weight. The comparison is based on current repository capabilities, issue #200 workflows, and the local synthetic prototype measurements below. A separate TypeScript candidate needed both gate passage and at least a 15-point material advantage to justify implementation.

| Criterion | Weight | Enhanced Razor | Separate TypeScript preflight | Rationale |
| --- | ---: | ---: | ---: | --- |
| Build/deploy complexity | 10 | 9 | 4 | Razor stays in the .NET solution; TypeScript adds package, lockfile, bundler, generated assets, and CI/release paths. |
| Auth/session/CSRF/CSP risk | 14 | 12 | 6 | Razor uses existing cookie/antiforgery model. A separate app would need explicit BFF/session, CSRF, CORS/origin, and CSP decisions. |
| Protected-field authorization | 12 | 12 | 6 | Current server repositories redact before Razor/API output. A client app would increase JSON payload and caching risk. |
| Accessible component availability | 10 | 8 | 7 | Current semantic HTML shell is adequate. TypeScript component ecosystems are available but require dependency/license/a11y audit. |
| Keyboard/responsive behavior | 8 | 7 | 7 | Both can meet the UX spec; Razor already has skip links, labelled forms, focus CSS, and responsive table patterns. |
| Large table/timeline rendering | 10 | 7 | 8 | Client virtualization could help later, but current bounded page sizes avoid unbounded DOM work. |
| Server pagination/cancellation | 8 | 8 | 5 | Razor handlers already receive cancellation tokens and use bounded repository offset/limit. |
| Testing fit | 8 | 7 | 5 | Existing xUnit/WebApplicationFactory tests cover auth, field policy, and pages. TypeScript would require another test stack. |
| Maintainability | 7 | 6 | 4 | One language/runtime is easier for the current team and keeps review surfaces together. |
| Dependency/license/supply-chain footprint | 6 | 6 | 2 | No new dependency is needed. TypeScript would add transitive npm supply-chain and license inventory. |
| Operational resource cost | 3 | 3 | 2 | Razor ships with the API. A separate frontend adds artifact hosting/cache invalidation concerns. |
| Current .NET integration | 4 | 4 | 1 | Razor directly uses ASP.NET Core auth, antiforgery, tag helpers, and server models. |
| **Total** | **100** | **89** | **57** | Razor wins; TypeScript is not justified. |

## Prototype and measurements

A temporary local-only Razor-shaped HTML prototype was generated under an ignored `.local/` path, served from loopback, measured with headless Chromium, and then deleted. The prototype used only synthetic identifiers (`DEMO-WIN11`, `DEMO-LNX-02`, `demo-agent-*`), no scripts, no cookies, no external fonts/assets, no raw responses, and no real host/user data.

A small non-production test harness is retained in `tests/Siem.Api.Tests/FrontendArchitecturePrototypeHarness.cs` so the spike remains reproducible without adding a routed page, parallel UI, JavaScript package pipeline, static bundle, or runtime dependency. The harness renders a Razor-shaped synthetic HTML slice in memory only, exercises cancellation before and after filtering, clamps pagination to a bounded page size, aggregates timeline buckets, and verifies role-dependent protected-field redaction. It is a test asset, not product UI.

Prototype coverage:

- 500 bounded synthetic result rows with active filter scope and page limit.
- Timeline buckets grouped by hour/source/status.
- Cancellation checked before filtering and after filtering; page size clamped to a bounded maximum.
- Loading, empty, error, unauthorized, stale/degraded, and partial/redacted state blocks.
- Labels, `main` landmark, primary nav label, skip link, visible-focus CSS rule, table caption, keyboard-reachable row action links, and responsive filter/table patterns.
- Protected-field behavior represented as redacted summaries for non-admin roles; durable enforcement remains the server-side repository policy.

Measured headless Chromium results:

| Viewport / run | Rows | Timeline buckets | Load measurement | Accessibility/responsive observations |
| --- | ---: | ---: | --- | --- |
| Desktop, reported `1440x1013` | 500 | 8 | DOMContentLoaded 12 ms; load 73 ms | `main#main-content` present; `nav aria-label="Primary"`; all labels associated; no external resources. |
| Tablet, reported `800x813` | 500 | 8 | load 55 ms | Filters collapsed to 2 columns; result table used horizontal overflow instead of page overflow. |
| Narrow run requested `390x844`, Chromium reported `500x757` | 500 | 8 | load 67 ms | Body scroll width 485 px stayed within the 500 px reported viewport; table overflow remained contained. CSS contains a 480 px single-column breakpoint, but this browser environment did not expose a sub-500 px viewport. |

Limitations:

- Measurements are synthetic and environment-dependent, not a production performance benchmark. PostgreSQL-backed browser release gates remain the authoritative validation path for release candidates.

## Security, accessibility, and CSP implications

- Keep sensitive search filters, raw payloads, command lines, account identifiers, paths, registry keys, packages, and network values server-filtered. Non-admin pages must show redaction/omission semantics rather than ambiguous blanks.
- Keep unsafe Razor mutations antiforgery-protected. Unsafe `/api/v1` mutations remain bearer-only to avoid cookie CSRF.
- Do not add external analytics, fonts, CDNs, telemetry beacons, or cross-origin frontend calls for search/timeline workflows.
- Preserve the current no-secret-browser-return rule: browser content may receive only safe rendered metadata and the protected session cookie via `Set-Cookie`; it must not receive operator API credentials.
- Future CSP hardening should favor same-origin static assets. Existing inline script surfaces, especially live workspace code, must be inventoried and moved to owned static assets or covered by a nonce/hash design before enabling a strict policy.
- Continue validating keyboard order, visible focus, landmarks, labels, table captions/alternatives, non-color status, text zoom/reflow, and reduced-motion behavior for each implemented slice.

## Migration slices for #202 onward

1. Keep `/events` as the current event-search route and evolve it in-place; do not introduce `/search` as a parallel replacement until a single migration cutover is ready.
2. Add server-side timeline aggregation endpoints or query methods only after the repository layer can bound time buckets, limit result windows, and honor cancellation.
3. Extend Razor view models with active filter summaries, query-cost/limit notices, timeline bucket summaries, and source-health/degraded state labels.
4. Add focused WebApplicationFactory and browser E2E coverage for viewer/analyst/admin roles, redaction notices, empty/error/stale/degraded states, pagination, and responsive widths.
5. Move any reusable client script to same-origin static assets with CSP-compatible loading; keep JavaScript optional for core search results and pagination.
6. Update [web-console-demo.md](web-console-demo.md) screenshots only from synthetic seeded data after visible page changes land.

## Deletion criteria for superseded UI code

A superseded UI path may remain only until its replacement is fully selected and cut over. Delete old Razor pages, partials, CSS, scripts, docs, tests, screenshots, and routes when all of these are true:

- The replacement passes the gates in this ADR and preserves protected-field authorization, auth/session/CSRF behavior, CSP posture, keyboard access, responsive behavior, and bounded pagination/cancellation.
- The replacement has equivalent or better tests and browser validation using synthetic data.
- Navigation, deep links, docs, and screenshots point to one active path.
- No feature switch, compatibility route, duplicate theme, stale static bundle, generated artifact, lockfile, or unused dependency remains.
- Repository safety checks show no local automation state, logs, traces, screenshots with private data, generated artifacts, or dependency caches staged.

## Consequences

- Positive: one deployable .NET application, smaller dependency surface, stronger alignment with current auth/RBAC/CSRF model, simpler review, and no new supply-chain inventory.
- Positive: high-density work can focus on server-side indexes, pagination, cancellation, field policy, and accessible Razor components rather than client framework plumbing.
- Tradeoff: very large client-side virtualization or offline interaction is deferred until a concrete workflow demonstrates measurable operator benefit that exceeds this ADR's threshold.
- Tradeoff: CSP hardening still requires cleanup of current inline JavaScript before a strict header can be enabled.
