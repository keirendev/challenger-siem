# Release gates for the web console

Challenger SIEM uses a .NET Playwright release-gate suite for the real ASP.NET Core/Razor Pages application backed by PostgreSQL. The suite is intentionally not a Node/TypeScript app: it uses the pinned NuGet package `Microsoft.Playwright`, starts the real `server/Siem.Api` process, seeds only synthetic data, and stores every generated browser/API/database artifact under ignored `.local/release-gates/`.

## Dependency and tool choice

The selected browser automation approach is **Microsoft.Playwright for .NET**. It aligns with the Razor frontend ADR because it does not add `package.json`, npm lockfiles, a client build pipeline, a separate frontend origin, CDN assets, or permanent generated static bundles.

| Component | Purpose | License / ownership |
| --- | --- | --- |
| `Microsoft.Playwright` NuGet, pinned in `tests/ReleaseGates/ReleaseGates.csproj` | Headless Chromium automation from xUnit/.NET | Apache 2.0 Playwright project; Microsoft-owned NuGet package. Browser binaries are installed only by explicit script under ignored `.local/release-gates/ms-playwright/` and are not redistributed by this repository. |
| Chromium browser runtime installed by Playwright | Local browser execution for release gates | Upstream Chromium/open-source notices apply. Operators own installation, cache cleanup, and supply-chain approval for their local environment. |

## Prerequisites

Required locally:

- .NET SDK compatible with the solution.
- PostgreSQL server reachable from this host.
- `psql`, `curl`, `python3`, and `pwsh` for Playwright browser installation.
- An ignored `.local/release-gates.env` or shell environment containing PostgreSQL admin connection values able to create and drop a uniquely named disposable database and role:

```bash
mkdir -p .local
cat > .local/release-gates.env <<'EOF'
SIEM_RELEASE_GATE_PGHOST='127.0.0.1'
SIEM_RELEASE_GATE_PGPORT='5432'
SIEM_RELEASE_GATE_PGMAINTDB='postgres'
SIEM_RELEASE_GATE_PGADMINUSER='<local-admin-user>'
SIEM_RELEASE_GATE_PGADMINPASSWORD='<local-admin-password>'
EOF
chmod 600 .local/release-gates.env
```

Do not put these values in tracked files, command transcripts, screenshots, issue text, or PR text.

## Install browser runtime

Install Chromium explicitly under the ignored local release-gate cache:

```bash
./scripts/release-gates.sh install-browsers
```

The script builds only the .NET test project and runs the Playwright install helper with `PLAYWRIGHT_BROWSERS_PATH=.local/release-gates/ms-playwright`. If `pwsh` or browser prerequisites are missing, the script fails with actionable guidance rather than silently passing.

## Run the full release gate

```bash
./scripts/release-gates.sh run
```

The runner:

1. creates a unique `siem_rg_*` database and `siem_rg_role_*` role;
2. writes state under `.local/release-gates/<run-id>/state.env`;
3. applies every PostgreSQL migration;
4. bootstraps one synthetic admin and creates synthetic viewer, analyst, and detection-engineer operators;
5. starts the real `server/Siem.Api` process on a loopback URL;
6. seeds a deterministic, uniquely named synthetic agent, heartbeat/source-health states, hundreds of synthetic events, one alert, one case, detection metadata, source-review/admin metadata, and a saved dashboard layout;
7. runs `dotnet test tests/ReleaseGates/ReleaseGates.csproj` with `SIEM_RELEASE_GATE_ENABLED=1`;
8. writes sanitized aggregate reports and test logs under `.local/release-gates/<run-id>/`.

The runner prints only paths, run IDs, and aggregate status. Generated credentials, API tokens, cookies, raw API responses, browser cache/profile data, TRX logs, and SQL logs remain ignored under `.local/`.

Optional bounded dataset and budget overrides:

```bash
SIEM_RELEASE_GATE_EVENT_COUNT=1000 \
SIEM_RELEASE_GATE_API_SEARCH_BUDGET_MS=3000 \
SIEM_RELEASE_GATE_API_TIMELINE_BUDGET_MS=3000 \
SIEM_RELEASE_GATE_BROWSER_LOAD_BUDGET_MS=8000 \
SIEM_RELEASE_GATE_CSS_BUDGET_BYTES=300000 \
SIEM_RELEASE_GATE_JS_BUDGET_BYTES=120000 \
./scripts/release-gates.sh run
```

## Cleanup

Destructive cleanup is deliberately separate and confirms scope. It refuses arbitrary names and only drops database/role names matching the owned release-gate patterns from the recorded state file:

```bash
./scripts/release-gates.sh cleanup \
  --state .local/release-gates/<run-id>/state.env \
  --confirm DELETE-RELEASE-GATE-RESOURCES
```

To run and then remove owned resources immediately:

```bash
./scripts/release-gates.sh run \
  --cleanup-owned \
  --confirm DELETE-RELEASE-GATE-RESOURCES
```

Do not use release-gate cleanup for development, shared, production, client, or unclassified databases.

## Automated gate coverage

The xUnit/Playwright suite covers these implemented release gates against the real app:

- login success and failure, logout/session revocation, unauthenticated redirects, unsafe external return URL handling, and exact viewer/analyst/detection-engineer/admin role navigation/forbidden states;
- role-aware navigation and server-enforced authorization for Cases, Administration, detection management, API mutations, and cookie-only unsafe API calls;
- event search filters, UTC timeline buckets, bounded pagination/rendering, saved searches, detail/asset pivots, admin export guards, and protected-field redaction/omission;
- asset/source-health states including healthy, degraded, stale, permission-denied, queue/capacity/gap signals;
- alert detail, seeded evidence, case lifecycle surfaces, detection prerequisites/tuning metadata, dashboards, admin audit/settings surfaces, and empty/error/partial/degraded copy;
- keyboard skip link/focus visibility, landmarks, one `h1`, labelled form controls, `aria-describedby` targets, table captions/headers, non-empty state badges, reduced motion, and desktop/tablet/mobile reflow;
- CSP, `nosniff`, referrer policy, cookie `HttpOnly`/`SameSite=Strict`, HTTPS secure-cookie check when running on HTTPS, XSS escaping, no secret/token return in browser content, CSV content-disposition/formula safety, and no operator API credential leakage in URLs/content;
- API search/timeline budgets, browser page-load budget, CSS/JS size budgets, cancellation observability, bounded row rendering, and bounded synthetic dataset size.

## Manual WCAG 2.2 AA checklist

Run this checklist before a release when browser gates pass:

- Navigate only with keyboard: skip link, primary nav, account/logout, filters, tables, pagination, dialogs/confirmation panels, and mutation forms are reachable in logical order.
- Confirm visible focus at normal zoom, 200% zoom, desktop, tablet, and 320-390px mobile widths.
- Confirm screen-reader landmarks: banner, primary nav, secondary nav where present, one main landmark, one `h1`, labelled sections, and descriptive table captions.
- Verify names/labels/descriptions for every filter, search field, select, textarea, checkbox, button, and link; field errors identify the field and fix.
- Review dialogs, tabs, menus, confirmation panels, and live regions for title/description, Escape/cancel behavior, focus restoration, and polite/assertive announcement use.
- Confirm state is never color-only: status/severity badges include text or icons with accessible labels.
- Check table semantics and available text alternatives for charts/timelines/graphs.
- Check 200% zoom/reflow and text spacing; only data tables/graphs may scroll horizontally and must retain accessible summaries.
- Enable reduced motion in the browser/OS and confirm nonessential animation/smooth scrolling is disabled.
- Check touch targets and spacing for primary actions on mobile and tablet.

## Failure interpretation

- Missing PostgreSQL admin variables, `psql`, `curl`, `python3`, `pwsh`, browser binaries, or local browser dependencies are **NOT RUN** prerequisites and fail release-gate mode.
- A failing browser/API assertion is a release blocker unless a documented product decision changes the relevant budget or requirement.
- Local performance numbers are synthetic and host-dependent; adjust budgets only with evidence and keep them stable across release candidates.
- Keep raw artifacts local. Public summaries should report command, pass/fail/skipped status, sanitized run ID, aggregate timings, and cleanup state only.
