# Contributor guide

This guide summarizes how to make safe, reviewable project changes. It complements [development.md](development.md), [versioning.md](versioning.md), and the repository README.

## Working principles

- Keep changes small, testable, and linked to the relevant issue or design note.
- Prefer C#/.NET for the Windows agent and ASP.NET Core for server/API/web work unless requirements change.
- Keep `/api/v1` and `contracts/v1/` backward compatible unless the change deliberately introduces a new versioned contract.
- Treat reliability and security behavior as core functionality: durable queueing, retry/backoff, deduplication, bookmark/state tracking, token handling, and secret-safe logging.
- This repository is public. Never commit secrets, real endpoint telemetry, local agent settings, browser cookies, raw event exports, logs, dumps, generated `bin/`, `obj/`, `dist/`, `.local/`, `.pi/`, or local coding-agent files.

## Local workflow

1. Synchronize with `main`.
2. Create a branch named for the issue or change.
3. Read the relevant docs, contracts, schemas, scripts, tests, and web pages before editing.
4. Implement code/docs/tests together.
5. Run the relevant validation:

   ```bash
   ./scripts/current-version.sh
   dotnet test Challenger.Siem.sln
   ./scripts/smoke-test-server.sh      # when API/storage/ingest behavior changes
   ./scripts/smoke-test-web.sh         # when web behavior or web docs/screenshots change
   ```

6. For web-app changes, perform browser E2E with Playwright or an equivalent headless browser harness against the real app; curl/HTML smoke checks supplement but do not replace browser validation.
7. For Windows agent changes, validate against the authorized lab path when safe and keep evidence bounded under ignored `.local/` paths.
8. Check repository hygiene before staging:

   ```bash
   git status --short --ignored
   git diff --cached --name-status
   ```

## Documentation-maintenance checklist

Answer this checklist for every pull request and update docs in the same change set when the answer is yes.

### README and wiki/docs

- Does the capability summary, quickstart, repository layout, or supported workflow change?
- Does [docs/index.md](index.md) need a new link or a changed page description?
- Do operator steps in [operators.md](operators.md), [runbooks.md](runbooks.md), or [troubleshooting.md](troubleshooting.md) need an update?
- Is a planning doc now implemented and ready to move under [archive/](archive/README.md)?

### API, contracts, and schema

- Did a route, request/response field, validation rule, auth requirement, status code, or error shape change?
- Do [api.md](api.md), [schema.md](schema.md), `contracts/v1/`, `shared/Contracts/`, or example payloads need updates?
- Is the change backward compatible with `/api/v1`? If not, create a new versioned route/schema instead of silently changing v1.

### Agent and operations

- Did agent configuration, queue/state behavior, channel coverage, service install assumptions, or Windows permissions change?
- Do [agent.md](agent.md), [agent-config.md](agent-config.md), validation runbooks, or install/uninstall scripts need updates?
- Does the Windows lab validation path or callback address change?

### Web console and screenshots

- Did Razor Pages, auth/session behavior, CSRF/cookies, navigation, view models, filters, routes, or user-visible browser behavior change?
- Do [web.md](web.md) and [web-console-demo.md](web-console-demo.md) need updated text or screenshots?
- Were screenshots regenerated only from synthetic data and inspected for tokens, cookies, real hostnames/users, connection strings, and raw private telemetry?
- Were browser traces/videos/raw captures kept under ignored `.local/` paths?

### Security and public-data safety

- Could any new example, fixture, screenshot, log, test output, or PR comment disclose a secret or real endpoint/client data?
- Are placeholder values clearly fake, such as `<long-random-review-token>`, `DEMO-WIN11`, `demo-agent-001`, or documentation-only RFC 5737 IP ranges?
- Are generated settings, queue/state databases, event exports, captures, and lab evidence excluded from staging?

### Versioning and changelog

- Run `./scripts/current-version.sh` and classify the change under [versioning.md](versioning.md).
- Update `VERSION` and [CHANGELOG.md](../CHANGELOG.md) for required SemVer bumps.
- For docs-only/tests-only/no-artifact refactors, explicitly state why no version bump is needed.

## Review expectations

A good review checks:

- Acceptance criteria from the issue are fully addressed.
- Tests and smoke/browser/Windows validation match the risk of the change.
- Documentation, contracts, examples, screenshots, and changelog are synchronized.
- API/schema compatibility and versioning decisions are explicit.
- No ignored/local/private data appears in staged files.
- Web screenshots are sanitized and reproducible from synthetic data.

## Public examples and fixtures

Use minimal synthetic examples. Prefer fake hostnames such as `DEMO-WIN11`, fake agent IDs such as `demo-agent-001`, fake users such as `DEMO\\analyst`, fake graph titles, and non-sensitive messages. Never adapt raw lab telemetry or customer/client data into fixtures.
