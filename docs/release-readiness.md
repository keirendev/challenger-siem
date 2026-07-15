# MVP release readiness checklist

Use this checklist before closing the parent MVP specification issue.

## Required local checks

- [ ] `./scripts/current-version.sh` returns the expected project version.
- [ ] `dotnet build Challenger.Siem.sln` passes.
- [ ] `dotnet test Challenger.Siem.sln` passes.
- [ ] PostgreSQL schema applies cleanly: `./scripts/apply-schema.sh`.
- [ ] PostgreSQL schema validation passes: `./scripts/validate-schema.sh`.
- [ ] Fake API smoke passes: `./scripts/smoke-test-server.sh`.
- [ ] Web console smoke passes: `./scripts/smoke-test-web.sh`.
- [ ] MCP tests cover bearer-only analyst authorization, discovery, role redaction, admin-only inventory, bounded/proposal-only behavior, and secret-safe audit metadata; see [mcp.md](mcp.md#validation).
- [ ] Real-app browser/accessibility/security/performance release gates pass against disposable PostgreSQL synthetic data: `./scripts/release-gates.sh install-browsers` then `./scripts/release-gates.sh run`.
- [ ] Release-gate cleanup is either completed with `./scripts/release-gates.sh cleanup --state .local/release-gates/<run-id>/state.env --confirm DELETE-RELEASE-GATE-RESOURCES` or intentionally deferred with the owned state path recorded locally.
- [ ] Frontend architecture remains consistent with [the Razor-selected ADR](frontend-architecture-adr.md): no rejected prototype, npm toolchain, lockfile, generated static bundle, external CDN/analytics/font dependency, or parallel UI route is included.
- [ ] Windows agent publish succeeds: `./scripts/publish-windows-agent.sh`.
- [ ] Copy-ready bundle generation succeeds with an ignored generated settings file.

## Windows lab evidence

Record sanitized evidence under ignored `.local/` only:

- [ ] API health from Linux host (`http://127.0.0.1:4444/health`).
- [ ] API health from the operator-approved Windows lab endpoint at its configured callback URL.
- [ ] Temporary agent process starts and exits/stops cleanly.
- [ ] At least one real `System` or `Application` event is ingested and searchable for the unique test agent.
- [ ] Optional channels are absent/skipped without crashing, or documented if present.
- [ ] Security-channel access succeeds under the service account or missing-permission symptoms are documented without changing host policy.
- [ ] API outage retry keeps events queued and a later live API run drains accepted/duplicate events.

## Linux local-host rollout evidence

Record live Linux evidence only under ignored `.local/` or approved target runtime paths, and publish only the sanitized aggregate template from [Linux local-host validation](linux-local-host-validation.md):

- [ ] Read-only Linux preflight plan reviewed with no unauthorized host-policy mutation.
- [ ] L1 24-hour soak is passed or explicitly blocked because no authorized systemd target/window was supplied.
- [ ] L1+L2 seven-day soak is passed before L2 expansion, or explicitly blocked/deferred with no fabricated evidence.
- [ ] API outage/restart, database restart, agent restart, journal rotation, permission-loss, and disk/queue-pressure recovery checks are passed, blocked for lack of approval, or not applicable with a sanitized reason.
- [ ] L3 self-integrity remains disabled unless a separate exact approval and plan hash are recorded privately.
- [ ] No raw host telemetry, generated settings, logs, queues, database dumps, screenshots, benchmark output, package lists, host identities, or private paths are tracked.

## Repository hygiene

- [ ] `git status --short --ignored` shows local automation state, `.local/` including `.local/release-gates/`, `bin/`, `obj/`, and `dist/` only as ignored or absent.
- [ ] `git diff --cached --name-status` contains only intended tracked project files.
- [ ] No secrets, generated agent settings, raw telemetry, logs, dumps, captures, or WinRM credentials are staged.
- [ ] `VERSION` and `CHANGELOG.md` follow `docs/versioning.md`.
- [ ] `/api/v1` and `contracts/v1` compatibility is preserved, or a deliberate new version exists.
- [ ] Tracked MCP client examples contain placeholders only; protocol captures, responses, and credentials remain under ignored `.local/` paths.

## Child issue disposition

The parent MVP issue can be closed only after child issues #7-#23 are closed or explicitly deferred with a documented non-MVP reason. The expected MVP path is to close them with evidence from the checks above.
