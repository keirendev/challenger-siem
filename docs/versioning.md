# Versioning

`VERSION` is the single source of truth for the Challenger SIEM project version.

## What uses `VERSION`

- `Directory.Build.props` applies it to .NET project `Version`, `PackageVersion`, and `InformationalVersion` metadata.
- The Windows agent reports the assembly informational version in heartbeat data.
- Local helper scripts use `./scripts/current-version.sh` as the default agent version for registration and copy-ready agent prep.

API and schema contract versions are separate compatibility tracks. `/api/v1` and `contracts/v1/` stay stable unless a deliberate contract version change is made.

## SemVer policy

Use semantic versioning: `MAJOR.MINOR.PATCH` with optional pre-release/build metadata.

- **MAJOR**: incompatible API/schema/database changes, or changes that require coordinated incompatible agent/server upgrades.
- **MINOR**: backward-compatible API/schema additions, new log sources, new agent/server capabilities, or significant operational behavior changes.
- **PATCH**: bug fixes, security/reliability fixes, packaging changes, and small operator-visible behavior changes.
- **No bump**: comments, tests, refactors with no artifact/behavior change, or docs-only changes that do not affect release artifacts.

Ask the operator before a major bump or whenever compatibility impact is unclear.

## Pi agent workflow for project changes

1. Check the current version:
   ```bash
   ./scripts/current-version.sh
   ```
2. For every change set, decide whether the project version must change. If no bump is needed, say so in the final response.
3. When a bump is needed, update `VERSION` in the same change set as the code/docs/contracts change.
4. Update `CHANGELOG.md` under `Unreleased` with the operator-visible impact. On an explicit release, move entries from `Unreleased` to a dated version section.
5. For incompatible API/schema changes, create a new versioned route/schema folder instead of silently changing `/api/v1` or `contracts/v1/`.
6. Do not update generated artifacts under `dist/`, `bin/`, or `obj/` unless the operator explicitly asks for release artifacts.
7. Run the relevant build/tests and report the resulting version or no-bump decision.
