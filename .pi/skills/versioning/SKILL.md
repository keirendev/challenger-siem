---
name: project-versioning
description: Use whenever changing this Challenger SIEM project or preparing a commit/PR to decide whether VERSION, CHANGELOG.md, API routes, or schema contract versions need updates.
allowed-tools: bash read edit write
---

# Project versioning

Follow the project-local policy in `docs/versioning.md`.

## Required workflow

1. Read `docs/versioning.md` before making or finalizing project changes.
2. Check the current version with:
   ```bash
   ./scripts/current-version.sh
   ```
3. Classify the change as major, minor, patch, or no-bump.
4. If a bump is needed, update `VERSION` and `CHANGELOG.md` in the same change set.
5. If API/schema compatibility changes, keep `/api/v1` and `contracts/v1/` stable unless explicitly creating a new versioned contract.
6. Do not edit generated `dist/`, `bin/`, or `obj/` artifacts unless the operator explicitly asks for release artifacts.
7. In the final response or PR summary, state the version bump made or why no bump was needed.
