---
description: Create a feature branch, commit staged/current project changes, push, and open a PR to main
argument-hint: "[branch-name] [commit-message]"
---
You are preparing a git commit and PR for this project.

Workflow:
1. Inspect `git status --short --branch` and ensure only intended project files are included.
2. Check project versioning: run `./scripts/current-version.sh`, review `docs/versioning.md`, and ensure `VERSION`/`CHANGELOG.md` changes are present when the change set requires them. If no bump is needed, note that in the PR summary.
3. If no branch name is provided, create a concise branch name from the current task, prefixed with `feature/`.
4. Create/switch to the feature branch from `main`.
5. Stage only files relevant to the current project/task. Do not stage unrelated sibling directories or local secrets.
6. Review the staged diff with `git diff --cached --stat` and `git diff --cached` when needed.
7. Commit with the provided commit message, or write a concise conventional commit message if omitted.
8. Push with upstream: `git push -u origin <branch>`.
9. Create a GitHub PR targeting `main` with `gh pr create --base main --head <branch>`.
10. Report the branch, commit SHA, PR URL, and version bump/no-bump decision.

User arguments: $ARGUMENTS
