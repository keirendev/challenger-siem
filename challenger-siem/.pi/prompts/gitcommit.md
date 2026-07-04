---
description: Create a feature branch, commit staged/current project changes, push, and open a PR to main
argument-hint: "[branch-name] [commit-message]"
---
You are preparing a git commit and PR for this project.

Workflow:
1. Inspect `git status --short --branch` and ensure only intended project files are included.
2. If no branch name is provided, create a concise branch name from the current task, prefixed with `feature/`.
3. Create/switch to the feature branch from `main`.
4. Stage only files relevant to the current project/task. Do not stage unrelated sibling directories or local secrets.
5. Review the staged diff with `git diff --cached --stat` and `git diff --cached` when needed.
6. Commit with the provided commit message, or write a concise conventional commit message if omitted.
7. Push with upstream: `git push -u origin <branch>`.
8. Create a GitHub PR targeting `main` with `gh pr create --base main --head <branch>`.
9. Report the branch, commit SHA, and PR URL.

User arguments: $ARGUMENTS
