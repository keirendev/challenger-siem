---
description: Review a PR, fix issues when practical, approve/merge it into main, and clean up branches
argument-hint: "[PR-url|PR-number|base..head|base head] [focus]"
---
You are performing an end-to-end pull request review for this Challenger SIEM project.

Review target arguments: $ARGUMENTS

Goal: review the PR or diff, fix any actionable issues when practical, re-validate, approve/accept the PR, merge it into `main`, then clean up the PR branch locally and remotely.

Workflow:
1. Identify the review target.
   - If a PR URL or number is provided, use `gh pr view` / `gh pr diff` when available.
   - If a `base..head` range or `base head` pair is provided, review that git diff; only merge/cleanup if it maps to a GitHub PR.
   - If no target is provided, infer the current branch PR with `gh pr view`; if that is unavailable, compare the current branch to `origin/main` for review only and stop before merge.
2. Inspect `git status --short --branch` first. Distinguish PR changes from unrelated local work, and do not overwrite, stage, or delete unrelated local changes.
3. Verify PR metadata before any merge action: base branch is `main`, head branch is identified, PR is not draft, there are no merge conflicts, required checks are passing or acceptable per repository policy, and no blocking findings remain.
4. Read the changed files and relevant surrounding code. Prefer targeted commands such as `git diff --stat`, `git diff --name-only`, `git diff -- <path>`, `gh pr diff`, and `rg -n`.
5. Check project versioning requirements by reviewing `docs/versioning.md` and running `./scripts/current-version.sh`. Verify whether `VERSION` and `CHANGELOG.md` changes are required and present.
6. Review for this project's priorities:
   - Security: secret handling, no token/password logging, auth/enrollment token behavior, HTTPS/API assumptions, protected Windows config paths.
   - Reliability: disk queue behavior, retry/backoff, deduplication, event bookmarks/positions, idempotent server writes.
   - Windows event collection: correct channels, Event Log parsing/normalization, batching, service behavior, authorized WinRM-only assumptions.
   - Server/storage/contracts: API validation, `/api/v1` compatibility, `contracts/v1/` stability, PostgreSQL write/query behavior, migration/schema impacts.
   - Tests and operations: relevant unit/integration coverage, local scripts, docs, examples, and operator-visible behavior.
7. Run lightweight, relevant validation when practical (for example `dotnet test`, targeted test projects, or script shell checks). Do not use WinRM unless the PR explicitly requires Windows lab validation and the operator authorized it.
8. If issues are found:
   - Fix actionable issues directly on the PR branch when safe and in scope.
   - Update tests/docs/versioning as required by `docs/versioning.md`.
   - Re-run relevant validation.
   - Commit only the review fixes with a concise commit message and push them to the PR branch.
   - Re-review the resulting diff before proceeding.
   - If an issue cannot be safely fixed or needs an operator/product decision, stop and report it instead of merging.
9. Approve/accept and merge only after there are no blocking findings and validation/checks are acceptable.
   - Approve with `gh pr review <pr> --approve` when permissions allow. If approval is not possible (for example, reviewer is the author), note that and continue only if merge permissions/policy allow.
   - Merge into `main` using the repository's required strategy. If no project-specific strategy is evident, use `gh pr merge <pr> --merge --delete-branch`.
   - Do not merge drafts, PRs with unresolved conflicts, PRs not targeting `main`, or PRs with failing required checks unless the operator explicitly instructs otherwise.
10. Clean up after a successful merge:
    - `git fetch --prune origin`.
    - Switch to `main` and fast-forward it from origin: `git switch main` then `git pull --ff-only origin main`.
    - Delete the local PR branch with `git branch -d <head-branch>` after confirming it is merged.
    - Ensure the remote PR branch was deleted by the merge command; if it still exists in the same repository, delete it with `git push origin --delete <head-branch>` after confirming it is the PR branch.
    - Never delete `main`, protected branches, unrelated branches, or branches containing unrelated unmerged work.

Output format:
- Start with a one-line status: `merged`, `blocked`, or `review-only`.
- List findings ordered by severity. Each finding must include severity, file path and line/reference, the issue, impact, and the fix applied or recommended.
- Include a `Fixes` section summarizing any commits pushed during review, or say none.
- Include a `Versioning` section with bump/changelog assessment.
- Include a `Validation` section listing commands run and results, or say not run.
- Include a `Merge and cleanup` section with PR approval/merge result, main sync result, local branch deletion, and remote branch deletion/prune status.
- Include `Questions/Assumptions` only if needed.

If there are no findings, say so explicitly and mention any residual risks or untested areas before merging.
