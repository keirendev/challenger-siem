#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
validator="$root/scripts/validate-repository-safety.sh"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

new_repo() {
  local name=$1
  local repo="$temporary/$name"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.name 'Synthetic Test'
  git -C "$repo" config user.email 'synthetic@example.invalid'
  printf '%s\n' "$repo"
}

expect_clean() {
  local repo=$1
  "$validator" "$repo" >/dev/null
}

expect_rejected() {
  local repo=$1
  local output="$temporary/output"
  if "$validator" "$repo" >"$output" 2>&1; then
    printf 'expected prohibited synthetic repository to be rejected\n' >&2
    exit 1
  fi
  if grep -q 'canary-content-must-not-be-printed' "$output"; then
    printf 'validator disclosed file content\n' >&2
    exit 1
  fi
}

clean=$(new_repo clean)
mkdir -p "$clean/tests/fixtures"
printf '{"host":"SYNTHETIC-LINUX-01","user":"synthetic-user"}\n' >"$clean/tests/fixtures/synthetic-linux-event.json"
git -C "$clean" add tests/fixtures/synthetic-linux-event.json
expect_clean "$clean"

for path in \
  'linux-agent-runtime/queue.db' \
  'captures/synthetic-session.pcap' \
  'audit-exports/synthetic-audit.log' \
  'tests/fixtures/linux-event.json' \
  'config/linux-agentsettings.generated.json' \
  'benchmarks/synthetic-results.txt'; do
  repo=$(new_repo "rejected-${path//\//-}")
  mkdir -p "$repo/$(dirname "$path")"
  printf 'canary-content-must-not-be-printed\n' >"$repo/$path"
  git -C "$repo" add -f "$path"
  expect_rejected "$repo"
done

printf 'repository safety tests: passed\n'
