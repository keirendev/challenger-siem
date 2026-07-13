#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
validator="$root/scripts/validate-repository-safety.sh"
temporary=$(mktemp -d)
trap 'chmod -R u+rwx "$temporary" 2>/dev/null || true; rm -rf "$temporary"' EXIT
new_repo() {
  local repo
  repo=$(mktemp -d "$temporary/case.XXXXXX")
  git -C "$repo" init -q
  printf '%s\n' "$repo"
}

expect_clean() {
  local repo=$1
  "$validator" "$repo" >/dev/null
}

expect_rejected() {
  local repo=$1
  local expected_path=$2
  local output="$temporary/output"
  if "$validator" "$repo" >"$output" 2>&1; then
    printf 'expected prohibited synthetic repository path to be rejected: %s\n' "$expected_path" >&2
    exit 1
  fi
  if ! grep -Fq -- " - $expected_path" "$output"; then
    printf 'validator diagnostic did not identify the prohibited path: %s\n' "$expected_path" >&2
    exit 1
  fi
  if grep -Fq 'canary-content-must-not-be-printed' "$output"; then
    printf 'validator disclosed file content\n' >&2
    exit 1
  fi
}

reject_path() {
  local path=$1
  local repo
  repo=$(new_repo)
  mkdir -p "$repo/$(dirname "$path")"
  printf 'canary-content-must-not-be-printed\n' >"$repo/$path"
  git -C "$repo" add -f -- "$path"
  expect_rejected "$repo" "$path"
}

# This fixture follows the documented public-fixture contract: a synthetic-
# filename and minimal, deterministic, hand-authored fake identifiers.
clean=$(new_repo)
mkdir -p "$clean/tests/parsers/fixtures"
printf '{"host":"SYNTHETIC-LINUX-01","user":"synthetic-user","ip":"192.0.2.10"}\n' \
  >"$clean/tests/parsers/fixtures/synthetic-linux-event.json"
printf '# Synthetic parser fixtures\n' >"$clean/tests/parsers/fixtures/README.md"
git -C "$clean" add tests/parsers/fixtures
expect_clean "$clean"

# The validator operates on index names only. An ignored and unreadable local
# autodev directory must neither affect validation nor be opened or traversed.
mkdir -p "$clean/.local/autodev"
printf 'canary-content-must-not-be-printed\n' >"$clean/.local/autodev/evidence"
chmod 000 "$clean/.local/autodev"
expect_clean "$clean"
chmod 700 "$clean/.local/autodev"

# Runtime directory names are prohibited as components at any nesting depth.
for path in \
  'nested/linux/queue/pending.data' \
  'agent/runtime/state/checkpoint.data' \
  'build/output/logs/agent.txt'; do
  reject_path "$path"
done

# Exercise every Linux generated-directory pattern added to .gitignore. These
# files are force-added so ignore rules cannot hide an indexed bypass.
for path in \
  'nested/generated-linux-agent/package.txt' \
  'nested/generated-linux-agent-debug/package.txt' \
  'nested/linux-agent-runtime/pending.data' \
  'nested/linux-runtime/checkpoint.data' \
  'nested/run/challenger-siem/socket.data' \
  'nested/var/lib/challenger-siem/pending.data' \
  'nested/var/log/challenger-siem/diagnostic.txt'; do
  reject_path "$path"
done

# Generated Linux settings patterns are basename rules and must also work when
# nested and force-added.
for path in \
  'nested/config/linux-agentsettings.json' \
  'nested/config/linux-agentsettings.generated.json' \
  'nested/config/linux-agent-settings.json' \
  'nested/config/linux-agent-settings.generated.json' \
  'nested/config/linux-agent.generated.toml'; do
  reject_path "$path"
done

# Fixture naming is enforced at any fixtures depth, while prohibited artifact
# types remain rejected even when their basename advertises synthetic data.
for path in \
  'tests/parsers/fixtures/linux-event.json' \
  'tests/parsers/fixtures/nested/event.json' \
  'tests/parsers/fixtures/synthetic-captured-session.pcap'; do
  reject_path "$path"
done

printf 'repository safety tests: passed\n'
