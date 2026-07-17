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
  shift
  "$validator" "$@" "$repo" >/dev/null
}

expect_rejected() {
  local repo=$1
  local expected_path=$2
  shift 2
  local output="$temporary/output"
  if "$validator" "$@" "$repo" >"$output" 2>&1; then
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

reject_content() {
  local path=$1
  local content=$2
  local expected_label=$3
  local repo output="$temporary/content-output"
  repo=$(new_repo)
  mkdir -p "$repo/$(dirname "$path")"
  printf '%s\n' "$content" >"$repo/$path"
  git -C "$repo" add -- "$path"
  if "$validator" "$repo" >"$output" 2>&1; then
    printf 'expected prohibited synthetic content marker to be rejected: %s\n' "$path" >&2
    exit 1
  fi
  grep -Fq -- "$path:" "$output" || { printf 'validator did not identify content path: %s\n' "$path" >&2; exit 1; }
  grep -Fq -- "$expected_label" "$output" || { printf 'validator did not identify content rule: %s\n' "$expected_label" >&2; exit 1; }
  if grep -Fq -- "$content" "$output"; then
    printf 'validator disclosed matched content\n' >&2
    exit 1
  fi
}

reject_binary_content() {
  local repo output="$temporary/binary-output"
  repo=$(new_repo)
  mkdir -p "$repo/assets"
  printf '\000canary-content-must-not-be-printed\n' >"$repo/assets/opaque.bin"
  git -C "$repo" add -- assets/opaque.bin
  if "$validator" "$repo" >"$output" 2>&1; then
    printf 'expected an unreviewable binary index blob to be rejected\n' >&2
    exit 1
  fi
  grep -Fq -- 'assets/opaque.bin (binary indexed blob requires review)' "$output" || {
    printf 'validator did not identify the binary index blob\n' >&2
    exit 1
  }
  if grep -Fq 'canary-content-must-not-be-printed' "$output"; then
    printf 'validator disclosed binary file content\n' >&2
    exit 1
  fi
}

reject_oversized_content() {
  local repo output="$temporary/oversized-output"
  repo=$(new_repo)
  mkdir -p "$repo/assets"
  python3 - "$repo/assets/oversized.txt" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(b"x" * (5 * 1024 * 1024 + 1))
PY
  git -C "$repo" add -- assets/oversized.txt
  if "$validator" "$repo" >"$output" 2>&1; then
    printf 'expected an oversized index blob to be rejected\n' >&2
    exit 1
  fi
  grep -Fq -- 'assets/oversized.txt (oversized indexed blob requires review)' "$output" || {
    printf 'validator did not identify the oversized index blob\n' >&2
    exit 1
  }
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

# The validator operates on the index and never walks ignored paths. Ignored and unreadable local
# evidence directories, including release-gate browser artifacts, must neither
# affect validation nor be opened or traversed.
mkdir -p "$clean/.local/autodev" "$clean/.local/release-gates/synthetic-run/browser-profile"
printf 'canary-content-must-not-be-printed\n' >"$clean/.local/autodev/evidence"
printf 'canary-content-must-not-be-printed\n' >"$clean/.local/release-gates/synthetic-run/browser-profile/cookies"
chmod 000 "$clean/.local/autodev" "$clean/.local/release-gates/synthetic-run/browser-profile"
expect_clean "$clean"
chmod 700 "$clean/.local/autodev" "$clean/.local/release-gates/synthetic-run/browser-profile"

# Runtime directory names and release-gate artifact paths are prohibited when
# force-added to the index at any nesting depth.
for path in \
  'nested/linux/queue/pending.data' \
  'agent/runtime/state/checkpoint.data' \
  'build/output/logs/agent.txt' \
  '.local/release-gates/synthetic-run/release-gates-report.jsonl' \
  '.mcp/servers.json' \
  '.local/release-gates/synthetic-run/trace.har' \
  '.local/release-gates/synthetic-run/browser-profile/cookies.txt' \
  'mcp.local.json' \
  'nested/mcp.client.local.json' \
  'nested/mcp-credentials-production.json' \
  'nested/config/agentsettings.json' \
  'nested/config/appsettings.Production.json' \
  'nested/config/registration-response.json' \
  'nested/runtime/l4-telemetry-state.synthetic.json' \
  'nested/export/events.json' \
  'nested/export/host-inventory.json' \
  'nested/export/network-connections.json' \
  'nested/export/process-list.json' \
  'nested/export/events.csv' \
  'nested/browser-profile/cookies.sqlite' \
  'nested/artifacts/endpoint-capture.zip' \
  'nested/artifacts/endpoint-capture.tar.gz' \
  'nested/build/agent.dll' \
  'nested/private/.netrc' \
  'artifacts/results.trx' \
  'artifacts/results.sarif'; do
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

# High-confidence secret markers and public-copy leakage are rejected without
# echoing matched values. String fragments keep the canaries out of this tracked
# test file while producing the exact marker only inside the temporary repository.
reject_content 'docs/public-guide.md' "-----BEGIN PRI""VATE KEY-----" 'private-key marker'
reject_content 'docs/public-guide.md' "10.""99.0.1" 'private IPv4 address'
reject_content 'docs/public-guide.md' "/home/""operator/private.txt" 'operator-specific home path'
reject_content 'docs/public-guide.md' "~/"".pi/agent/auth.json" 'local automation path'
reject_content 'src/runtime.cs' "const string LocalPath = \"/home/""operator/private.txt\";" 'operator-specific home path'
reject_content 'config/runtime.json' '{"api_token":"canary-private-token-1234567890"}' 'secret-bearing configuration value'
reject_content 'config/runtime.json' '{"database":"Host=localhost;Password=canary-private-pass-1234"}' 'connection-string credential'
reject_content 'notes/request.txt' 'Authorization: Bearer canary-private-''bearer-12345678901234567890' 'bearer credential marker'

# Text-only content scanning cannot establish that opaque or unbounded blobs
# are publication-safe, so both require explicit review without being opened or
# printed by the validator.
reject_binary_content
reject_oversized_content

# Documentation-only addresses, placeholders, and ignored local-evidence wording remain valid.
safe_content=$(new_repo)
mkdir -p "$safe_content/docs"
printf '%s\n' 'Use 192.0.2.10 in examples and keep private evidence under .local/.' > "$safe_content/docs/public-guide.md"
mkdir -p "$safe_content/config"
printf '%s\n' '{"api_token":"<replace-with-private-token>","database":"Host=localhost;Password=change-me"}' \
  > "$safe_content/config/settings.json"
printf '%s\n' 'synthetic_id,synthetic_value' > "$safe_content/config/synthetic-events.csv"
git -C "$safe_content" add docs/public-guide.md
git -C "$safe_content" add config/settings.json config/synthetic-events.csv
expect_clean "$safe_content"

# Staged mode reads the index blob, not a subsequently edited working-tree
# copy. It also ignores an unstaged tracked edit because that content cannot be
# committed until it is staged.
staged=$(new_repo)
mkdir -p "$staged/config"
printf '%s\n' '{"api_token":"<replace-with-private-token>"}' > "$staged/config/settings.json"
git -C "$staged" add config/settings.json
git -C "$staged" -c user.name='Synthetic Test' -c user.email='synthetic@example.invalid' commit -qm baseline

printf '%s\n' '{"api_token":"canary-staged-token-1234567890"}' > "$staged/config/settings.json"
git -C "$staged" add config/settings.json
printf '%s\n' '{"api_token":"<replace-with-private-token>"}' > "$staged/config/settings.json"
expect_rejected "$staged" 'config/settings.json' --staged

git -C "$staged" restore --worktree config/settings.json
git -C "$staged" reset -q HEAD -- config/settings.json
printf '%s\n' '{"api_token":"canary-unstaged-token-1234567890"}' > "$staged/config/settings.json"
expect_clean "$staged" --staged

printf 'repository safety tests: passed\n'
