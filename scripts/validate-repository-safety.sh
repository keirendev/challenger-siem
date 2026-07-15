#!/usr/bin/env bash
set -euo pipefail

repository=${1:-.}
if ! git -C "$repository" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'repository safety: target is not a Git work tree\n' >&2
  exit 2
fi

# Inspect index names first. This covers tracked files and staged additions and
# deliberately avoids walking ignored local evidence.
mapfile -d '' indexed_paths < <(git -C "$repository" ls-files --cached -z)
violations=()

for path in "${indexed_paths[@]}"; do
  normalized=${path#./}
  lower=${normalized,,}
  base=${lower##*/}

  prohibited=false
  case "/$lower/" in
    */.local/*|*/.pi/*|*/.mcp/*|*/dist/*|*/bin/*|*/obj/*|*/collections/*|*/collection/*|*/client-data/*|*/agent-data/*|*/collected-data/*|*/private-data/*|*/raw-data/*|*/telemetry/*|*/captures/*|*/exports/*|*/evidence/*|*/eventlogs/*|*/event-logs/*|*/events-raw/*|*/journal/*|*/journals/*|*/journal-exports/*|*/audit/*|*/audit-exports/*|*/syslog-exports/*|*/browser-artifacts/*|*/screenshots/*|*/benchmarks/*|*/benchmark-results/*|*/traces/*|*/linux-agent-runtime/*|*/linux-runtime/*|*/generated-linux-agent*/*|*/run/challenger-siem/*|*/var/lib/challenger-siem/*|*/var/log/challenger-siem/*)
      prohibited=true ;;
  esac

  # These lowercase names are generated runtime locations. Preserve case here
  # so source namespaces such as WindowsAgent/Queue and WindowsAgent/State stay valid.
  case "/$normalized/" in
    */queue/*|*/state/*|*/logs/*) prohibited=true ;;
  esac

  case "$base" in
    agents.md|*.env|.env.*|*.key|*.pem|*.pfx|*.p12|*.ppk|*.kdbx|id_rsa*|id_ed25519*|credentials.json|credentials.*|*.credentials.json|auth.json|auth.*.json|*.auth.json|passwords.*|tokens.*|connectionstrings*.json|connection-strings*.json|mcp.local.json|mcp.*.local.json|mcp-credentials*.json|*.secrets.json|*.secret|*.secrets|*.token|*.tokens|linux-agentsettings*.json|linux-agent-settings*.json|linux-agent.generated.*|*.evtx|*.etl|*.wevt|*.journal|*.journal-export|*.audit|*.audit.log|*.jsonl|*.ndjson|*.har|*.pcap|*.pcapng|*.dmp|*.dump|*.trace|*.trace.json|*.trace.zip|*.diag|*.trx|*.sarif|*.db|*.db-shm|*.db-wal|*.sqlite|*.sqlite3|*.log|*.perf.data|*.benchmark.json)
      prohibited=true ;;
  esac

  # Public test fixtures must advertise that they are synthetic. This is a
  # filename check only; real telemetry must never be copied in for inspection.
  case "/$lower" in
    */fixtures/*)
      case "$base" in synthetic-*|readme.md) ;; *) prohibited=true ;; esac
      ;;
  esac

  if [[ $prohibited == true ]]; then
    violations+=("$normalized")
  fi
done

if ((${#violations[@]})); then
  printf 'repository safety: prohibited indexed path(s) detected:\n' >&2
  printf ' - %s\n' "${violations[@]}" >&2
  printf 'repository safety: file contents were not inspected\n' >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf 'repository safety: python3 is required for secret-safe indexed-content checks\n' >&2
  exit 2
fi

# Inspect indexed text blobs without printing their contents. The checks are
# intentionally high confidence: private-key/token prefixes plus public-copy
# markers that previously exposed operator-specific host and tooling details.
# Binary files are skipped and continue to require manual screenshot review.
mapfile -t content_violations < <(python3 - "$repository" <<'PY'
from pathlib import Path
import re
import subprocess
import sys

repository = sys.argv[1]
paths = subprocess.check_output(
    ["git", "-C", repository, "ls-files", "--cached", "-z"]
).split(b"\0")

secret_patterns = (
    (re.compile(("-" * 5) + r"BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY" + ("-" * 5)), "private-key marker"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "cloud access-key marker"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "source-hosting token marker"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "source-hosting token marker"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "chat token marker"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b"), "provider key marker"),
)
public_copy_patterns = (
    (re.compile(r"192[.]168[.]122[.]"), "operator-specific lab topology"),
    (re.compile(r"(?:/home|/Users)/[A-Za-z0-9._-]+/"), "operator-specific home path"),
    (re.compile(r"(?:^|[^A-Za-z0-9])[.]pi/", re.IGNORECASE), "local automation path"),
    (re.compile(r"\bPi(?:-managed|/coding-agent| agent| auth)", re.IGNORECASE), "local automation wording"),
    (re.compile(r"assigned worktree", re.IGNORECASE), "implementation-diary wording"),
    (re.compile(r"current authorized[^\n]{0,40}lab", re.IGNORECASE), "operator-specific lab wording"),
)

for encoded in paths:
    if not encoded:
        continue
    path = encoded.decode("utf-8", "surrogateescape")
    try:
        data = subprocess.check_output(["git", "-C", repository, "show", f":{path}"], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        continue
    if b"\0" in data[:8192]:
        continue
    text = data.decode("utf-8", "replace")
    patterns = list(secret_patterns)
    if path in {"README.md", "CHANGELOG.md"} or path.startswith(("docs/", "examples/")):
        patterns.extend(public_copy_patterns)
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, label in patterns:
            if pattern.search(line):
                print(f"{path}:{line_number} ({label})")
PY
)

if ((${#content_violations[@]})); then
  printf 'repository safety: prohibited indexed content marker(s) detected:\n' >&2
  printf ' - %s\n' "${content_violations[@]}" >&2
  printf 'repository safety: matched content was not printed\n' >&2
  exit 1
fi

printf 'repository safety: indexed paths and text content are clean (%d paths checked)\n' "${#indexed_paths[@]}"
