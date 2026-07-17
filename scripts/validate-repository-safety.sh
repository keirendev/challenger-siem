#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/validate-repository-safety.sh [--index|--staged] [repository]

Checks Git index paths and blobs without walking the working tree or ignored
private directories. Findings contain only a safely escaped repository path,
line number when applicable, and rule label; matched content is never printed.

  --index    Check the complete index (default; tracked plus staged content).
  --staged   Check only added, copied, modified, or renamed staged candidates.
EOF
}

scope=index
repository=.
repository_set=false
while (($#)); do
  case "$1" in
    --index) scope=index; shift ;;
    --staged) scope=staged; shift ;;
    -h|--help) usage; exit 0 ;;
    --)
      shift
      if (($# > 1)); then
        printf 'repository safety: expected at most one repository path\n' >&2
        exit 2
      fi
      if (($# == 1)); then repository=$1; repository_set=true; shift; fi
      ;;
    -*)
      printf 'repository safety: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ $repository_set == true ]]; then
        printf 'repository safety: expected at most one repository path\n' >&2
        exit 2
      fi
      repository=$1
      repository_set=true
      shift
      ;;
  esac
done

if ! git -C "$repository" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'repository safety: target is not a Git work tree\n' >&2
  exit 2
fi

candidate_paths() {
  if [[ $scope == staged ]]; then
    git -C "$repository" diff --cached --name-only --diff-filter=ACMR -z --
  else
    git -C "$repository" ls-files --cached -z
  fi
}

if [[ $scope == staged ]]; then
  git -C "$repository" diff --cached --name-only --diff-filter=ACMR -z -- >/dev/null
else
  git -C "$repository" ls-files --cached -z >/dev/null
fi

# Read names from Git rather than walking the checkout. In index mode this
# covers the complete prospective repository snapshot. Staged mode narrows the
# same index-backed checks to files changed relative to HEAD.
mapfile -d '' candidate_paths_index < <(candidate_paths)
violations=()

for path in "${candidate_paths_index[@]}"; do
  normalized=${path#./}
  lower=${normalized,,}
  base=${lower##*/}

  prohibited=false
  case "/$lower/" in
    */.local/*|*/.pi/*|*/.mcp/*|*/dist/*|*/bin/*|*/obj/*|*/artifacts/*|*/collections/*|*/collection/*|*/client-data/*|*/agent-data/*|*/collected-data/*|*/private-data/*|*/raw-data/*|*/telemetry/*|*/captures/*|*/exports/*|*/evidence/*|*/eventlogs/*|*/event-logs/*|*/events-raw/*|*/journal/*|*/journals/*|*/journal-exports/*|*/audit/*|*/audit-exports/*|*/syslog-exports/*|*/browser-artifacts/*|*/browser-profile/*|*/browser-cache/*|*/cookie-jars/*|*/screenshots/*|*/benchmarks/*|*/benchmark-results/*|*/traces/*|*/crash-dumps/*|*/core-dumps/*|*/packet-captures/*|*/process-dumps/*|*/linux-agent-runtime/*|*/linux-runtime/*|*/generated-linux-agent*/*|*/run/challenger-siem/*|*/var/lib/challenger-siem/*|*/var/log/challenger-siem/*)
      prohibited=true ;;
  esac

  # These lowercase names are generated runtime locations. Preserve case here
  # so source namespaces such as WindowsAgent/Queue and WindowsAgent/State stay valid.
  case "/$normalized/" in
    */queue/*|*/state/*|*/logs/*) prohibited=true ;;
  esac

  case "$base" in
    agents.md|*.env|.env.*|.envrc|*.envrc|.netrc|_netrc|.npmrc|.pypirc|pip.conf|authorized_keys|known_hosts|kubeconfig|*.key|*.pem|*.pfx|*.p12|*.ppk|*.kdbx|id_rsa*|id_ed25519*|credentials.json|credentials.*|*.credentials.json|auth.json|auth.*.json|*.auth.json|passwords.*|tokens.*|connectionstrings*.json|connection-strings*.json|mcp.local.json|mcp.*.local.json|mcp-credentials*.json|*.secrets.json|*.secret|*.secrets|*.token|*.tokens|agentsettings.json|agentsettings.*.json|appsettings.development.json|appsettings.production.json|appsettings.staging.json|appsettings.*.local.json|linux-agentsettings*.json|linux-agent-settings*.json|linux-agent.generated.*|passive-telemetry-state*.json|self-integrity-state*.json|l4-telemetry-state*.json|*registration-response*.json|events.json|raw-events*.json|event-export*.json|telemetry.json|telemetry-export*.json|endpoint-telemetry*.json|journal-export*.json|audit-export*.json|host-inventory*.json|process-list*.json|network-connections*.json|cookie-jar*|cookies.*|storage-state*.json|*.evtx|*.etl|*.wevt|*.journal|*.journal-export|*.audit|*.audit.log|*.jsonl|*.ndjson|*.har|*.pcap|*.pcapng|*.dmp|*.dump|*.core|core|core.*|*.trace|*.trace.json|*.trace.zip|*.diag|*.trx|*.sarif|*.db|*.db-shm|*.db-wal|*.sqlite|*.sqlite3|*.log|*.stdout|*.stderr|*.perf.data|*.benchmark.json|*.coverage|*.lcov|*.nupkg|*.snupkg|*.dll|*.exe|*.so|*.dylib|*.zip|*.7z|*.tar|*.tgz|*.tar.gz|*.gz|*.bz2|*.xz|*.zst)
      prohibited=true ;;
  esac

  case "$base" in
    *.csv|*.tsv)
      case "$base" in synthetic-*) ;; *) prohibited=true ;; esac
      ;;
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
  if [[ $scope == staged ]]; then
    printf 'repository safety: prohibited staged path(s) detected:\n' >&2
  else
    printf 'repository safety: prohibited indexed path(s) detected:\n' >&2
  fi
  printf ' - %q\n' "${violations[@]}" >&2
  printf 'repository safety: file contents were not inspected\n' >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf 'repository safety: python3 is required for secret-safe indexed-content checks\n' >&2
  exit 2
fi

# Inspect Git blobs, not checkout paths. Binary and oversized blobs are rejected
# for explicit review because a text-only secret scan cannot establish that they
# are safe. No matched value or blob content is printed.
content_scan_output=
if ! content_scan_output=$(python3 - "$repository" "$scope" <<'PY'
from pathlib import PurePosixPath
import re
import subprocess
import sys

repository, scope = sys.argv[1:3]
MAX_BLOB_BYTES = 5 * 1024 * 1024


def git_output(arguments):
    return subprocess.check_output(
        ["git", "-C", repository, *arguments], stderr=subprocess.DEVNULL
    )


if scope == "staged":
    encoded_paths = git_output(
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", "--"]
    ).split(b"\0")
else:
    encoded_paths = git_output(["ls-files", "--cached", "-z"]).split(b"\0")


def display_path(path):
    if re.fullmatch(r"[A-Za-z0-9._/@+:-]+", path):
        return path
    return path.encode("unicode_escape", "backslashreplace").decode("ascii")


def is_placeholder(value):
    normalized = value.strip().strip('"\'').lower()
    if normalized in {"", "null", "none", "nil", "false", "changeme", "change-me", "password"}:
        return True
    if normalized.startswith("<") and normalized.endswith(">"):
        return True
    if normalized.startswith(("$", "%", "env:", "secretref:", "vault:")):
        return True
    markers = (
        "example", "synthetic", "placeholder", "replace", "redacted",
        "not-secret", "not_secret", "dummy", "fake", "sample", "test-only",
        "example.invalid", "only-used", "first-run", "per-agent-token",
        "stored-after-registration",
    )
    return any(marker in normalized for marker in markers)


secret_patterns = (
    (re.compile(("-" * 5) + r"BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY" + ("-" * 5)), "private-key marker"),
    (re.compile(("-" * 5) + r"BEGIN PGP PRIVATE KEY BLOCK" + ("-" * 5)), "private-key marker"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "cloud access-key marker"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "cloud temporary-access marker"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "provider key marker"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "source-hosting token marker"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "source-hosting token marker"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "source-hosting token marker"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "chat token marker"),
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b"), "provider key marker"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), "package-registry token marker"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b"), "package-registry token marker"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"), "signed-token marker"),
)

host_specific_patterns = (
    (re.compile(
        r"(?<![0-9])(?:"
        r"10[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}|"
        r"192[.]168[.][0-9]{1,3}[.][0-9]{1,3}|"
        r"172[.](?:1[6-9]|2[0-9]|3[01])[.][0-9]{1,3}[.][0-9]{1,3}"
        r")(?![0-9])"
    ), "private IPv4 address"),
    (re.compile(r"(?:/home|/Users)/[A-Za-z0-9._-]+/"), "operator-specific home path"),
)

public_copy_patterns = (
    (re.compile(r"(?:^|[^A-Za-z0-9])[.]pi/", re.IGNORECASE), "local automation path"),
    (re.compile(r"\bPi(?:-managed|/coding-agent| agent| auth)", re.IGNORECASE), "local automation wording"),
    (re.compile(r"assigned worktree", re.IGNORECASE), "implementation-diary wording"),
    (re.compile(r"current authorized[^\n]{0,40}lab", re.IGNORECASE), "operator-specific lab wording"),
)

secret_assignment = re.compile(
    r'''(?ix)
    (?<![A-Za-z0-9_-])
    ["']?
    (?P<key>
      password|passwd|pwd|protected[_-]?api[_-]?token|api[_-]?key|api[_-]?token|access[_-]?token|
      refresh[_-]?token|enrollment[_-]?token|operator[_-]?token|
      client[_-]?secret|secret[_-]?key|private[_-]?key|
      connection[_-]?string|database[_-]?url
    )
    ["']?\s*(?::|=)\s*
    (?:"(?P<double>[^"\r\n]{0,1024})"|'(?P<single>[^'\r\n]{0,1024})'|(?P<bare>[^\s,;#}\]]{1,1024}))
    ''')

connection_password = re.compile(
    r'''(?ix)\b(?:password|pwd)\s*=\s*(?:"(?P<double>[^";\r\n]+)"|'(?P<single>[^';\r\n]+)'|(?P<bare>[^;\s"']+))'''
)

bearer_value = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{24,})\b")

config_suffixes = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config",
    ".properties", ".service", ".xml", ".sql",
}


def config_candidate(path):
    item = PurePosixPath(path)
    name = item.name.lower()
    return item.suffix.lower() in config_suffixes or name in {
        "config", "credentials", "secrets", "auth",
    }


def captured_value(match):
    return next((match.group(name) for name in ("double", "single", "bare") if match.group(name) is not None), "")


findings = set()
for encoded in encoded_paths:
    if not encoded:
        continue
    path = encoded.decode("utf-8", "surrogateescape")
    shown = display_path(path)
    object_name = f":{path}"
    try:
        size = int(git_output(["cat-file", "-s", object_name]).strip())
    except (subprocess.CalledProcessError, ValueError):
        findings.add((shown, 0, "unreadable indexed blob requires review"))
        continue
    if size > MAX_BLOB_BYTES:
        findings.add((shown, 0, "oversized indexed blob requires review"))
        continue
    try:
        data = git_output(["show", object_name])
    except subprocess.CalledProcessError:
        continue
    if b"\0" in data:
        findings.add((shown, 0, "binary indexed blob requires review"))
        continue

    text = data.decode("utf-8", "replace")
    patterns = list(secret_patterns) + list(host_specific_patterns)
    public_surface = path in {"README.md", "CHANGELOG.md"} or path.startswith(("docs/", "examples/"))
    if public_surface:
        patterns.extend(public_copy_patterns)

    scan_assignments = config_candidate(path) or public_surface
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, label in patterns:
            if pattern.search(line):
                findings.add((shown, line_number, label))
        for match in bearer_value.finditer(line):
            if not is_placeholder(match.group(1)):
                findings.add((shown, line_number, "bearer credential marker"))
        if not scan_assignments:
            continue
        for match in secret_assignment.finditer(line):
            value = captured_value(match)
            minimum = 4 if match.group("key").lower() in {"password", "passwd", "pwd"} else 8
            if len(value.strip()) >= minimum and not is_placeholder(value):
                findings.add((shown, line_number, "secret-bearing configuration value"))
        for match in connection_password.finditer(line):
            value = captured_value(match)
            if len(value.strip()) >= 4 and not is_placeholder(value):
                findings.add((shown, line_number, "connection-string credential"))

for path, line_number, label in sorted(findings):
    location = f"{path}:{line_number}" if line_number else path
    print(f"{location} ({label})")
PY
); then
  printf 'repository safety: indexed-content scanner failed without printing blob contents\n' >&2
  exit 2
fi

content_violations=()
if [[ -n $content_scan_output ]]; then
  mapfile -t content_violations <<<"$content_scan_output"
fi

if ((${#content_violations[@]})); then
  printf 'repository safety: prohibited indexed content marker(s) detected:\n' >&2
  printf ' - %s\n' "${content_violations[@]}" >&2
  printf 'repository safety: matched content was not printed\n' >&2
  exit 1
fi

if [[ $scope == staged ]]; then
  printf 'repository safety: staged paths and text content are clean (%d paths checked)\n' "${#candidate_paths_index[@]}"
else
  printf 'repository safety: indexed paths and text content are clean (%d paths checked)\n' "${#candidate_paths_index[@]}"
fi
