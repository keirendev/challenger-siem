#!/usr/bin/env bash
set -euo pipefail

repository=${1:-.}
if ! git -C "$repository" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'repository safety: target is not a Git work tree\n' >&2
  exit 2
fi

# Inspect index names only. This covers tracked files and staged additions without
# reading file contents, and deliberately avoids walking ignored local evidence.
mapfile -d '' indexed_paths < <(git -C "$repository" ls-files --cached -z)
violations=()

for path in "${indexed_paths[@]}"; do
  normalized=${path#./}
  lower=${normalized,,}
  base=${lower##*/}

  prohibited=false
  case "/$lower/" in
    */.local/*|*/.pi/*|*/dist/*|*/bin/*|*/obj/*|*/collections/*|*/collection/*|*/client-data/*|*/agent-data/*|*/collected-data/*|*/private-data/*|*/raw-data/*|*/telemetry/*|*/captures/*|*/exports/*|*/evidence/*|*/eventlogs/*|*/event-logs/*|*/events-raw/*|*/journal/*|*/journals/*|*/journal-exports/*|*/audit/*|*/audit-exports/*|*/syslog-exports/*|*/browser-artifacts/*|*/screenshots/*|*/benchmarks/*|*/benchmark-results/*|*/traces/*|*/linux-agent-runtime/*|*/linux-runtime/*|*/run/challenger-siem/*|*/var/lib/challenger-siem/*|*/var/log/challenger-siem/*)
      prohibited=true ;;
  esac

  case "$lower" in
    queue/*|state/*|logs/*) prohibited=true ;;
  esac

  case "$base" in
    agents.md|*.env|.env.*|*.key|*.pem|*.pfx|*.p12|*.ppk|*.kdbx|id_rsa*|id_ed25519*|credentials.json|credentials.*|*.credentials.json|auth.json|auth.*.json|*.auth.json|passwords.*|tokens.*|connectionstrings*.json|connection-strings*.json|*.secrets.json|*.secret|*.secrets|*.token|*.tokens|linux-agentsettings*.json|linux-agent-settings*.json|linux-agent.generated.*|*.evtx|*.etl|*.wevt|*.journal|*.journal-export|*.audit|*.audit.log|*.jsonl|*.ndjson|*.har|*.pcap|*.pcapng|*.dmp|*.dump|*.trace|*.trace.json|*.trace.zip|*.diag|*.db|*.db-shm|*.db-wal|*.sqlite|*.sqlite3|*.log|*.perf.data|*.benchmark.json)
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

printf 'repository safety: indexed paths are clean (%d checked)\n' "${#indexed_paths[@]}"
