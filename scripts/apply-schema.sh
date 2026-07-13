#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

CONNECTION_STRING="${1:-${ConnectionStrings__SiemDatabase:-${CHALLENGER_SIEM_DATABASE:-}}}"
if [[ -z "$CONNECTION_STRING" ]]; then
  echo "A PostgreSQL connection string is required. Pass it as argv[1] or set ConnectionStrings__SiemDatabase in an ignored local env file." >&2
  exit 2
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql was not found. Install PostgreSQL client tools to apply the schema without Docker." >&2
  exit 2
fi

psql_args_from_connection_string() {
  PSQL_ARGS=()
  if [[ "$CONNECTION_STRING" == *";"* && "$CONNECTION_STRING" == *"="* ]]; then
    local IFS=';'
    local part key value lower
    for part in $CONNECTION_STRING; do
      [[ -z "$part" ]] && continue
      key="${part%%=*}"
      value="${part#*=}"
      lower="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
      case "$lower" in
        host|server) PSQL_ARGS+=(--host "$value") ;;
        port) PSQL_ARGS+=(--port "$value") ;;
        database|dbname) PSQL_ARGS+=(--dbname "$value") ;;
        username|userid|user) PSQL_ARGS+=(--username "$value") ;;
        password|pwd) export PGPASSWORD="$value" ;;
        sslmode) export PGSSLMODE="$value" ;;
      esac
    done
  else
    PSQL_ARGS+=("$CONNECTION_STRING")
  fi
}

psql_args_from_connection_string
mapfile -t migrations < <(find server/Siem.Api/Database -maxdepth 1 -type f -name '[0-9][0-9][0-9]_*.sql' | sort)
if [[ ${#migrations[@]} -eq 0 ]]; then
  echo "No numbered database migrations were found." >&2
  exit 1
fi
for migration in "${migrations[@]}"; do
  psql "${PSQL_ARGS[@]}" -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  printf 'Applied %s\n' "$(basename "$migration")"
done
printf 'Schema applied successfully.\n'
