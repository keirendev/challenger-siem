#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repository"
if [[ $# -eq 0
  && -z ${ConnectionStrings__SiemDatabase:-}
  && -z ${CHALLENGER_SIEM_DATABASE:-}
  && -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

connection_string=${1:-${ConnectionStrings__SiemDatabase:-${CHALLENGER_SIEM_DATABASE:-}}}
[[ -n $connection_string ]] || { printf 'A PostgreSQL connection string is required.\n' >&2; exit 2; }
command -v psql >/dev/null 2>&1 || { printf 'psql is required.\n' >&2; exit 2; }

psql_args=()
if [[ $connection_string == *";"* && $connection_string == *"="* ]]; then
  IFS=';' read -ra parts <<< "$connection_string"
  for part in "${parts[@]}"; do
    key=${part%%=*}
    value=${part#*=}
    key=${key,,}
    key=${key// /}
    case $key in
      host|server) psql_args+=(--host "$value") ;;
      port) psql_args+=(--port "$value") ;;
      database|dbname) psql_args+=(--dbname "$value") ;;
      username|userid|user) psql_args+=(--username "$value") ;;
      password|pwd) export PGPASSWORD=$value ;;
      sslmode) export PGSSLMODE=${value,,} ;;
    esac
  done
else
  psql_args+=("$connection_string")
fi

psql "${psql_args[@]}" -X -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
begin read only;
select event_time,source_id,destination_ip,event_code,hostname,agent_id,process_image,normalized_json
from events where false;
select health.status
from source_health health
join agents agent on agent.agent_id=health.agent_id
where false;
rollback;
SQL
printf 'Traffic-map read-only database compatibility validation passed.\n'
