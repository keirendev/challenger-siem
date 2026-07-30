#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ $# -eq 0
  && -z "${ConnectionStrings__SiemDatabase:-}"
  && -z "${CHALLENGER_SIEM_DATABASE:-}"
  && -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

CONNECTION_STRING="${1:-${ConnectionStrings__SiemDatabase:-${CHALLENGER_SIEM_DATABASE:-}}}"
[[ -n "$CONNECTION_STRING" ]] || { echo "A PostgreSQL connection string is required." >&2; exit 2; }
command -v psql >/dev/null 2>&1 || { echo "psql is required." >&2; exit 2; }

PSQL_ARGS=()
if [[ "$CONNECTION_STRING" == *";"* && "$CONNECTION_STRING" == *"="* ]]; then
  IFS=';' read -ra parts <<< "$CONNECTION_STRING"
  for part in "${parts[@]}"; do
    key="${part%%=*}"; value="${part#*=}"; key="${key,,}"; key="${key// /}"
    case "$key" in
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

psql "${PSQL_ARGS[@]}" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
do $$
declare missing text;
begin
  if not exists(select 1 from schema_metadata where schema_name='challenger-siem-linux' and schema_version=2) then
    raise exception 'Linux v2 schema marker is missing';
  end if;
  select string_agg(name, ', ') into missing
  from unnest(array['agents','events','agent_heartbeats','source_health','alerts','alert_evidence','cases','investigation_graphs','security_audit_events','managed_retention_runs']) name
  where to_regclass('public.' || name) is null;
  if missing is not null then raise exception 'Missing tables: %', missing; end if;
  if to_regclass('public.operators') is not null or to_regclass('public.soc_agent_sessions') is not null or to_regclass('public.dashboard_layouts') is not null then
    raise exception 'Legacy operator, SOC-agent, or web-layout tables are present';
  end if;
end $$;
SQL
echo "Linux v2 schema validation passed."
