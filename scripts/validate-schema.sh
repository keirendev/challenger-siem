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
  echo "psql was not found. Install PostgreSQL client tools to validate the schema without Docker." >&2
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

CHECK_SQL="$(cat <<'SQL'
with required_tables(name) as (
    values ('agents'), ('events'), ('agent_heartbeats'), ('source_health'), ('coverage_exceptions'), ('asset_inventory_snapshots'), ('detection_rules'), ('alerts'), ('alert_evidence'), ('soc_agent_turns'), ('ingestion_errors'), ('operators'), ('operator_sessions'), ('security_audit_events')
), missing_tables as (
    select 'missing table ' || name as problem
    from required_tables
    where to_regclass('public.' || name) is null
), required_indexes(name) as (
    values
        ('idx_events_agent_id'),
        ('idx_events_hostname'),
        ('idx_events_event_time'),
        ('idx_events_windows_event_id'),
        ('idx_events_channel'),
        ('idx_events_provider'),
        ('idx_events_raw_json'),
        ('idx_events_event_category'),
        ('idx_events_event_action'),
        ('idx_events_user_name'),
        ('idx_events_process_image'),
        ('idx_events_destination_ip'),
        ('idx_events_source_time'),
        ('idx_events_source_id_time'),
        ('idx_events_event_code_time'),
        ('idx_events_agent_source_time'),
        ('idx_agent_heartbeats_agent_id'),
        ('idx_agent_heartbeats_time'),
        ('idx_source_health_status'),
        ('idx_source_health_agent'),
        ('idx_asset_inventory_agent_type'),
        ('idx_detection_rules_category'),
        ('idx_alerts_status'),
        ('idx_alerts_agent'),
        ('idx_alerts_created'),
        ('idx_alert_evidence_alert'),
        ('idx_soc_agent_turns_created'),
        ('idx_soc_agent_turns_context_agent'),
        ('idx_ingestion_errors_agent_id'),
        ('idx_ingestion_errors_time'),
        ('idx_operator_sessions_operator'),
        ('idx_operator_sessions_active'),
        ('idx_security_audit_occurred'),
        ('idx_security_audit_operator')
), missing_indexes as (
    select 'missing index ' || name as problem
    from required_indexes
    where to_regclass('public.' || name) is null
), required_columns(table_name, column_name) as (
    values
        ('agents', 'host_timezone'),
        ('events', 'host_timezone'),
        ('events', 'platform'),
        ('events', 'source_id'),
        ('events', 'event_code'),
        ('events', 'facility'),
        ('events', 'unit'),
        ('events', 'checkpoint_json'),
        ('events', 'deduplication_json'),
        ('events', 'data_handling_json'),
        ('agent_heartbeats', 'host_timezone'),
        ('source_health', 'host_timezone'),
        ('asset_inventory_snapshots', 'host_timezone'),
        ('alert_evidence', 'host_timezone'),
        ('operators', 'password_hash'),
        ('operators', 'api_token_hash'),
        ('operators', 'locked_until'),
        ('operator_sessions', 'token_hash'),
        ('operator_sessions', 'expires_at'),
        ('operator_sessions', 'revoked_at'),
        ('security_audit_events', 'details')
), missing_columns as (
    select 'missing column ' || table_name || '.' || column_name as problem
    from required_columns rc
    where not exists (
        select 1
        from information_schema.columns c
        where c.table_schema = 'public'
          and c.table_name = rc.table_name
          and c.column_name = rc.column_name
    )
), missing_constraints as (
    select 'missing unique constraint uq_events_agent_event' as problem
    where not exists (
        select 1
        from pg_constraint
        where conname = 'uq_events_agent_event'
          and conrelid = 'public.events'::regclass
    )
)
select problem from missing_tables
union all select problem from missing_indexes
union all select problem from missing_columns
union all select problem from missing_constraints
order by problem;
SQL
)"

psql_args_from_connection_string
PROBLEMS="$(psql "${PSQL_ARGS[@]}" -v ON_ERROR_STOP=1 -Atc "$CHECK_SQL")"
if [[ -n "$PROBLEMS" ]]; then
  echo "Schema validation failed:" >&2
  echo "$PROBLEMS" >&2
  exit 1
fi

printf 'Schema validation passed.\n'
