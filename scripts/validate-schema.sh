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
    values ('agents'), ('events'), ('agent_heartbeats'), ('source_health'), ('coverage_exceptions'), ('asset_inventory_snapshots'), ('detection_rules'), ('alerts'), ('alert_evidence'), ('soc_agent_turns'), ('soc_agent_sessions'), ('soc_agent_messages'), ('ingestion_errors'), ('operators'), ('operator_sessions'), ('security_audit_events'), ('managed_retention_runs'), ('managed_retention_removed_events')
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
        ('idx_events_package_name'),
        ('idx_agent_heartbeats_agent_id'),
        ('idx_agent_heartbeats_time'),
        ('idx_source_health_status'),
        ('idx_source_health_agent'),
        ('idx_source_health_portable_source'),
        ('idx_source_health_requirement'),
        ('idx_source_health_transition_state'),
        ('idx_source_health_observed_at'),
        ('idx_agents_platform'),
        ('idx_asset_inventory_agent_type'),
        ('idx_detection_rules_category'),
        ('idx_detection_rules_tactics'),
        ('idx_events_linux_auth_correlation'),
        ('idx_alerts_rule_agent_created'),
        ('idx_alerts_status'),
        ('idx_alerts_agent'),
        ('idx_alerts_created'),
        ('idx_alert_evidence_alert'),
        ('idx_soc_agent_turns_created'),
        ('idx_soc_agent_turns_context_agent'),
        ('idx_soc_agent_sessions_updated'),
        ('idx_soc_agent_sessions_context_agent'),
        ('idx_soc_agent_messages_session'),
        ('idx_ingestion_errors_agent_id'),
        ('idx_ingestion_errors_time'),
        ('idx_managed_retention_runs_started'),
        ('idx_managed_retention_runs_status'),
        ('idx_managed_retention_removed_events_time'),
        ('idx_managed_retention_removed_events_removed'),
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
        ('agents', 'platform'),
        ('agents', 'host_id'),
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
        ('agent_heartbeats', 'resource_metrics'),
        ('source_health', 'host_timezone'),
        ('source_health', 'platform'),
        ('source_health', 'source_kind'),
        ('source_health', 'source_namespace'),
        ('source_health', 'applicability'),
        ('source_health', 'requirement_kind'),
        ('source_health', 'applicable_roles'),
        ('source_health', 'prerequisite_statuses'),
        ('source_health', 'event_family_statuses'),
        ('source_health', 'collected_checkpoint'),
        ('source_health', 'acknowledged_checkpoint'),
        ('source_health', 'observed_at'),
        ('source_health', 'silence_seconds'),
        ('source_health', 'event_rate_per_minute'),
        ('source_health', 'gap_count'),
        ('source_health', 'permission_denied_since'),
        ('source_health', 'recovered_at'),
        ('source_health', 'transition_state'),
        ('source_health', 'transitioned_at'),
        ('source_health', 'dropped_events'),
        ('source_health', 'poison_events'),
        ('detection_rules', 'tactics'),
        ('detection_rules', 'correlation_window_seconds'),
        ('detection_rules', 'suppression_keys'),
        ('detection_rules', 'false_positive_notes'),
        ('detection_rules', 'response_guidance'),
        ('asset_inventory_snapshots', 'host_timezone'),
        ('alert_evidence', 'host_timezone'),
        ('soc_agent_turns', 'reasoning_effort'),
        ('soc_agent_sessions', 'reasoning_effort'),
        ('soc_agent_messages', 'reasoning_effort'),
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
), missing_unique_indexes as (
    select 'missing unique index uq_alert_evidence_alert_agent_event' as problem
    where to_regclass('public.uq_alert_evidence_alert_agent_event') is null
)
select problem from missing_tables
union all select problem from missing_indexes
union all select problem from missing_columns
union all select problem from missing_constraints
union all select problem from missing_unique_indexes
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
