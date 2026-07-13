#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage: ./scripts/release-gates.sh <install-browsers|run|cleanup> [options]

Release-gating browser/accessibility/security/performance validation for the
real Challenger SIEM Razor app and PostgreSQL. Generated credentials, browser
profiles, traces, cookies, API responses, logs, and reports stay below ignored
.local/release-gates/.

Commands:
  install-browsers  Restore/build the .NET Playwright test project and install
                    Chromium under .local/release-gates/ms-playwright.
  run               Create a unique disposable database/role, apply schema,
                    seed synthetic operators/data, start the real app, and run
                    the release-gate test project.
  cleanup           Drop only the owned database/role and delete the owned
                    .local/release-gates run directory from a state file.

Run prerequisites (set in ignored .local/release-gates.env or environment):
  SIEM_RELEASE_GATE_PGHOST            PostgreSQL host for admin connection.
  SIEM_RELEASE_GATE_PGADMINUSER       PostgreSQL admin/superuser or owner able
                                      to CREATE ROLE and CREATE DATABASE.
  SIEM_RELEASE_GATE_PGADMINPASSWORD   Admin password (kept local/ignored).
Optional:
  SIEM_RELEASE_GATE_PGPORT            Default 5432.
  SIEM_RELEASE_GATE_PGMAINTDB         Default postgres.
  SIEM_RELEASE_GATE_EVENT_COUNT       Default 300, bounded 1-5000.
  SIEM_RELEASE_GATE_BASE_PORT         Default random free loopback port.
  SIEM_RELEASE_GATE_API_SEARCH_BUDGET_MS / API_TIMELINE / BROWSER_LOAD / CSS / JS.

Cleanup requires exact confirmation:
  ./scripts/release-gates.sh cleanup --state .local/release-gates/<run>/state.env \
    --confirm DELETE-RELEASE-GATE-RESOURCES

Run can perform confirmed cleanup after tests:
  ./scripts/release-gates.sh run --cleanup-owned --confirm DELETE-RELEASE-GATE-RESOURCES
EOF
}

load_env() {
  if [[ -f .local/release-gates.env ]]; then
    local had_allexport=0
    case "$-" in *a*) had_allexport=1 ;; *) set -a ;; esac
    # shellcheck disable=SC1091
    source .local/release-gates.env
    if [[ "$had_allexport" == "0" ]]; then set +a; fi
  fi
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "release gates: required tool not found: $1" >&2
    exit 2
  fi
}

psql_admin() {
  PGPASSWORD="$SIEM_RELEASE_GATE_PGADMINPASSWORD" \
    psql --host "$SIEM_RELEASE_GATE_PGHOST" --port "$SIEM_RELEASE_GATE_PGPORT" --username "$SIEM_RELEASE_GATE_PGADMINUSER" --dbname "$SIEM_RELEASE_GATE_PGMAINTDB" "$@"
}

psql_app() {
  PGPASSWORD="$DB_PASSWORD" psql --host "$SIEM_RELEASE_GATE_PGHOST" --port "$SIEM_RELEASE_GATE_PGPORT" --username "$DB_ROLE" --dbname "$DB_NAME" "$@"
}

random_hex() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(6))
PY
}

strong_password() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits + '!@#$%^&*_-+=' 
print('Rg1!' + ''.join(secrets.choice(alphabet) for _ in range(28)))
PY
}

json_string() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

choose_port() {
  if [[ -n "${SIEM_RELEASE_GATE_BASE_PORT:-}" ]]; then
    printf '%s\n' "$SIEM_RELEASE_GATE_BASE_PORT"
    return
  fi
  python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    print(s.getsockname()[1])
PY
}

install_browsers() {
  require_tool dotnet
  mkdir -p .local/release-gates/ms-playwright .local/release-gates/install
  export PLAYWRIGHT_BROWSERS_PATH="$ROOT_DIR/.local/release-gates/ms-playwright"
  dotnet build tests/ReleaseGates/ReleaseGates.csproj -nologo > .local/release-gates/install/build.log
  local script
  script=$(find tests/ReleaseGates/bin -path '*/net8.0/playwright.ps1' -print -quit)
  if [[ -z "$script" ]]; then
    echo "release gates: Microsoft.Playwright install script was not generated; inspect .local/release-gates/install/build.log" >&2
    exit 1
  fi
  if ! command -v pwsh >/dev/null 2>&1; then
    echo "release gates: PowerShell (pwsh) is required by Microsoft.Playwright to install browser binaries." >&2
    echo "Install pwsh, then rerun: ./scripts/release-gates.sh install-browsers" >&2
    exit 2
  fi
  pwsh "$script" install chromium > .local/release-gates/install/playwright-install.log
  echo "release gates: Chromium installed under .local/release-gates/ms-playwright"
}

create_database() {
  require_tool psql
  local suffix
  suffix="$(date -u +%Y%m%d%H%M%S)_$(random_hex)"
  DB_NAME="siem_rg_${suffix}"
  DB_ROLE="siem_rg_role_${suffix}"
  DB_PASSWORD="$(strong_password)"
  psql_admin -v ON_ERROR_STOP=1 -v db="$DB_NAME" -v role="$DB_ROLE" -v pass="$DB_PASSWORD" <<'SQL' >/dev/null
create role :"role" login password :'pass';
create database :"db" owner :"role";
SQL
}

write_state() {
  cat > "$STATE_FILE" <<EOF
RUN_ID=$RUN_ID
DB_NAME=$DB_NAME
DB_ROLE=$DB_ROLE
DB_PASSWORD=$(json_string "$DB_PASSWORD")
ARTIFACT_DIR=$ARTIFACT_DIR
BASE_URL=$BASE_URL
PID_FILE=$PID_FILE
LOG_FILE=$LOG_FILE
CREATED_AT_UTC=$(date -u +%FT%TZ)
EOF
  chmod 600 "$STATE_FILE"
}

app_connection_string() {
  printf 'Host=%s;Port=%s;Database=%s;Username=%s;Password=%s;Include Error Detail=false' \
    "$SIEM_RELEASE_GATE_PGHOST" "$SIEM_RELEASE_GATE_PGPORT" "$DB_NAME" "$DB_ROLE" "$DB_PASSWORD"
}

operator_cmd() {
  local password="$1"; shift
  ConnectionStrings__SiemDatabase="$APP_CONNECTION_STRING" SIEM_OPERATOR_PASSWORD="$password" \
    dotnet run --project server/Siem.Api --no-launch-profile -- operator "$@"
}

rotate_token() {
  local username="$1"
  ConnectionStrings__SiemDatabase="$APP_CONNECTION_STRING" \
    dotnet run --project server/Siem.Api --no-launch-profile -- operator rotate-api-token --username "$username" \
    | tail -n 1
}

start_app() {
  ASPNETCORE_ENVIRONMENT=Development \
  ASPNETCORE_URLS="$BASE_URL" \
  ConnectionStrings__SiemDatabase="$APP_CONNECTION_STRING" \
  Auth__EnrollmentToken="$ENROLLMENT_TOKEN" \
  SocAgent__Provider=Local \
  SocAgent__ProviderDisplayName='Local soc-agent' \
  SocAgent__AuthMode=Local \
  SocAgent__Model=soc-agent-local-v1 \
  SocAgent__ExternalCallsEnabled=false \
    dotnet run --project server/Siem.Api --no-launch-profile > "$LOG_FILE" 2>&1 &
  API_PID=$!
  printf '%s\n' "$API_PID" > "$PID_FILE"
  for _ in {1..120}; do
    if curl --silent --fail --max-time 2 "$BASE_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$API_PID" >/dev/null 2>&1; then
      echo "release gates: API exited before becoming healthy; see $LOG_FILE" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "release gates: API did not become healthy; see $LOG_FILE" >&2
  return 1
}

stop_app() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" >/dev/null 2>&1; then
    kill "$API_PID" >/dev/null 2>&1 || true
    wait "$API_PID" >/dev/null 2>&1 || true
  elif [[ -f "${PID_FILE:-}" ]]; then
    local pid
    pid=$(tr -d '[:space:]' < "$PID_FILE" || true)
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  fi
}

create_operator_api() {
  local username="$1" display="$2" role="$3" password="$4"
  python3 - "$username" "$display" "$role" "$password" > "$ARTIFACT_DIR/operator-create-$role.json" <<'PY'
import json, sys
print(json.dumps({"username": sys.argv[1], "display_name": sys.argv[2], "role": sys.argv[3], "password": sys.argv[4]}))
PY
  curl --silent --fail "$BASE_URL/api/v1/operators" \
    -H "Authorization: Bearer $ADMIN_API_TOKEN" \
    -H 'Content-Type: application/json' \
    --data @"$ARTIFACT_DIR/operator-create-$role.json" > "$ARTIFACT_DIR/operator-create-$role.response.json"
}

seed_api_data() {
  python3 - "$RUN_ID" "$AGENT_ID" "$HOSTNAME" "$EVENT_COUNT" > "$ARTIFACT_DIR/registration.json" <<'PY'
import json, sys
run, agent, host, count = sys.argv[1:5]
print(json.dumps({"agent_id": agent, "hostname": host, "machine_guid": f"synthetic-{run}", "os_version": "Synthetic Windows 11", "agent_version": "1.5.0", "platform": "windows"}))
PY
  curl --silent --fail "$BASE_URL/api/v1/agents/register" \
    -H "X-Enrollment-Token: $ENROLLMENT_TOKEN" \
    -H 'Content-Type: application/json' \
    --data @"$ARTIFACT_DIR/registration.json" > "$ARTIFACT_DIR/registration.response.json"
  AGENT_TOKEN=$(python3 - <<PY
import json
print(json.load(open('$ARTIFACT_DIR/registration.response.json', encoding='utf-8'))['api_token'])
PY
)

  python3 - "$RUN_ID" "$AGENT_ID" "$HOSTNAME" "$EVENT_COUNT" > "$ARTIFACT_DIR/ingest.json" <<'PY'
import json, sys, uuid
from datetime import datetime, timedelta, timezone
run, agent, host, count_text = sys.argv[1:5]
count = int(count_text)
now = datetime.now(timezone.utc).replace(microsecond=0)
events = []
for i in range(count):
    event_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{run}:{agent}:{i}"))
    when = now - timedelta(minutes=i)
    message = f"Synthetic release gate event {run} index {i}"
    if i == 0:
        message = f"Synthetic release gate XSS marker {run} <script>alert('blocked')</script><img src=x onerror=alert(1)>"
    elif i == 1:
        message = f"=cmd|' /C calc'!A0 synthetic release gate spreadsheet marker {run}"
    events.append({
        "event_id": event_id,
        "agent_id": agent,
        "hostname": host,
        "source": "windows_event_log",
        "channel": "Security" if i % 2 == 0 else "System",
        "provider": "Challenger-Synthetic-ReleaseGate",
        "windows_event_id": 4625 if i % 3 == 0 else 6005,
        "record_id": 900000 + i,
        "event_time": when.isoformat().replace('+00:00','Z'),
        "ingest_time": None,
        "severity": "warning" if i % 3 == 0 else "information",
        "message": message,
        "normalized": {
            "category": "authentication" if i % 3 == 0 else "system",
            "action": "logon" if i % 3 == 0 else "service_start",
            "outcome": "failure" if i % 3 == 0 else "success",
            "target_user_name": "synthetic-user",
            "process_image": "C:/Synthetic/tool.exe",
            "process_command_line": "synthetic.exe --syntheticSecret=redacted-source-value",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "entities": [{"type": "user", "value": "synthetic-user"}, {"type": "host", "value": host}]
        },
        "raw": {"synthetic": True, "run_id": run, "protected": "syntheticSecret=must-not-render-to-non-admin", "index": i}
    })
print(json.dumps({"agent_id": agent, "batch_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f'{run}:batch')), "sent_at": now.isoformat().replace('+00:00','Z'), "events": events}))
PY
  FIRST_EVENT_ID=$(python3 - <<PY
import json
print(json.load(open('$ARTIFACT_DIR/ingest.json', encoding='utf-8'))['events'][0]['event_id'])
PY
)
  curl --silent --fail "$BASE_URL/api/v1/ingest/events" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H 'Content-Type: application/json' \
    --data @"$ARTIFACT_DIR/ingest.json" > "$ARTIFACT_DIR/ingest.response.json"

  python3 - "$AGENT_ID" "$HOSTNAME" > "$ARTIFACT_DIR/heartbeat.json" <<'PY'
import json, sys
from datetime import datetime, timezone, timedelta
agent, host = sys.argv[1:3]
now = datetime.now(timezone.utc).replace(microsecond=0)
def t(delta=0): return (now - timedelta(minutes=delta)).isoformat().replace('+00:00','Z')
print(json.dumps({
  "agent_id": agent,
  "hostname": host,
  "agent_version": "1.5.0",
  "os": "Synthetic Windows 11",
  "last_event_time": t(1),
  "queue_depth": 3,
  "cpu_percent": 2.5,
  "memory_mb": 128,
  "config_hash": "sha256-synthetic-release-gate-config",
  "queue_metrics": {"queue_depth": 3, "poison_depth": 1, "oldest_queued_age_seconds": 120, "last_successful_send_time": t(2), "max_size_mb": 512, "warning_size_percent": 80, "pressure_state": "normal", "send_state": "recovered"},
  "source_health": [
    {"source_id":"security","display_name":"Windows Security","channel":"Security","coverage_level":"L1","status":"healthy","required":True,"enabled":True,"last_event_time":t(1),"lag_seconds":60,"newest_record_id":900001,"details":{"release_gate":"healthy"}},
    {"source_id":"system","display_name":"Windows System","channel":"System","coverage_level":"L1","status":"degraded","required":True,"enabled":True,"last_event_time":t(15),"lag_seconds":900,"gap_detected":True,"details":{"release_gate":"gap"}},
    {"source_id":"defender-operational","display_name":"Defender Operational","channel":"Microsoft-Windows-Windows Defender/Operational","coverage_level":"L2","status":"permission_denied","required":False,"enabled":True,"error_code":"access_denied","details":{"release_gate":"permission_denied"}},
    {"source_id":"sysmon-operational","display_name":"Sysmon Operational","channel":"Microsoft-Windows-Sysmon/Operational","coverage_level":"L3","status":"stale","required":False,"enabled":True,"last_event_time":t(120),"lag_seconds":7200,"details":{"release_gate":"stale"}}
  ]
}))
PY
  curl --silent --fail "$BASE_URL/api/v1/agents/heartbeat" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H 'Content-Type: application/json' \
    --data @"$ARTIFACT_DIR/heartbeat.json" > "$ARTIFACT_DIR/heartbeat.response.json"
}

seed_database_data() {
  ALERT_ID=$(python3 - <<PY
import uuid
print(uuid.uuid5(uuid.NAMESPACE_DNS, '$RUN_ID:alert'))
PY
)
  CASE_ID=$(python3 - <<PY
import uuid
print(uuid.uuid5(uuid.NAMESPACE_DNS, '$RUN_ID:case'))
PY
)
  psql_app -v ON_ERROR_STOP=1 \
    -v run="$RUN_ID" -v agent="$AGENT_ID" -v host="$HOSTNAME" -v alert="$ALERT_ID" -v case="$CASE_ID" -v event="$FIRST_EVENT_ID" \
    -v admin="$ADMIN_USERNAME" <<'SQL' > "$ARTIFACT_DIR/seed.sql.log"
insert into detection_rules(rule_id, version, name, description, severity, confidence, category, required_sources, required_fields, mitre_attack, enabled, tactics, correlation_window_seconds, suppression_keys, false_positive_notes, response_guidance)
values('auth.release-gate.synthetic', 1, 'Synthetic release gate authentication signal', 'Synthetic rule used only for release-gate validation.', 'high', 'medium', 'authentication', array['security','system'], array['target_user_name','source_ip'], array['T1110'], true, array['credential-access'], 300, array['agent_id','target_user_name'], 'Synthetic test windows may create this signal.', 'Review source coverage, event evidence, and case links.')
on conflict (rule_id, version) do update set enabled=excluded.enabled;
insert into detection_rule_management(rule_id, version, enabled, lifecycle_state, validation_status, tuning_notes, suppression_notes, updated_by)
values('auth.release-gate.synthetic', 1, true, 'active', 'synthetic_passed', 'Synthetic release gate tuning note.', 'Synthetic release gate suppression note.', :'admin')
on conflict (rule_id, version) do update set tuning_notes=excluded.tuning_notes, suppression_notes=excluded.suppression_notes;
insert into alerts(alert_id, rule_id, rule_version, title, severity, confidence, status, agent_id, hostname, summary, affected_entities, owner, last_actor, last_action)
values(:'alert', 'auth.release-gate.synthetic', 1, 'Synthetic release gate alert', 'high', 'medium', 'new', :'agent', :'host', 'Synthetic alert summary with degraded prerequisite context.', '[{"type":"host","value":"synthetic-release-gate-host"}]'::jsonb, 'synthetic-analyst', :'admin', 'seed')
on conflict (alert_id) do nothing;
insert into alert_evidence(alert_id, agent_id, event_id, event_time, channel, windows_event_id, summary)
values(:'alert', :'agent', :'event', now(), 'Security', 4625, 'Synthetic retained release-gate evidence')
on conflict do nothing;
insert into cases(case_id, case_key, title, description, owner, severity, priority, status, closure_criteria, coverage_gap_acknowledged, last_actor, last_action)
values(:'case', 'CASE-RG-' || :'run', 'Synthetic release gate case', 'Synthetic case for release-gating lifecycle validation.', 'synthetic-analyst', 'high', 'urgent', 'investigating', 'Review synthetic evidence and acknowledge degraded source state.', false, :'admin', 'seed')
on conflict (case_id) do nothing;
insert into case_alerts(case_id, alert_id, relationship, created_by) values(:'case', :'alert', 'primary', :'admin') on conflict do nothing;
insert into case_evidence(case_evidence_id, case_id, alert_id, agent_id, event_id, event_time, evidence_kind, summary, created_by)
values(gen_random_uuid(), :'case', :'alert', :'agent', :'event', now(), 'event', 'Synthetic case evidence linked to release-gate event.', :'admin')
on conflict do nothing;
insert into case_notes(note_id, case_id, body, created_by) values(gen_random_uuid(), :'case', 'Synthetic release-gate note: coverage gap acknowledged during validation.', :'admin') on conflict do nothing;
insert into case_activities(activity_id, case_id, actor, action, from_status, to_status, summary)
values(gen_random_uuid(), :'case', :'admin', 'case.seed', null, 'investigating', 'Synthetic release-gate case seeded.') on conflict do nothing;
insert into dashboard_layouts(layout_id, owner_operator_id, name, visibility, time_range_hours, refresh_minutes, layout_json)
select gen_random_uuid(), operator_id, 'Synthetic release gate layout', 'shared', 24, 15, '{"widgets":[{"kind":"events"},{"kind":"alerts"},{"kind":"source_health"}]}'::jsonb
from operators where username=:'admin'
on conflict do nothing;
insert into source_review_settings(source_id, display_name, review_note, updated_by)
values('system', 'Windows System', 'Synthetic release-gate degraded source review note.', :'admin')
on conflict (source_id) do update set review_note=excluded.review_note, updated_by=excluded.updated_by;
insert into server_config_settings(setting_key, setting_value, updated_by)
values('retention.max_batches_per_run', '20', :'admin')
on conflict (setting_key) do update set setting_value=excluded.setting_value, updated_by=excluded.updated_by;
SQL
}

write_test_env() {
  cat > "$TEST_ENV_FILE" <<EOF
export SIEM_RELEASE_GATE_ENABLED=1
export SIEM_RELEASE_GATE_RUN_ID='$RUN_ID'
export SIEM_RELEASE_GATE_BASE_URL='$BASE_URL'
export SIEM_RELEASE_GATE_ARTIFACT_DIR='$ARTIFACT_DIR'
export SIEM_RELEASE_GATE_REPORT='$ARTIFACT_DIR/release-gates-report.jsonl'
export SIEM_RELEASE_GATE_AGENT_ID='$AGENT_ID'
export SIEM_RELEASE_GATE_ALERT_ID='$ALERT_ID'
export SIEM_RELEASE_GATE_CASE_ID='$CASE_ID'
export SIEM_RELEASE_GATE_ADMIN_USERNAME='$ADMIN_USERNAME'
export SIEM_RELEASE_GATE_ADMIN_PASSWORD='$ADMIN_PASSWORD'
export SIEM_RELEASE_GATE_VIEWER_USERNAME='$VIEWER_USERNAME'
export SIEM_RELEASE_GATE_VIEWER_PASSWORD='$VIEWER_PASSWORD'
export SIEM_RELEASE_GATE_ANALYST_USERNAME='$ANALYST_USERNAME'
export SIEM_RELEASE_GATE_ANALYST_PASSWORD='$ANALYST_PASSWORD'
export SIEM_RELEASE_GATE_DETECTION_ENGINEER_USERNAME='$DETECTION_USERNAME'
export SIEM_RELEASE_GATE_DETECTION_ENGINEER_PASSWORD='$DETECTION_PASSWORD'
export SIEM_RELEASE_GATE_ADMIN_API_TOKEN='$ADMIN_API_TOKEN'
export SIEM_RELEASE_GATE_VIEWER_API_TOKEN='$VIEWER_API_TOKEN'
export PLAYWRIGHT_BROWSERS_PATH='$ROOT_DIR/.local/release-gates/ms-playwright'
export ConnectionStrings__SiemDatabase='$APP_CONNECTION_STRING'
EOF
  for name in SIEM_RELEASE_GATE_API_SEARCH_BUDGET_MS SIEM_RELEASE_GATE_API_TIMELINE_BUDGET_MS SIEM_RELEASE_GATE_BROWSER_LOAD_BUDGET_MS SIEM_RELEASE_GATE_CSS_BUDGET_BYTES SIEM_RELEASE_GATE_JS_BUDGET_BYTES; do
    if [[ -n "${!name:-}" ]]; then printf 'export %s=%q\n' "$name" "${!name}" >> "$TEST_ENV_FILE"; fi
  done
  chmod 600 "$TEST_ENV_FILE"
}

run_tests() {
  # shellcheck disable=SC1090
  source "$TEST_ENV_FILE"
  dotnet test tests/ReleaseGates/ReleaseGates.csproj -nologo --logger "trx;LogFileName=release-gates.trx" --results-directory "$ARTIFACT_DIR/test-results" \
    | tee "$ARTIFACT_DIR/dotnet-test.log"
}

cleanup_owned() {
  local state_file="" confirm=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --state) state_file="${2:-}"; shift 2 ;;
      --confirm) confirm="${2:-}"; shift 2 ;;
      *) echo "release gates cleanup: unknown option $1" >&2; exit 2 ;;
    esac
  done
  if [[ "$confirm" != "DELETE-RELEASE-GATE-RESOURCES" ]]; then
    echo "release gates cleanup: refusing cleanup without --confirm DELETE-RELEASE-GATE-RESOURCES" >&2
    exit 2
  fi
  if [[ -z "$state_file" || ! -f "$state_file" ]]; then
    echo "release gates cleanup: --state must point to an existing state.env under .local/release-gates" >&2
    exit 2
  fi
  case "$state_file" in .local/release-gates/*/state.env|"$ROOT_DIR"/.local/release-gates/*/state.env) ;; *) echo "release gates cleanup: state file is outside .local/release-gates" >&2; exit 2 ;; esac
  # shellcheck disable=SC1090
  source "$state_file"
  if [[ ! "${DB_NAME:-}" =~ ^siem_rg_[0-9]{14}_[0-9a-f]{12}$ || ! "${DB_ROLE:-}" =~ ^siem_rg_role_[0-9]{14}_[0-9a-f]{12}$ ]]; then
    echo "release gates cleanup: state file does not describe owned release-gate database/role names" >&2
    exit 2
  fi
  load_env
  : "${SIEM_RELEASE_GATE_PGHOST:?SIEM_RELEASE_GATE_PGHOST is required for cleanup}"
  : "${SIEM_RELEASE_GATE_PGADMINUSER:?SIEM_RELEASE_GATE_PGADMINUSER is required for cleanup}"
  : "${SIEM_RELEASE_GATE_PGADMINPASSWORD:?SIEM_RELEASE_GATE_PGADMINPASSWORD is required for cleanup}"
  SIEM_RELEASE_GATE_PGPORT="${SIEM_RELEASE_GATE_PGPORT:-5432}"
  SIEM_RELEASE_GATE_PGMAINTDB="${SIEM_RELEASE_GATE_PGMAINTDB:-postgres}"
  stop_app || true
  psql_admin -v ON_ERROR_STOP=1 -v db="$DB_NAME" -v role="$DB_ROLE" <<'SQL' >/dev/null
select pg_terminate_backend(pid) from pg_stat_activity where datname = :'db';
drop database if exists :"db";
drop role if exists :"role";
SQL
  if [[ -n "${ARTIFACT_DIR:-}" && "$ARTIFACT_DIR" == "$ROOT_DIR/.local/release-gates/"* ]]; then
    rm -rf -- "$ARTIFACT_DIR"
  elif [[ -n "${ARTIFACT_DIR:-}" && "$ARTIFACT_DIR" == .local/release-gates/* ]]; then
    rm -rf -- "$ARTIFACT_DIR"
  fi
  echo "release gates cleanup: owned database, role, and run artifacts removed"
}

run_release_gates() {
  local cleanup_after=0 confirm=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cleanup-owned) cleanup_after=1; shift ;;
      --confirm) confirm="${2:-}"; shift 2 ;;
      *) echo "release gates run: unknown option $1" >&2; exit 2 ;;
    esac
  done
  if [[ "$cleanup_after" == "1" && "$confirm" != "DELETE-RELEASE-GATE-RESOURCES" ]]; then
    echo "release gates run: --cleanup-owned requires --confirm DELETE-RELEASE-GATE-RESOURCES" >&2
    exit 2
  fi

  load_env
  require_tool dotnet
  require_tool curl
  require_tool python3
  require_tool psql
  : "${SIEM_RELEASE_GATE_PGHOST:?SIEM_RELEASE_GATE_PGHOST is required}"
  : "${SIEM_RELEASE_GATE_PGADMINUSER:?SIEM_RELEASE_GATE_PGADMINUSER is required}"
  : "${SIEM_RELEASE_GATE_PGADMINPASSWORD:?SIEM_RELEASE_GATE_PGADMINPASSWORD is required}"
  SIEM_RELEASE_GATE_PGPORT="${SIEM_RELEASE_GATE_PGPORT:-5432}"
  SIEM_RELEASE_GATE_PGMAINTDB="${SIEM_RELEASE_GATE_PGMAINTDB:-postgres}"
  EVENT_COUNT="${SIEM_RELEASE_GATE_EVENT_COUNT:-300}"
  if ! [[ "$EVENT_COUNT" =~ ^[0-9]+$ ]] || (( EVENT_COUNT < 1 || EVENT_COUNT > 5000 )); then
    echo "release gates: SIEM_RELEASE_GATE_EVENT_COUNT must be between 1 and 5000" >&2
    exit 2
  fi

  RUN_ID="rg-$(date -u +%Y%m%d%H%M%S)-$(random_hex)"
  ARTIFACT_DIR="$ROOT_DIR/.local/release-gates/$RUN_ID"
  mkdir -p "$ARTIFACT_DIR/browser-profile" "$ARTIFACT_DIR/test-results"
  STATE_FILE="$ARTIFACT_DIR/state.env"
  TEST_ENV_FILE="$ARTIFACT_DIR/test.env"
  PID_FILE="$ARTIFACT_DIR/api.pid"
  LOG_FILE="$ARTIFACT_DIR/api.log"
  BASE_URL="http://127.0.0.1:$(choose_port)"
  ENROLLMENT_TOKEN="enroll-${RUN_ID}-not-secret"
  AGENT_ID="release-gate-${RUN_ID}"
  HOSTNAME="SYNTHETIC-RG-HOST"
  ADMIN_USERNAME="rg-admin-${RUN_ID}"
  VIEWER_USERNAME="rg-viewer-${RUN_ID}"
  ANALYST_USERNAME="rg-analyst-${RUN_ID}"
  DETECTION_USERNAME="rg-detect-${RUN_ID}"
  ADMIN_PASSWORD="$(strong_password)"
  VIEWER_PASSWORD="$(strong_password)"
  ANALYST_PASSWORD="$(strong_password)"
  DETECTION_PASSWORD="$(strong_password)"

  create_database
  write_state
  APP_CONNECTION_STRING="$(app_connection_string)"
  echo "release gates: created owned PostgreSQL database/role for run $RUN_ID"
  ./scripts/apply-schema.sh "$APP_CONNECTION_STRING" > "$ARTIFACT_DIR/apply-schema.log"
  operator_cmd "$ADMIN_PASSWORD" bootstrap --username "$ADMIN_USERNAME" --display-name 'Release gate admin' --role admin > "$ARTIFACT_DIR/bootstrap-admin.log"
  ADMIN_API_TOKEN="$(rotate_token "$ADMIN_USERNAME")"
  start_app
  trap 'stop_app || true' EXIT
  create_operator_api "$VIEWER_USERNAME" 'Release gate viewer' viewer "$VIEWER_PASSWORD"
  create_operator_api "$ANALYST_USERNAME" 'Release gate analyst' analyst "$ANALYST_PASSWORD"
  create_operator_api "$DETECTION_USERNAME" 'Release gate detection engineer' detection-engineer "$DETECTION_PASSWORD"
  VIEWER_API_TOKEN="$(rotate_token "$VIEWER_USERNAME")"
  ANALYST_API_TOKEN="$(rotate_token "$ANALYST_USERNAME")"
  DETECTION_API_TOKEN="$(rotate_token "$DETECTION_USERNAME")"
  seed_api_data
  seed_database_data
  write_test_env
  echo "release gates: seeded synthetic run $RUN_ID with $EVENT_COUNT events"
  run_tests
  echo "release gates: report $ARTIFACT_DIR/release-gates-report.jsonl"
  echo "release gates: state $STATE_FILE"
  if [[ "$cleanup_after" == "1" ]]; then
    stop_app || true
    cleanup_owned --state "$STATE_FILE" --confirm "$confirm"
  fi
}

main() {
  local command="${1:-}"
  if [[ $# -gt 0 ]]; then shift; fi
  case "$command" in
    install-browsers) load_env; install_browsers "$@" ;;
    run) run_release_gates "$@" ;;
    cleanup) cleanup_owned "$@" ;;
    -h|--help|help|"") usage ;;
    *) echo "Unknown release-gates command: $command" >&2; usage >&2; exit 2 ;;
  esac
}

main "$@"
