#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage: ./scripts/platform.sh <start|stop|restart|status|check>

Controls the local Challenger SIEM API and web-console process. The script
loads .local/dev.env when present, writes runtime state under .local/platform/,
and never prints connection strings or tokens.

Commands:
  start     Start the API/web console in the background and wait for /health.
  stop      Stop the background API/web console process if it is running.
  restart   Stop, then start the API/web console process.
  status    Show process, listener, health, and log-file status.
  check     Alias for status.

Environment overrides:
  CHALLENGER_SIEM_PLATFORM_URLS                 Bind URLs for ASP.NET Core.
                                                Default: ASPNETCORE_URLS or http://127.0.0.1:5081
  CHALLENGER_SIEM_PLATFORM_HEALTH_URL           Health URL to check.
                                                Default: first bind URL plus /health.
  CHALLENGER_SIEM_PLATFORM_STATE_DIR            Runtime state directory.
                                                Default: .local/platform
  CHALLENGER_SIEM_PLATFORM_LOG_FILE             Runtime log path.
                                                Default: .local/platform/platform.log
  CHALLENGER_SIEM_PLATFORM_STARTUP_TIMEOUT_SECONDS  Start health timeout. Default: 30
  CHALLENGER_SIEM_PLATFORM_STOP_TIMEOUT_SECONDS     Stop timeout. Default: 15

Required for start, usually from .local/dev.env:
  ConnectionStrings__SiemDatabase
  Auth__EnrollmentToken
EOF
}

load_local_env() {
  if [[ -f .local/dev.env ]]; then
    local had_allexport=0
    case "$-" in
      *a*) had_allexport=1 ;;
      *) set -a ;;
    esac
    # shellcheck disable=SC1091
    source .local/dev.env
    if [[ "$had_allexport" == "0" ]]; then
      set +a
    fi
  fi
}

health_url_from_urls() {
  local urls="$1"
  local base="${urls%%;*}"
  base="${base%%,*}"
  base="${base%/}"
  base="${base//0.0.0.0/127.0.0.1}"
  base="${base//\[::\]/127.0.0.1}"
  base="${base//\*/127.0.0.1}"
  base="${base//+/127.0.0.1}"
  printf '%s/health\n' "$base"
}

state_value() {
  local key="$1"
  [[ -f "$STATE_FILE" ]] || return 1
  awk -F= -v key="$key" '
    $1 == key {
      sub(/^[^=]*=/, "")
      print
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$STATE_FILE"
}

read_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(tr -d '[:space:]' < "$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$pid"
}

process_alive() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

process_args() {
  local pid="$1"
  ps -p "$pid" -o args= 2>/dev/null || true
}

is_platform_pid() {
  local pid="$1"
  local args
  args="$(process_args "$pid")"
  [[ "$args" == *"server/Siem.Api"* || "$args" == *"Siem.Api"* ]]
}

require_start_config() {
  if ! command -v dotnet >/dev/null 2>&1; then
    echo "dotnet was not found. Install the .NET SDK before starting Challenger SIEM." >&2
    return 2
  fi

  local missing=()
  local name
  for name in ConnectionStrings__SiemDatabase Auth__EnrollmentToken; do
    if [[ -z "${!name:-}" ]]; then
      missing+=("$name")
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    echo "Missing required configuration key(s): ${missing[*]}" >&2
    echo "Set them in the environment or in ignored .local/dev.env before starting." >&2
    return 2
  fi
}

write_state() {
  local pid="$1"
  local started_at="$2"
  cat > "$STATE_FILE" <<EOF
pid=$pid
urls=$PLATFORM_URLS
health_url=$HEALTH_URL
log_file=$LOG_FILE
environment=$ASPNETCORE_ENVIRONMENT_EFFECTIVE
started_at=$started_at
EOF
}

wait_for_health() {
  local pid="$1"
  local timeout_seconds="${CHALLENGER_SIEM_PLATFORM_STARTUP_TIMEOUT_SECONDS:-30}"
  if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]]; then
    timeout_seconds=30
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "curl was not found; process started but health was not checked."
    return 0
  fi

  local attempts=$((timeout_seconds * 2))
  if (( attempts < 1 )); then
    attempts=1
  fi

  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if curl --silent --fail --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
      return 0
    fi

    if ! process_alive "$pid"; then
      return 1
    fi

    sleep 0.5
  done

  return 1
}

start_platform() {
  local pid
  if pid="$(read_pid 2>/dev/null)" && process_alive "$pid"; then
    if is_platform_pid "$pid"; then
      echo "Challenger SIEM platform is already running."
      status_platform
      return $?
    fi

    echo "Refusing to start: $PID_FILE points to a live non-Challenger process (pid=$pid)." >&2
    echo "Inspect the PID file before removing it." >&2
    return 1
  fi

  rm -f "$PID_FILE" "$STATE_FILE"
  require_start_config
  mkdir -p "$STATE_DIR" "$(dirname "$PID_FILE")" "$(dirname "$STATE_FILE")" "$(dirname "$LOG_FILE")"

  local started_at
  started_at="$(date -Is)"
  {
    printf '\n[%s] Starting Challenger SIEM platform\n' "$started_at"
    printf '[%s] ASPNETCORE_ENVIRONMENT=%s\n' "$started_at" "$ASPNETCORE_ENVIRONMENT_EFFECTIVE"
    printf '[%s] ASPNETCORE_URLS=%s\n' "$started_at" "$PLATFORM_URLS"
  } >> "$LOG_FILE"

  export ASPNETCORE_ENVIRONMENT="$ASPNETCORE_ENVIRONMENT_EFFECTIVE"
  export ASPNETCORE_URLS="$PLATFORM_URLS"
  export ConnectionStrings__SiemDatabase Auth__EnrollmentToken

  nohup dotnet run --project server/Siem.Api --no-launch-profile >> "$LOG_FILE" 2>&1 &
  pid=$!
  printf '%s\n' "$pid" > "$PID_FILE"
  write_state "$pid" "$started_at"
  disown "$pid" >/dev/null 2>&1 || true

  echo "Started Challenger SIEM platform."
  echo "pid=$pid"
  echo "urls=$PLATFORM_URLS"
  echo "health_url=$HEALTH_URL"
  echo "log_file=$LOG_FILE"

  if wait_for_health "$pid"; then
    echo "health=ok"
    return 0
  fi

  echo "health=not_ready"
  echo "The process did not become healthy before the timeout. See $LOG_FILE." >&2
  return 1
}

wait_for_exit() {
  local pid="$1"
  local timeout_seconds="${CHALLENGER_SIEM_PLATFORM_STOP_TIMEOUT_SECONDS:-15}"
  if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]]; then
    timeout_seconds=15
  fi

  local elapsed
  for ((elapsed = 0; elapsed < timeout_seconds; elapsed++)); do
    if ! process_alive "$pid"; then
      return 0
    fi
    sleep 1
  done

  return 1
}

stop_platform() {
  local pid
  if ! pid="$(read_pid 2>/dev/null)"; then
    echo "Challenger SIEM platform is stopped."
    rm -f "$PID_FILE" "$STATE_FILE"
    return 0
  fi

  if ! process_alive "$pid"; then
    echo "Challenger SIEM platform is stopped; removing stale PID file."
    rm -f "$PID_FILE" "$STATE_FILE"
    return 0
  fi

  if ! is_platform_pid "$pid"; then
    echo "Refusing to stop pid=$pid because it is not recognized as Challenger SIEM." >&2
    echo "Inspect $PID_FILE before taking manual action." >&2
    return 1
  fi

  echo "Stopping Challenger SIEM platform (pid=$pid)..."
  kill "$pid" >/dev/null 2>&1 || true

  if ! wait_for_exit "$pid"; then
    echo "Process did not exit before timeout; sending SIGKILL to pid=$pid." >&2
    kill -KILL "$pid" >/dev/null 2>&1 || true
    wait_for_exit "$pid" || true
  fi

  rm -f "$PID_FILE" "$STATE_FILE"
  echo "Stopped Challenger SIEM platform."
}

status_platform() {
  local pid=""
  local urls="$PLATFORM_URLS"
  local health_url="$HEALTH_URL"
  local log_file="$LOG_FILE"
  urls="$(state_value urls 2>/dev/null || printf '%s' "$urls")"
  health_url="$(state_value health_url 2>/dev/null || printf '%s' "$health_url")"
  log_file="$(state_value log_file 2>/dev/null || printf '%s' "$log_file")"

  if ! pid="$(read_pid 2>/dev/null)"; then
    echo "Challenger SIEM platform status: stopped"
    echo "pid_file=$PID_FILE"
    echo "log_file=$log_file"
    return 3
  fi

  if ! process_alive "$pid"; then
    echo "Challenger SIEM platform status: stopped"
    echo "stale_pid=$pid"
    echo "pid_file=$PID_FILE"
    echo "log_file=$log_file"
    return 3
  fi

  if ! is_platform_pid "$pid"; then
    echo "Challenger SIEM platform status: unknown"
    echo "pid=$pid"
    echo "message=PID file points to a live non-Challenger process; inspect $PID_FILE."
    return 1
  fi

  echo "Challenger SIEM platform status: running"
  echo "pid=$pid"
  echo "urls=$urls"
  echo "health_url=$health_url"
  echo "log_file=$log_file"

  if ! command -v curl >/dev/null 2>&1; then
    echo "health=not_checked (curl not found)"
    return 0
  fi

  if curl --silent --fail --max-time 2 "$health_url" >/dev/null 2>&1; then
    echo "health=ok"
    return 0
  fi

  echo "health=unreachable"
  return 2
}

restart_platform() {
  stop_platform
  start_platform
}

load_local_env
STATE_DIR="${CHALLENGER_SIEM_PLATFORM_STATE_DIR:-.local/platform}"
PID_FILE="${CHALLENGER_SIEM_PLATFORM_PID_FILE:-$STATE_DIR/platform.pid}"
STATE_FILE="${CHALLENGER_SIEM_PLATFORM_STATE_FILE:-$STATE_DIR/platform.state}"
LOG_FILE="${CHALLENGER_SIEM_PLATFORM_LOG_FILE:-$STATE_DIR/platform.log}"
PLATFORM_URLS="${CHALLENGER_SIEM_PLATFORM_URLS:-${ASPNETCORE_URLS:-http://127.0.0.1:5081}}"
HEALTH_URL="${CHALLENGER_SIEM_PLATFORM_HEALTH_URL:-$(health_url_from_urls "$PLATFORM_URLS")}"
ASPNETCORE_ENVIRONMENT_EFFECTIVE="${ASPNETCORE_ENVIRONMENT:-Development}"

command="${1:-}"
case "$command" in
  start)
    start_platform
    ;;
  stop)
    stop_platform
    ;;
  restart)
    restart_platform
    ;;
  status|check)
    status_platform
    ;;
  help|-h|--help)
    usage
    ;;
  "")
    usage >&2
    exit 2
    ;;
  *)
    echo "Unknown command: $command" >&2
    usage >&2
    exit 2
    ;;
esac
