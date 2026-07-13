#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

: "${ConnectionStrings__SiemDatabase:?ConnectionStrings__SiemDatabase is required}"
: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"
: "${SIEM_OPERATOR_API_TOKEN:?SIEM_OPERATOR_API_TOKEN is required}"
: "${SIEM_OPERATOR_USERNAME:?SIEM_OPERATOR_USERNAME is required}"
: "${SIEM_OPERATOR_PASSWORD:?SIEM_OPERATOR_PASSWORD is required}"

BASE_URL="${SIEM_WEB_SMOKE_BASE_URL:-http://127.0.0.1:5081}"
RUN_API="${SIEM_WEB_SMOKE_RUN_API:-1}"
AGENT_ID="web-smoke-$(date +%s)-$$"
HOSTNAME="WEB-SMOKE-HOST"
LOG_FILE=".local/web-smoke-api.log"
COOKIE_JAR=".local/web-smoke-cookies.txt"
LOGIN_HTML=".local/web-smoke-login.html"
DASHBOARD_HTML=".local/web-smoke-dashboard.html"
AGENTS_HTML=".local/web-smoke-agents.html"
EVENTS_HTML=".local/web-smoke-events.html"
DETAIL_HTML=".local/web-smoke-detail.html"
SOC_AGENT_HTML=".local/web-smoke-soc-agent.html"
SOC_AGENT_CHAT_HTML=".local/web-smoke-soc-agent-chat.html"
SOC_AGENT_CHAT_HEADERS=".local/web-smoke-soc-agent-chat.headers"
GRAPHS_HTML=".local/web-smoke-graphs.html"
REGISTER_REQUEST=".local/web-smoke-register-request.json"
REGISTER_RESPONSE=".local/web-smoke-register-response.json"
INGEST_REQUEST=".local/web-smoke-ingest-request.json"
INGEST_RESPONSE=".local/web-smoke-ingest-response.json"
QUERY_RESPONSE=".local/web-smoke-query-response.json"

mkdir -p .local
rm -f "$COOKIE_JAR" "$LOGIN_HTML" "$DASHBOARD_HTML" "$AGENTS_HTML" "$EVENTS_HTML" "$DETAIL_HTML" "$SOC_AGENT_HTML" "$SOC_AGENT_CHAT_HTML" "$SOC_AGENT_CHAT_HEADERS" "$GRAPHS_HTML" \
  "$REGISTER_REQUEST" "$REGISTER_RESPONSE" "$INGEST_REQUEST" "$INGEST_RESPONSE" "$QUERY_RESPONSE" "$LOG_FILE"

API_PID=""
if [[ "$RUN_API" == "1" ]]; then
  ASPNETCORE_URLS="$BASE_URL" ASPNETCORE_ENVIRONMENT=Development \
    dotnet run --project server/Siem.Api --no-launch-profile >"$LOG_FILE" 2>&1 &
  API_PID=$!
  trap 'if [[ -n "${API_PID:-}" ]]; then kill "$API_PID" >/dev/null 2>&1 || true; fi' EXIT
fi

for _ in {1..60}; do
  if curl --silent --fail "$BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl --silent --fail "$BASE_URL/health" >/dev/null 2>&1; then
  echo "API did not become healthy. See $LOG_FILE" >&2
  exit 1
fi

python - <<PY > "$REGISTER_REQUEST"
import json
print(json.dumps({
    "agent_id": "$AGENT_ID",
    "hostname": "$HOSTNAME",
    "machine_guid": None,
    "os_version": "Synthetic OS",
    "agent_version": "$(./scripts/current-version.sh)",
}))
PY

curl --silent --fail "$BASE_URL/api/v1/agents/register" \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @"$REGISTER_REQUEST" > "$REGISTER_RESPONSE"

API_TOKEN="$(python - <<'PY'
import json
print(json.load(open('.local/web-smoke-register-response.json', encoding='utf-8'))['api_token'])
PY
)"

python - <<PY > "$INGEST_REQUEST"
import json, uuid
from datetime import datetime, timezone
now = datetime.now(timezone.utc).isoformat()
event_id = str(uuid.uuid4())
payload = {
    "agent_id": "$AGENT_ID",
    "batch_id": str(uuid.uuid4()),
    "sent_at": now,
    "events": [{
        "event_id": event_id,
        "agent_id": "$AGENT_ID",
        "hostname": "$HOSTNAME",
        "source": "windows_event_log",
        "channel": "System",
        "provider": "Challenger-Synthetic",
        "windows_event_id": 6005,
        "record_id": 424242,
        "event_time": now,
        "ingest_time": None,
        "severity": "information",
        "message": "web smoke unique marker $AGENT_ID",
        "raw": {"synthetic": True, "marker": "$AGENT_ID"}
    }]
}
print(json.dumps(payload))
PY

curl --silent --fail "$BASE_URL/api/v1/ingest/events" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data @"$INGEST_REQUEST" > "$INGEST_RESPONSE"

curl --silent --fail "$BASE_URL/api/v1/events?agent_id=$AGENT_ID&limit=1" \
  -H "Authorization: Bearer $SIEM_OPERATOR_API_TOKEN" > "$QUERY_RESPONSE"

curl --silent --fail -c "$COOKIE_JAR" "$BASE_URL/login" > "$LOGIN_HTML"
CSRF_TOKEN="$(python - <<'PY'
import html, re
text = open('.local/web-smoke-login.html', encoding='utf-8').read()
match = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', text)
if not match:
    raise SystemExit('login page did not contain an antiforgery token')
print(html.unescape(match.group(1)))
PY
)"

curl --silent --fail -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -X POST "$BASE_URL/login" \
  --data-urlencode "__RequestVerificationToken=$CSRF_TOKEN" \
  --data-urlencode "Username=$SIEM_OPERATOR_USERNAME" \
  --data-urlencode "Password=$SIEM_OPERATOR_PASSWORD" \
  --data-urlencode "ReturnUrl=/" >/dev/null

curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL/" > "$DASHBOARD_HTML"
curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL/agents?agent_id=$AGENT_ID" > "$AGENTS_HTML"
curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL/events?agent_id=$AGENT_ID&keyword=$AGENT_ID&limit=10" > "$EVENTS_HTML"
DETAIL_URL="$(python - <<'PY'
import json
response = json.load(open('.local/web-smoke-query-response.json', encoding='utf-8'))
event = response['events'][0]
print(f"/events/detail?agent_id={event['agent_id']}&event_id={event['event_id']}")
PY
)"
curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL$DETAIL_URL" > "$DETAIL_HTML"
curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL/soc-agent?agent_id=$AGENT_ID" > "$SOC_AGENT_HTML"
SOC_AGENT_CSRF_TOKEN="$(python - <<'PY'
import html, re
text = open('.local/web-smoke-soc-agent.html', encoding='utf-8').read()
match = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', text)
if not match:
    raise SystemExit('soc-agent page did not contain an antiforgery token')
print(html.unescape(match.group(1)))
PY
)"
curl --silent --fail -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -D "$SOC_AGENT_CHAT_HEADERS" \
  -o /dev/null \
  -X POST "$BASE_URL/soc-agent?handler=Send" \
  --data-urlencode "__RequestVerificationToken=$SOC_AGENT_CSRF_TOKEN" \
  --data-urlencode "Message=Synthetic web smoke soc-agent marker $AGENT_ID" \
  --data-urlencode "ComposerContextAgentId=$AGENT_ID"
SOC_AGENT_CHAT_LOCATION="$(python - <<'PY'
from pathlib import Path
headers = Path('.local/web-smoke-soc-agent-chat.headers').read_text(encoding='utf-8', errors='ignore').splitlines()
for line in headers:
    if line.lower().startswith('location:'):
        print(line.split(':', 1)[1].strip())
        break
else:
    raise SystemExit('soc-agent chat post did not redirect')
PY
)"
curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL$SOC_AGENT_CHAT_LOCATION" > "$SOC_AGENT_CHAT_HTML"
curl --silent --fail -b "$COOKIE_JAR" "$BASE_URL/graphs" > "$GRAPHS_HTML"

python - <<PY
from pathlib import Path
agent_id = "$AGENT_ID"
checks = {
    'agents': Path('$AGENTS_HTML').read_text(encoding='utf-8'),
    'events': Path('$EVENTS_HTML').read_text(encoding='utf-8'),
    'detail': Path('$DETAIL_HTML').read_text(encoding='utf-8'),
    'soc-agent': Path('$SOC_AGENT_HTML').read_text(encoding='utf-8'),
    'soc-agent-chat': Path('$SOC_AGENT_CHAT_HTML').read_text(encoding='utf-8'),
}
missing = [name for name, body in checks.items() if agent_id not in body]
if missing:
    raise SystemExit(f'web smoke failed; marker missing from: {", ".join(missing)}')
dashboard = Path('$DASHBOARD_HTML').read_text(encoding='utf-8')
if 'Dashboard' not in dashboard or 'active agents' not in dashboard:
    raise SystemExit('web smoke failed; dashboard did not render expected metrics')
soc_agent = Path('$SOC_AGENT_HTML').read_text(encoding='utf-8')
if 'soc-agent workspace' not in soc_agent or 'Provider status' not in soc_agent:
    raise SystemExit('web smoke failed; soc-agent workspace did not render expected status')
soc_agent_chat = Path('$SOC_AGENT_CHAT_HTML').read_text(encoding='utf-8')
if 'Tool activity' not in soc_agent_chat or 'Synthetic web smoke soc-agent marker' not in soc_agent_chat:
    raise SystemExit('web smoke failed; soc-agent chat did not persist the synthetic conversation')
graphs = Path('$GRAPHS_HTML').read_text(encoding='utf-8')
if 'Investigation graphs' not in graphs or 'Create graph' not in graphs:
    raise SystemExit('web smoke failed; investigation graphs page did not render')
print('Web smoke test passed')
print(f'agent_id={agent_id}')
PY

if [[ "${SIEM_WEB_SMOKE_CLEANUP:-0}" == "1" ]]; then
  ./scripts/cleanup-synthetic-data.sh --no-defaults --agent-id "$AGENT_ID" --execute --confirm DELETE-SYNTHETIC-DATA \
    > .local/web-smoke-cleanup.txt
  echo "web_smoke_cleanup=.local/web-smoke-cleanup.txt"
fi
