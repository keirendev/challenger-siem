#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

: "${ConnectionStrings__SiemDatabase:?ConnectionStrings__SiemDatabase is required}"
: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"
: "${SIEM_OPERATOR_API_TOKEN:?SIEM_OPERATOR_API_TOKEN is required}"

BASE_URL="${SIEM_SMOKE_BASE_URL:-http://127.0.0.1:5080}"
LOG_FILE=".local/smoke-api.log"
REGISTER_RESPONSE=".local/smoke-register-response.json"
INGEST_RESPONSE=".local/smoke-ingest-response.json"
QUERY_RESPONSE=".local/smoke-query-response.json"

mkdir -p .local
rm -f "$REGISTER_RESPONSE" "$INGEST_RESPONSE" "$QUERY_RESPONSE" "$LOG_FILE"

ASPNETCORE_URLS="$BASE_URL" ASPNETCORE_ENVIRONMENT=Development \
  dotnet run --project server/Siem.Api --no-build --no-launch-profile >"$LOG_FILE" 2>&1 &
API_PID=$!
trap 'kill "$API_PID" >/dev/null 2>&1 || true' EXIT

for _ in {1..40}; do
  if curl --silent --fail "$BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl --silent --fail "$BASE_URL/health" >/dev/null 2>&1; then
  echo "API did not become healthy. See $LOG_FILE" >&2
  exit 1
fi

curl --silent --fail "$BASE_URL/api/v1/agents/register" \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @examples/agent-registration.json \
  > "$REGISTER_RESPONSE"

API_TOKEN="$(python - <<'PY'
import json
with open('.local/smoke-register-response.json', encoding='utf-8') as handle:
    print(json.load(handle)['api_token'])
PY
)"

curl --silent --fail "$BASE_URL/api/v1/ingest/events" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data @examples/fake-event-batch.json \
  > "$INGEST_RESPONSE"

curl --silent --fail "$BASE_URL/api/v1/events?windows_event_id=4625" \
  -H "Authorization: Bearer $SIEM_OPERATOR_API_TOKEN" \
  > "$QUERY_RESPONSE"

python - <<'PY'
import json
import sys
from pathlib import Path

ingest = json.loads(Path('.local/smoke-ingest-response.json').read_text(encoding='utf-8'))
query = json.loads(Path('.local/smoke-query-response.json').read_text(encoding='utf-8'))
accepted = int(ingest.get('accepted') or 0)
duplicates = int(ingest.get('duplicates') or 0)
rejected = int(ingest.get('rejected') or 0)
events_returned = len(query.get('events', []))

if accepted + duplicates < 1 or rejected != 0 or events_returned < 1:
    print('Smoke test failed', file=sys.stderr)
    print(f'accepted={accepted} duplicates={duplicates} rejected={rejected}', file=sys.stderr)
    print(f'events_returned={events_returned}', file=sys.stderr)
    sys.exit(1)

print('Smoke test passed')
print(f'accepted={accepted} duplicates={duplicates} rejected={rejected}')
print(f'events_returned={events_returned}')
PY

if [[ "${SIEM_SMOKE_CLEANUP:-0}" == "1" ]]; then
  ./scripts/cleanup-synthetic-data.sh --no-defaults --agent-id "win11-test-001" --execute --confirm DELETE-SYNTHETIC-DATA \
    > .local/smoke-cleanup.txt
  echo "smoke_cleanup=.local/smoke-cleanup.txt"
fi
