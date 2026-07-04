#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"

BASE_URL="${1:-${SIEM_REGISTER_BASE_URL:-http://127.0.0.1:4444}}"
AGENT_ID="${2:-${SIEM_REGISTER_AGENT_ID:-win11-test-001}}"
HOSTNAME="${3:-${SIEM_REGISTER_HOSTNAME:-WIN11-TEST}}"
OS_VERSION="${4:-${SIEM_REGISTER_OS_VERSION:-Windows 11}}"
AGENT_VERSION="${5:-${SIEM_REGISTER_AGENT_VERSION:-0.1.0}}"
MACHINE_GUID="${SIEM_REGISTER_MACHINE_GUID:-}"

REQUEST_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$REQUEST_FILE" "$RESPONSE_FILE"' EXIT

python - <<PY > "$REQUEST_FILE"
import json
payload = {
    "agent_id": "$AGENT_ID",
    "hostname": "$HOSTNAME",
    "machine_guid": "$MACHINE_GUID" or None,
    "os_version": "$OS_VERSION",
    "agent_version": "$AGENT_VERSION",
}
print(json.dumps(payload))
PY

curl --silent --show-error --fail "$BASE_URL/api/v1/agents/register" \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @"$REQUEST_FILE" \
  > "$RESPONSE_FILE"

python - <<'PY' "$RESPONSE_FILE" "$BASE_URL"
import json
import sys
from pathlib import Path

response = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
base_url = sys.argv[2]
print('Agent registered')
print(f"agent_id={response['agent_id']}")
print(f"server_base_url_for_windows=http://192.168.122.1:4444")
print(f"api_token={response['api_token']}")
print('')
print('Put these values into C:\\ProgramData\\ChallengerSIEM\\Agent\\agentsettings.json:')
print(f"  AgentId: {response['agent_id']}")
print('  ServerBaseUrl: http://192.168.122.1:4444')
print(f"  ApiToken: {response['api_token']}")
PY
