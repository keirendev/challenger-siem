#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"

PROJECT_VERSION="$(./scripts/current-version.sh)"

BASE_URL="${1:-${SIEM_REGISTER_BASE_URL:-http://127.0.0.1:4444}}"
AGENT_ID="${2:-${SIEM_REGISTER_AGENT_ID:-demo-agent-001}}"
HOSTNAME="${3:-${SIEM_REGISTER_HOSTNAME:-DEMO-WIN11}}"
OS_VERSION="${4:-${SIEM_REGISTER_OS_VERSION:-Windows 11}}"
AGENT_VERSION="${5:-${SIEM_REGISTER_AGENT_VERSION:-$PROJECT_VERSION}}"
MACHINE_GUID="${SIEM_REGISTER_MACHINE_GUID:-}"
RESPONSE_FILE="${SIEM_REGISTER_RESPONSE_FILE:-.local/registration-response.json}"

case "$RESPONSE_FILE" in
  .local/*|"$ROOT_DIR"/.local/*) ;;
  /*)
    if [[ "$RESPONSE_FILE" == "$ROOT_DIR/"* ]]; then
      echo "A private response path inside the repository must be under .local/." >&2
      exit 2
    fi
    ;;
  *)
    echo "A relative private response path must be under .local/." >&2
    exit 2
    ;;
esac

REQUEST_FILE="$(mktemp)"
trap 'rm -f "$REQUEST_FILE"' EXIT
mkdir -p "$(dirname "$RESPONSE_FILE")"
rm -f "$RESPONSE_FILE"

python3 - "$AGENT_ID" "$HOSTNAME" "$MACHINE_GUID" "$OS_VERSION" "$AGENT_VERSION" <<'PY' > "$REQUEST_FILE"
import json
import sys

payload = {
    "agent_id": sys.argv[1],
    "hostname": sys.argv[2],
    "machine_guid": sys.argv[3] or None,
    "os_version": sys.argv[4],
    "agent_version": sys.argv[5],
}
print(json.dumps(payload))
PY

curl --silent --show-error --fail "$BASE_URL/api/v1/agents/register" \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @"$REQUEST_FILE" \
  > "$RESPONSE_FILE"
chmod 600 "$RESPONSE_FILE"

python3 - <<'PY' "$RESPONSE_FILE"
import json
import sys
from pathlib import Path

response = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if not response.get('agent_id') or not response.get('api_token'):
    raise SystemExit('registration response was missing required fields')
print('Agent registered')
PY
printf 'private_response=%s\n' "$RESPONSE_FILE"
printf 'The private response contains a one-time agent credential; keep it mode 0600 and out of logs.\n'
