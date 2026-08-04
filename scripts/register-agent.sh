#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
[[ -z "${Auth__EnrollmentToken:-}" && -f .local/dev.env ]] && source .local/dev.env
: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"

BASE_URL="${1:-${SIEM_REGISTER_BASE_URL:-http://127.0.0.1:55443}}"
AGENT_ID="${2:-${SIEM_REGISTER_AGENT_ID:-linux-demo-001}}"
HOSTNAME_VALUE="${3:-${SIEM_REGISTER_HOSTNAME:-linux-demo}}"
HOST_ID="${SIEM_REGISTER_HOST_ID:-synthetic-linux-host-id}"
OS_VERSION="${SIEM_REGISTER_OS_VERSION:-Linux}"
AGENT_VERSION="${SIEM_REGISTER_AGENT_VERSION:-$(./scripts/current-version.sh)}"
RESPONSE_FILE="${SIEM_REGISTER_RESPONSE_FILE:-.local/registration-response.json}"
[[ "$RESPONSE_FILE" == .local/* ]] || { echo "The private response path must be under .local/." >&2; exit 2; }

request_file="$(mktemp)"
trap 'rm -f "$request_file"' EXIT
mkdir -p "$(dirname "$RESPONSE_FILE")"
python3 - "$AGENT_ID" "$HOSTNAME_VALUE" "$HOST_ID" "$OS_VERSION" "$AGENT_VERSION" >"$request_file" <<'PY'
import json, sys
print(json.dumps({"agent_id":sys.argv[1],"hostname":sys.argv[2],"platform":"linux","host_id":sys.argv[3],"os_version":sys.argv[4],"agent_version":sys.argv[5]}))
PY
curl --silent --show-error --fail "$BASE_URL/api/v2/agents/register" -H "X-Enrollment-Token: $Auth__EnrollmentToken" -H 'Content-Type: application/json' --data @"$request_file" >"$RESPONSE_FILE"
chmod 600 "$RESPONSE_FILE"
echo "Linux agent registered; private response written under .local/."
