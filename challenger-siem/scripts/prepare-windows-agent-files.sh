#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"

API_BASE_URL="${1:-${SIEM_PREPARE_API_BASE_URL:-http://127.0.0.1:4444}}"
AGENT_SERVER_BASE_URL="${2:-${SIEM_PREPARE_AGENT_SERVER_BASE_URL:-http://192.168.122.1:4444}}"
AGENT_ID="${3:-${SIEM_PREPARE_AGENT_ID:-win11-test-001}}"
HOSTNAME="${4:-${SIEM_PREPARE_HOSTNAME:-WIN11-TEST}}"
OS_VERSION="${5:-${SIEM_PREPARE_OS_VERSION:-Windows 11}}"
AGENT_VERSION="${6:-${SIEM_PREPARE_AGENT_VERSION:-0.1.0}}"
OUTPUT_DIR="${SIEM_PREPARE_OUTPUT_DIR:-dist/windows-agent-copy}"

./scripts/publish-windows-agent.sh >/dev/null
mkdir -p "$OUTPUT_DIR"
cp -f dist/WindowsAgent.exe "$OUTPUT_DIR/WindowsAgent.exe"

REQUEST_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$REQUEST_FILE" "$RESPONSE_FILE"' EXIT

python - <<PY > "$REQUEST_FILE"
import json
payload = {
    "agent_id": "$AGENT_ID",
    "hostname": "$HOSTNAME",
    "machine_guid": None,
    "os_version": "$OS_VERSION",
    "agent_version": "$AGENT_VERSION",
}
print(json.dumps(payload))
PY

curl --silent --show-error --fail "$API_BASE_URL/api/v1/agents/register" \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @"$REQUEST_FILE" \
  > "$RESPONSE_FILE"

python - <<'PY' "$RESPONSE_FILE" "$OUTPUT_DIR/agentsettings.json" "$AGENT_SERVER_BASE_URL"
import json
import sys
from pathlib import Path

response = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
output_path = Path(sys.argv[2])
server_base_url = sys.argv[3]
config = {
    "Agent": {
        "AgentId": response["agent_id"],
        "ServerBaseUrl": server_base_url,
        "ApiToken": response["api_token"],
        "Channels": ["Security", "System", "Application"],
        "OptionalChannels": [
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
        ],
        "StartAtEndWhenNoState": True,
        "PollIntervalSeconds": 10,
        "HeartbeatIntervalSeconds": 60,
        "Batching": {"MaxEvents": 100, "MaxIntervalSeconds": 10},
        "Queue": {
            "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\queue.sqlite",
            "MaxSizeMb": 512,
        },
        "State": {
            "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\state.json",
        },
    }
}
output_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
PY

cat <<EOF
Prepared Windows agent files:
  $ROOT_DIR/$OUTPUT_DIR/WindowsAgent.exe
  $ROOT_DIR/$OUTPUT_DIR/agentsettings.json

Copy both files into the same folder on Windows, then run:
  .\\WindowsAgent.exe

The config points the agent at:
  $AGENT_SERVER_BASE_URL
EOF
