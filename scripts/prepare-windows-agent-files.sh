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

API_BASE_URL="${1:-${SIEM_PREPARE_API_BASE_URL:-http://127.0.0.1:4444}}"
AGENT_SERVER_BASE_URL="${2:-${SIEM_PREPARE_AGENT_SERVER_BASE_URL:-}}"
AGENT_ID="${3:-${SIEM_PREPARE_AGENT_ID:-demo-agent-001}}"
HOSTNAME="${4:-${SIEM_PREPARE_HOSTNAME:-DEMO-WIN11}}"
OS_VERSION="${5:-${SIEM_PREPARE_OS_VERSION:-Windows 11}}"
AGENT_VERSION="${6:-${SIEM_PREPARE_AGENT_VERSION:-$PROJECT_VERSION}}"
OUTPUT_DIR="${SIEM_PREPARE_OUTPUT_DIR:-dist/windows-agent-copy}"

if [[ -z "$AGENT_SERVER_BASE_URL" ]]; then
  echo "An agent-reachable server URL is required as argv[2] or SIEM_PREPARE_AGENT_SERVER_BASE_URL." >&2
  exit 2
fi

./scripts/publish-windows-agent.sh >/dev/null
mkdir -p "$OUTPUT_DIR"
cp -f dist/WindowsAgent.exe "$OUTPUT_DIR/WindowsAgent.exe"
if [[ -d dist/windows-agent-win-x64/Sysmon ]]; then
  rm -rf "$OUTPUT_DIR/Sysmon"
  cp -R dist/windows-agent-win-x64/Sysmon "$OUTPUT_DIR/Sysmon"
fi

REQUEST_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$REQUEST_FILE" "$RESPONSE_FILE"' EXIT

python3 - "$AGENT_ID" "$HOSTNAME" "$OS_VERSION" "$AGENT_VERSION" <<'PY' > "$REQUEST_FILE"
import json
import sys

payload = {
    "agent_id": sys.argv[1],
    "hostname": sys.argv[2],
    "machine_guid": None,
    "os_version": sys.argv[3],
    "agent_version": sys.argv[4],
}
print(json.dumps(payload))
PY

curl --silent --show-error --fail "$API_BASE_URL/api/v1/agents/register" \
  -H "X-Enrollment-Token: $Auth__EnrollmentToken" \
  -H 'Content-Type: application/json' \
  --data @"$REQUEST_FILE" \
  > "$RESPONSE_FILE"

python3 - <<'PY' "$RESPONSE_FILE" "$OUTPUT_DIR/agentsettings.json" "$AGENT_SERVER_BASE_URL"
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
        "Enrollment": {"Enabled": False, "EnrollmentToken": "", "MachineGuid": None},
        "Channels": ["Security", "System", "Application"],
        "OptionalChannels": [
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-WMI-Activity/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "Microsoft-Windows-WinRM/Operational",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "Microsoft-Windows-GroupPolicy/Operational",
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "Microsoft-Windows-AppLocker/MSI and Script",
            "Microsoft-Windows-AppLocker/Packaged app-Execution",
            "Microsoft-Windows-Sysmon/Operational",
        ],
        "StartAtEndWhenNoState": True,
        "PollIntervalSeconds": 10,
        "HeartbeatIntervalSeconds": 60,
        "InventoryIntervalSeconds": 3600,
        "Batching": {"MaxEvents": 100, "MaxIntervalSeconds": 10},
        "Queue": {
            "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\queue.sqlite",
            "MaxSizeMb": 512,
            "MaxSendAttempts": 10,
            "MaxBackoffSeconds": 300,
            "WarningSizePercent": 80,
        },
        "State": {
            "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\state.json",
        },
        "Sysmon": {
            "ConfigPath": "C:\\ProgramData\\ChallengerSIEM\\Agent\\sysmon\\challenger-siem-sysmon-l3.xml",
            "ProfileVersion": "challenger-siem-l3-2026.07.06",
        },
    }
}
output_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
output_path.chmod(0o600)
PY

cat <<EOF
Prepared Windows agent files:
  $OUTPUT_DIR/WindowsAgent.exe
  $OUTPUT_DIR/agentsettings.json
  $OUTPUT_DIR/Sysmon/challenger-siem-sysmon-l3.xml (when published)

Copy the executable, settings, and optional Sysmon profile together, then run:
  .\\WindowsAgent.exe

The ignored private config contains the supplied agent-reachable server URL.
EOF
