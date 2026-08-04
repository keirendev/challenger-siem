#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ -z "${ConnectionStrings__SiemDatabase:-}"
  && -z "${Auth__EnrollmentToken:-}"
  && -z "${Auth__ServiceToken:-}"
  && -f .local/dev.env ]]; then
  source .local/dev.env
fi
: "${ConnectionStrings__SiemDatabase:?ConnectionStrings__SiemDatabase is required}"
: "${Auth__EnrollmentToken:?Auth__EnrollmentToken is required}"
: "${Auth__ServiceToken:?Auth__ServiceToken is required}"

BASE_URL="${SIEM_SMOKE_BASE_URL:-http://127.0.0.1:55445}"
mkdir -p .local
ASPNETCORE_URLS="$BASE_URL" ASPNETCORE_ENVIRONMENT=Development dotnet run --project server/Siem.Api --no-build --no-launch-profile >.local/smoke-api.log 2>&1 &
api_pid=$!
trap 'kill "$api_pid" >/dev/null 2>&1 || true' EXIT
for _ in {1..40}; do curl --silent --fail "$BASE_URL/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl --silent --fail "$BASE_URL/health" >/dev/null
SIEM_REGISTER_BASE_URL="$BASE_URL" SIEM_REGISTER_RESPONSE_FILE=.local/smoke-register-response.json ./scripts/register-agent.sh
curl --silent --fail "$BASE_URL/api/v2/events?platform=linux&limit=1" -H "Authorization: Bearer $Auth__ServiceToken" >.local/smoke-query-response.json
echo "Headless Linux API smoke test passed."
