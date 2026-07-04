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
: "${Auth__ReviewToken:?Auth__ReviewToken is required}"

export ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Development}"
export ASPNETCORE_URLS="${ASPNETCORE_URLS:-http://0.0.0.0:4444}"

echo "Starting Challenger SIEM API on ${ASPNETCORE_URLS}"
echo "Windows agents should use ServerBaseUrl: http://192.168.122.1:4444"

dotnet run --project server/Siem.Api --no-launch-profile
