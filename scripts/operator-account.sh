#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ -f .local/dev.env ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi
: "${ConnectionStrings__SiemDatabase:?ConnectionStrings__SiemDatabase is required}"
if [[ "${1:-}" != "rotate-api-token" ]]; then
  : "${SIEM_OPERATOR_PASSWORD:?Set SIEM_OPERATOR_PASSWORD privately for this command}"
fi
exec dotnet run --project server/Siem.Api --no-launch-profile -- operator "$@"
