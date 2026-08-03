#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
ui="$repository/web/Siem.Ui"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  printf 'Challenger SIEM UI requires Node.js and npm.\n' >&2
  exit 1
fi

npm --prefix "$ui" ci
npm --prefix "$ui" run build
