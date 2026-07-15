#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUTPUT_DIR="${1:-dist/windows-agent-win-x64}"

dotnet publish agent/WindowsAgent/WindowsAgent.csproj \
  -c Release \
  -r win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true \
  -o "$OUTPUT_DIR"

cp -f "$OUTPUT_DIR/WindowsAgent.exe" dist/WindowsAgent.exe

cat <<EOF

Published standalone Windows agent:
  $ROOT_DIR/dist/WindowsAgent.exe

Copy this exact 36MB file to the Windows host. Do not copy the smaller exe from bin/Release.
It does not require WindowsAgent.dll or a .NET runtime install.

SHA256:
  $(sha256sum dist/WindowsAgent.exe | awk '{print $1}')

The agent still requires configuration at:
  C:\\ProgramData\\ChallengerSIEM\\Agent\\agentsettings.json

The published directory also includes the versioned Sysmon L3 profile at:
  $ROOT_DIR/$OUTPUT_DIR/Sysmon/challenger-siem-sysmon-l3.xml

Example config:
  $ROOT_DIR/examples/windows-agentsettings.example.json
EOF
