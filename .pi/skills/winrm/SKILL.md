---
name: winrm
description: Use for authorized Windows lab administration and validation over WinRM in this Challenger SIEM project, including running PowerShell, copying the Windows agent, checking services, and querying Windows Event Logs.
allowed-tools: bash read winrm
---

# WinRM lab operations

Use this skill only for operator-authorized Windows lab hosts related to this project. Do not scan, brute-force, bypass authentication, or run WinRM commands against unknown systems.

## Current authorized local lab

- Windows VM for E2E validation: `192.168.122.240`.
- SIEM API address that the Windows VM should call back to on this host: `http://192.168.122.1:4444`.
- Do not point the Windows agent at `127.0.0.1` from the VM; that would resolve to the VM itself.

## Connection configuration

Keep credentials out of git and out of command lines. Prefer `.local/winrm.env` (already ignored by this project) or exported environment variables:

```bash
CHALLENGER_WINRM_HOST=192.168.122.240
CHALLENGER_WINRM_USER=replace-with-lab-user
CHALLENGER_WINRM_PASSWORD=replace-with-lab-password
CHALLENGER_WINRM_SSL=false
CHALLENGER_WINRM_AUTH=ntlm
CHALLENGER_WINRM_CERT_VALIDATION=false
```

Optional variables: `CHALLENGER_WINRM_PORT`, `CHALLENGER_WINRM_PASSWORD_FILE`, `CHALLENGER_WINRM_CONNECTION_TIMEOUT`, `CHALLENGER_WINRM_READ_TIMEOUT`, `CHALLENGER_WINRM_OPERATION_TIMEOUT`, `CHALLENGER_WINRM_NO_PROXY`.

## Preferred usage

The helper requires the Python `pypsrp` package on the Pi host. It is documented as optional project tooling in `docs/dependencies.md`.

If the project-local `winrm` Pi tool is active, use it for remote PowerShell/cmd/copy/fetch operations.

If the tool is not active, use the helper script from the repository root:

```bash
python3 .pi/skills/winrm/scripts/winrm.py test
python3 .pi/skills/winrm/scripts/winrm.py ps --script 'Get-Service ChallengerSiemAgent -ErrorAction SilentlyContinue'
python3 .pi/skills/winrm/scripts/winrm.py cmd --command 'hostname & whoami'
python3 .pi/skills/winrm/scripts/winrm.py copy dist/windows-agent-copy/WindowsAgent.exe 'C:\Temp\ChallengerSIEM\WindowsAgent.exe'
python3 .pi/skills/winrm/scripts/winrm.py fetch 'C:\ProgramData\ChallengerSIEM\Agent\agentsettings.json' .local/fetched-agentsettings.json
```

For longer PowerShell, prefer a here-doc or local script file rather than fragile one-line quoting:

```bash
python3 .pi/skills/winrm/scripts/winrm.py ps <<'PS'
$ErrorActionPreference = 'Stop'
Get-ComputerInfo | Select-Object CsName, WindowsProductName, OsVersion
PS
```

## Project validation examples

For an E2E smoke path, run the API on this host with `./scripts/run-server-4444.sh`, prepare the Windows agent files with `./scripts/prepare-windows-agent-files.sh`, then copy and run them on the lab VM. The generated `agentsettings.json` must contain `ServerBaseUrl` set to `http://192.168.122.1:4444`; do not print the full file because it contains the per-agent API token.

Before copying the agent, a bounded connectivity check from the VM can verify the callback route:

```bash
python3 .pi/skills/winrm/scripts/winrm.py ps --script "Invoke-RestMethod -Uri 'http://192.168.122.1:4444/health' | ConvertTo-Json -Compress"
```

Create a temporary directory and copy the prepared Windows agent files:

```bash
python3 .pi/skills/winrm/scripts/winrm.py ps --script "New-Item -ItemType Directory -Force -Path 'C:\Temp\ChallengerSIEM' | Out-Null"
python3 .pi/skills/winrm/scripts/winrm.py copy dist/windows-agent-copy/WindowsAgent.exe 'C:\Temp\ChallengerSIEM\WindowsAgent.exe'
python3 .pi/skills/winrm/scripts/winrm.py copy dist/windows-agent-copy/agentsettings.json 'C:\Temp\ChallengerSIEM\agentsettings.json'
```

Run the agent interactively for smoke validation:

```bash
python3 .pi/skills/winrm/scripts/winrm.py ps --script "Set-Location 'C:\Temp\ChallengerSIEM'; .\WindowsAgent.exe"
```

Check service install and runtime state:

```bash
python3 .pi/skills/winrm/scripts/winrm.py ps --script "Get-Service ChallengerSiemAgent -ErrorAction SilentlyContinue | Format-List *"
python3 .pi/skills/winrm/scripts/winrm.py ps --script "Get-ChildItem 'C:\ProgramData\ChallengerSIEM\Agent' -Force | Select-Object Name,Length,LastWriteTime"
```

Query recent event log records while keeping output small:

```bash
python3 .pi/skills/winrm/scripts/winrm.py ps --script "Get-WinEvent -LogName System -MaxEvents 5 | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Depth 3"
```

## Safety rules

- Never print passwords, tokens, or full `agentsettings.json` content unless the user explicitly asks and it is necessary.
- Ask before rebooting, changing firewall/auth settings, uninstalling software/services, deleting data, or clearing event logs.
- Keep remote output bounded with `Select-Object -First`, `-MaxEvents`, or targeted filters.
- Use HTTPS/certificate validation for non-lab environments. HTTP/5985 and disabled certificate validation are acceptable only for isolated local lab testing.
