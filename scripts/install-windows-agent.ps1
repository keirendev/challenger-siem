#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PublishPath = (Resolve-Path (Join-Path $PSScriptRoot "..\dist\windows-agent-win-x64") -ErrorAction SilentlyContinue),
    [string]$InstallDir = "C:\Program Files\ChallengerSIEM\Agent",
    [string]$DataDir = "C:\ProgramData\ChallengerSIEM\Agent",
    [string]$ServiceName = "ChallengerSiemAgent",
    [string]$DisplayName = "Challenger SIEM Agent",
    [switch]$Start
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Protect-Directory {
    param([Parameter(Mandatory)] [string]$Path)

    New-Item -ItemType Directory -Path $Path -Force | Out-Null

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl

    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new("BUILTIN\Administrators", $fullControl, $inheritance, $propagation, "Allow"))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new("NT AUTHORITY\SYSTEM", $fullControl, $inheritance, $propagation, "Allow"))
    Set-Acl -Path $Path -AclObject $acl
}

Assert-Administrator

if ([string]::IsNullOrWhiteSpace($PublishPath) -or -not (Test-Path $PublishPath)) {
    throw "PublishPath does not exist. Run: ./scripts/publish-windows-agent.sh"
}

$agentExe = Join-Path $PublishPath "WindowsAgent.exe"
if (-not (Test-Path $agentExe)) {
    throw "WindowsAgent.exe was not found in PublishPath: $PublishPath"
}

Protect-Directory -Path $InstallDir
Protect-Directory -Path $DataDir

Copy-Item -Path (Join-Path $PublishPath "*") -Destination $InstallDir -Recurse -Force

$configPath = Join-Path $DataDir "agentsettings.json"
if (-not (Test-Path $configPath)) {
    @'
{
  "Agent": {
    "AgentId": "CHANGE-ME",
    "ServerBaseUrl": "https://siem.example.local",
    "ApiToken": "CHANGE-ME",
    "Channels": [
      "Security",
      "System",
      "Application"
    ],
    "OptionalChannels": [
      "Windows PowerShell",
      "Microsoft-Windows-PowerShell/Operational",
      "Microsoft-Windows-Sysmon/Operational",
      "Microsoft-Windows-Windows Defender/Operational"
    ],
    "StartAtEndWhenNoState": true,
    "PollIntervalSeconds": 10,
    "HeartbeatIntervalSeconds": 60,
    "Batching": {
      "MaxEvents": 100,
      "MaxIntervalSeconds": 10
    },
    "Queue": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\queue.sqlite",
      "MaxSizeMb": 512
    },
    "State": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\state.json"
    }
  }
}
'@ | Set-Content -Path $configPath -Encoding UTF8 -NoNewline
}

Protect-Directory -Path $DataDir

$imagePath = '"{0}"' -f (Join-Path $InstallDir "WindowsAgent.exe")
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existingService) {
    & sc.exe config $ServiceName binPath= $imagePath start= delayed-auto DisplayName= $DisplayName | Out-Null
}
else {
    & sc.exe create $ServiceName binPath= $imagePath start= delayed-auto DisplayName= $DisplayName | Out-Null
}

& sc.exe description $ServiceName "Collects Windows endpoint events and forwards them to the Challenger SIEM ingestion API." | Out-Null

if ($Start) {
    Start-Service -Name $ServiceName
}

Write-Host "Installed $DisplayName as service '$ServiceName'."
Write-Host "Config path: $configPath"
Write-Host "Edit agentsettings.json with the registered AgentId and ApiToken before starting the service."
