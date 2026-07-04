#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\ChallengerSIEM\Agent",
    [string]$DataDir = "C:\ProgramData\ChallengerSIEM\Agent",
    [string]$ServiceName = "ChallengerSiemAgent",
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

Assert-Administrator

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    & sc.exe delete $ServiceName | Out-Null
}

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -Path $DataDir -Recurse -Force
    Write-Host "Removed service, install directory, and data directory."
}
else {
    Write-Host "Removed service and install directory. Data directory preserved: $DataDir"
}
