#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\ChallengerSIEM\Agent",
    [string]$DataDir = "C:\ProgramData\ChallengerSIEM\Agent",
    [string]$ServiceName = "ChallengerSiemAgent"
)

$ErrorActionPreference = "Stop"

function Show-DirectoryAclSummary {
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Host "Path missing: $Path"
        return
    }

    $acl = Get-Acl -Path $Path
    $identityNames = $acl.Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique
    Write-Host "ACL identities for $Path: $($identityNames -join ', ')"

    $unexpected = $identityNames | Where-Object {
        $_ -notin @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')
    }
    if ($unexpected) {
        Write-Warning "Unexpected ACL identities found on $Path: $($unexpected -join ', ')"
    }
}

Show-DirectoryAclSummary -Path $InstallDir
Show-DirectoryAclSummary -Path $DataDir

$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Service '$ServiceName' runs as: $($service.StartName)"
}
else {
    Write-Host "Service '$ServiceName' is not installed."
}

try {
    $latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    Write-Host "Security log read check: success (latest record id $($latest.RecordId))."
}
catch {
    Write-Warning "Security log read check failed: $($_.Exception.Message)"
}
