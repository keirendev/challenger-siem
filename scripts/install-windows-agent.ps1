#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet("plan", "install", "upgrade", "repair", "validate", "uninstall")]
    [string]$Mode = "install",
    [string]$PublishPath = (Join-Path $PSScriptRoot "..\dist\windows-agent-win-x64"),
    [string]$InstallDir = "C:\Program Files\ChallengerSIEM\Agent",
    [string]$DataDir = "C:\ProgramData\ChallengerSIEM\Agent",
    [string]$ServiceName = "ChallengerSiemAgent",
    [string]$DisplayName = "Challenger SIEM Agent",
    [string]$ServiceAccount = "LocalSystem",
    [ValidateSet("L1", "L2", "L3", "L4")]
    [string]$TargetLevel = "L2",
    [switch]$ConfigurePrerequisites,
    [switch]$ConfigurePrivacySensitiveAuditPolicy,
    [switch]$ManageSysmon,
    [switch]$AcceptSysmonEula,
    [string]$SysmonSourcePath = "",
    [string]$SysmonExpectedSha256 = "",
    [string]$SysmonConfigPath = "",
    [switch]$Start,
    [switch]$RestartService,
    [switch]$RemoveData,
    [switch]$PlanOnly
)

$ErrorActionPreference = "Stop"

if ($PlanOnly) {
    $Mode = "plan"
}
$Mode = $Mode.ToLowerInvariant()

$SysmonProfileFileName = "challenger-siem-sysmon-l3.xml"
$SysmonProfileVersion = "challenger-siem-l3-2026.07.06"

$ChannelMatrix = @(
    [pscustomobject]@{ Id = "security"; Channel = "Security"; Level = "L1"; Required = $true; MinimumSizeMb = 128; EnableByDefault = $true },
    [pscustomobject]@{ Id = "system"; Channel = "System"; Level = "L1"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "application"; Channel = "Application"; Level = "L1"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "powershell-classic"; Channel = "Windows PowerShell"; Level = "L2"; Required = $true; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "powershell-operational"; Channel = "Microsoft-Windows-PowerShell/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "defender-operational"; Channel = "Microsoft-Windows-Windows Defender/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "task-scheduler"; Channel = "Microsoft-Windows-TaskScheduler/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "wmi-activity"; Channel = "Microsoft-Windows-WMI-Activity/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "terminalservices-local-sessionmanager"; Channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "terminalservices-remoteconnectionmanager"; Channel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "rdp-corets"; Channel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "winrm-operational"; Channel = "Microsoft-Windows-WinRM/Operational"; Level = "L2"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "firewall-advanced"; Channel = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; Level = "L2"; Required = $true; MinimumSizeMb = 64; EnableByDefault = $true },
    [pscustomobject]@{ Id = "group-policy"; Channel = "Microsoft-Windows-GroupPolicy/Operational"; Level = "L2"; Required = $false; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "code-integrity"; Channel = "Microsoft-Windows-CodeIntegrity/Operational"; Level = "L2"; Required = $false; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "applocker-exe-dll"; Channel = "Microsoft-Windows-AppLocker/EXE and DLL"; Level = "L2"; Required = $false; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "applocker-msi-script"; Channel = "Microsoft-Windows-AppLocker/MSI and Script"; Level = "L2"; Required = $false; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "applocker-packaged-app"; Channel = "Microsoft-Windows-AppLocker/Packaged app-Execution"; Level = "L2"; Required = $false; MinimumSizeMb = 32; EnableByDefault = $true },
    [pscustomobject]@{ Id = "sysmon-operational"; Channel = "Microsoft-Windows-Sysmon/Operational"; Level = "L3"; Required = $true; MinimumSizeMb = 128; EnableByDefault = $true }
)

$AuditPolicyMatrix = @(
    [pscustomobject]@{ Name = "Credential Validation"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "User Account Management"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Security Group Management"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Other Account Management Events"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Process Creation"; Success = $true; Failure = $false; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "DPAPI Activity"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Logon"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Logoff"; Success = $true; Failure = $false; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Account Lockout"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Special Logon"; Success = $true; Failure = $false; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Other Logon/Logoff Events"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Audit Policy Change"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Authentication Policy Change"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Authorization Policy Change"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "MPSSVC Rule-Level Policy Change"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Filtering Platform Policy Change"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Filtering Platform Connection"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Security State Change"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Security System Extension"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "System Integrity"; Success = $true; Failure = $true; ConfigureByDefault = $true },
    [pscustomobject]@{ Name = "Sensitive Privilege Use"; Success = $true; Failure = $true; ConfigureByDefault = $false },
    [pscustomobject]@{ Name = "File System"; Success = $true; Failure = $true; ConfigureByDefault = $false },
    [pscustomobject]@{ Name = "Registry"; Success = $true; Failure = $true; ConfigureByDefault = $false },
    [pscustomobject]@{ Name = "Removable Storage"; Success = $true; Failure = $true; ConfigureByDefault = $false }
)

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session for this mode."
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

function Get-ExpectedChannels {
    switch ($TargetLevel) {
        "L1" { $levels = @("L1") }
        "L2" { $levels = @("L1", "L2") }
        "L3" { $levels = @("L1", "L2", "L3") }
        "L4" { $levels = @("L1", "L2", "L3") }
        default { $levels = @("L1", "L2") }
    }

    $ChannelMatrix | Where-Object { $_.Level -in $levels }
}

function Resolve-SysmonConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($SysmonConfigPath)) {
        return $SysmonConfigPath
    }

    $publishCandidate = Join-Path $PublishPath ("Sysmon\{0}" -f $SysmonProfileFileName)
    if (Test-Path $publishCandidate) {
        return $publishCandidate
    }

    return Join-Path $PSScriptRoot ("..\agent\WindowsAgent\Sysmon\{0}" -f $SysmonProfileFileName)
}

function Write-InstallerPlan {
    $channels = @(Get-ExpectedChannels)
    $requiredChannels = @($channels | Where-Object { $_.Required })
    $sysmonConfig = Resolve-SysmonConfigPath

    Write-Output "mode=plan"
    Write-Output "target_level=$TargetLevel"
    Write-Output "Plan: validate published WindowsAgent.exe under '$PublishPath'."
    Write-Output "Plan: protect install directory '$InstallDir' and data directory '$DataDir' for BUILTIN\Administrators and NT AUTHORITY\SYSTEM."
    Write-Output "Plan: install, upgrade, or repair service '$ServiceName' ('$DisplayName') as '$ServiceAccount' while preserving existing config, queue, and state."
    Write-Output "Plan: validate $($channels.Count) expected event channels ($($requiredChannels.Count) mandatory for target level $TargetLevel)."
    Write-Output "Plan: validate $($AuditPolicyMatrix.Count) audit-policy subcategories, process command-line auditing, PowerShell logging, Defender/firewall visibility, and source-health prerequisites."
    if ($ConfigurePrerequisites) {
        Write-Output "Plan: configure approved Windows prerequisites because -ConfigurePrerequisites was specified."
        Write-Output "Plan: enable expected event channels, apply log-size baselines, configure approved audit-policy subcategories, process command-line auditing, and PowerShell script-block/module logging."
        if ($ConfigurePrivacySensitiveAuditPolicy) {
            Write-Output "Plan: include privacy-sensitive audit subcategories such as Sensitive Privilege Use, File System, Registry, and Removable Storage because -ConfigurePrivacySensitiveAuditPolicy was specified."
        }
        else {
            Write-Output "Plan: privacy-sensitive audit subcategories remain validation-only unless -ConfigurePrivacySensitiveAuditPolicy is specified."
        }
    }
    else {
        Write-Output "Plan: prerequisite checks are read-only; no audit policy, channel, or registry policy changes will be made without -ConfigurePrerequisites."
    }

    if ($ManageSysmon) {
        Write-Output "Plan: manage Sysmon from an operator-provided Microsoft Sysinternals binary, validate Authenticode signature, optional SHA256 pin, explicit EULA acceptance, and config '$sysmonConfig'."
    }
    else {
        Write-Output "Plan: Sysmon will be validated only; install/config/uninstall requires -ManageSysmon and explicit operator approval."
    }

    if ($RestartService) {
        Write-Output "Plan: stop and restart service '$ServiceName' if needed because -RestartService was specified."
    }
    elseif ($Start) {
        Write-Output "Plan: start service '$ServiceName' after install if it is not already running because -Start was specified."
    }

    if ($RemoveData) {
        Write-Output "Plan: data removal would occur only in -Mode uninstall with -RemoveData; queue/state/config removal is destructive and not part of plan mode."
    }

    Write-Output "Plan complete. No changes were made."
}

function Get-AgentSettingsTemplate {
@'
{
  "Agent": {
    "AgentId": "CHANGE-ME",
    "ServerBaseUrl": "https://siem.example.local",
    "ApiToken": "CHANGE-ME-OR-LEAVE-BLANK-FOR-ENROLLMENT",
    "Enrollment": {
      "Enabled": false,
      "EnrollmentToken": "CHANGE-ME-ONLY-FOR-FIRST-RUN",
      "MachineGuid": null
    },
    "Channels": [
      "Security",
      "System",
      "Application"
    ],
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
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "StartAtEndWhenNoState": true,
    "PollIntervalSeconds": 10,
    "HeartbeatIntervalSeconds": 60,
    "InventoryIntervalSeconds": 3600,
    "Batching": {
      "MaxEvents": 100,
      "MaxIntervalSeconds": 10
    },
    "Queue": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\queue.sqlite",
      "MaxSizeMb": 512,
      "MaxSendAttempts": 10,
      "MaxBackoffSeconds": 300,
      "WarningSizePercent": 80
    },
    "State": {
      "Path": "C:\\ProgramData\\ChallengerSIEM\\Agent\\state.json"
    },
    "Sysmon": {
      "ConfigPath": "C:\\ProgramData\\ChallengerSIEM\\Agent\\sysmon\\challenger-siem-sysmon-l3.xml",
      "ProfileVersion": "challenger-siem-l3-2026.07.06"
    }
  }
}
'@
}

function Install-OrUpdateAgentService {
    Assert-Administrator

    if ([string]::IsNullOrWhiteSpace($PublishPath) -or -not (Test-Path $PublishPath)) {
        throw "PublishPath does not exist. Run: ./scripts/publish-windows-agent.sh"
    }

    $agentExe = Join-Path $PublishPath "WindowsAgent.exe"
    if (-not (Test-Path $agentExe)) {
        throw "WindowsAgent.exe was not found in PublishPath: $PublishPath"
    }

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $wasRunning = $existingService -and $existingService.Status -ne "Stopped"
    if ($wasRunning -and -not $RestartService) {
        throw "Service '$ServiceName' is running. Re-run with -RestartService after reviewing the plan, or stop the service manually before upgrade/repair."
    }

    if ($wasRunning -and $RestartService) {
        Stop-Service -Name $ServiceName -Force
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    Protect-Directory -Path $InstallDir
    Protect-Directory -Path $DataDir

    Copy-Item -Path (Join-Path $PublishPath "*") -Destination $InstallDir -Recurse -Force

    $configPath = Join-Path $DataDir "agentsettings.json"
    if (-not (Test-Path $configPath)) {
        Get-AgentSettingsTemplate | Set-Content -Path $configPath -Encoding UTF8 -NoNewline
    }

    $sysmonConfig = Resolve-SysmonConfigPath
    if (Test-Path $sysmonConfig) {
        $sysmonDataDir = Join-Path $DataDir "sysmon"
        Protect-Directory -Path $sysmonDataDir
        Copy-Item -Path $sysmonConfig -Destination (Join-Path $sysmonDataDir $SysmonProfileFileName) -Force
    }

    Protect-Directory -Path $DataDir

    $imagePath = '"{0}"' -f (Join-Path $InstallDir "WindowsAgent.exe")
    $scAccount = if ($ServiceAccount -eq "LocalSystem") { "LocalSystem" } else { $ServiceAccount }

    if ($existingService) {
        & sc.exe config $ServiceName binPath= $imagePath start= delayed-auto DisplayName= $DisplayName obj= $scAccount | Out-Null
    }
    else {
        & sc.exe create $ServiceName binPath= $imagePath start= delayed-auto DisplayName= $DisplayName obj= $scAccount | Out-Null
    }

    & sc.exe description $ServiceName "Collects Windows endpoint events and forwards them to the Challenger SIEM ingestion API." | Out-Null

    if ($ConfigurePrerequisites) {
        Set-WindowsPrerequisites
    }

    if ($ManageSysmon) {
        Invoke-SysmonInstallOrUpdate
    }

    if ($Start -or ($wasRunning -and $RestartService)) {
        Start-Service -Name $ServiceName
    }

    Write-Output "install_status=complete service=$ServiceName config_path=$configPath sysmon_profile_version=$SysmonProfileVersion"
    Write-Output "secret_notice=Edit protected agentsettings.json with enrollment or per-agent token outside public logs before starting the service."
}

function Uninstall-AgentService {
    Assert-Administrator

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        }

        & sc.exe delete $ServiceName | Out-Null
    }

    if ($ManageSysmon) {
        Invoke-SysmonUninstall
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
    }

    if ($RemoveData -and (Test-Path $DataDir)) {
        Remove-Item -Path $DataDir -Recurse -Force
        Write-Output "uninstall_status=complete data=removed"
    }
    else {
        Write-Output "uninstall_status=complete data=preserved data_dir=$DataDir"
    }
}

function Set-WindowsPrerequisites {
    Assert-Administrator
    $classicChannels = @("Security", "System", "Application", "Windows PowerShell")
    foreach ($entry in Get-ExpectedChannels) {
        if (-not $entry.EnableByDefault) {
            continue
        }

        try {
            $sizeBytes = [int64]$entry.MinimumSizeMb * 1024 * 1024
            if ($classicChannels -contains $entry.Channel) {
                & wevtutil.exe sl "$($entry.Channel)" "/ms:$sizeBytes" | Out-Null
            }
            else {
                & wevtutil.exe sl "$($entry.Channel)" /e:true "/ms:$sizeBytes" | Out-Null
            }
        }
        catch {
            Write-Warning "channel_config_status id=$($entry.Id) status=failed"
        }
    }

    foreach ($item in $AuditPolicyMatrix | Where-Object { $_.ConfigureByDefault -or $ConfigurePrivacySensitiveAuditPolicy }) {
        try {
            $success = if ($item.Success) { "enable" } else { "disable" }
            $failure = if ($item.Failure) { "enable" } else { "disable" }
            & auditpol.exe /set ("/subcategory:{0}" -f $item.Name) ("/success:{0}" -f $success) ("/failure:{0}" -f $failure) | Out-Null
        }
        catch {
            Write-Warning "audit_policy_config_status subcategory='$($item.Name)' status=failed"
        }
    }

    try {
        $processAuditPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        New-Item -Path $processAuditPath -Force | Out-Null
        New-ItemProperty -Path $processAuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null

        $scriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        New-Item -Path $scriptBlockPath -Force | Out-Null
        New-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null

        $moduleLoggingPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $moduleNamesPath = Join-Path $moduleLoggingPath "ModuleNames"
        New-Item -Path $moduleNamesPath -Force | Out-Null
        New-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $moduleNamesPath -Name "*" -PropertyType String -Value "*" -Force | Out-Null
    }
    catch {
        Write-Warning "policy_config_status status=failed"
    }
}

function Test-EventChannels {
    foreach ($entry in Get-ExpectedChannels) {
        try {
            $log = Get-WinEvent -ListLog $entry.Channel -ErrorAction Stop
            $sizeMb = if ($log.MaximumSizeInBytes) { [math]::Round($log.MaximumSizeInBytes / 1MB, 0) } else { 0 }
            $status = if ($log.IsEnabled) { "enabled" } else { "disabled" }
            $baseline = if ($sizeMb -ge $entry.MinimumSizeMb) { "met" } else { "below_minimum" }
            Write-Output ("channel_status id={0} level={1} required={2} status={3} size_mb={4} size_baseline={5}" -f $entry.Id, $entry.Level, $entry.Required.ToString().ToLowerInvariant(), $status, $sizeMb, $baseline)
        }
        catch {
            $status = if ($entry.Required) { "missing" } else { "not_applicable" }
            Write-Output ("channel_status id={0} level={1} required={2} status={3}" -f $entry.Id, $entry.Level, $entry.Required.ToString().ToLowerInvariant(), $status)
        }
    }
}

function Get-AuditPolicySetting {
    param([Parameter(Mandatory)] [string]$Subcategory)

    try {
        $output = & auditpol.exe /get ("/subcategory:{0}" -f $Subcategory) 2>$null
        foreach ($line in $output) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith($Subcategory, [StringComparison]::OrdinalIgnoreCase)) {
                $parts = [System.Text.RegularExpressions.Regex]::Split($trimmed, "\s{2,}")
                if ($parts.Length -ge 2) {
                    return $parts[$parts.Length - 1].Trim()
                }
            }
        }
    }
    catch {
        return $null
    }

    return $null
}

function Test-AuditPolicyBaseline {
    foreach ($item in $AuditPolicyMatrix) {
        $actual = Get-AuditPolicySetting -Subcategory $item.Name
        if ([string]::IsNullOrWhiteSpace($actual)) {
            Write-Output ("audit_policy_status subcategory='{0}' status=unknown configure_by_default={1}" -f $item.Name, $item.ConfigureByDefault.ToString().ToLowerInvariant())
            continue
        }

        $hasSuccess = $actual -match "Success"
        $hasFailure = $actual -match "Failure"
        $meets = ((-not $item.Success) -or $hasSuccess) -and ((-not $item.Failure) -or $hasFailure)
        $status = if ($meets) { "healthy" } else { "drift" }
        Write-Output ("audit_policy_status subcategory='{0}' status={1} configure_by_default={2}" -f $item.Name, $status, $item.ConfigureByDefault.ToString().ToLowerInvariant())
    }
}

function Test-PolicySettings {
    $processCmdValue = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    $processStatus = if ($processCmdValue -eq 1) { "enabled" } else { "missing" }
    Write-Output "policy_status id=process_command_line_auditing status=$processStatus"

    $scriptBlockValue = Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    $moduleValue = Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    $powerShellStatus = if ($scriptBlockValue -eq 1 -and $moduleValue -eq 1) { "enabled" } else { "missing" }
    Write-Output "policy_status id=powershell_script_block_module_logging status=$powerShellStatus"

    try {
        $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $enabledCount = @($firewallProfiles | Where-Object { $_.Enabled }).Count
        Write-Output "policy_status id=windows_firewall status=$enabledCount/$($firewallProfiles.Count)_profiles_enabled"
    }
    catch {
        Write-Output "policy_status id=windows_firewall status=unknown"
    }

    try {
        $defenderEnabled = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
        $defenderStatus = if ($defenderEnabled) { "enabled" } else { "disabled" }
        Write-Output "policy_status id=defender_realtime status=$defenderStatus"
    }
    catch {
        Write-Output "policy_status id=defender_realtime status=unavailable"
    }
}

function Test-AgentInstallState {
    $exePath = Join-Path $InstallDir "WindowsAgent.exe"
    $configPath = Join-Path $DataDir "agentsettings.json"
    $queuePath = Join-Path $DataDir "queue.sqlite"
    $statePath = Join-Path $DataDir "state.json"
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $serviceStatus = if ($service) { $service.Status.ToString().ToLowerInvariant() } else { "not_installed" }
    Write-Output "agent_install_status service=$serviceStatus exe_present=$((Test-Path $exePath).ToString().ToLowerInvariant()) config_present=$((Test-Path $configPath).ToString().ToLowerInvariant()) queue_present=$((Test-Path $queuePath).ToString().ToLowerInvariant()) state_present=$((Test-Path $statePath).ToString().ToLowerInvariant())"
}

function Test-SysmonBinary {
    if ([string]::IsNullOrWhiteSpace($SysmonSourcePath)) {
        Write-Host "sysmon_binary_status status=not_provided signature=not_checked hash=not_checked"
        return $false
    }

    if (-not (Test-Path $SysmonSourcePath)) {
        Write-Host "sysmon_binary_status status=missing signature=not_checked hash=not_checked"
        return $false
    }

    $signature = Get-AuthenticodeSignature -FilePath $SysmonSourcePath
    $signatureOk = $signature.Status -eq "Valid" -and $signature.SignerCertificate -and $signature.SignerCertificate.Subject -match "Microsoft"
    $hashOk = $true
    if (-not [string]::IsNullOrWhiteSpace($SysmonExpectedSha256)) {
        $hash = (Get-FileHash -Path $SysmonSourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $hashOk = $hash -eq $SysmonExpectedSha256.ToLowerInvariant()
    }

    $status = if ($signatureOk -and $hashOk) { "valid" } else { "failed" }
    $hashStatus = if ([string]::IsNullOrWhiteSpace($SysmonExpectedSha256)) { "not_pinned" } elseif ($hashOk) { "matched" } else { "mismatch" }
    Write-Host "sysmon_binary_status status=$status signature=$($signature.Status) hash=$hashStatus"
    return ($signatureOk -and $hashOk)
}

function Test-SysmonState {
    $config = Resolve-SysmonConfigPath
    $configPresent = Test-Path $config
    $managedConfig = Join-Path (Join-Path $DataDir "sysmon") $SysmonProfileFileName
    $managedConfigPresent = Test-Path $managedConfig
    $configHash = if ($managedConfigPresent) { (Get-FileHash -Path $managedConfig -Algorithm SHA256).Hash.ToLowerInvariant() } elseif ($configPresent) { (Get-FileHash -Path $config -Algorithm SHA256).Hash.ToLowerInvariant() } else { "" }
    $services = @(Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue)
    $serviceStatus = if ($services.Count -gt 0) { $services[0].Status.ToString().ToLowerInvariant() } else { "not_installed" }
    Write-Output "sysmon_status service=$serviceStatus profile_version=$SysmonProfileVersion config_present=$($configPresent.ToString().ToLowerInvariant()) managed_config_present=$($managedConfigPresent.ToString().ToLowerInvariant()) config_hash=$configHash"
}

function Quote-NativeArgument {
    param([Parameter(Mandatory)] [string]$Value)

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-SysmonCommand {
    param([Parameter(Mandatory)] [string[]]$Arguments)

    $outPath = Join-Path $env:TEMP ("challenger-sysmon-out-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    $errPath = Join-Path $env:TEMP ("challenger-sysmon-err-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    try {
        $argumentLine = ($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' '
        $process = Start-Process -FilePath $SysmonSourcePath -ArgumentList $argumentLine -Wait -PassThru -NoNewWindow -RedirectStandardOutput $outPath -RedirectStandardError $errPath
        return $process.ExitCode
    }
    finally {
        Remove-Item -Path $outPath, $errPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-SysmonInstallOrUpdate {
    Assert-Administrator
    if (-not $AcceptSysmonEula) {
        throw "Sysmon management requires -AcceptSysmonEula after the operator has reviewed Microsoft Sysinternals license/EULA terms."
    }

    if (-not (Test-SysmonBinary)) {
        throw "Sysmon binary validation failed. Provide the official Microsoft Sysinternals Sysmon64.exe and optional expected SHA256."
    }

    $sourceConfig = Resolve-SysmonConfigPath
    if (-not (Test-Path $sourceConfig)) {
        throw "Sysmon config profile not found: $sourceConfig"
    }

    $sysmonDataDir = Join-Path $DataDir "sysmon"
    Protect-Directory -Path $sysmonDataDir
    $managedConfig = Join-Path $sysmonDataDir $SysmonProfileFileName
    Copy-Item -Path $sourceConfig -Destination $managedConfig -Force

    $services = @(Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue)
    $sysmonArgs = if ($services.Count -gt 0) { @("-accepteula", "-c", $managedConfig) } else { @("-accepteula", "-i", $managedConfig) }
    $exitCode = Invoke-SysmonCommand -Arguments $sysmonArgs
    if ($exitCode -ne 0) {
        throw "Sysmon install/config update failed with exit code $exitCode."
    }

    Write-Output "sysmon_manage_status=complete profile_version=$SysmonProfileVersion"
}

function Invoke-SysmonUninstall {
    Assert-Administrator
    if (-not (Test-SysmonBinary)) {
        throw "Sysmon binary validation failed; Sysmon uninstall was not attempted."
    }

    $exitCode = Invoke-SysmonCommand -Arguments @("-u")
    if ($exitCode -ne 0) {
        throw "Sysmon uninstall failed with exit code $exitCode."
    }

    Write-Output "sysmon_uninstall_status=complete"
}

function Invoke-Validation {
    Write-Output "mode=validate target_level=$TargetLevel"
    Test-AgentInstallState
    Test-EventChannels
    Test-AuditPolicyBaseline
    Test-PolicySettings
    Test-SysmonState
    if (-not [string]::IsNullOrWhiteSpace($SysmonSourcePath)) {
        [void](Test-SysmonBinary)
    }
    if ($TargetLevel -eq "L4") {
        Write-Output "l4_role_pack_status status=manual_role_pack_validation_required"
    }
    Write-Output "validation_status=complete"
}

switch ($Mode) {
    "plan" {
        Write-InstallerPlan
    }
    "install" {
        Install-OrUpdateAgentService
        Invoke-Validation
    }
    "upgrade" {
        Install-OrUpdateAgentService
        Invoke-Validation
    }
    "repair" {
        Install-OrUpdateAgentService
        Invoke-Validation
    }
    "validate" {
        Invoke-Validation
    }
    "uninstall" {
        Uninstall-AgentService
    }
}
