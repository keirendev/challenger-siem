# Windows agent installer workflow

The Windows installer workflow is a PowerShell bundle around the published `WindowsAgent.exe`, protected config/data paths, Windows prerequisite validation, and the versioned Challenger SIEM Sysmon L3 profile.

Use only authorized Windows hosts. Preview first, and get explicit operator approval before changing audit policy, event-channel settings, Sysmon, service state, or local data.

## Modes

```powershell
.\scripts\install-windows-agent.ps1 -Mode plan -TargetLevel L3
.\scripts\install-windows-agent.ps1 -Mode install -PublishPath .\dist\windows-agent-win-x64
.\scripts\install-windows-agent.ps1 -Mode upgrade -PublishPath .\dist\windows-agent-win-x64 -RestartService
.\scripts\install-windows-agent.ps1 -Mode repair -PublishPath .\dist\windows-agent-win-x64
.\scripts\install-windows-agent.ps1 -Mode validate -TargetLevel L3
.\scripts\install-windows-agent.ps1 -Mode uninstall
```

`-PlanOnly` remains as a compatibility alias for `-Mode plan`.

Install, upgrade, repair, and uninstall require an elevated PowerShell session. Validate mode is read-only, but some Security/audit-policy checks may report `unknown` without elevation.

## Default paths and preservation

Defaults:

- service: `ChallengerSiemAgent` (`Challenger SIEM Agent`)
- install path: `C:\Program Files\ChallengerSIEM\Agent`
- data/config path: `C:\ProgramData\ChallengerSIEM\Agent`
- config: `C:\ProgramData\ChallengerSIEM\Agent\agentsettings.json`
- Sysmon profile copy: `C:\ProgramData\ChallengerSIEM\Agent\sysmon\challenger-siem-sysmon-l3.xml`

The workflow preserves existing `agentsettings.json`, queue, state, and Sysmon profile copies during install/upgrade/repair. `-Mode uninstall` preserves data by default; `-RemoveData` removes config, queue, and state and should be used only in disposable labs after explicit approval.

If an existing agent service is running, upgrade/repair refuses to replace files unless `-RestartService` is supplied or the operator stops the service first.

## Windows prerequisite handling

Plan and validate are read-only. Host prerequisite mutation requires `-ConfigurePrerequisites`.

With `-ConfigurePrerequisites`, the installer applies approved L2/L3 baseline settings where supported:

- enables expected Windows Event Log channels and log-size baselines;
- configures approved advanced audit-policy subcategories;
- enables process command-line auditing;
- enables PowerShell script-block and module logging.

Noise- or privacy-sensitive audit categories such as Sensitive Privilege Use, File System, Registry, and Removable Storage are checked but not configured by default. Add `-ConfigurePrivacySensitiveAuditPolicy` only after operator approval for the added privacy/noise impact and use role-specific runbooks plus SACL-scoped policy for file-system/registry object telemetry.

## Sysmon L3 management

The versioned profile is tracked at:

```text
agent/WindowsAgent/Sysmon/challenger-siem-sysmon-l3.xml
```

The installer validates Sysmon state by default. Installing or updating Sysmon requires all of:

```powershell
-ManageSysmon `
-AcceptSysmonEula `
-SysmonSourcePath C:\Path\To\Sysmon64.exe
```

The binary must be the official Microsoft Sysinternals Sysmon executable with a valid Microsoft Authenticode signature. Add `-SysmonExpectedSha256 <sha256>` to pin an expected hash. The script does not silently fetch or run third-party binaries.

The bundled Sysmon profile covers L3 process, network/DNS, file, registry, image/driver, process-access, raw-disk, WMI, named-pipe, config-change, and error/tamper families with conservative high-risk-path and security-control targeting. Clipboard collection is intentionally not enabled.

## Validation evidence

`-Mode validate` writes aggregate status lines only, such as channel status, audit-policy drift, policy status, service status, Sysmon profile hash, and L4 role-pack follow-up markers. Keep raw command output, generated settings, tokens, logs, screenshots, and endpoint telemetry under ignored `.local/` paths.
