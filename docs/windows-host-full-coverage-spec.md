# Windows host full-coverage SIEM specification

Status: reference specification; 0.4.x foundation implemented
Specification version: 0.2
Primary audience: SIEM engineers, endpoint-agent engineers, detection engineers, operators
Applies to project release line: 0.4.x foundation and later releases

Implementation note: the generated GitHub issue backlog that originally accompanied this specification has been implemented and archived at `docs/archive/windows-host-full-coverage-github-issues-implemented.md`. This file remains the live target/reference specification for coverage semantics, source expectations, and future hardening.

## 1. Purpose

This document defines the target SIEM capability required to cover a Windows host as completely as practical with a custom endpoint agent, ingestion API, storage layer, review UI/API, and detection content.

"Full coverage" in this specification means:

1. **Collection coverage** across native Windows event logs, Sysmon when installed, Defender, PowerShell, remote-management logs, security-policy logs, host inventory, and selected high-value ETW or snapshot sources.
2. **Behavior coverage** for authentication, process execution, scripts, network, DNS, file/object access, registry changes, persistence, privilege changes, service/driver changes, security control changes, malware protection, host health, and tamper attempts.
3. **Reliability coverage** so events are durably queued, acknowledged, deduplicated, and checkpointed without silent loss under expected outages.
4. **Operational coverage** so an operator can verify source health, audit configuration, endpoint identity, queue health, event latency, data gaps, and rule status.
5. **Detection coverage** for the major Windows attack and misuse patterns a host-based SIEM sensor is expected to expose.

No host sensor can guarantee absolute visibility against a kernel-level adversary, an attacker with unrestricted local administrative control, disabled audit policy, overwritten event logs before collection, or hardware/offline attacks. This specification therefore defines the strongest practical software telemetry baseline and explicitly requires tamper and gap detection.

## 2. Coverage levels

Use these coverage levels when planning rollout, testing, and reporting endpoint posture.

| Level | Name | Required capability | Intended use |
| --- | --- | --- | --- |
| L0 | No coverage | Agent absent or not heartbeating | Not acceptable for monitored assets |
| L1 | Native baseline | Security, System, Application, agent heartbeat, durable queue | Minimal MVP collection |
| L2 | Windows security baseline | L1 plus PowerShell, Defender, Task Scheduler, WMI, RDP, WinRM, firewall/audit-policy channels, required audit policy | Practical default for workstations and servers |
| L3 | Enhanced endpoint telemetry | L2 plus Sysmon with approved configuration, DNS/network/process/file/registry enrichment, host inventory snapshots | Recommended production baseline |
| L4 | Full target coverage | L3 plus role-specific source packs, selected ETW sessions, file integrity monitoring for high-value paths, policy drift checks, detection correlation, source-health SLOs | Target state for high-value Windows hosts |

Coverage reports must identify the current level per host and list missing mandatory sources, disabled logs, failed collectors, stale heartbeats, and audit-policy drift.

## 3. Scope

### 3.1 In scope

- Windows workstation and server hosts.
- Windows Security, System, Application, PowerShell, Defender, Sysmon, remote-management, WMI, Task Scheduler, firewall, code-integrity, AppLocker/WDAC, and other native event channels.
- Optional role-specific packs for domain controllers, file servers, IIS hosts, certificate authorities, Hyper-V hosts, print servers, DNS servers, RDS hosts, and other Windows server roles.
- Host inventory snapshots and state-diff telemetry for users, groups, services, drivers, scheduled tasks, autoruns, network listeners, installed software, patches, Defender state, audit policy, and local policy.
- Agent health, queue health, source health, and tamper detection.
- Server-side ingestion, normalization, storage, search, detection, alerting, and operational review requirements.

### 3.2 Out of scope for this specification

- Network packet capture as a primary data source.
- Memory forensics, full disk forensics, and malware sandboxing.
- Non-Windows endpoint coverage.
- Proprietary EDR/SIEM product integration as a dependency.
- Domain-wide Active Directory analytics beyond host-local event collection, except where a monitored Windows host is itself a domain controller or role server.

## 4. High-level architecture

```text
Windows host
  Windows service agent
    -> event-log collectors
    -> Sysmon collector
    -> Defender collector
    -> PowerShell collector
    -> ETW collectors for selected high-value streams
    -> snapshot/diff collectors
    -> self-health and tamper collector
    -> normalization/enrichment pipeline
    -> durable local queue
    -> HTTPS batch forwarder
  Ingestion API
    -> authenticate agent
    -> validate schema
    -> deduplicate
    -> persist normalized fields and raw payload
    -> acknowledge accepted/duplicate/rejected events
  Storage and processing
    -> PostgreSQL event storage
    -> asset and source-health state
    -> detection evaluation
    -> alert and case records
  Review surfaces
    -> event search API
    -> web review console
    -> health dashboards
    -> detection/alert review
```

## 5. Endpoint-agent functional requirements

### 5.1 Service identity and permissions

| ID | Requirement |
| --- | --- |
| WHC-AGENT-001 | The agent MUST run as a Windows service with automatic start. |
| WHC-AGENT-002 | The default service identity SHOULD be LocalSystem for MVP/full Security log access unless a hardened managed service account model is implemented and validated. |
| WHC-AGENT-003 | Agent binaries, configuration, state, queue, and logs MUST be ACL-restricted to Administrators and SYSTEM. |
| WHC-AGENT-004 | Agent secrets MUST be protected at rest with Windows DPAPI or an equivalent host-bound protection mechanism. |
| WHC-AGENT-005 | The service MUST not print enrollment tokens, API tokens, private keys, raw secrets, authorization headers, or connection strings in logs. |
| WHC-AGENT-006 | The agent MUST support explicit source enable/disable configuration and MUST report disabled mandatory sources as coverage gaps. |
| WHC-AGENT-007 | The agent MUST expose local version, build, configuration hash, active collectors, queue depth, and last successful send time in heartbeat data. |

### 5.2 Collection pipeline

| ID | Requirement |
| --- | --- |
| WHC-PIPE-001 | Collectors MUST acquire events with durable bookmarks or record positions where the source supports it. |
| WHC-PIPE-002 | Events MUST be normalized before or during queue insertion and MUST retain bounded raw source data for later review. |
| WHC-PIPE-003 | The agent MUST persist events to a local durable queue before acknowledging internal collector progress. |
| WHC-PIPE-004 | The agent MUST update source bookmarks only after events are durably queued. |
| WHC-PIPE-005 | The sender MUST delete queued events only after server acknowledgement as accepted or duplicate. |
| WHC-PIPE-006 | The sender MUST retain rejected events long enough for operator diagnosis, then quarantine poison events without blocking later events. |
| WHC-PIPE-007 | The agent MUST implement bounded exponential backoff for source or transport failures. |
| WHC-PIPE-008 | The agent MUST apply backpressure when queue limits are reached and MUST emit health events before dropping or pausing collection. |
| WHC-PIPE-009 | The agent MUST detect source gaps, event-log truncation, bookmark invalidation, and record-ID rollback. |
| WHC-PIPE-010 | The agent MUST report per-source lag, last event time, last record ID/bookmark, collection errors, and enabled/disabled state. |

### 5.3 Collection methods

| Method | Required for full coverage | Notes |
| --- | --- | --- |
| Windows Event Log subscription/query | Yes | Primary source for most Windows telemetry. Uses channel bookmarks/record IDs. |
| Sysmon channel collection | Yes when Sysmon is installed or mandated | Preferred source for process, DNS, network, file, registry, and tamper details. |
| ETW session collection | Yes for L4 selected streams | Use only for high-value low-noise providers or when event logs cannot provide required details. |
| Snapshot/diff collection | Yes | Periodically captures host state that may not emit reliable events. |
| File integrity monitoring | Conditional | Required for selected high-value paths and role-specific assets. |
| Local health checks | Yes | Validates audit policy, service state, channel state, queue, clock skew, and source freshness. |

## 6. Required endpoint configuration baseline

### 6.1 Operating-system assumptions

- Windows 10/11 and Windows Server versions supported by .NET 8 and the Windows Event Log API.
- Event channels required by this document must exist or be explicitly marked as not applicable for the host role.
- Endpoint time synchronization must be enabled. Agent heartbeat must report local time and observed server time skew.
- Event log sizes must be large enough to survive expected offline windows before collection. Small default log sizes are not acceptable for L3/L4.

### 6.2 Advanced audit policy baseline

The agent must collect audit-policy state and report drift. The following policy subcategories are required unless the host role has a documented exception.

| Category | Subcategory | Success | Failure | Why it is required |
| --- | --- | --- | --- | --- |
| Account Logon | Credential Validation | Yes | Yes | NTLM/local credential validation, brute force, password spray. |
| Account Logon | Kerberos Authentication Service | Role-based | Role-based | Required on domain controllers; useful on Kerberos endpoints when available. |
| Account Logon | Kerberos Service Ticket Operations | Role-based | Role-based | Required on domain controllers for service ticket analytics. |
| Account Logon | Other Account Logon Events | Role-based | Role-based | Catches less common authentication paths. |
| Account Management | User Account Management | Yes | Yes | Local user creation, deletion, enable/disable, password reset. |
| Account Management | Security Group Management | Yes | Yes | Local Administrators and privileged group changes. |
| Account Management | Other Account Management Events | Yes | Yes | Account metadata changes not covered elsewhere. |
| Detailed Tracking | Process Creation | Yes | No | Process execution visibility. Command line must be included. |
| Detailed Tracking | Process Termination | Yes | No | Optional for high-fidelity lifecycle and ransomware investigations. |
| Detailed Tracking | DPAPI Activity | Yes | Yes | Credential/key material access indicators. |
| Detailed Tracking | PNP Activity | Yes | Yes | New device insertion and driver/device changes. |
| Logon/Logoff | Logon | Yes | Yes | Interactive, network, batch, service, RDP, cached, and unlock logons. |
| Logon/Logoff | Logoff | Yes | No | Session lifecycle. |
| Logon/Logoff | Account Lockout | Yes | Yes | Brute force and password spray outcomes. |
| Logon/Logoff | Special Logon | Yes | No | Administrative/privileged logons. |
| Logon/Logoff | Other Logon/Logoff Events | Yes | Yes | RDP reconnect/disconnect and related session events. |
| Object Access | File System | Path-scoped | Path-scoped | Required only with SACLs for high-value paths to control noise. |
| Object Access | Registry | Key-scoped | Key-scoped | Required only with SACLs for high-value keys to control noise. |
| Object Access | File Share | Role-based | Role-based | Required for file servers; optional otherwise. |
| Object Access | Detailed File Share | Role-based | Role-based | Required for high-value file shares. |
| Object Access | Filtering Platform Connection | Yes | Yes | Native firewall/network connection decisions when Sysmon/ETW is absent. |
| Object Access | Filtering Platform Packet Drop | Role-based | Yes | Firewall block visibility. |
| Object Access | Removable Storage | Yes | Yes | USB/removable media object access. |
| Policy Change | Audit Policy Change | Yes | Yes | Detect reduced visibility and tampering. |
| Policy Change | Authentication Policy Change | Yes | Yes | Domain/local authentication policy drift. |
| Policy Change | Authorization Policy Change | Yes | Yes | User rights and privilege policy drift. |
| Policy Change | MPSSVC Rule-Level Policy Change | Yes | Yes | Windows Firewall rule changes. |
| Policy Change | Filtering Platform Policy Change | Yes | Yes | Network filtering changes. |
| Privilege Use | Sensitive Privilege Use | Yes | Yes | High-risk privilege use. Tune carefully for noise. |
| System | Security State Change | Yes | Yes | Boot, shutdown, security subsystem state. |
| System | Security System Extension | Yes | Yes | Security package/extension loads. |
| System | System Integrity | Yes | Yes | Code integrity, protected process, boot integrity. |
| System | IPsec Driver | Role-based | Role-based | Required where IPsec is used. |
| System | Other System Events | Yes | Yes | Miscellaneous security-relevant host state. |

### 6.3 Required Windows policy settings

| Setting | Required value | Reason |
| --- | --- | --- |
| Include command line in process creation events | Enabled | Enriches Security 4688 process events. |
| PowerShell module logging | Enabled for all modules or approved high-value modules | Captures cmdlet and pipeline detail. |
| PowerShell script block logging | Enabled unless privacy exception approved | Captures deobfuscated script content. |
| PowerShell transcription | Optional/role-based | Useful for admin servers; high privacy impact. |
| PowerShell v2 engine | Disabled when possible | Reduces downgrade/evasion paths. |
| Windows Defender real-time protection | Enabled when Defender is the local AV | Malware and ASR telemetry. |
| Defender tamper protection | Enabled where available | Detect/prevent security control changes. |
| Windows Firewall | Enabled and logging configured | Network policy and drop/allow context. |
| AppLocker or WDAC auditing/enforcement | Role-based | Execution policy visibility. |
| Event log maximum size | Increased from defaults | Prevents overwrite during offline windows. |
| Event log retention behavior | Do not overwrite before collection target, or size appropriately | Prevents source-side data loss. |

### 6.4 Required event-log channel settings

| Requirement | Description |
| --- | --- |
| WHC-CONFIG-001 | Mandatory channels MUST be enabled or explicitly marked not applicable. |
| WHC-CONFIG-002 | Channel maximum sizes MUST be reported in heartbeat/source-health data. |
| WHC-CONFIG-003 | The agent MUST detect disabled channels and changes in enabled state. |
| WHC-CONFIG-004 | The agent MUST detect channel clear events and record the user/process if available. |
| WHC-CONFIG-005 | The agent MUST report oldest/newest record metadata to support gap analysis. |

## 7. Source inventory

### 7.1 Mandatory core channels for all Windows hosts

| Source | Channel/provider | Coverage | Minimum level |
| --- | --- | --- | --- |
| Security | `Security` | Authentication, account management, process creation, policy changes, object access, firewall auditing, log clear events | L1 |
| System | `System` | Service installs, service state, driver load failures, boot/shutdown, time changes, system errors | L1 |
| Application | `Application` | Application crashes, MSI installer, application/service-specific events | L1 |
| Agent health | Agent self-events and heartbeat | Collection health, queue health, source health, tamper signals | L1 |

### 7.2 Mandatory security baseline channels for L2+

| Source | Channel/provider | Coverage |
| --- | --- | --- |
| Windows PowerShell classic | `Windows PowerShell` | Engine lifecycle, provider lifecycle, legacy script activity. |
| PowerShell Operational | `Microsoft-Windows-PowerShell/Operational` | Script block logging, module logging, pipeline detail. |
| Defender Operational | `Microsoft-Windows-Windows Defender/Operational` | Malware detections, remediation, ASR, configuration changes. |
| Task Scheduler Operational | `Microsoft-Windows-TaskScheduler/Operational` | Task registration, updates, action starts/stops, failures. |
| WMI Activity Operational | `Microsoft-Windows-WMI-Activity/Operational` | WMI queries, consumer/provider errors, suspicious WMI activity. |
| TerminalServices LocalSessionManager | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | RDP session connect, disconnect, reconnect, logoff. |
| TerminalServices RemoteConnectionManager | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | RDP authentication and connection attempts. |
| RdpCoreTS Operational | `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` | RDP transport and protocol events. |
| WinRM Operational | `Microsoft-Windows-WinRM/Operational` | PowerShell remoting and remote-management activity. |
| Windows Firewall | `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | Firewall rule and profile changes. |
| Group Policy Operational | `Microsoft-Windows-GroupPolicy/Operational` | Policy application and drift context. |
| Code Integrity Operational | `Microsoft-Windows-CodeIntegrity/Operational` | Code integrity, blocked images, signing problems. |
| AppLocker EXE/DLL | `Microsoft-Windows-AppLocker/EXE and DLL` | Execution policy audit/block events. |
| AppLocker MSI/Script | `Microsoft-Windows-AppLocker/MSI and Script` | Script and installer policy audit/block events. |
| AppLocker packaged apps | `Microsoft-Windows-AppLocker/Packaged app-Execution` | Store/UWP packaged app policy events. |

### 7.3 Enhanced telemetry channels for L3+

| Source | Channel/provider | Coverage |
| --- | --- | --- |
| Sysmon Operational | `Microsoft-Windows-Sysmon/Operational` | High-fidelity process, network, DNS, file, registry, driver, image, WMI, pipe, clipboard, and tamper events. |
| DNS Client Operational | `Microsoft-Windows-DNS-Client/Operational` | DNS query/response behavior when enabled and available. |
| SMB Client Security/Connectivity | `Microsoft-Windows-SmbClient/Security`, `Microsoft-Windows-SmbClient/Connectivity` | SMB client authentication, connection, and access issues. |
| SMB Server Security/Operational | `Microsoft-Windows-SMBServer/Security`, `Microsoft-Windows-SMBServer/Operational` | File server and remote admin activity on hosts exposing SMB. |
| NTLM Operational | `Microsoft-Windows-NTLM/Operational` | NTLM use and failures when enabled. |
| Kerberos Operational | `Microsoft-Windows-Kerberos/Operational` | Kerberos client issues and failures where available. |
| CAPI2 Operational | `Microsoft-Windows-CAPI2/Operational` | Certificate chain validation and trust anomalies; tune for volume. |
| Certificate Services Client | `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational` and user lifecycle channels | Certificate enrollment, renewal, and trust changes. |
| BITS Client Operational | `Microsoft-Windows-Bits-Client/Operational` | Background transfer jobs used for download/exfiltration. |
| Windows Update Client Operational | `Microsoft-Windows-WindowsUpdateClient/Operational` | Patch installation and update failures. |
| PrintService Operational/Admin | `Microsoft-Windows-PrintService/Operational`, `Microsoft-Windows-PrintService/Admin` | Print job, print driver, and print service activity. |
| DriverFrameworks UserMode Operational | `Microsoft-Windows-DriverFrameworks-UserMode/Operational` | USB/device activity and driver framework events. |
| BitLocker Management | `Microsoft-Windows-BitLocker/BitLocker Management` | Encryption state and recovery events. |
| DeviceGuard Operational | `Microsoft-Windows-DeviceGuard/Operational` | Credential Guard, HVCI, WDAC and virtualization-based security state. |

### 7.4 Role-specific source packs

A host is not considered fully covered unless every installed high-value Windows role has a matching source pack enabled or an approved exception.

| Role | Required additional sources |
| --- | --- |
| Domain controller | Directory Service, DNS Server, DFS Replication, File Replication Service if present, Kerberos Key Distribution Center, AD Web Services, Security account logon/account management categories, SYSVOL file integrity monitoring. |
| File server | SMB Server channels, Security object access for high-value shares, shadow copy events, FSRM if used, share configuration snapshots, file integrity monitoring for sensitive directories. |
| IIS/web server | IIS W3C request logs, IIS configuration changes, HTTPERR logs if available, Windows Process Activation Service, application pool identity and recycle events. |
| Certificate authority | AD CS service logs, CA database/audit events, certificate template changes, key archival/recovery events, CAPI2, certificate enrollment channels. |
| Hyper-V host | Hyper-V VMMS/Admin, Hyper-V Worker/Admin, Hyper-V Hypervisor/Admin, virtual switch events, VM inventory snapshots. |
| RDS/session host | TerminalServices channels, user profile service logs, RDS licensing where applicable, session inventory snapshots. |
| DNS server | DNS Server audit/analytical logs as approved, DNS service logs, zone/record change tracking. |
| DHCP server | DHCP Server audit logs and service logs, scope configuration snapshots. |
| Print server | PrintService Admin/Operational, print driver install events, spooler service changes. |
| SQL Server host | SQL Server error logs and audit logs if SQL Server is installed, service account/configuration snapshots. |
| OpenSSH server/client | OpenSSH Operational/Admin logs if installed, service configuration snapshots. |

## 8. Detailed signal requirements

### 8.1 Authentication and session visibility

| ID | Requirement |
| --- | --- |
| WHC-AUTH-001 | Collect successful and failed logons with user, domain, SID, logon type, authentication package, source IP, source hostname, workstation name, target host, process name, status/substatus, and logon ID when available. |
| WHC-AUTH-002 | Distinguish interactive, network, batch, service, unlock, cleartext/network-cleartext, new credentials, remote interactive/RDP, cached interactive, and remote credential guard logon types. |
| WHC-AUTH-003 | Capture privileged logons and assigned privileges. |
| WHC-AUTH-004 | Capture logoff, session disconnect, reconnect, lock, and unlock events. |
| WHC-AUTH-005 | Detect impossible or suspicious patterns: brute force, password spray, repeated account lockouts, disabled account use, expired password use, RDP from unusual source, remote logon by local admin, and service account interactive logon. |
| WHC-AUTH-006 | Capture local and domain credential validation events where emitted by the host. |

High-value native event IDs include: `4624`, `4625`, `4634`, `4647`, `4648`, `4672`, `4776`, `4778`, `4779`, `4800`, `4801`, and domain-controller Kerberos events when the monitored host is a domain controller.

### 8.2 Account, group, and privilege changes

| ID | Requirement |
| --- | --- |
| WHC-ID-001 | Capture local user creation, deletion, enable, disable, password change, password reset, rename, and property changes. |
| WHC-ID-002 | Capture additions/removals to local Administrators, Remote Desktop Users, Backup Operators, Event Log Readers, and other privileged groups. |
| WHC-ID-003 | Snapshot local users and local groups at enrollment and periodically thereafter. |
| WHC-ID-004 | Capture user-rights assignment and local security policy changes. |
| WHC-ID-005 | Preserve subject actor, target account/group, changed attributes, and outcome. |

High-value native event IDs include: `4720`, `4722`, `4723`, `4724`, `4725`, `4726`, `4732`, `4733`, `4738`, `4740`, `4756`, `4757`, `4781`, `4798`, `4799`, and related domain events on domain controllers.

### 8.3 Process and execution visibility

| ID | Requirement |
| --- | --- |
| WHC-PROC-001 | Capture process start with executable path, command line, parent process, user, session/logon ID, integrity level, elevation/token context, current directory, hashes, signer, original file name, and product/company metadata when available. |
| WHC-PROC-002 | Capture process termination when available or when high-value process lifecycle tracking is enabled. |
| WHC-PROC-003 | Generate stable process entity identifiers that can correlate Security 4688, Sysmon process GUIDs, ETW process IDs, network connections, file writes, and script events. |
| WHC-PROC-004 | Capture image loads and driver loads for high-risk paths, unsigned code, vulnerable drivers, and protected processes when enabled. |
| WHC-PROC-005 | Detect unusual parent/child relationships, LOLBin execution, suspicious command lines, process hollowing/tampering, remote thread creation, suspicious handle access, LSASS access, and execution from user-writable locations. |

Primary sources: Security `4688`/`4689`, Sysmon process/image/driver/process-access events, Code Integrity, AppLocker/WDAC, and selected ETW process providers.

### 8.4 PowerShell, script, and interpreter visibility

| ID | Requirement |
| --- | --- |
| WHC-SCRIPT-001 | Capture PowerShell engine starts/stops, host application, version, runspace/pipeline IDs, user, and host process. |
| WHC-SCRIPT-002 | Capture module logging and script block logging with deobfuscated script content when enabled. |
| WHC-SCRIPT-003 | Capture encoded commands, download cradle patterns, reflection, AMSI bypass indicators, execution policy bypass, hidden windows, remote sessions, and constrained language mode changes. |
| WHC-SCRIPT-004 | Capture activity from common interpreters and scripting engines through process telemetry: `powershell.exe`, `pwsh.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `msbuild.exe`, `installutil.exe`, `python.exe`, and similar. |
| WHC-SCRIPT-005 | Redact or protect script content according to privacy policy while preserving detection-relevant metadata and hashes. |

High-value PowerShell events include classic engine lifecycle events and Operational channel events such as module and script-block logging events.

### 8.5 Network, DNS, and remote-management visibility

| ID | Requirement |
| --- | --- |
| WHC-NET-001 | Capture outbound and inbound network connections with process, user, protocol, source/destination IP, source/destination port, direction, action, and transport metadata when available. |
| WHC-NET-002 | Capture DNS queries with process correlation where possible, query name, query type, result, response codes, and resolved IPs when available. |
| WHC-NET-003 | Capture Windows Firewall rule/profile changes, connection allows/blocks, and packet drops according to noise budget. |
| WHC-NET-004 | Capture RDP, WinRM, SMB, WMI, and remote-service activity with source host/IP and authenticated account. |
| WHC-NET-005 | Detect suspicious remote management, lateral movement, unusual external destinations, new listeners, uncommon ports, C2-like beaconing, DNS tunneling indicators, and large data-transfer anomalies. |

Primary sources: Sysmon network/DNS events, Security Filtering Platform events, DNS Client, WinRM, TerminalServices, SMB Client/Server, Windows Firewall, BITS, and selected ETW network providers.

### 8.6 File, object, and removable-media visibility

| ID | Requirement |
| --- | --- |
| WHC-FILE-001 | Capture file creation, deletion, rename, stream creation, and timestamp changes for high-risk paths and executable/script content. |
| WHC-FILE-002 | Capture object access for high-value files/directories using SACLs rather than broad noisy auditing. |
| WHC-FILE-003 | Capture executable drops in user-writable paths, startup folders, temporary directories, downloads, web roots, administrative shares, and service/task directories. |
| WHC-FILE-004 | Capture alternate data stream creation and Zone.Identifier/mark-of-the-web where available. |
| WHC-FILE-005 | Capture removable media insertion/access and file movement to/from removable storage where policy permits. |
| WHC-FILE-006 | Capture mass file modifications, suspicious extension changes, shadow copy deletion commands, and ransomware-like behavior. |

Primary sources: Sysmon file events, Security object access events with SACLs, DriverFrameworks, removable storage auditing, Application/System service events, and file integrity monitoring.

### 8.7 Registry and configuration visibility

| ID | Requirement |
| --- | --- |
| WHC-REG-001 | Capture registry key/value creation, deletion, rename, and modification for high-risk persistence, security-control, and policy locations. |
| WHC-REG-002 | Capture changes to Run/RunOnce keys, services, drivers, Image File Execution Options, Winlogon, AppInit DLLs, LSA providers, firewall policy, Defender policy, RDP settings, PowerShell policy, UAC policy, and certificate trust stores. |
| WHC-REG-003 | Use snapshots/diffs for high-value keys that do not reliably emit events. |
| WHC-REG-004 | Preserve actor process/user, key path, value name, value type, old/new value when safe, and outcome. |

Primary sources: Sysmon registry events, Security registry object access with SACLs, GroupPolicy, Defender, Windows Firewall, and snapshot collectors.

### 8.8 Persistence mechanisms

| ID | Requirement |
| --- | --- |
| WHC-PERSIST-001 | Capture service creation, deletion, binary path changes, start type changes, and service account changes. |
| WHC-PERSIST-002 | Capture driver installation/load, unsigned driver load attempts, and vulnerable driver indicators. |
| WHC-PERSIST-003 | Capture scheduled task registration, deletion, update, enable/disable, action execution, and failure. |
| WHC-PERSIST-004 | Capture WMI event filters, consumers, and filter-to-consumer bindings. |
| WHC-PERSIST-005 | Capture startup folder, autorun, logon script, shell extension, browser extension, Office add-in, and service DLL persistence through file/registry/snapshot telemetry. |

High-value native event IDs include service install events (`4697`, System service-control-manager events such as service installation), scheduled task events (`4698`, `4699`, `4700`, `4701`, `4702`), and Sysmon WMI/service/registry/file events.

### 8.9 Security controls, audit policy, and tamper visibility

| ID | Requirement |
| --- | --- |
| WHC-TAMPER-001 | Capture event-log clear, service stop, audit-policy change, channel disable, source collection errors, and log overwrite/gap conditions. |
| WHC-TAMPER-002 | Capture Defender disablement, tamper-protection events, exclusion changes, ASR changes, real-time protection changes, and remediation failures. |
| WHC-TAMPER-003 | Capture firewall disablement, rule changes, profile changes, and filtering platform policy changes. |
| WHC-TAMPER-004 | Capture Sysmon configuration changes, service state changes, and driver/service errors. |
| WHC-TAMPER-005 | Capture agent binary/config changes, agent service stop/start, queue deletion attempts, local ACL drift, and token/config read failures. |
| WHC-TAMPER-006 | Server MUST alert on stale heartbeat, source silence, sudden event-rate drop, repeated authentication failures from an agent, and unexpected agent version/config changes. |

High-value native event IDs include `1102`, `4719`, `4902`, Windows Firewall policy events, Defender configuration events, and agent self-events.

### 8.10 Malware protection and exploit prevention visibility

| ID | Requirement |
| --- | --- |
| WHC-MAL-001 | Capture malware detections, remediation actions, remediation failures, quarantine events, scan results, ASR blocks/audits, exploit protection events, and security intelligence update failures. |
| WHC-MAL-002 | Normalize threat name, severity, category, affected file/process/user, action taken, remediation status, and engine/signature versions. |
| WHC-MAL-003 | Detect Defender disabled/tampered, repeated remediation failures, malware found in high-value paths, and blocked credential theft behavior. |

Primary source: Microsoft Defender Operational channel plus Defender configuration snapshots where available.

### 8.11 Software, patch, and asset inventory visibility

| ID | Requirement |
| --- | --- |
| WHC-ASSET-001 | Capture host identity: hostname, FQDN, domain/workgroup, machine GUID, OS edition/version/build, architecture, install date, boot time, time zone, IP/MAC addresses, and primary users when available. |
| WHC-ASSET-002 | Snapshot installed software, Windows features/roles, services, drivers, scheduled tasks, local users/groups, startup entries, firewall profiles, Defender state, BitLocker state, and patch state. |
| WHC-ASSET-003 | Capture software install/update/uninstall events from MSI Installer, Windows Update, package managers where visible, and role-specific installers. |
| WHC-ASSET-004 | Maintain current asset state server-side and retain historical state changes. |

### 8.12 Role-specific visibility

| ID | Requirement |
| --- | --- |
| WHC-ROLE-001 | The agent MUST detect installed Windows roles/features and recommend or auto-enable applicable role source packs. |
| WHC-ROLE-002 | The server MUST store role/source-pack applicability and show missing role telemetry as coverage gaps. |
| WHC-ROLE-003 | Role packs MUST include source inventory, required audit policy, parsing, normalization, detections, and validation tests. |

## 9. Sysmon target requirements

Sysmon is not a substitute for Security logs, but full host coverage requires a high-quality Sysmon configuration where policy allows it.

| Sysmon capability | Required for full coverage | Notes |
| --- | --- | --- |
| Process creation | Yes | Include command line, hashes, parent, user, process GUID. |
| File creation time changes | Yes | Timestamp tampering indicators. |
| Network connections | Yes | Include process correlation. |
| Process termination | Optional | Useful for lifecycle; can increase volume. |
| Driver loaded | Yes | Unsigned/vulnerable drivers. |
| Image loaded | Targeted | Tune heavily; high volume. |
| Create remote thread | Yes | Injection/lateral movement indicators. |
| Raw disk access | Yes | Credential dumping/disk tampering. |
| Process access | Yes, targeted | LSASS/process dumping; tune to avoid volume. |
| File create | Yes, targeted | Executables/scripts/high-risk paths. |
| Registry events | Yes, targeted | Persistence and security-control keys. |
| Alternate data streams | Yes | Mark-of-the-web/evasion. |
| Named pipe events | Yes, targeted | Lateral movement tools and C2. |
| WMI events | Yes | Permanent event subscription persistence. |
| DNS query | Yes | Process-correlated DNS. |
| File delete/archive | Targeted | Ransomware/malware cleanup. |
| Clipboard/change/tamper events | Policy-based | Useful but privacy-sensitive; disable or restrict unless approved. |
| Sysmon configuration change | Yes | Detect telemetry reduction. |

Sysmon configuration requirements:

- Include, exclude, and rule names must be versioned.
- Configuration hash and version must be reported by the agent.
- Configuration changes must generate events and server-side alerts.
- Rules must avoid broad image-load/file/registry collection without include filters.
- Rules must preserve enough detail for process, DNS, network, file, registry, WMI, and tamper detections.

## 10. Normalization specification

### 10.1 Core event envelope

All collected telemetry MUST be normalized to a common envelope with these concepts. The current v1 contract can carry many source-specific values in `raw`; future contract revisions should add structured objects additively where possible.

| Field group | Required fields |
| --- | --- |
| Event identity | `event_id`, `source`, `channel`, `provider`, `record_id` or source equivalent, `event_code`, `event_action`, `event_category`, `event_type`, `event_outcome`, `severity`, `message`. |
| Time | `event_time`, `ingest_time`, `agent_observed_time`, optional `source_created_time`, clock-skew metadata. |
| Host | `agent_id`, `hostname`, `fqdn`, `domain`, `machine_guid`, `os_name`, `os_version`, `ip_addresses`, `mac_addresses`. |
| User | `user.name`, `user.domain`, `user.sid`, `user.id`, `user.type`, `user.logon_id`, `user.effective_privileges`. |
| Process | `process.entity_id`, `pid`, `parent_pid`, `image`, `command_line`, `working_directory`, `hashes`, `signer`, `integrity_level`, `elevation`, `session_id`. |
| File | `file.path`, `file.name`, `file.extension`, `file.directory`, `file.hashes`, `file.size`, `file.created`, `file.modified`, `file.zone_id`, `file.signature`. |
| Registry | `registry.key`, `registry.value_name`, `registry.value_type`, `registry.value_data`, `registry.operation`. |
| Network | `network.direction`, `transport`, `protocol`, `source.ip`, `source.port`, `destination.ip`, `destination.port`, `destination.domain`, `dns.question.name`, `dns.answers`. |
| Service/task/WMI | Service name/display/binary/account/start type; task name/path/actions/triggers; WMI namespace/filter/consumer/binding. |
| Security control | Defender/threat details, firewall profile/rule, audit policy, AppLocker/WDAC decision, code-integrity status. |
| Raw | Original event XML/rendered fields/source payload in bounded JSON. |

### 10.2 Event identity and deduplication

| ID | Requirement |
| --- | --- |
| WHC-NORM-001 | Event IDs MUST be deterministic for event-log records and stable across retry. |
| WHC-NORM-002 | Deduplication MUST include agent ID and normalized event ID. |
| WHC-NORM-003 | Event-log records SHOULD derive identity from agent ID, channel, provider, record ID, event ID/code, and event time. |
| WHC-NORM-004 | Snapshot diff events SHOULD derive identity from agent ID, snapshot type, object key, change type, and effective time/version. |
| WHC-NORM-005 | ETW events MUST include a collector-generated sequence/checkpoint value when the provider lacks durable record IDs. |

### 10.3 Severity and outcome normalization

| Source value | Normalized severity |
| --- | --- |
| Windows Critical | critical |
| Windows Error | error |
| Windows Warning | warning |
| Windows Information/Verbose | information |
| Security audit success | information with outcome `success` |
| Security audit failure | warning or error with outcome `failure`, depending on event type |
| Defender malware detected | error or critical based on threat severity/action |
| Detection alert | low/medium/high/critical according to rule severity |

### 10.4 Raw payload handling

| ID | Requirement |
| --- | --- |
| WHC-RAW-001 | Raw source data MUST be preserved enough to re-render or re-parse important fields. |
| WHC-RAW-002 | Raw payloads MUST be bounded by configured size limits. Oversized payloads must be truncated with explicit metadata. |
| WHC-RAW-003 | Raw payloads MUST NOT include agent secrets, authorization headers, enrollment tokens, or local private keys. |
| WHC-RAW-004 | Script content and command lines are sensitive and MUST be protected by access controls and optional redaction policies. |
| WHC-RAW-005 | The original Windows event record XML SHOULD be preserved for event-log sources when feasible. |

## 11. Ingestion API requirements

| ID | Requirement |
| --- | --- |
| WHC-API-001 | Agents MUST authenticate with a per-agent token or stronger mechanism after enrollment. |
| WHC-API-002 | Enrollment MUST require a temporary enrollment token and MUST return a unique per-agent credential. |
| WHC-API-003 | All non-development traffic MUST use HTTPS. Future high-assurance deployments SHOULD support mTLS. |
| WHC-API-004 | Ingest requests MUST include `agent_id`, `batch_id`, `sent_at`, and one or more events. |
| WHC-API-005 | Server MUST validate schema, agent identity, event count, event size, timestamp sanity, required fields, and source authorization. |
| WHC-API-006 | Server MUST deduplicate by `(agent_id, event_id)` and return accepted, duplicate, and rejected event IDs. |
| WHC-API-007 | Server MUST persist authenticated validation failures in a bounded secret-safe error table. |
| WHC-API-008 | Server MUST reject events claiming a different `agent_id` than the authenticated agent. |
| WHC-API-009 | Server MUST rate-limit abusive agents while preserving clear operator diagnostics. |
| WHC-API-010 | API responses MUST not echo secrets or unbounded raw event data. |

## 12. Storage and indexing requirements

### 12.1 Event storage

| ID | Requirement |
| --- | --- |
| WHC-STORE-001 | Store normalized searchable columns plus raw JSON payload. |
| WHC-STORE-002 | Partition large event tables by ingest time or event time for retention and query performance. |
| WHC-STORE-003 | Index agent, host, time, channel/source, provider, event code, user, process image, destination IP/domain, file path, registry key, severity, outcome, and detection fields as they become structured. |
| WHC-STORE-004 | Preserve server ingest time separately from endpoint event time. |
| WHC-STORE-005 | Store source-health records separate from event records. |
| WHC-STORE-006 | Store asset inventory current state and historical changes. |
| WHC-STORE-007 | Store detection alerts separately from raw events and link alerts to evidence event IDs. |

### 12.2 Suggested logical tables beyond the MVP

| Table | Purpose |
| --- | --- |
| `agents` | Registered endpoints and token metadata. |
| `agent_source_health` | Per-channel/per-collector status, lag, errors, and freshness. |
| `events` | Primary normalized event store. |
| `event_entities` | Optional entity extraction for users, processes, files, registry keys, IPs, domains. |
| `asset_inventory_current` | Current host state. |
| `asset_inventory_changes` | Historical snapshot diff events. |
| `detections` | Detection rule metadata and versions. |
| `alerts` | Detection outcomes and lifecycle status. |
| `alert_evidence` | Event IDs and entity references supporting alerts. |
| `ingestion_errors` | Authenticated validation failures. |
| `coverage_exceptions` | Approved source/audit-policy exceptions. |

### 12.3 Retention requirements

| Data type | Minimum recommended hot retention | Notes |
| --- | --- | --- |
| Security/authentication/process events | 90 days | Longer for regulated/high-value environments. |
| Sysmon process/network/DNS/file/registry | 30-90 days | Depends on volume and cost. |
| Defender and security-control events | 180 days | Useful for incident timelines. |
| Asset inventory current state | Current plus full history of changes | Low volume. |
| Alerts/cases | 1 year or policy-defined | Operator-visible audit trail. |
| Agent health/source health | 90 days | Supports coverage reporting and incident validation. |
| Raw payloads | Same as event or shorter with structured retention | Must align with privacy policy. |

## 13. Search and review requirements

| ID | Requirement |
| --- | --- |
| WHC-SEARCH-001 | Operators MUST be able to search by time range, host, agent, source/channel, provider, event code, severity, outcome, user, process, file path, registry key, source/destination IP, domain, keyword, and detection rule. |
| WHC-SEARCH-002 | Event detail MUST show normalized fields, raw JSON/XML, related process/user/network/file entities, and acknowledgement/ingest metadata. |
| WHC-SEARCH-003 | Host detail MUST show coverage level, source-health status, queue status, audit-policy status, OS/build, role packs, and recent high-severity events. |
| WHC-SEARCH-004 | Source-health views MUST show stale channels, disabled channels, collection errors, log clears, record gaps, oldest/newest record age, and event rates. |
| WHC-SEARCH-005 | Alert detail MUST show detection logic version, severity, confidence, evidence events, related entities, timeline, and analyst status. |
| WHC-SEARCH-006 | Search APIs MUST enforce maximum limits, paging, authorization, and bounded keyword queries. |

## 14. Detection-content specification

### 14.1 Detection rule metadata

Each detection rule MUST include:

- Stable rule ID.
- Name and description.
- Version and last updated date.
- Severity and confidence.
- Required data sources and minimum coverage level.
- Query/correlation logic.
- Suppression/tuning parameters.
- Evidence fields to retain.
- False-positive notes.
- Response guidance.
- Mapping to broad tactics such as initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, and impact.

### 14.2 Required detection families

| Family | Example detections | Required sources |
| --- | --- | --- |
| Authentication attacks | Password spray, brute force, disabled account use, expired account use, unusual RDP/WinRM logon, local admin remote logon, service account interactive logon | Security, TerminalServices, WinRM, source IP enrichment |
| Privilege and account changes | New local admin, privileged group membership change, new local user, password reset by unusual actor, user-rights assignment change | Security, local users/groups snapshot |
| Execution and LOLBins | Suspicious PowerShell, encoded command, suspicious `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, `wmic`, Office spawning script/interpreter | Security 4688, Sysmon process, PowerShell |
| Credential access | LSASS access, suspicious minidump creation, SAM/SYSTEM hive access, DPAPI abuse, credential manager access, suspicious handle access | Sysmon process access/file, Security object access, process telemetry |
| Persistence | New service, service binary path change, scheduled task created/updated, Run key change, WMI permanent event subscription, startup folder executable | Security/System, TaskScheduler, Sysmon registry/file/WMI, snapshots |
| Defense evasion | Event log cleared, audit policy changed, Defender disabled/exclusion added, Sysmon config changed, firewall disabled, PowerShell logging disabled, agent stopped | Security, Defender, Sysmon, firewall, agent health |
| Lateral movement | PsExec-like service creation, remote scheduled task, WinRM remoting, WMI remote execution, SMB admin share access, RDP from unusual host | Security, System, WinRM, WMI, SMB, TerminalServices, Sysmon |
| Malware and exploit prevention | Defender malware detection, ASR block, exploit protection hit, repeated remediation failure, malware in startup path | Defender, Sysmon file/process |
| Network/C2 | Unusual external destination, new listener, rare domain, suspicious DNS patterns, high-frequency beaconing, DNS tunneling indicators | Sysmon network/DNS, DNS Client, firewall, BITS |
| Ransomware/impact | Mass file modifications, shadow copy deletion, backup service stop, suspicious encryption tooling, high-rate file rename/delete | Sysmon file/process, Security object access, System service events |
| Data staging/exfiltration | Archive creation in sensitive directories, large outbound transfer, BITS job to external endpoint, unusual cloud upload process | Process/file/network/BITS telemetry |
| Policy and compliance drift | Audit policy disabled, log size reduced, channel disabled, missing Sysmon/Defender, stale source, patch/Defender signatures outdated | Source health, snapshots, Defender, Windows Update |

### 14.3 Detection execution requirements

| ID | Requirement |
| --- | --- |
| WHC-DETECT-001 | Detections MUST declare required source coverage and MUST mark results as low-confidence if prerequisite telemetry is missing. |
| WHC-DETECT-002 | Detections MUST avoid relying solely on rendered message strings when structured fields are available. |
| WHC-DETECT-003 | Correlation windows MUST be explicit and configurable. |
| WHC-DETECT-004 | Rules MUST support suppression by host, user, process, path, hash, IP/domain, and approved maintenance window. |
| WHC-DETECT-005 | Alerts MUST retain evidence event IDs and the exact rule version that fired. |
| WHC-DETECT-006 | Detection testing MUST include positive and negative synthetic fixtures with fake hostnames/users/IPs. |

## 15. Agent/source health specification

### 15.1 Heartbeat fields

Agent heartbeat MUST include:

- Agent ID, hostname, FQDN, machine GUID.
- Agent version and configuration hash.
- OS name/version/build, boot time, time zone.
- Service account identity type.
- Queue depth, oldest queued event age, poison event count, disk usage, backoff state.
- Last successful registration, heartbeat, ingest send, and acknowledgement times.
- Collector list with enabled state, last event time, last collection time, lag, error count, last error code, last record ID/bookmark summary, channel enabled state, and oldest/newest source record age where available.
- Source coverage level and missing mandatory sources.
- Audit policy hash/status and drift summary.
- Sysmon/Defender/PowerShell/firewall state summary.

### 15.2 Server-side health rules

| Condition | Required status/alert |
| --- | --- |
| No heartbeat within expected interval | Host stale; alert by criticality. |
| Source stale while host heartbeat is fresh | Collector/source issue. |
| Event rate drops to near zero unexpectedly | Possible telemetry loss or quiet host; investigate with source health. |
| Channel disabled | Coverage gap; high severity for Security/Sysmon/Defender/PowerShell. |
| Event log cleared | High severity tamper event. |
| Bookmark invalid/record gap | Data-loss risk; show gap interval. |
| Queue growing or oldest queued age exceeds SLO | Ingestion/network/server issue. |
| Poison events present | Schema/parser compatibility issue. |
| Audit policy drift | Coverage downgrade and compliance finding. |
| Agent version/config unexpected | Possible unauthorized change or rollout drift. |

## 16. Security and privacy requirements

| ID | Requirement |
| --- | --- |
| WHC-SEC-001 | Production transport MUST use HTTPS with modern TLS settings. |
| WHC-SEC-002 | Enrollment tokens MUST be temporary, revocable, and never stored in logs. |
| WHC-SEC-003 | Per-agent tokens MUST be stored hashed server-side and protected endpoint-side. |
| WHC-SEC-004 | Operators MUST authenticate separately from agents and MUST not use agent credentials. |
| WHC-SEC-005 | Role-based access control SHOULD separate event review, alert management, admin/configuration, and secret management. |
| WHC-SEC-006 | Raw script content, command lines, file paths, usernames, IPs, and hostnames MUST be treated as sensitive telemetry. |
| WHC-SEC-007 | The system MUST support redaction or field-level access restrictions for script content and raw payloads. |
| WHC-SEC-008 | Logs produced by the server and agent MUST be secret-safe and bounded. |
| WHC-SEC-009 | Agent update packages SHOULD be signed and versioned; the agent SHOULD verify update authenticity before applying updates. |
| WHC-SEC-010 | Server backups MUST protect event data and credentials according to the same sensitivity as production storage. |

## 17. Performance and scale requirements

| Area | Target requirement |
| --- | --- |
| Endpoint CPU | Average under 2% on typical workstation; short bursts allowed during backlog catch-up. |
| Endpoint memory | Under 250 MB steady state for baseline collectors unless ETW/high-volume role packs are enabled. |
| Endpoint disk queue | Configurable; default large enough for at least 24 hours of normal workstation telemetry. |
| Event latency | 95% of events ingested within 60 seconds when network/server are healthy. |
| Offline tolerance | No data loss during network outage while queue disk capacity remains available and source logs are not overwritten. |
| Batch size | Configurable event count and byte limits; server enforces maximum payload size. |
| Backlog catch-up | Throttled to avoid endpoint/server overload. |
| Workstation event rate | Design for normal 5-50 EPS bursts with lower average. |
| Server event rate | Role-based; file servers, domain controllers, and ETW-heavy hosts require separate sizing. |
| Search latency | Recent filtered searches should complete in seconds with proper indexes and bounded limits. |

## 18. Validation and acceptance criteria

### 18.1 Host coverage acceptance

A Windows host reaches L4 full target coverage only when all of the following are true:

1. Agent installed, enrolled, heartbeating, and running the approved version/configuration.
2. Mandatory L1/L2 channels enabled and actively collected.
3. Sysmon installed/configured or formally excepted.
4. Defender/PowerShell/firewall/audit-policy state meets baseline or has approved exceptions.
5. Applicable role source packs are enabled and active.
6. Host inventory snapshot is current.
7. Source-health data shows no stale mandatory collectors.
8. Queue depth and oldest queued event age are within SLO.
9. Last validation test confirms key event types are searchable in the SIEM.
10. Server-side coverage report shows no unapproved gaps.

### 18.2 Source validation tests

Validation must use controlled lab-safe actions or synthetic fixtures and avoid clearing event logs or deleting operator data unless explicitly approved in a disposable lab.

| Test area | Acceptance evidence |
| --- | --- |
| Registration and heartbeat | New/updated agent visible with current version/config hash and queue metrics. |
| Security log | Successful logon/process/audit-policy test events collected and searchable. |
| System log | Service state/install test event collected in controlled lab. |
| Application log | Synthetic application event collected. |
| PowerShell | Benign script-block/module event collected with expected user/process fields. |
| Defender | Defender state/config visible; test detections only in approved lab using safe mechanisms. |
| Sysmon | Process, network/DNS, file, registry, and config-change test events collected according to config. |
| Task Scheduler | Benign task registration/update/deletion visible in controlled lab. |
| WMI | Benign WMI query/activity visible; permanent consumer tests only in lab. |
| RDP/WinRM | Successful and failed remote-management events visible in authorized lab. |
| Firewall | Rule/profile change or allow/block event visible in controlled lab. |
| Queue/retry | Server outage test proves local queue growth and later drain without duplicates/loss. |
| Source gap | Disabled-channel or stale-source simulation produces coverage warning. |

### 18.3 Release acceptance for this capability

| ID | Criterion |
| --- | --- |
| WHC-ACCEPT-001 | Unit tests cover normalization for each mandatory source family. |
| WHC-ACCEPT-002 | Integration tests cover ingest validation, deduplication, partial acknowledgement, ingestion errors, search, and source health. |
| WHC-ACCEPT-003 | Windows lab validation covers at least one real Windows endpoint for L2 and one Sysmon-enabled endpoint for L3. |
| WHC-ACCEPT-004 | Documentation includes installation, audit-policy configuration, Sysmon configuration, privacy controls, validation, and troubleshooting. |
| WHC-ACCEPT-005 | Operators can view host coverage level and missing sources from the web console/API. |
| WHC-ACCEPT-006 | Detections declare missing-source confidence impacts. |
| WHC-ACCEPT-007 | No secrets or real endpoint telemetry are committed as fixtures; tests use synthetic/fake data. |

## 19. Implementation status for this repository

### Implemented foundation

The 0.4.x foundation implemented the original Phase A-D backlog at a practical skeleton/foundation level:

- configurable L2/L3 source manifests and default channels;
- heartbeat source-health reporting with source status, coverage level, record range, log size, gap/clear indicators, queue SLO metrics, configuration hash, and tamper summary fields;
- PostgreSQL storage and review APIs for source health, coverage summaries, inventory snapshots, detection rule metadata, alerts, alert evidence, and expanded event-search filters;
- web coverage summary, host/source-health detail, alert list/detail, and audit-policy drift review pages;
- parser/normalization catalogs and synthetic fixtures for mandatory L2 sources plus Sysmon L3 event groups;
- audit-policy, PowerShell logging policy, process command-line policy, security-control, role-detection, and role-pack design helpers/docs;
- detection metadata, detection-engine skeleton, alert/evidence schema, and coverage-aware prerequisite handling;
- DPAPI protected-token support, raw/script/command-line redaction policy, mTLS readiness design, agent binary/config hash telemetry, validation runbooks, and Windows role-pack designs.

### Remaining target work

This specification still describes deeper target capabilities beyond the foundation:

- production-grade collector implementations for every inventory/diff source rather than design/skeleton helpers;
- richer field extraction directly from structured event payloads for every parser group;
- Sysmon configuration management and process/entity correlation depth;
- full detection evaluation, alert lifecycle/triage mutations, backtesting, and approved detection activation;
- operator accounts/RBAC and field-level access controls;
- selected ETW collectors, file integrity monitoring, and higher-assurance agent self-protection;
- production TLS/mTLS rollout decisions, release packaging/signing, and upgrade/migration guidance.

## 20. Current project status summary

The current project includes Windows Event Log collection, source-health coverage reporting, normalized/searchable event fields, durable queueing, enrollment, per-agent tokens, ingestion API, PostgreSQL storage, deduplication, heartbeat, review APIs, alert/detection/inventory skeletons, web review console, and a local `soc-agent` workspace.

Use the live operational docs for current behavior:

- `docs/agent.md`
- `docs/api.md`
- `docs/schema.md`
- `docs/web.md`
- `docs/soc-agent.md`
- `docs/security-hardening-roadmap.md`
- `docs/windows-l2-validation-runbook.md`
- `docs/sysmon-l3-validation-runbook.md`
- `docs/windows-role-packs.md`

## Appendix A: High-value Windows event IDs

This appendix is a planning checklist, not an exhaustive parser contract. Parsers must rely on provider metadata and structured event fields rather than message text when possible.

| Area | Common event IDs |
| --- | --- |
| Logon/session | `4624`, `4625`, `4634`, `4647`, `4648`, `4672`, `4776`, `4778`, `4779`, `4800`, `4801` |
| Process/object | `4656`, `4660`, `4663`, `4688`, `4689`, `4690`, `4657` |
| Services/tasks | `4697`, `4698`, `4699`, `4700`, `4701`, `4702`, System service-control-manager service install/start/stop events |
| Account management | `4720`, `4722`, `4723`, `4724`, `4725`, `4726`, `4728`, `4729`, `4732`, `4733`, `4738`, `4740`, `4756`, `4757`, `4781`, `4798`, `4799` |
| Policy/security changes | `4616`, `4719`, `4739`, `4902`, `4904`, `4905` |
| Firewall/filtering | `4946`-`4958`, `5031`, `5152`-`5159` |
| Event log/audit health | `1100`, `1101`, `1102`, `1104`, `1105` where available |
| Defender | Malware detection/remediation/configuration/ASR events from Defender Operational channel, including detection, remediation, failure, tamper/configuration, and ASR audit/block families |
| PowerShell | Engine lifecycle, provider lifecycle, module logging, and script-block logging events from classic and Operational PowerShell channels |
| Sysmon | Process, file-time, network, service-state, process-terminate, driver, image-load, remote-thread, raw-access, process-access, file-create, registry, alternate-stream, config-change, pipe, WMI, DNS, file-delete, clipboard, and tamper families |

## Appendix B: Minimum normalized parser coverage by source

| Source | Parser must extract at minimum |
| --- | --- |
| Security logon | Subject user, target user, logon type, auth package, source IP/host, workstation, process, status/substatus, logon ID, outcome. |
| Security process | New process path, command line, parent process, creator user, token/elevation fields, integrity level where present. |
| Security account/group | Actor, target account/group, changed attribute, operation, outcome. |
| System service | Service name, display name, binary path when present, account, start type, action, outcome. |
| PowerShell | Host application, engine version, runspace/pipeline/script block ID, script/module content or hash, user, process. |
| Defender | Threat name/category/severity, resource path/process/user, action, remediation status, engine/signature version. |
| Sysmon process | Process GUID, image, command line, parent, user, hashes, signer, integrity level, logon GUID/session. |
| Sysmon network/DNS | Process GUID/image/user, source/destination IP/port, protocol, query name/type/results. |
| Sysmon file/registry | Process GUID/image/user, object path/key/value, operation, hashes/metadata when present. |
| TaskScheduler | Task name/path, author/user, actions, triggers, change type, result code. |
| WMI | Namespace, query, consumer/filter/binding, process ID, user, client machine where present. |
| RDP/WinRM/SMB | Source host/IP, target host, account, session ID, auth result, protocol/transport, failure reason. |
| Firewall | Rule/profile/action/direction/protocol/ports/app path/source/destination and actor when present. |

## Appendix C: Open design decisions

1. Whether expanded structured fields remain additive in `contracts/v1` or require a future `contracts/v2` route/schema.
2. Which ETW providers are worth enabling by default without unacceptable volume or reliability risk.
3. Whether mTLS is required for first production deployment or introduced after per-agent bearer-token hardening.
4. How much script content and command-line data operators are allowed to view by role.
5. Which Sysmon baseline configuration is approved for workstation, server, and high-value server profiles.
6. How alerting and case management should be exposed in the web console.
7. Whether full-text indexing is required in PostgreSQL for raw payload search or whether structured extraction is sufficient.
