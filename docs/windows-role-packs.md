# Windows role source-pack designs

These role-pack designs extend the Windows full-coverage baseline for high-value server roles. All fixtures and examples must remain synthetic; do not commit event-log exports or client telemetry.

## Domain controller

- Sources: Security, Directory Service, DNS Server, DFS Replication, Kerberos/NTLM operational logs, Group Policy, Sysmon when available.
- Parsers: authentication, account/group changes, directory replication, DC service state, DNS query/zone changes.
- Detections: DCSync/replication abuse, Kerberoasting indicators, privileged group changes, DC log clearing, suspicious service creation, GPO tamper.
- Validation: synthetic Security events for 4768/4769/4771/4720/4732 plus synthetic Directory Service samples.
- Privacy/volume: account names and directory object names can be sensitive; bound result counts and redact raw attributes by default.

## File server

- Sources: Security object access, SMB server operational/security logs, share inventory snapshots, Sysmon file events when available.
- Parsers: share access, file create/delete/rename, permission changes, high-volume object access.
- Detections: ransomware-like file bursts, unusual share enumeration, permission weakening, suspicious admin-share access.
- Validation: synthetic 4663/5140/5145 and Sysmon 11/23 samples.
- Privacy/volume: file paths can expose client data; use redaction policy and avoid raw file listings in docs.

## IIS/web server

- Sources: IIS logs when configured, HTTPERR, Windows Application, Sysmon network/process, certificate and service inventory.
- Parsers: worker process crashes, web shell process spawns, HTTP error bursts, module/config changes.
- Detections: web shell command execution, suspicious child processes from `w3wp.exe`, anomalous module changes, brute-force/admin path bursts.
- Validation: synthetic process, application crash, and IIS-like metadata fixtures.
- Privacy/volume: URLs can contain tokens or PII; query strings must be redacted before provider/tool sharing.

## Certificate authority

- Sources: CertificationAuthority operational logs, Security, CA service/config snapshots.
- Detections: template changes, suspicious certificate issuance, CA service tamper, privileged CA group changes.
- Privacy: certificate subjects and SANs can contain sensitive identity data.

## Hyper-V

- Sources: Hyper-V VMMS/Admin, Hyper-V Worker/Admin, System, Security, VM inventory snapshots.
- Detections: unexpected VM creation/export/checkpoint, virtual switch changes, host service tamper.
- Privacy: VM names and paths can be sensitive.

## RDS/session host

- Sources: TerminalServices LocalSessionManager/RemoteConnectionManager, Security, WinStation events, Sysmon.
- Detections: unusual RDP source, repeated failures, shadowing/tamper, suspicious child process from user sessions.

## DNS server

- Sources: DNS Server analytical/audit logs when enabled, DNS inventory, Sysmon DNS query events.
- Detections: suspicious zone changes, dynamic update anomalies, high-volume NXDOMAIN/C2-like patterns.

## DHCP server

- Sources: DHCP Server audit logs, System, service inventory.
- Detections: scope changes, rogue lease patterns, service tamper.

## Print server

- Sources: PrintService operational/admin logs, spooler service state, driver inventory.
- Detections: suspicious driver installation, spooler crashes, exploitation-like process activity.

## SQL Server host

- Sources: Windows Application/System/Security, SQL error/audit logs if enabled, service/process inventory.
- Detections: SQL service tamper, suspicious `sqlservr.exe` child processes, failed login bursts, backup/file exfil patterns.

## OpenSSH server

- Sources: OpenSSH operational logs, Security logon events, service inventory, firewall logs.
- Detections: SSH brute force, unusual successful login source, authorized_keys or service configuration tamper.
