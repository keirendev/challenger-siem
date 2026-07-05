# Archived: Windows host full-coverage GitHub issue backlog

> Archived after implementation. The issue series described in this file was implemented and closed by the Windows host full-coverage foundation work. Use live docs such as `docs/windows-host-full-coverage-spec.md`, `docs/api.md`, `docs/schema.md`, `docs/agent.md`, and `docs/web.md` for current behavior.

# Windows host full-coverage GitHub issue backlog

Status: draft issue series
Source specification: `docs/windows-host-full-coverage-spec.md`

This document turns the Windows host full-coverage SIEM specification into bite-sized GitHub issue drafts. The goal is to keep each issue small enough for a focused pull request, while preserving ordering and dependencies.

## Usage

- Copy each issue into GitHub as a separate issue when ready to schedule it.
- Use the suggested labels and milestones, or adapt them to the repository's GitHub label taxonomy.
- Keep production secrets and real endpoint telemetry out of issue bodies, comments, fixtures, and screenshots.
- Use only synthetic test data in issue attachments and examples.
- Split any issue further if implementation exceeds a small, reviewable change.

## Suggested labels

- `type/design`
- `type/enhancement`
- `type/test`
- `type/docs`
- `area/agent`
- `area/api`
- `area/contracts`
- `area/database`
- `area/web`
- `area/detections`
- `area/security`
- `area/validation`
- `source/security-log`
- `source/powershell`
- `source/defender`
- `source/sysmon`
- `source/inventory`
- `priority/p0`
- `priority/p1`
- `priority/p2`

## Suggested milestones

1. **L2 coverage foundation** - coverage levels, source health, API/storage support.
2. **L2 Windows source expansion** - native Windows source collection and parsers.
3. **Windows configuration baseline** - audit policy, logging policy, and drift reporting.
4. **L3 Sysmon coverage** - Sysmon source pack, normalization, and correlation.
5. **Inventory and asset state** - snapshot/diff collectors and asset APIs.
6. **Search, coverage UI, and alerts foundation** - operator workflows and alert models.
7. **Detection MVP** - initial coverage-aware host detections.
8. **Security and privacy hardening** - secret protection, redaction, RBAC, mTLS design.
9. **Validation and role packs** - lab validation and role-specific source packs.

---

## Issue 001: Add Windows coverage-level model

Labels: `type/enhancement`, `area/contracts`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 2, 15, 18

### Goal

Define a shared model for host coverage levels `L0` through `L4` and the status values used to report missing or degraded coverage.

### Scope

- Add coverage-level enum/model in shared contracts or server domain code.
- Define source status values such as `healthy`, `missing`, `disabled`, `stale`, `error`, `not_applicable`, and `excepted`.
- Add unit tests for serialization if exposed through API contracts.

### Acceptance criteria

- Coverage levels match the specification.
- Source status values are documented in code comments or docs.
- No existing API behavior is broken.

---

## Issue 002: Design the source-health heartbeat payload

Labels: `type/design`, `area/contracts`, `area/agent`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 5.2, 15.1

### Goal

Design the additive heartbeat fields required for per-source health reporting.

### Scope

- Define source-health fields for collector name, channel, enabled state, read status, last event time, last collection time, lag, last error code, last record ID/bookmark summary, and stale state.
- Define queue-health additions for oldest queued event age and poison event count.
- Decide whether these fields stay in `/api/v1` as additive fields.

### Acceptance criteria

- A reviewed design note or contract draft exists.
- Compatibility impact is explicitly documented.
- Follow-up implementation issues can use the design directly.

---

## Issue 003: Add database storage for agent source health

Labels: `type/enhancement`, `area/database`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 12.2, 15.2
Depends on: Issue 002

### Goal

Persist current and historical per-source health from agent heartbeats.

### Scope

- Add a schema migration/table for current source health.
- Add historical source-health observations if needed for trend and incident review.
- Add indexes for `agent_id`, `source`, `channel`, and last update time.
- Add repository tests using synthetic data.

### Acceptance criteria

- Source-health records can be inserted and updated by agent/source key.
- Queries can find stale or unhealthy sources efficiently.
- Schema validation script covers the new table/indexes.

---

## Issue 004: Persist source health from heartbeat requests

Labels: `type/enhancement`, `area/api`, `area/database`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 11, 15
Depends on: Issues 002, 003

### Goal

Accept additive source-health fields in heartbeat requests and persist them server-side.

### Scope

- Extend heartbeat validation for source-health arrays.
- Ensure authenticated agent ID matches heartbeat agent ID.
- Persist source-health details without logging sensitive values.
- Add API tests for valid, missing, and malformed source-health payloads.

### Acceptance criteria

- Heartbeats with source health are accepted and stored.
- Older heartbeats without source health still work.
- Malformed source-health entries are rejected with safe errors.

---

## Issue 005: Add source-health review API

Labels: `type/enhancement`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 13, 15.2
Depends on: Issue 004

### Goal

Expose source-health status for operators and future web UI pages.

### Scope

- Add an authenticated review endpoint for host/source health.
- Support filters by agent ID, hostname, source status, channel, and stale state.
- Return bounded paged results.
- Add API tests for authorization and filters.

### Acceptance criteria

- Operators can query unhealthy/stale sources.
- Results include enough detail to explain coverage gaps.
- Endpoint enforces review authentication and result limits.

---

## Issue 006: Add web coverage summary to host/agent inventory

Labels: `type/enhancement`, `area/web`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 13, 15.2, 18.1
Depends on: Issue 005

### Goal

Show each host's coverage level and highest-priority source-health issues in the web console.

### Scope

- Add coverage level, stale source count, missing mandatory source count, queue age, and last heartbeat to agent inventory.
- Add status styling for healthy/warning/critical hosts.
- Link to source-health details when available.

### Acceptance criteria

- Operator can quickly identify hosts below target coverage.
- Page handles hosts with no source-health data gracefully.
- Web tests cover healthy and unhealthy source states.

---

## Issue 007: Add coverage exception model

Labels: `type/design`, `area/api`, `area/database`, `priority/p2`
Milestone: L2 coverage foundation
Spec refs: sections 2, 12.2, 18.1

### Goal

Model approved exceptions for missing sources, unsupported roles, or intentionally disabled telemetry.

### Scope

- Design exception fields: host/agent selector, source/channel, reason, approver, expiration, and status.
- Add database table and review API draft if implementation is included.
- Ensure exceptions do not hide raw health data.

### Acceptance criteria

- Exceptions can be represented without deleting source-health findings.
- Expired exceptions are distinguishable from active exceptions.
- Design explains how coverage level calculations use exceptions.

---

## Issue 008: Add mandatory source manifest

Labels: `type/enhancement`, `area/agent`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 7.1, 7.2, 18.1

### Goal

Define the mandatory L1/L2 Windows source inventory in a versioned manifest used by agent and server logic.

### Scope

- Create a manifest for required and optional channels by coverage level.
- Include source IDs, channel names, display names, minimum coverage level, and not-applicable handling.
- Add tests that validate manifest uniqueness and required fields.

### Acceptance criteria

- The manifest includes Security, System, Application, PowerShell, Defender, Task Scheduler, WMI, RDP, WinRM, firewall, Group Policy, Code Integrity, and AppLocker entries.
- Manifest can drive coverage gap calculations.
- Missing optional channels can be distinguished from missing mandatory channels.

---

## Issue 009: Add event-log channel state probe

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 6.4, 15.1
Depends on: Issue 008

### Goal

Probe configured Windows Event Log channels for existence, enabled state, and readability.

### Scope

- Implement a read-only channel state probe in the Windows agent.
- Capture exists, enabled, readable, access denied, and not found states.
- Include source-health output for each configured channel.
- Add unit tests around state translation using abstractions/fakes.

### Acceptance criteria

- Agent can report missing, disabled, and unreadable channels.
- Security log access failures are clearly reported without crashing the agent.
- Probe results are suitable for heartbeat source-health data.

---

## Issue 010: Report event-log size and record range metrics

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 6.1, 6.4, 15.1
Depends on: Issue 009

### Goal

Report channel size, retention mode, oldest record, newest record, and last collected record metadata.

### Scope

- Extend event-log probing to collect log size/retention metadata where available.
- Capture oldest/newest record IDs and timestamps when safe and efficient.
- Add heartbeat fields or raw source-health metadata for these values.

### Acceptance criteria

- Operator can see if log sizes are too small for expected offline windows.
- Source-health data supports gap analysis.
- Collection failures are bounded and reported safely.

---

## Issue 011: Detect event-log clear, truncation, and bookmark gaps

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 5.2, 6.4, 8.9, 15.2
Depends on: Issue 010

### Goal

Detect source-side data loss conditions and emit source-health or tamper events.

### Scope

- Detect record ID rollback, bookmark invalidation, missing expected records, and log clear events.
- Emit bounded agent self-events or source-health findings.
- Add tests for rollback/gap state transitions using fake channel state.

### Acceptance criteria

- Agent reports suspected log truncation or record gaps.
- Event log clear events are normalized when collected from Security/System channels.
- Gap reporting includes affected channel and approximate record/time range when available.

---

## Issue 012: Add agent configuration hash to heartbeat

Labels: `type/enhancement`, `area/agent`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 5.1, 15.1, 15.2

### Goal

Report a stable non-secret hash of the active agent configuration and collector manifest in heartbeats.

### Scope

- Compute a hash after removing secret fields.
- Include agent version, config hash, enabled collectors, and manifest version in heartbeat.
- Persist and display unexpected changes later through source-health views.

### Acceptance criteria

- Config hash changes when non-secret collector settings change.
- Tokens/enrollment secrets do not influence logged/debug output.
- Heartbeat tests cover hash stability and secret exclusion.

---

## Issue 013: Add queue SLO metrics to heartbeat

Labels: `type/enhancement`, `area/agent`, `area/api`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 5.2, 15.1, 17

### Goal

Report queue depth, oldest queued event age, poison event count, disk usage, and sender backoff state.

### Scope

- Extend local queue repository to compute required metrics.
- Add heartbeat fields additively.
- Add unit tests for empty queue, active backlog, and poison event scenarios.

### Acceptance criteria

- Server receives enough queue data to flag backlog and poison event issues.
- Metrics are bounded and do not include raw event payloads.
- Existing queue behavior is unchanged.

---

## Issue 014: Add source silence and stale-source health rules

Labels: `type/enhancement`, `area/api`, `area/database`, `priority/p1`
Milestone: L2 coverage foundation
Spec refs: sections 15.2, 18.1
Depends on: Issues 004, 013

### Goal

Classify stale hosts and stale sources server-side using heartbeat/source-health data.

### Scope

- Define default staleness thresholds for heartbeat and per-source collection.
- Add server-side status calculation.
- Add tests for stale heartbeat, fresh heartbeat with stale source, and queue backlog conditions.

### Acceptance criteria

- API can identify stale hosts and stale sources.
- Queue backlog and source stale states are separate findings.
- Thresholds are configurable or centralized.

---

## Issue 015: Add default L2 Windows channel configuration

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 19 Phase A
Depends on: Issue 008

### Goal

Add a default configuration profile for L2 Windows security baseline channels.

### Scope

- Include PowerShell, Defender, Task Scheduler, WMI, TerminalServices, RDP Core, WinRM, Windows Firewall, Group Policy, Code Integrity, and AppLocker channels.
- Mark absent optional channels as skipped with source-health findings rather than fatal errors.
- Update example configuration without including secrets.

### Acceptance criteria

- New installs can opt into L2 channel collection with a clear config profile.
- Optional absent channels are reported cleanly.
- Documentation explains volume and privacy considerations.

---

## Issue 016: Add Security log parser fixtures

Labels: `type/test`, `area/agent`, `source/security-log`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 8.1, 8.2, 8.3, Appendix A, Appendix B

### Goal

Create synthetic Security log parser fixtures for high-value event families.

### Scope

- Add fake fixtures for logon/session, account/group changes, process creation, policy changes, service/task events, and event-log clear events.
- Use fake hostnames, users, SIDs, IPs, and paths.
- Add baseline normalization tests that currently assert generic fields if parser work is pending.

### Acceptance criteria

- Fixtures contain no real endpoint telemetry.
- Tests cover all planned Security parser families.
- Future parser issues can extend the same fixtures.

---

## Issue 017: Normalize Security logon and session events

Labels: `type/enhancement`, `area/agent`, `source/security-log`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 8.1, Appendix B
Depends on: Issue 016

### Goal

Extract structured authentication and session fields from Security log events.

### Scope

- Parse events such as successful logon, failed logon, explicit credentials, special logon, logoff, RDP reconnect/disconnect, lock, and unlock.
- Extract user, domain, SID, logon type, auth package, source IP/host, workstation, status/substatus, process, logon ID, and outcome when available.
- Add unit tests for each fixture.

### Acceptance criteria

- Logon/session events have normalized user, source, outcome, and logon type fields in raw or structured output.
- Unknown/missing fields degrade gracefully.
- Message-string parsing is avoided when structured event data is available.

---

## Issue 018: Normalize Security account, group, and privilege events

Labels: `type/enhancement`, `area/agent`, `source/security-log`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 8.2, Appendix B
Depends on: Issue 016

### Goal

Extract structured account and group-management details from Security events.

### Scope

- Parse local/domain user create, delete, enable, disable, password change/reset, rename, account lockout, and property change events.
- Parse privileged group membership additions/removals.
- Preserve actor, target, group, changed attributes, and outcome.

### Acceptance criteria

- Account and group events are searchable by actor and target identities.
- Privileged group changes can be detected without raw message parsing.
- Synthetic tests cover success and failure variants where available.

---

## Issue 019: Normalize Security process, object, policy, and tamper events

Labels: `type/enhancement`, `area/agent`, `source/security-log`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 8.3, 8.6, 8.9, Appendix B
Depends on: Issue 016

### Goal

Extract structured process, object-access, policy-change, and tamper fields from Security events.

### Scope

- Parse process creation/termination, object access, registry object access, audit policy changes, system time changes, firewall/filtering events, and log clear events.
- Extract process path, command line, parent process, subject user, object path/key, policy name, changed value, action, and outcome.

### Acceptance criteria

- Process creation events expose executable and command-line data when present.
- Audit-policy/log-clear events are clearly categorized as tamper or visibility-impacting events.
- Tests cover malformed or missing optional fields.

---

## Issue 020: Normalize System service, driver, boot, shutdown, and time events

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.1, 8.8, Appendix B

### Goal

Add source-specific normalization for high-value System channel events.

### Scope

- Parse service installation, service start/stop/failure, driver load/failure, boot, shutdown, unexpected shutdown, and time-service events.
- Extract service name, display name, binary path when available, account, start type, driver/service action, result code, and provider.
- Add synthetic tests.

### Acceptance criteria

- Service and driver events support persistence and tamper detections.
- Boot/shutdown events support host timeline review.
- Parser handles provider-specific field differences safely.

---

## Issue 021: Normalize Application, MSI Installer, and app crash events

Labels: `type/enhancement`, `area/agent`, `priority/p2`
Milestone: L2 Windows source expansion
Spec refs: sections 7.1, 8.11

### Goal

Extract useful software-install and application-failure fields from the Application channel.

### Scope

- Parse common MSI Installer install/update/uninstall events.
- Parse application crash/error events with executable/module names when available.
- Preserve provider-specific raw data for unknown application events.

### Acceptance criteria

- Software install/update/uninstall events are categorized consistently.
- Application failures remain searchable by provider, executable, and product where available.
- Tests use synthetic Application event fixtures.

---

## Issue 022: Normalize classic Windows PowerShell events

Labels: `type/enhancement`, `area/agent`, `source/powershell`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.4, Appendix B

### Goal

Parse the classic `Windows PowerShell` event channel for engine and provider lifecycle telemetry.

### Scope

- Extract host application, engine version, provider, runspace/pipeline IDs where present, user, and process context.
- Categorize engine start/stop and provider events.
- Add synthetic fixtures and parser tests.

### Acceptance criteria

- Classic PowerShell activity is distinguishable from generic Windows events.
- PowerShell version/downgrade indicators are extractable when present.
- Parser is resilient to localized/rendered message differences.

---

## Issue 023: Normalize PowerShell Operational script and module events

Labels: `type/enhancement`, `area/agent`, `source/powershell`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.4, Appendix B

### Goal

Parse `Microsoft-Windows-PowerShell/Operational` module and script-block logging events.

### Scope

- Extract script block ID, script content or content hash, module/cmdlet, host application, user, process, runspace, and pipeline metadata.
- Add payload size bounding and truncation metadata for large script content.
- Add privacy notes in docs or comments.

### Acceptance criteria

- Script block/module events can be searched and detected without relying on raw message text.
- Oversized script content is safely bounded.
- Tests cover encoded command and benign script examples using fake data.

---

## Issue 024: Normalize Microsoft Defender Operational events

Labels: `type/enhancement`, `area/agent`, `source/defender`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.10, Appendix B

### Goal

Parse Defender malware, remediation, ASR, and configuration events.

### Scope

- Extract threat name, category, severity, resource path, process/user, action, remediation status, engine/signature versions, and configuration changes when available.
- Categorize malware detection, remediation success/failure, ASR block/audit, and tamper/config events.
- Add synthetic parser fixtures.

### Acceptance criteria

- Defender events support malware and security-control detections.
- Remediation failures are clearly represented.
- Tests cover detection and configuration-change examples.

---

## Issue 025: Normalize Task Scheduler Operational events

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.8, Appendix B

### Goal

Parse scheduled task registration, update, deletion, action execution, and failure events.

### Scope

- Extract task path/name, author/user, action path/arguments where available, trigger metadata, result code, and operation.
- Correlate Security scheduled-task event IDs when present.
- Add synthetic tests.

### Acceptance criteria

- Scheduled task persistence can be detected from normalized fields.
- Task action details are captured when present and bounded.
- Parser handles both registration and execution events.

---

## Issue 026: Normalize WMI Activity events

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.8, Appendix B

### Goal

Parse `Microsoft-Windows-WMI-Activity/Operational` events for WMI queries and suspicious activity.

### Scope

- Extract namespace, query, operation, user, client machine, process ID, result code, and provider/consumer metadata where present.
- Add support for failed WMI operations and potential remote-origin fields.
- Add synthetic tests.

### Acceptance criteria

- WMI activity is searchable by namespace, user, client, and query text/hash.
- Parser supports future WMI lateral-movement and persistence detections.
- Query content is bounded to avoid oversized payloads.

---

## Issue 027: Normalize RDP and TerminalServices events

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.1, 8.5, Appendix B

### Goal

Parse TerminalServices and RDP Core channels for remote interactive session activity.

### Scope

- Parse LocalSessionManager, RemoteConnectionManager, and RdpCoreTS channels.
- Extract source IP/host, user, session ID, connection state, authentication result, disconnect/reconnect, and failure reason where available.
- Add synthetic tests.

### Acceptance criteria

- RDP connection attempts and session lifecycle events are searchable by user and source IP.
- Events can be correlated with Security logon events by session/logon context when possible.
- Missing channels are reported through source health.

---

## Issue 028: Normalize WinRM Operational events

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.5, Appendix B

### Goal

Parse WinRM Operational telemetry for PowerShell remoting and remote-management activity.

### Scope

- Extract remote address, user, shell/plugin/session identifiers, operation, auth result, and failure reason where available.
- Categorize remote shell creation, command execution indicators, failures, and service/configuration changes.
- Add synthetic tests.

### Acceptance criteria

- WinRM activity supports lateral-movement detections.
- Parser handles missing optional fields safely.
- Events can be searched by source IP/user/operation.

---

## Issue 029: Normalize Windows Firewall and filtering events

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.5, 8.9

### Goal

Parse Windows Firewall and Security filtering-platform events for firewall policy and connection visibility.

### Scope

- Extract rule/profile/action/direction/protocol/ports/application path/source/destination and actor when present.
- Categorize firewall profile changes, rule additions/removals, allowed connections, blocked connections, and packet drops.
- Add synthetic fixtures.

### Acceptance criteria

- Firewall configuration changes are normalized as security-control changes.
- Connection allow/block events are searchable by process/path/IP/port when available.
- Parser volume considerations are documented.

---

## Issue 030: Normalize Group Policy, Code Integrity, and AppLocker/WDAC events

Labels: `type/enhancement`, `area/agent`, `priority/p2`
Milestone: L2 Windows source expansion
Spec refs: sections 7.2, 8.9

### Goal

Add baseline parsers for policy application and execution-control telemetry.

### Scope

- Parse Group Policy Operational events for policy application success/failure and drift context.
- Parse Code Integrity events for blocked images, signing problems, and integrity failures.
- Parse AppLocker/WDAC audit/block events for executable, script, MSI, DLL, and packaged app decisions.

### Acceptance criteria

- Execution-control decisions are searchable by path, signer, policy, and decision.
- Policy application failures are visible to operators.
- Tests cover representative synthetic events.

---

## Issue 031: Add audit-policy snapshot collector

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: Windows configuration baseline
Spec refs: sections 6.2, 15.1, 19 Phase A

### Goal

Collect advanced audit policy state and report compliance with the required baseline.

### Scope

- Query advanced audit policy subcategories read-only.
- Normalize success/failure settings and category/subcategory names.
- Include a baseline evaluation summary in heartbeat or inventory snapshots.
- Add tests around parser/evaluator logic using fake command output or abstraction.

### Acceptance criteria

- Agent can report enabled/disabled audit policy subcategories.
- Drift from the documented baseline is clearly identified.
- No host policy is modified by the collector.

---

## Issue 032: Add process command-line audit policy check

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: Windows configuration baseline
Spec refs: sections 6.3, 8.3

### Goal

Check whether command-line inclusion for process creation events is enabled.

### Scope

- Read the relevant Windows policy/registry state without changing it.
- Report enabled, disabled, unknown, and access-denied states.
- Include result in configuration baseline health.

### Acceptance criteria

- Operators can see whether Security 4688 command lines should be expected.
- Unknown/access denied states are reported safely.
- Unit tests cover state evaluation.

---

## Issue 033: Add PowerShell logging policy check

Labels: `type/enhancement`, `area/agent`, `source/powershell`, `priority/p1`
Milestone: Windows configuration baseline
Spec refs: sections 6.3, 8.4

### Goal

Report PowerShell module logging, script block logging, transcription, and v2 engine status.

### Scope

- Read relevant local policy/registry state.
- Report enabled/disabled/partial/unknown values.
- Include privacy-sensitive settings in documentation.

### Acceptance criteria

- Coverage report explains whether PowerShell telemetry is expected.
- Disabled script block/module logging appears as a coverage gap unless excepted.
- Collector does not alter policy.

---

## Issue 034: Add event-log size and retention baseline evaluation

Labels: `type/enhancement`, `area/agent`, `priority/p1`
Milestone: Windows configuration baseline
Spec refs: sections 6.1, 6.4, 17
Depends on: Issue 010

### Goal

Evaluate whether required channel sizes and retention settings can support the target offline window.

### Scope

- Add configurable minimum size/retention expectations per source profile.
- Compare actual channel metadata against baseline.
- Report findings through source health.

### Acceptance criteria

- Small or overwrite-prone mandatory channels are flagged.
- Findings include channel name and actual observed settings.
- Thresholds are documented and configurable.

---

## Issue 035: Add security-control state summary collector

Labels: `type/enhancement`, `area/agent`, `source/defender`, `priority/p1`
Milestone: Windows configuration baseline
Spec refs: sections 6.3, 8.9, 8.10, 15.1

### Goal

Report Defender, firewall, PowerShell, Sysmon, and core security-control state in heartbeat or inventory.

### Scope

- Read Defender real-time protection/tamper/exclusion summary where available.
- Read Windows Firewall profile state.
- Read Sysmon service/config state when installed.
- Report missing or disabled controls as coverage/security findings.

### Acceptance criteria

- Operators can distinguish source missing from security control disabled.
- Collector uses read-only checks.
- No secrets or full exclusion lists are logged unless explicitly approved and bounded.

---

## Issue 036: Add audit-policy drift API and web view

Labels: `type/enhancement`, `area/api`, `area/web`, `priority/p2`
Milestone: Windows configuration baseline
Spec refs: sections 6.2, 13, 15.2
Depends on: Issues 031, 005

### Goal

Show audit-policy baseline drift in review API and web console.

### Scope

- Store current audit-policy evaluation per agent.
- Add review endpoint or extend source-health endpoint.
- Add web display for missing success/failure audit categories.

### Acceptance criteria

- Operator can identify hosts with audit policy below baseline.
- Drift details are searchable by host and subcategory.
- Approved exceptions can be displayed when available.

---

## Issue 037: Add Sysmon source-pack manifest

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 7.3, 9, 19 Phase B

### Goal

Define Sysmon as an L3 source pack with expected event families and source-health metadata.

### Scope

- Add source-pack metadata for `Microsoft-Windows-Sysmon/Operational`.
- List required Sysmon event families and parser coverage.
- Include config version/hash fields in the pack definition.

### Acceptance criteria

- Sysmon coverage can be marked healthy, missing, disabled, or excepted.
- Manifest distinguishes required and targeted/high-volume Sysmon families.
- Documentation notes Sysmon is additive, not a replacement for Security logs.

---

## Issue 038: Normalize Sysmon process creation and termination events

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.3, 9, Appendix B
Depends on: Issue 037

### Goal

Parse Sysmon process lifecycle events into normalized process fields.

### Scope

- Extract process GUID, image, command line, current directory, user, logon GUID/session, hashes, signer, integrity level, parent process GUID/image/command line, and outcome where available.
- Add synthetic fixtures and parser tests.

### Acceptance criteria

- Sysmon process events can be correlated by process GUID.
- Hash and signer fields are preserved when present.
- Parser handles missing optional fields without failing the event.

---

## Issue 039: Normalize Sysmon network and DNS events

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.5, 9, Appendix B
Depends on: Issue 037

### Goal

Parse Sysmon process-correlated network connection and DNS query events.

### Scope

- Extract process GUID/image/user, source/destination IP and port, protocol, direction, query name/type/status/results where available.
- Add tests for IPv4, IPv6, internal, external, and failed query examples.

### Acceptance criteria

- Network and DNS events are searchable by process, destination, and query name.
- DNS fields are normalized separately from raw payload.
- Parser supports future C2 and beaconing detections.

---

## Issue 040: Normalize Sysmon file, alternate data stream, and delete events

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.6, 9, Appendix B
Depends on: Issue 037

### Goal

Parse Sysmon file creation, file delete/archive, file creation time change, and alternate data stream events.

### Scope

- Extract process GUID/image/user, file path, target filename, hashes, timestamps, stream name/content hash where available, and operation.
- Add bounded handling for paths and stream metadata.

### Acceptance criteria

- File events support executable-drop, ADS, timestamp-tampering, and ransomware detections.
- Tests cover high-risk paths using fake paths.
- Large or missing fields are handled safely.

---

## Issue 041: Normalize Sysmon registry events

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.7, 9, Appendix B
Depends on: Issue 037

### Goal

Parse Sysmon registry key/value create, set, delete, and rename events.

### Scope

- Extract process GUID/image/user, key path, value name, value type, value data or hash/truncated value, and operation.
- Categorize high-risk persistence and security-control paths where possible.

### Acceptance criteria

- Registry events are searchable by key and value name.
- Value data is bounded and marked if truncated.
- Tests cover Run key, service, Defender policy, and IFEO examples with fake data.

---

## Issue 042: Normalize Sysmon injection, access, image, driver, and raw disk events

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.3, 8.8, 9
Depends on: Issue 037

### Goal

Parse Sysmon events used for credential access, injection, and driver/image load detections.

### Scope

- Parse process access, create remote thread, raw disk access, image load, and driver load events.
- Extract source/target process GUIDs, access masks/call trace where present, image/driver path, hashes, signatures, and operation.
- Add synthetic tests for LSASS-access and unsigned-driver examples.

### Acceptance criteria

- Credential-access and injection signals are normalized enough for detections.
- High-volume image-load data can be filtered or tagged as targeted.
- Parser bounds call trace and signature metadata.

---

## Issue 043: Normalize Sysmon WMI, named pipe, config change, and tamper events

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.8, 8.9, 9
Depends on: Issue 037

### Goal

Parse Sysmon telemetry for WMI persistence, named pipes, configuration changes, and Sysmon tamper.

### Scope

- Parse WMI filter/consumer/binding events.
- Parse named pipe create/connect events.
- Parse Sysmon configuration change and service state/tamper events.
- Add synthetic tests.

### Acceptance criteria

- WMI persistence and named-pipe activity are searchable by key fields.
- Sysmon config changes include config hash/version when available.
- Tamper-related events are categorized consistently.

---

## Issue 044: Report Sysmon configuration hash and version

Labels: `type/enhancement`, `area/agent`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 9, 15.1
Depends on: Issue 037

### Goal

Report the active Sysmon configuration version/hash and service state in source health.

### Scope

- Read Sysmon service status and configuration metadata where available.
- Compute a stable config hash without logging full config unless explicitly enabled.
- Report missing, stopped, changed, or unknown state.

### Acceptance criteria

- Operators can identify hosts with unexpected Sysmon config drift.
- Sysmon config hash is included in source-health data.
- No sensitive local paths or full configs are logged by default.

---

## Issue 045: Add process entity correlation model

Labels: `type/design`, `area/agent`, `area/api`, `area/database`, `source/sysmon`, `priority/p1`
Milestone: L3 Sysmon coverage
Spec refs: sections 8.3, 10.1, 19 Phase B
Depends on: Issues 017, 019, 038

### Goal

Design and implement a stable process entity model to correlate Security, Sysmon, network, file, registry, and script events.

### Scope

- Define process entity ID fields and correlation keys.
- Map Sysmon process GUIDs and Security process IDs/logon IDs where possible.
- Add storage/indexing requirements for process entity fields.

### Acceptance criteria

- Events from the same process can be linked when source data supports it.
- Correlation is best-effort and exposes confidence/limitations.
- Tests cover direct Sysmon GUID correlation and Security-only fallback.

---

## Issue 046: Add host identity and network snapshot collector

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `priority/p1`
Milestone: Inventory and asset state
Spec refs: sections 8.11, 15.1, 19 Phase C

### Goal

Collect host identity and network attributes for asset context.

### Scope

- Capture hostname, FQDN, domain/workgroup, machine GUID, OS edition/version/build, architecture, boot time, time zone, IP addresses, and MAC addresses.
- Emit current inventory in heartbeat or a dedicated inventory event.
- Add tests using fake collector abstraction data.

### Acceptance criteria

- Server receives enough identity data for asset records.
- Snapshot excludes secrets and volatile excessive detail.
- Values are updated periodically and on service start.

---

## Issue 047: Add local users and groups snapshot/diff collector

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `priority/p1`
Milestone: Inventory and asset state
Spec refs: sections 8.2, 8.11, 19 Phase C

### Goal

Capture current local users, groups, and privileged memberships, then emit changes.

### Scope

- Collect local users and local group membership read-only.
- Identify privileged groups such as Administrators, Remote Desktop Users, Backup Operators, and Event Log Readers.
- Emit snapshot and diff events with fake-data tests.

### Acceptance criteria

- Local privileged membership state is visible even if change events were missed.
- Diffs identify added/removed accounts.
- Sensitive fields are minimized and bounded.

---

## Issue 048: Add services and drivers snapshot/diff collector

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `priority/p1`
Milestone: Inventory and asset state
Spec refs: sections 8.8, 8.11, 19 Phase C

### Goal

Capture current services and drivers for persistence and configuration drift review.

### Scope

- Collect service name, display name, binary path, start type, status, account, and driver metadata when available.
- Emit diffs for new, removed, or changed services/drivers.
- Add tests for service binary path changes.

### Acceptance criteria

- Service/driver persistence can be found even if event logs rolled over.
- Diff events are deterministic and deduplicated.
- Sensitive account details are handled according to privacy policy.

---

## Issue 049: Add scheduled tasks and autoruns snapshot/diff collector

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `priority/p1`
Milestone: Inventory and asset state
Spec refs: sections 8.8, 8.11, 19 Phase C

### Goal

Capture scheduled tasks and common autorun persistence locations.

### Scope

- Snapshot scheduled tasks, actions, triggers, author/user, enabled state, and last result where available.
- Snapshot startup folders and selected autorun registry locations.
- Emit bounded diffs for additions, removals, and changes.

### Acceptance criteria

- Persistence sources are visible through inventory even without real-time events.
- Large task definitions are bounded or hashed.
- Tests cover new task and Run key changes with fake data.

---

## Issue 050: Add installed software, patch, and Windows feature snapshot collector

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `priority/p2`
Milestone: Inventory and asset state
Spec refs: sections 8.11, 19 Phase C

### Goal

Collect software and patch context for incident review and asset posture.

### Scope

- Snapshot installed software from approved local sources.
- Snapshot Windows update/patch state and installed Windows features/roles.
- Emit current state and changes without high-frequency polling.

### Acceptance criteria

- Operators can search hosts by software/features/patch context.
- Collector is bounded and does not create excessive event volume.
- Tests use fake inventory data.

---

## Issue 051: Add Defender, firewall, BitLocker, and local policy inventory snapshot

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `area/security`, `priority/p2`
Milestone: Inventory and asset state
Spec refs: sections 6.3, 8.9, 8.10, 8.11

### Goal

Collect security posture snapshots that complement event-based telemetry.

### Scope

- Snapshot Defender state, firewall profiles, BitLocker state, and selected local security policy values.
- Emit state changes and current-state updates.
- Bound sensitive fields such as exclusions.

### Acceptance criteria

- Security posture is visible from asset state.
- Changes can be linked to tamper/policy drift review.
- Privacy-sensitive values are redacted or hashed according to policy.

---

## Issue 052: Add server asset inventory storage and API

Labels: `type/enhancement`, `area/api`, `area/database`, `priority/p1`
Milestone: Inventory and asset state
Spec refs: sections 12.2, 13, 19 Phase C
Depends on: Issues 046, 047, 048, 049

### Goal

Persist current asset inventory and inventory changes server-side.

### Scope

- Add database tables for current asset inventory and historical changes.
- Add ingestion handling for inventory snapshot/diff events or dedicated endpoint if designed.
- Add review API filters by host, software, service, user/group, role, and security-control state.

### Acceptance criteria

- Current asset state can be queried by host.
- Historical changes link back to agent and time.
- Tests cover insert/update/diff behavior using synthetic data.

---

## Issue 053: Extract normalized entities into searchable fields

Labels: `type/enhancement`, `area/database`, `area/api`, `priority/p1`
Milestone: Search, coverage UI, and alerts foundation
Spec refs: sections 10.1, 12.1, 13

### Goal

Store high-value normalized entities in indexed searchable columns or entity tables.

### Scope

- Add structured extraction/storage for user, process image, command line hash, file path, registry key, source/destination IP, destination domain, severity, outcome, and event category.
- Add indexes aligned with search requirements.
- Preserve raw JSON for full detail.

### Acceptance criteria

- Search does not rely only on unindexed raw JSON for common fields.
- Existing event ingestion remains backward-compatible.
- Database tests verify indexes and query filters.

---

## Issue 054: Expand event search filters for full-coverage fields

Labels: `type/enhancement`, `area/api`, `priority/p1`
Milestone: Search, coverage UI, and alerts foundation
Spec refs: section 13
Depends on: Issue 053

### Goal

Add review API filters for normalized full-coverage fields.

### Scope

- Support filters for user, process image, file path, registry key, source IP, destination IP, destination domain, severity, outcome, event category, and detection rule where applicable.
- Enforce pagination and maximum limits.
- Add tests for filter combinations.

### Acceptance criteria

- Operators can search common investigation pivots efficiently.
- Filters are bounded and authenticated.
- Keyword search remains limited and safe.

---

## Issue 055: Add host detail coverage and source-health page

Labels: `type/enhancement`, `area/web`, `priority/p1`
Milestone: Search, coverage UI, and alerts foundation
Spec refs: sections 13, 15, 18.1
Depends on: Issues 005, 006

### Goal

Provide a web detail page for a host's coverage, sources, queue, and posture.

### Scope

- Show coverage level, mandatory source status, stale/missing sources, queue metrics, config hash, audit-policy drift, OS/build, and role packs.
- Link to recent events and alerts for the host.
- Add web tests with synthetic data.

### Acceptance criteria

- Operator can explain why a host is or is not L2/L3/L4 covered.
- Critical source gaps are highlighted.
- Page handles partial MVP data gracefully.

---

## Issue 056: Add alert and evidence database model

Labels: `type/enhancement`, `area/database`, `area/detections`, `priority/p1`
Milestone: Search, coverage UI, and alerts foundation
Spec refs: sections 12.2, 14.1

### Goal

Create storage for detection alerts and linked evidence events.

### Scope

- Add `detections`, `alerts`, and `alert_evidence` tables or equivalent.
- Store rule ID/version, severity, confidence, status, timestamps, host/user/process pivots, and evidence event IDs.
- Add tests and schema validation.

### Acceptance criteria

- Alerts can link to one or more evidence events.
- Rule version that fired is retained.
- Alert storage does not duplicate full raw event payloads unnecessarily.

---

## Issue 057: Add alert review API and web skeleton

Labels: `type/enhancement`, `area/api`, `area/web`, `area/detections`, `priority/p1`
Milestone: Search, coverage UI, and alerts foundation
Spec refs: sections 13, 14.1
Depends on: Issue 056

### Goal

Expose basic alert list and alert detail review workflows.

### Scope

- Add authenticated alert list/detail endpoints.
- Add web pages for alert list and detail with evidence links.
- Support status fields such as new, triaged, closed, and suppressed if included in the model.

### Acceptance criteria

- Operator can list alerts and inspect linked evidence.
- Alert detail shows rule ID/version, severity, confidence, and affected entities.
- API and web tests cover authorization and empty states.

---

## Issue 058: Add detection rule metadata model

Labels: `type/design`, `area/detections`, `priority/p1`
Milestone: Detection MVP
Spec refs: section 14.1

### Goal

Define the metadata required for every detection rule.

### Scope

- Define fields for stable rule ID, name, description, version, severity, confidence, required sources, minimum coverage level, logic, suppression fields, evidence fields, false-positive notes, and response guidance.
- Add JSON/YAML or code-based representation decision.
- Add validation tests for rule metadata.

### Acceptance criteria

- Rule metadata can declare required telemetry and coverage prerequisites.
- Invalid or incomplete rule definitions fail tests.
- Rule IDs and versions are stable and documented.

---

## Issue 059: Build detection engine skeleton

Labels: `type/enhancement`, `area/detections`, `area/api`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 14.2, 14.3
Depends on: Issues 056, 058

### Goal

Implement a minimal detection execution framework that can evaluate rules and write alerts.

### Scope

- Add scheduled or ingest-time rule evaluation architecture.
- Add correlation window and suppression hooks.
- Write alerts with evidence event IDs.
- Add tests with synthetic positive and negative cases.

### Acceptance criteria

- At least one trivial test rule can create an alert from synthetic events.
- Rule execution records rule version and evidence IDs.
- Missing prerequisites can suppress or lower confidence according to rule metadata.

---

## Issue 060: Add authentication attack detections

Labels: `type/enhancement`, `area/detections`, `source/security-log`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.1, 14.2
Depends on: Issues 017, 059

### Goal

Detect common Windows authentication attacks and suspicious session patterns.

### Scope

- Add rules for brute force, password spray, disabled account use, expired account use, unusual RDP/WinRM source, remote local-admin logon, and service account interactive logon.
- Include coverage prerequisites and tuning parameters.
- Add synthetic tests.

### Acceptance criteria

- Each rule produces evidence-linked alerts from synthetic positive fixtures.
- Negative fixtures avoid obvious false positives.
- Rules annotate confidence when RDP/WinRM source telemetry is missing.

---

## Issue 061: Add account and privilege change detections

Labels: `type/enhancement`, `area/detections`, `source/security-log`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.2, 14.2
Depends on: Issues 018, 059

### Goal

Detect high-risk identity and privilege changes on Windows hosts.

### Scope

- Add rules for new local admin, privileged group membership change, new local user, account enabled after disabled, password reset by unusual actor, and user-rights assignment change.
- Add suppression fields for approved admin tooling and maintenance windows.

### Acceptance criteria

- Alerts include actor, target account/group, host, and evidence event IDs.
- Rules can be tuned by allowed groups/tools.
- Tests cover positive and benign administrative examples.

---

## Issue 062: Add suspicious PowerShell and LOLBin detections

Labels: `type/enhancement`, `area/detections`, `source/powershell`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.4, 14.2
Depends on: Issues 019, 022, 023, 059

### Goal

Detect suspicious script and living-off-the-land binary execution.

### Scope

- Add rules for encoded PowerShell, download cradles, execution-policy bypass, hidden window, suspicious child processes, Office spawning interpreters, and high-risk LOLBins such as `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, and `wmic`.
- Use process and PowerShell fields where available.

### Acceptance criteria

- Rules work with Security-only telemetry and improve confidence with PowerShell/Sysmon data.
- Alerts include command line or safe hash/truncated detail.
- Tests use fake commands and paths.

---

## Issue 063: Add credential-access detections

Labels: `type/enhancement`, `area/detections`, `source/sysmon`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.3, 14.2
Depends on: Issues 042, 059

### Goal

Detect likely credential theft and sensitive process access activity.

### Scope

- Add rules for LSASS access, suspicious dump file creation, SAM/SYSTEM hive access, DPAPI abuse indicators, raw disk access, and suspicious handle access.
- Include coverage prerequisites for Sysmon process access/file events and Security object access where applicable.

### Acceptance criteria

- Alerts identify source process, target process/file, user, and host.
- Rules avoid alerting on allowlisted security tools when configured.
- Tests include positive and allowlisted negative cases.

---

## Issue 064: Add persistence detections

Labels: `type/enhancement`, `area/detections`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.8, 14.2
Depends on: Issues 020, 025, 041, 048, 049, 059

### Goal

Detect common persistence mechanisms on Windows hosts.

### Scope

- Add rules for new service, service binary path change, scheduled task create/update, Run key change, WMI permanent event subscription, startup folder executable, and suspicious service account changes.
- Use event telemetry and inventory diffs where available.

### Acceptance criteria

- Alerts identify persistence object, actor/process, and host.
- Rules declare required sources and lower confidence if only inventory diff is available.
- Tests cover each persistence type with fake data.

---

## Issue 065: Add defense evasion and tamper detections

Labels: `type/enhancement`, `area/detections`, `area/security`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.9, 14.2, 15.2
Depends on: Issues 011, 024, 029, 031, 035, 043, 059

### Goal

Detect attempts to reduce visibility or disable security controls.

### Scope

- Add rules for event log cleared, audit policy changed, Defender disabled/exclusion added, firewall disabled/rule weakened, PowerShell logging disabled, Sysmon config changed/stopped, agent stopped/stale heartbeat, and channel disabled.
- Include high severity for critical telemetry sources.

### Acceptance criteria

- Tamper alerts include affected source/control and actor when available.
- Source-health-only alerts are supported for stale/disabled sources.
- Tests cover both event-based and health-based tamper conditions.

---

## Issue 066: Add malware and Defender detections

Labels: `type/enhancement`, `area/detections`, `source/defender`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 8.10, 14.2
Depends on: Issues 024, 059

### Goal

Detect high-value Defender and malware-protection conditions.

### Scope

- Add rules for malware detected, remediation failed, repeated detections on a host, threat in startup/system path, ASR block, exploit protection hit, Defender signatures stale, and Defender disabled.
- Link alerts to threat name, affected file/process/user, action, and remediation status.

### Acceptance criteria

- Malware alerts include normalized threat and remediation details.
- Repeated/failed remediation rules correlate over a configurable window.
- Tests use synthetic Defender event fixtures only.

---

## Issue 067: Add network, C2, and BITS detections

Labels: `type/enhancement`, `area/detections`, `source/sysmon`, `priority/p2`
Milestone: Detection MVP
Spec refs: sections 8.5, 14.2
Depends on: Issues 039, 059

### Goal

Detect suspicious network behavior from endpoint telemetry.

### Scope

- Add initial rules for suspicious external destination by process, new listener, rare domain, high-frequency beacon-like pattern, suspicious DNS query pattern, and BITS transfer to external endpoint where source data exists.
- Include tuning controls for approved software and destinations.

### Acceptance criteria

- Rules declare Sysmon/DNS/firewall/BITS prerequisites.
- Alerts include process, destination, domain, and correlation window.
- Tests use synthetic internal/external IPs and fake domains.

---

## Issue 068: Add ransomware and impact detections

Labels: `type/enhancement`, `area/detections`, `source/sysmon`, `priority/p2`
Milestone: Detection MVP
Spec refs: sections 8.6, 14.2
Depends on: Issues 040, 059

### Goal

Detect host-level ransomware and destructive impact patterns.

### Scope

- Add rules for mass file modification/rename/delete, suspicious extension changes, shadow copy deletion commands, backup service stopped, and suspicious encryption tooling.
- Use configurable event-rate thresholds and high-value path lists.

### Acceptance criteria

- Rules include safe thresholds to avoid excessive false positives.
- Alerts include affected paths/counts and process evidence.
- Tests simulate event bursts with fake file paths.

---

## Issue 069: Add coverage-aware detection prerequisite handling

Labels: `type/enhancement`, `area/detections`, `priority/p1`
Milestone: Detection MVP
Spec refs: sections 14.3, 15.2
Depends on: Issues 014, 058, 059

### Goal

Make detections aware of missing or degraded telemetry sources.

### Scope

- Evaluate rule prerequisites against host source-health data.
- Suppress, downgrade confidence, or annotate alerts when required sources are missing.
- Include missing-source details in alert records.

### Acceptance criteria

- Alerts show whether source gaps affected confidence.
- Rules do not silently produce high-confidence results when required telemetry is absent.
- Tests cover healthy, missing, excepted, and stale source states.

---

## Issue 070: Protect agent secrets at rest with DPAPI

Labels: `type/enhancement`, `area/agent`, `area/security`, `priority/p1`
Milestone: Security and privacy hardening
Spec refs: sections 5.1, 16

### Goal

Protect per-agent API tokens and enrollment material at rest on Windows.

### Scope

- Use Windows DPAPI or an equivalent host-bound mechanism for stored agent tokens.
- Maintain a migration path from plaintext local lab settings without logging secrets.
- Add tests for secret redaction and config persistence logic where feasible.

### Acceptance criteria

- New persisted tokens are protected at rest.
- Enrollment tokens are cleared after successful enrollment.
- Logs and errors never print secret values.

---

## Issue 071: Add raw/script/command-line redaction policy

Labels: `type/design`, `area/security`, `area/contracts`, `priority/p1`
Milestone: Security and privacy hardening
Spec refs: sections 10.4, 16

### Goal

Define and implement a policy for bounding and redacting sensitive telemetry fields.

### Scope

- Identify fields requiring protection: raw XML/JSON, script content, command lines, file paths, usernames, hostnames, and IPs.
- Define truncation, hashing, redaction, and role-based visibility options.
- Implement initial size limits and truncation metadata if not already present.

### Acceptance criteria

- Oversized payloads are bounded with explicit metadata.
- Redaction/truncation behavior is tested.
- Policy is documented for operators.

---

## Issue 072: Design operator RBAC and field-level access controls

Labels: `type/design`, `area/security`, `area/web`, `area/api`, `priority/p2`
Milestone: Security and privacy hardening
Spec refs: section 16

### Goal

Design role-based access control for event review, alert management, administration, and sensitive-field access.

### Scope

- Define operator roles and permissions.
- Define which fields require elevated access.
- Identify changes needed to current review-token MVP auth.
- Produce follow-up implementation issues.

### Acceptance criteria

- Design separates agent auth from operator auth.
- Sensitive raw/script fields can be restricted by role.
- Migration path from MVP review token is documented.

---

## Issue 073: Design mTLS readiness for agent transport

Labels: `type/design`, `area/security`, `area/api`, `area/agent`, `priority/p2`
Milestone: Security and privacy hardening
Spec refs: sections 11, 16

### Goal

Plan optional mutual TLS for high-assurance agent-to-server authentication.

### Scope

- Define certificate issuance/enrollment model.
- Define token plus mTLS or mTLS-only modes.
- Identify server configuration, agent configuration, rotation, revocation, and diagnostics requirements.

### Acceptance criteria

- Design explains compatibility with current bearer-token enrollment.
- Secret/certificate storage requirements are documented.
- Follow-up implementation issues are identified.

---

## Issue 074: Add agent binary/config tamper checks

Labels: `type/enhancement`, `area/agent`, `area/security`, `priority/p2`
Milestone: Security and privacy hardening
Spec refs: sections 8.9, 16
Depends on: Issue 012

### Goal

Detect local tampering with agent binary, configuration, queue, ACLs, and service state.

### Scope

- Check expected file ACLs and selected hashes/signatures.
- Report agent service restarts, unexpected config hash changes, queue deletion/recreation, and ACL drift.
- Emit agent self-health events or source-health findings.

### Acceptance criteria

- Tamper findings are visible in heartbeat/source health.
- Checks are read-only and bounded.
- No secret-bearing config contents are transmitted or logged.

---

## Issue 075: Create L2 Windows lab validation runbook

Labels: `type/docs`, `area/validation`, `priority/p1`
Milestone: Validation and role packs
Spec refs: section 18.2

### Goal

Document safe validation steps for L2 Windows coverage in the authorized lab.

### Scope

- Cover registration, heartbeat, Security/System/Application, PowerShell, Defender, Task Scheduler, WMI, RDP, WinRM, firewall, queue/retry, and source-health checks.
- Avoid event-log clearing, reboot, service uninstall, or destructive actions unless explicitly approved for a disposable lab.
- Include expected search/API evidence.

### Acceptance criteria

- Runbook uses safe, bounded validation actions.
- Commands do not include secrets.
- Results can prove L2 coverage on a lab host.

---

## Issue 076: Create Sysmon L3 lab validation runbook

Labels: `type/docs`, `area/validation`, `source/sysmon`, `priority/p1`
Milestone: Validation and role packs
Spec refs: sections 9, 18.2
Depends on: Issue 037

### Goal

Document validation steps for Sysmon L3 telemetry in a lab environment.

### Scope

- Cover process, network/DNS, file, registry, process access, WMI, named pipe, config hash, and tamper/source-health validation.
- Use benign actions and fake domains/paths.
- Include expected queries and evidence fields.

### Acceptance criteria

- Runbook can validate Sysmon collection without destructive actions.
- No real client data or secrets are included.
- Missing Sysmon is clearly treated as a coverage gap or approved exception.

---

## Issue 077: Add source gap and backlog validation tests

Labels: `type/test`, `area/agent`, `area/api`, `area/validation`, `priority/p1`
Milestone: Validation and role packs
Spec refs: sections 5.2, 15.2, 18.2
Depends on: Issues 011, 013, 014

### Goal

Automate tests for source gaps, stale sources, queue backlog, and retry/drain behavior.

### Scope

- Add tests for simulated disabled channel, bookmark invalidation, record rollback, stale source, server outage, queue growth, retry, acknowledgement, and drain.
- Use fake collectors and test server abstractions where possible.

### Acceptance criteria

- Tests prove no queued event is deleted before accepted/duplicate acknowledgement.
- Source gap conditions produce source-health findings.
- Retry and drain behavior does not create duplicate stored events.

---

## Issue 078: Add synthetic fixtures for mandatory L2 parsers

Labels: `type/test`, `area/agent`, `area/validation`, `priority/p1`
Milestone: Validation and role packs
Spec refs: Appendix A, Appendix B
Depends on: Issues 016, 022, 024, 025, 026, 027, 028, 029

### Goal

Centralize synthetic event fixtures for all mandatory L2 parser families.

### Scope

- Add fixture naming conventions and fake data rules.
- Include Security, System, Application, PowerShell, Defender, Task Scheduler, WMI, RDP, WinRM, firewall, Group Policy, Code Integrity, and AppLocker samples.
- Document how to add new fixtures without real telemetry.

### Acceptance criteria

- Parser tests can run without Windows and without real endpoint data.
- Fixtures cover positive and malformed examples.
- Repository data-protection rules are followed.

---

## Issue 079: Add Windows role detection collector

Labels: `type/enhancement`, `area/agent`, `source/inventory`, `priority/p2`
Milestone: Validation and role packs
Spec refs: sections 7.4, 8.12, 19 Phase C
Depends on: Issue 050

### Goal

Detect installed Windows roles/features and recommend applicable source packs.

### Scope

- Identify domain controller, file server, IIS, certificate authority, Hyper-V, RDS, DNS, DHCP, print server, SQL Server, and OpenSSH roles where possible.
- Report role applicability in inventory/source health.
- Do not enable noisy sources automatically without configuration approval.

### Acceptance criteria

- Server can show missing role-specific source packs.
- Role detection is best-effort and explainable.
- Tests use fake role/feature data.

---

## Issue 080: Add domain controller source-pack design

Labels: `type/design`, `area/agent`, `area/detections`, `priority/p2`
Milestone: Validation and role packs
Spec refs: section 7.4
Depends on: Issue 079

### Goal

Design the telemetry, parsers, and detections required for monitored domain controllers.

### Scope

- Define required channels for Directory Service, DNS Server, DFS Replication, Kerberos KDC, AD Web Services, and Security account logon/account management events.
- Define SYSVOL file integrity monitoring needs.
- Identify high-value DC detections and validation steps.

### Acceptance criteria

- Design lists source channels, audit policy, parser needs, detection needs, and validation tests.
- Volume and privacy considerations are documented.
- Follow-up implementation issues are ready to create.

---

## Issue 081: Add file server source-pack design

Labels: `type/design`, `area/agent`, `area/detections`, `priority/p2`
Milestone: Validation and role packs
Spec refs: section 7.4
Depends on: Issue 079

### Goal

Design the telemetry and detections required for monitored Windows file servers.

### Scope

- Define SMB Server channels, Security object access needs, high-value share SACL guidance, shadow copy events, share configuration snapshots, and file integrity monitoring targets.
- Identify ransomware, access anomaly, and share-permission detections.

### Acceptance criteria

- Design separates high-value SACL auditing from broad noisy auditing.
- Source pack includes validation and tuning guidance.
- Follow-up implementation issues are ready to create.

---

## Issue 082: Add IIS/web server source-pack design

Labels: `type/design`, `area/agent`, `area/detections`, `priority/p2`
Milestone: Validation and role packs
Spec refs: section 7.4
Depends on: Issue 079

### Goal

Design the telemetry and detections required for monitored IIS/web servers.

### Scope

- Define IIS W3C request log ingestion requirements, HTTPERR, WAS/application pool events, web root file monitoring, and configuration-change snapshots.
- Identify web shell, suspicious upload, app pool identity, and exploitation detections.

### Acceptance criteria

- Design covers log locations, rotation, parsing, privacy, and volume controls.
- Web-root file monitoring is scoped to avoid excessive collection.
- Follow-up implementation issues are ready to create.

---

## Issue 083: Add additional Windows role-pack designs

Labels: `type/design`, `area/agent`, `area/detections`, `priority/p2`
Milestone: Validation and role packs
Spec refs: section 7.4
Depends on: Issue 079

### Goal

Design source packs for remaining high-value Windows roles.

### Scope

- Create separate short design notes or follow-up issues for certificate authority, Hyper-V, RDS/session host, DNS server, DHCP server, print server, SQL Server host, and OpenSSH roles.
- For each role, list sources, parsers, detections, validation, and volume/privacy considerations.

### Acceptance criteria

- Each role has enough detail to estimate implementation work.
- Any role too large for this issue is split into its own issue before coding.
- Designs follow the full-coverage specification and data-protection rules.
