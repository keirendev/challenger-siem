# Sysmon L3 validation runbook

Sysmon L3 validation is optional and must not install, uninstall, or reconfigure Sysmon unless the operator explicitly authorizes that action.

## Preconditions

- A lab host already has Sysmon installed and running, or the validation is limited to parser/source-health behavior that reports Sysmon as missing/not applicable.
- If installing or updating Sysmon is approved, use `install-windows-agent.ps1 -ManageSysmon -AcceptSysmonEula -SysmonSourcePath <official Sysmon64.exe>` after verifying the Microsoft signature and optional pinned hash.
- The agent configuration includes `Microsoft-Windows-Sysmon/Operational` as an optional L3 source and `Sysmon.ConfigPath` points at the versioned Challenger SIEM profile.
- Source-health and event search APIs are available.

## Safe validation path

1. Preview with `install-windows-agent.ps1 -Mode plan -TargetLevel L3`; do not mutate the host unless separately approved.
2. Verify whether `Microsoft-Windows-Sysmon/Operational` exists with a bounded query or `install-windows-agent.ps1 -Mode validate -TargetLevel L3`.
3. Run the installed or temporary agent with Sysmon optional and L2 mandatory sources.
4. Check source health for `sysmon-operational`:
   - `healthy` when present and readable;
   - `missing` or `not_applicable` when absent;
   - `error` when present but unreadable.
5. If synthetic Sysmon fixtures are used in tests, cover event IDs 1, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, and 255.

## Evidence

Keep raw outputs under ignored `.local/`. Public summaries should include only status counts, event IDs covered, and pass/fail result.

## Pass criteria

- The installer/validate mode reports aggregate Sysmon state and profile hash without raw event data.
- The agent reports a bounded, non-secret source-health result for Sysmon, including the configured profile version/hash when the profile file is present.
- Parser catalog/tests cover the L3 Sysmon process, network/DNS, file, registry, injection/access/image/driver/raw-disk, WMI/named-pipe/config/tamper groups.
- No raw Sysmon event exports are committed.
