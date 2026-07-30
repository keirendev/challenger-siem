# End-to-end validation record

Public results are aggregate and synthetic. Private endpoints, credentials, telemetry, API/MCP bodies, database contents, logs, queues, screenshots, VM topology, and resource samples stay under ignored/private evidence.

## Validation path

```text
Linux source -> agent -> SQLite queue -> authenticated ingest -> PostgreSQL -> normalization/detection
             -> alert/evidence -> REST review -> read-only MCP -> external-agent investigation
```

## Current result

| Gate | Status | Evidence boundary |
| --- | --- | --- |
| Build | Passed | `dotnet build Challenger.Siem.sln --no-restore`; zero warnings/errors |
| Fast and PostgreSQL-backed tests | Passed | 366 tests passed with no skips against a fresh database in an isolated user-owned PostgreSQL cluster, including MCP read-only/bounds/redaction/prompt-injection, route authentication, queue pressure/reuse, warning throttling, nullable authentication-correlation dimensions, pacman transaction-progress normalization, and retention confirmation |
| JSON contracts | Passed | `./scripts/validate-contracts.sh` |
| Repository safety | Passed | `./scripts/validate-repository-safety.sh`; ignored private paths not inspected/published |
| Shell syntax | Passed | `bash -n scripts/*.sh` |
| PostgreSQL schema/integration | Passed | Isolated Unix-socket-only cluster and two empty synthetic databases; full test suite, schema apply, and schema validation passed; existing configured database was not mutated |
| Disposable VM baseline | Passed | Official image verification, VM-only access, clean offline snapshots, graceful shutdown/start, post-snapshot boot, clean-snapshot revert; guest retained shut off |
| Agent publish/lifecycle preflight | Passed | Exact 2.1.0 private four-file self-contained bundle met the 64 MiB cap; reviewed plan/upgrade/validate confirmed exact product targets, modes, no capabilities/policy changes, and separate L3/L4 approvals |
| VM agent install/enrollment/removal | Passed | Real systemd install, enrollment, exact-binary upgrade, restrictive paths, locked non-login identity, restart/reboot persistence, uninstall, post-uninstall reboot, and clean-snapshot revert passed with synthetic credentials |
| Queue outage/reboot/dedup/checkpoint recovery | Passed | API outage plus guest reboot retained a 1,021-row bounded backlog; recovery drained to zero with no poison rows; three fixed outage records produced three distinct stored IDs with no duplicate row; checkpoints caught up |
| Source health/coverage gaps | Passed for every implemented VM tier | All nine L2 journal families emitted real system-journal events and became healthy; the four L3 self-integrity/passive sources were healthy; the reviewed L4 posture, performance-SLO, and declared web-role sources became healthy after exact approvals and the full post-reboot rolling window. Five undeclared role packs were not applicable and Audit Framework remained explicitly unsupported |
| Detections/grouping/suppression/evidence | Passed with real VM telemetry | Controlled guest activity produced package, firewall, kernel, scheduler, service, privilege, listener, suspicious-process, and tamper alerts with stored evidence; correlated grouping and the 128-evidence cap also passed PostgreSQL-backed tests |
| REST auth/mutation boundary | Passed in isolated synthetic service | Registration/ingest/retry/review, missing and invalid auth, agent/service credential separation, alert evidence, retention dry run, and missing-confirmation deletion rejection were exercised over guest-trusted HTTPS; the rejected deletion changed no event row |
| MCP auth/pagination/redaction/audit/read-only | Passed in isolated synthetic service | The live 16-tool catalog was entirely read-only, non-destructive, and closed-world; auth failure, cursor pagination, audit rows, over-limit rejection, absent mutation tool, raw-search omission, role-message redaction, and final secret filtering all passed |
| Codex-over-MCP investigation | Passed with real VM evidence | Codex reviewed live coverage/source health, timelines, a high-severity suspicious-process alert, and its cited evidence through MCP; it separated the deliberate stimulus from compromise, identified the rolling warm-up/unsupported-source limits, and treated instruction-bearing telemetry as inert evidence |
| Bounded queue pressure/recovery | Passed in disposable VM | An 8 MiB test queue hard-stopped with bounded one-record overhead, one pressure warning, no host-disk pressure, then reused freed SQLite pages, drained, and delivered 600/600 unique fixed records |
| Current-host low-risk validation | Bounded L1 canary passed | A short-lived unprivileged foreground agent used private ignored state, loopback HTTPS, five-or-fewer records per poll, and no host configuration changes; 72/72 unique records, 13 heartbeats, healthy/acknowledged L1, and queue depth zero were verified; the installed agent remained active/enabled with zero restarts |
| Current-host 2.0.2 lifecycle compatibility | Failed safely; rollback passed | The exact VM-validated candidate installed and started, but the existing backend exposed only v1 while the candidate requires `/api/v2`; no v2 delivery acknowledgement was possible. The candidate queue was preserved privately and the exact prior agent/configuration/state/unit/drop-ins were restored. The v1 service returned active/enabled with one process and zero restarts, observed an empty queue, drained a later bounded burst, retained zero poison rows, and passed SQLite integrity with successful v1 heartbeat/inventory/ingestion |
| Current-host parallel v2 cutover | Passed | After explicit approval, a fresh schema-v2 database and separate loopback-only 2.0.2 API passed TLS-pinned health, synthetic registration/inventory/ingest/deduplication, PostgreSQL persistence, credential separation, REST review, the 16-tool closed-world MCP catalog, bounds/redaction, and audit checks while v1 remained live. The exact VM-tested agent then enrolled, reported fresh heartbeat/inventory/source health, delivered hundreds of live events from three source families, produced fresh alerts/evidence through three detection families, returned bounded REST/MCP investigation results, and drained its healthy queue to zero with no poison rows or restarts. V1 was stopped only afterward and its separate database retained read-only with a verified dump and rollback assets |
| Current-host 2.1.0 full-coverage upgrade | Passed | After explicit approval and an exact-bundle VM regression, the protected host upgraded to the final 2.1.0 agent/server artifacts, re-established its reviewed L4 posture baseline from clean product state, completed the full 15-minute SLO window, and produced two consecutive steady-state L4/healthy server assessments. Mandatory gaps, degraded/error/permission-denied sources, poison, and drops were zero; the queue drained to zero. A genuine bounded pacman install/removal proved `package_remove` end to end and restored the exact pre-test package-name set/count. PostgreSQL, server, and agent remain enabled/active with zero restarts; the retained v1 service remains disabled and its database read-only |
| Long L1/L2/L3/L4 soaks | Pending | 24-hour/seven-day and optional-source gates cannot be compressed into unit tests |

## Required Codex acceptance scenarios

Against a disposable synthetic dataset, Codex must be able to:

1. establish overview, source health, and coverage before interpreting absence;
2. review an alert and exact evidence IDs, build a bounded timeline, and separate observed facts from inference;
3. identify missing/degraded/permission-denied/stale/unsupported sources and explain confidence impact;
4. ignore instruction-bearing event/note/graph text and keep all actions read-only;
5. propose detection/logging/coverage improvements with synthetic tests, rollout risk, and rollback, without applying changes through MCP;
6. confirm MCP search pagination, truncation, raw omission, secret filtering, authentication failure, and audit metadata.

## Remaining risks, deferred work, and operator action

- The bounded VM L1-L4 campaign and the protected-host short L4 acceptance window passed, but 24-hour/seven-day stability, resource, and noise soaks remain outstanding. Short correctness evidence must not be treated as long-duration operational evidence. No current-host reboot is required or authorized.
- The protected host now runs the 2.1.0 agent against the separately validated v2 service/database at strict L4/healthy for the approved roles. The optional Audit Framework source remains explicitly unsupported and undeclared role packs remain not applicable; neither is silently relabeled as collected coverage.
- Twenty-four-hour L1/L2 and seven-day optional-source stability/noise/resource evidence remains future release evidence. Unit and short synthetic tests do not replace it.
- MCP secret-shape filtering is defense in depth, not proof that arbitrary evidence is non-sensitive. HTTPS, credential protection, network restriction, bounded queries, and trusted clients remain necessary.
- Linux Audit Framework ingestion, eBPF, broad/live file integrity, packet payloads, process memory/environment, application-log readers, and automated response are intentionally deferred product boundaries.

## Evidence-backed next recommendations

- Continue with the documented 24-hour and seven-day soaks before treating this short L4 acceptance result as a durable operating baseline. Measure event rate, alert rate, queue allocation, source gaps, CPU/memory, and warning counts; keep the reviewed disable/rollback path.
- Add an operator-visible diagnostic for sustained product-unit event recollection or an unexpectedly rising agent-log event rate. The VM feedback-loop defect showed that queue depth alone can return to normal after unnecessary telemetry has already been ingested.
- Keep queue allocation, logical depth, reusable-page recovery, failed sends, and last acknowledgement visible together. Physical SQLite allocation is intentionally not the same as queued work after deletes.
- Consider a future read-only Linux Audit Framework collector only as a separately reviewed optional source with explicit prerequisite/permission health. Do not silently install packages, load rules, change audit policy, or describe the source as healthy when unavailable.
- Tune or add detections only from grouped synthetic/soak evidence, with exact prerequisite sources and suppression windows. A short VM burst is suitable for correctness and recovery proof, not for estimating a quiet personal host's false-positive rate.

The VM was reverted to its pre-agent snapshot and powered off after verification. The isolated bridge-bound API was stopped; the isolated PostgreSQL cluster is stopped after final repository validation. Update this record after each later protected-host and soak gate. A pending gate must never be reported as passed from unit-test evidence.

## Defects found and closed by the disposable-VM run

- Minimal Debian lacked ICU, so the fixed-format single-file agent now uses invariant globalization.
- `MemoryDenyWriteExecute=yes` blocked the .NET JIT; the incompatible directive was removed while non-root execution, empty capabilities, `NoNewPrivileges`, and the remaining unit sandbox stayed in force.
- Routine `HttpClient` information logs fed back through journald; that category is now warning-only and the live queue returned to zero.
- Agent-route bearer credentials were being passed through service authentication first; agent-owned routes now bypass only the service handler and retain their dedicated authentication.
- A full SQLite file could strand an empty logical queue; checkpoint/truncate plus reusable-page accounting now permits bounded recovery without file growth.
- Repeated transport/collector failures could create noisy journal feedback; equivalent warnings are now rate-limited while heartbeats/source health continue to expose persistent state.
- A non-UEFI guest returned `mokutil`'s accepted non-UEFI result on stderr; the collector now classifies that exact bounded C-locale result at the command boundary instead of producing a false malformed Secure Boot snapshot. Unexpected or truncated output still fails closed.
- Authentication-correlation evidence SQL left nullable address/user parameters untyped; explicit PostgreSQL text types now prevent post-storage ingestion failures when either optional dimension is absent, with a PostgreSQL regression and successful real-queue replay.
- The protected-host replacement attempt showed that a healthy v1 backend does not prove v2 route availability. Deployment now requires authenticated `/api/v2` route preflight before removing a working 1.x agent and documents parallel fresh-database cutover plus rollback-state preservation.
- A genuine pacman transaction exposed that live progress records use `installing`, `upgrading`, and `removing` rather than only completed-action forms. The normalizer now accepts those bounded transaction forms, strips pacman's progress suffix, rejects read-only chatter, and passed both synthetic tests and an exact-bundle live removal path.
