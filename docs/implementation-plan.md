# Phased implementation and validation plan

This plan evolves the existing Linux-only v2 foundation without changing the public contract version, adding another operating system, introducing a browser/model client, or performing a 1.x database migration. Each phase uses synthetic fixtures and keeps live evidence private.

| Phase | Deliverable | Entry and exit gate |
| --- | --- | --- |
| 0. Inventory and safety baseline | Repository/contract/test architecture map; worktree safety; read-only protected-host/libvirt baseline | Required guidance read; no private tracked changes; no host mutation; explicit VM/resource/rollback decision |
| 1. External-agent and mutation hardening | Final MCP structured secret filtering, raw-search omission, injection tests, manual retention confirmation/audit | Fast tests/contracts/safety pass; `/api/v2` and `contracts/v2` compatible; version/changelog updated |
| 2. Disposable data plane | Empty PostgreSQL v2 database, all integration tests, schema validation, synthetic API/MCP server exercise | Exact disposable database/cleanup target; no existing database modified; raw outputs ignored |
| 3. Disposable endpoint | VM agent plan/install/enroll, L1 collection, queue/outage/dedup/checkpoint/reboot/uninstall/rollback | Clean snapshot exists; synthetic credentials; host resource gate; guest recovery and teardown proven |
| 4. Awareness quality | Coverage/source-health review, detection evidence/grouping/suppression/noise, retention/disk-pressure recovery, Codex investigation/injection workflows | PostgreSQL and VM phases pass; all limits/citations/gaps verified; no MCP mutation |
| 5. Protected-host canary | Bounded current-host L1 observation, then separately approved L2/L3/L4 only when prior soak gates pass | Exact operation/window/rollback approval; no service restart or config/permission/policy change by implication; aggregate results only |
| 6. Release handoff | Architecture/security/threat model, deployment, MCP, coverage, VM, host-safety, validation, remaining-risk/deferred-work records | Build/tests/contracts/schema/safety/shell gates pass; pending long soaks/operator actions called out honestly |

Stop a phase on secret/private-data exposure, unauthorized host mutation, host pressure or instability, boot/network/authentication risk, queue/state corruption, silent loss, unbounded growth, false-healthy coverage, or an untested rollback. A passing VM test is necessary for risky work but never authorizes the equivalent current-host change.
