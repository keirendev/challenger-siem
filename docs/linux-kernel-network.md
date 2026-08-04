# Linux kernel network flow telemetry

`linux-network-flow-summary` is an optional Linux x86_64 L3 source for correlating retained TCP/UDP network activity with the process that caused it. It is disabled by default. Enrollment, a requested coverage level, missing evidence, or installation alone cannot enable it.

## Evidence and privacy boundary

The fixed embedded eBPF object observes IPv4/IPv6 TCP/UDP cgroup traffic at the host cgroup-v2 root. It retains only the local/remote tuple, protocol, direction, packet count, SKB-length byte count, TCP flags, PID, fixed 16-byte kernel task name, UID when available at an owner hook, interval times, attribution basis, and explicit parser/map/ring loss counters. Cgroup-SKB execution context is never treated as a process owner; attribution comes from the recent bounded socket-owner map populated by connect, bind, send/receive, sock-ops, and socket-state hooks. When an owner hook supplies a PID but no UID, the unprivileged agent may fill UID from bounded `/proc/<pid>/status`; the sanitized kernel task name is the process-image fallback when procfs executable/command-line access is unavailable. It never copies application payload; it does not parse DNS, TLS, HTTP, process environment, process memory, file content, Unix sockets, or ICMP. The helper cannot open raw/packet sockets and cannot load a caller-selected object or pin programs/maps in bpffs.

Packet counts are cgroup SKB observations and byte counts are SKB lengths. GSO/GRO, segmentation, retransmission, offload, namespace/cgroup placement, non-initial IP fragments, ESP or excessive/malformed IPv6 extension chains, process exit/reuse, and pressure mean these are not wire-accurate accounting. The parser reads from the kernel network-header origin and walks at most four hop-by-hop, routing, first-fragment, AH, destination, or mobility headers before TCP/UDP; every other target-traffic omission remains an explicit loss counter. Process attribution is exact to the current kernel task when available, otherwise a recent full/local/remote socket-owner association no older than 60 seconds; procfs executable/command-line enrichment is best-effort, sanitizer-bounded, and explicitly racy.

## Privileged boundary

The main `challenger-siem` agent gains no capability. A separate locked, non-login `challenger-siem-ebpf` account runs only `Challenger.Siem.EbpfHelper` with exactly:

- `CAP_BPF`
- `CAP_PERFMON`
- `CAP_NET_ADMIN`

`CAP_SYS_ADMIN`, `CAP_NET_RAW`, root execution, writable product state, arbitrary BPF paths, and bpffs pinning are not permitted. systemd creates a mode-0660 `SOCK_SEQPACKET` endpoint owned by the helper and the `challenger-siem` group beneath a non-writable `root:root` directory. The helper verifies the connecting agent UID. The agent validates the exact non-symlink permission profile and accepts only the dedicated helper UID for a direct peer or PID 1/root attested as systemd for the socket-activated listener, then enforces the fixed hello. Frames have a 16-KiB maximum, a fixed property allowlist, helper epoch and monotonic sequence, and strict hello/capacity/privacy constants.

The fixed hook catalog covers socket creation, IPv4/IPv6 bind/connect/sendmsg/recvmsg, TCP sock-ops establishment, accepted/closed TCP socket-state raw tracepoints, and cgroup ingress/egress. Every cgroup program uses an additive BPF link, so stopping or killing the helper detaches it without replacing a pre-existing attachment; the helper rejects a missing, additional, renamed, or re-sectioned embedded program before attachment. All programs are observational and return allow/pass results; they do not replace policy or block traffic.

The kernel maps are bounded at 16,384 flow rows and 32,768 owner rows, with a 1-MiB ring. The helper atomically drains kernel intervals every ten seconds into its equally bounded accumulator. It emits `network_flow_started` for first evidence, `network_flow_sample` after each 60-second active interval, and `network_flow_closed` after TCP FIN/RST or 60 seconds of inactivity, with at most 500 flow records per drain plus one sequenced no-payload health frame. The agent receives and validates the complete drain through that health delimiter before beginning procfs enrichment, so enrichment cannot consume the helper's one-second per-send stall budget. Within the drain, enrichment is cached once for each bounded PID/UID/kernel-command/attribution-basis identity; original frame order, one event per frame, and racy/partial attribution labels are preserved.

Before the first queue write, the agent durably reserves the drain's complete agent-sequence range without advancing its collected checkpoint. It partitions the unchanged events into transactions of at most 100 events or 1 MiB and, after each successful transaction, atomically finalizes the collected/helper/health state for that committed prefix. An interrupted reserved suffix is abandoned exactly once, is never reused, and remains an explicit active gap; already committed queue rows, acknowledged rows, and cumulative helper-loss evidence remain intact. Bounded source health reports the last/high-water drain count, serialized bytes, unique enrichment identities, cache hits, receive duration, and persist duration. These are additive fields in state schema 2, so an older rollback agent ignores them while retaining the advanced sequence boundary.

Delivery remains sequential and bounded: a full outbound batch is followed by a 250-millisecond backlog delay, while a partial or empty batch returns to the five-second idle cadence. This lets the transport drain the helper's bounded burst ceiling without parallel requests or a permanent high-rate poll. The agent reserves one maximum drain and stops consuming before the configured 20,000-row pause boundary so journal, heartbeat, and delivery remain higher priority. Queue insertion precedes collected-checkpoint persistence; accepted/duplicate server acknowledgement precedes acknowledged-checkpoint persistence. Sequence gaps, newly increased map/parser/ring/IPC counters, helper restarts/connections, queue pressure, and stale helper contact remain explicit. Three consecutive clean health frames clear the active-loss state without erasing cumulative counters. Owner misses remain a separate partial-attribution counter because they do not lose the underlying flow observation.

## Signed plan and activation

Build/publish the candidate agent first. Put a private Ed25519 signing key only in ignored operator storage and derive a separate public key. Never put the private key, real configuration, bundle, or validation output in Git.

1. Publish the candidate agent, build the fixed helper, and calculate the helper file SHA-256 and the Ed25519 public-key DER SHA-256. Put the lowercase `sha256:` values in `ApprovedHelperSha256` and `ApprovedSignerPublicKeySha256`; leave `ApprovedPlanHash` empty and set `Enabled=true` only for plan generation.
2. Run the candidate agent with `--kernel-network-plan`, put that exact hash in `ApprovedPlanHash`, and rebuild the plan. The plan hash binds the approved helper and signer hashes as well as every path, limit, version, privacy boundary, and queue threshold.
3. Build a signed bundle with `scripts/build-kernel-network-bundle.sh OUTPUT AGENT_BINARY PRIVATE_KEY PUBLIC_KEY PLAN_HASH`. The lifecycle preflight rejects a signed helper or signer whose hash differs from either the configuration or the candidate plan, and requires the manifest's helper and collector versions to match the candidate agent. Collector identity `linux-network-flow-summary-v2` retains helper protocol and event schema v1.
4. Run `scripts/kernel-network.sh plan --bundle ... --config ... --public-key ...` and review the signed file hashes, signer fingerprint, three capabilities, attachments, service impact, and rollback.
5. After explicit approval, run `enable`. It validates or creates only the dedicated locked helper identity, installs the fixed helper/units/agent ordering profile/trusted public key, reloads systemd, and starts the socket. It does not restart the agent.
6. Restart only `challenger-siem-agent.service` in the separately approved activation step, then run `validate` and the live acceptance checks below.

The helper dynamically requires `libbpf.so.1`, libelf, zlib, cgroup v2, and readable kernel BTF. An endpoint compiler is not used. The initial native helper supports x86_64; ARM64 agents continue operating with this source reported unsupported.

## Validation

Run `tests/kernel-network-lifecycle/run.sh` for a synthetic isolated-root test of single-file publication, Ed25519 manifest/hash binding, plan/config agreement, fixed file staging, tamper rejection, and rollback preservation. This test does not start services, attach BPF programs, create identities, or use real credentials.

Validate in an approved disposable VM before a protected host:

- signed manifest, exact installed hashes, locked identities, mode/ownership, and no symlinks;
- configured and effective helper capabilities equal only the three approved values;
- the fixed cgroup links coexist with existing programs, and stop removes them without leftover Challenger SIEM bpffs pins;
- synthetic TCP and no-application-payload UDP flows produce cited `network_flow_started`, 60-second `network_flow_sample`, and FIN/RST or inactivity `network_flow_closed` evidence with direction, tuple, PID/process metadata, interval counters, `payload_capture=false`, and healthy source evidence;
- malformed/oversized/duplicate/unknown IPC fields are rejected; wrong peers cannot connect;
- flow pressure, parser omissions, helper/agent/backend restart, queue pause/drain, and server rejection produce explicit loss/health state without silent checkpoint advancement;
- REST `/api/v2/network/activity`, `/ui/traffic`, and `siem_search_network_activity` return the same retained event citation; MCP does not create or update the geolocation cache.

For the collector-v2 patch, use an authorized disposable Linux x86_64 VM and a bounded synthetic workload that reaches 500 flow records per ten-second drain for at least 30 minutes. Acceptance requires average agent writes below 1,048,576 bytes/second; average CPU below 2%, p95 CPU below 5%, and RSS below 250 MiB; normal queue pressure with age below 30 seconds and no sustained growth; acknowledgement gap returning to zero; and no poison/drop increase, helper connection failure, new sequence gap, parser/ring/map/IPC loss, crash, or restart. API/database reads must remain available, and strict L4 must remain healthy after warm-up for one additional complete rolling window.

For any new protected-host rollout, first perform the read-only incident review in [Runbooks](runbooks.md); if kernel flow is not the largest time-aligned event/payload contributor, keep the independently valid IPC and queue fixes but block rollout pending a revised source diagnosis. A canary requires a newly signed bundle, refreshed kernel plan and L4 plan/baseline approvals, exact rollback copies of the prior agent artifact and configuration, and an agent-only restart. The unchanged helper must not be restarted. Follow with the documented 24-hour read-only soak, and stop/roll back on an SLO breach, helper discontinuity, queue growth, silent loss, host impact, or inability to restore the prior agent while preserving queue and state.

Current sanitized status (2026-08-04): the exact 2.8.1 single-host development deployment passed the initial agent-only acceptance window and one additional complete healthy L4 rolling window. The queue remained bounded, acknowledgements caught up, active loss cleared without resetting cumulative historical gaps, the unchanged helper remained continuous, and the API/database read path remained available. The 24-hour read-only soak is in progress; this short result is not a broader production-readiness claim.

For an explicitly designated single-host development deployment, the operator may avoid a persistent external signer by generating a one-use Ed25519 key only in a root-owned mode-0700 directory under `/run`. Set `CHALLENGER_SIEM_FIXED_HELPER_BINARY` to the exact installed regular helper when building the signed candidate bundle, complete the normal manifest/candidate/config validation, install only the public key, and permanently destroy the private key and temporary signer directory immediately after staging. This local workflow does not permit an unsigned bundle, a helper replacement or restart, weaker manifest checks, a persistent endpoint private key, or reuse of an old approval; every candidate still needs fresh kernel and L4 plan/baseline approval plus rollback copies.

## Rollback

For an agent-only collector-v2 canary rollback, restore the exact prior agent artifact and protected configuration and restart only the agent; preserve queue, WAL/SHM, credentials, checkpoints, source state, helper process, helper attachments, and server evidence. Do not restart or replace the unchanged helper.

Full source removal is a separate operation: disable the source in configuration and restart only the agent, then run the lifecycle `disable` command. It stops the socket/service (detaching links), removes only the fixed helper files/units/profile/trusted public key, reloads systemd, and preserves agent configuration, queue, credentials, source state, server evidence, and the locked helper identity. Verify that no Challenger SIEM cgroup links or bpffs pins remain and that the other agent sources continue reporting normally.
