#!/usr/bin/env bash
set -euo pipefail
umask 077

command_name=${1:-}
shift || true
bundle=''
config=''
public_key=''
root=/
no_service=false
while (($#)); do
  case "$1" in
    --bundle) bundle=${2:?}; shift 2 ;;
    --config) config=${2:?}; shift 2 ;;
    --public-key) public_key=${2:?}; shift 2 ;;
    --root) root=${2:?}; shift 2 ;;
    --no-service) no_service=true; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$command_name" in plan|enable|validate|disable) ;; *) echo 'Usage: kernel-network.sh plan|enable|validate|disable --bundle DIR --config FILE --public-key FILE [--root DIR] [--no-service]' >&2; exit 2 ;; esac

p(){ [[ $root == / ]] && printf '%s' "$1" || printf '%s%s' "${root%/}" "$1"; }
opt=$(p /opt/challenger-siem-agent)
unit_dir=$(p /etc/systemd/system)
agent_dropin_dir=$unit_dir/challenger-siem-agent.service.d
agent_dropin=$agent_dropin_dir/40-kernel-network.conf
helper_service=$unit_dir/challenger-siem-ebpf-helper.service
helper_socket=$unit_dir/challenger-siem-ebpf-helper.socket
agent_binary=$opt/Challenger.Siem.LinuxAgent
agent_service=$unit_dir/challenger-siem-agent.service
helper_binary=$opt/Challenger.Siem.EbpfHelper
trusted_key=$(p /etc/challenger-siem-agent/kernel-network-signing-key.pem)
trusted_key_dir=$(dirname "$trusted_key")
runtime_dir=$(p /run/challenger-siem-ebpf)

require_file(){
  local path=$1 maximum=$2 label=$3 size=''
  [[ -f $path && ! -L $path && -r $path ]] || { echo "$label must be a readable regular non-symlink file." >&2; return 1; }
  size=$(stat -c %s "$path" 2>/dev/null || true)
  [[ $size =~ ^[0-9]+$ && $size -gt 0 && $size -le $maximum ]] || { echo "$label is empty, oversized, or unreadable." >&2; return 1; }
}

preflight(){
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Kernel network telemetry currently requires Linux x86_64.' >&2; return 1; }
  [[ $root != / || -d /run/systemd/system ]] || { echo 'systemd is required.' >&2; return 1; }
  [[ $command_name == plan || $command_name == validate || $root != / || $EUID -eq 0 ]] || { echo 'Administrative execution is required.' >&2; return 1; }
  [[ -n $bundle && -n $config && -n $public_key ]] || { echo '--bundle, --config, and --public-key are required.' >&2; return 1; }
  require_file "$config" $((256 * 1024)) 'Agent configuration'
  require_file "$public_key" $((64 * 1024)) 'Trusted Ed25519 public key'
  require_file "$bundle/kernel-network-manifest.json" $((256 * 1024)) 'Signed bundle manifest'
  require_file "$bundle/kernel-network-manifest.sig" $((64 * 1024)) 'Bundle manifest signature'
  for name in Challenger.Siem.LinuxAgent Challenger.Siem.EbpfHelper challenger-siem-agent.service challenger-siem-agent-kernel-network.conf challenger-siem-ebpf-helper.service challenger-siem-ebpf-helper.socket; do
    require_file "$bundle/$name" $((80 * 1024 * 1024)) "Bundle file $name"
  done
  openssl pkeyutl -verify -pubin -inkey "$public_key" -rawin \
    -in "$bundle/kernel-network-manifest.json" -sigfile "$bundle/kernel-network-manifest.sig" >/dev/null
  local fingerprint=''
  fingerprint=$(openssl pkey -pubin -in "$public_key" -outform DER | sha256sum | awk '{print $1}')
  python3 - "$bundle" "$fingerprint" <<'PY'
import hashlib, json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / 'kernel-network-manifest.json').read_text(encoding='utf-8'))
expected = {
    'Challenger.Siem.LinuxAgent', 'Challenger.Siem.EbpfHelper', 'challenger-siem-agent.service',
    'challenger-siem-agent-kernel-network.conf', 'challenger-siem-ebpf-helper.service',
    'challenger-siem-ebpf-helper.socket',
}
if manifest.get('schema_version') != 1 or manifest.get('bundle_type') != 'challenger-siem-kernel-network-linux-x64':
    raise SystemExit('signed manifest identity is invalid')
if manifest.get('signer_public_key_sha256') != sys.argv[2]:
    raise SystemExit('trusted public key fingerprint does not match the signed manifest')
if manifest.get('required_capabilities') != ['CAP_BPF', 'CAP_PERFMON', 'CAP_NET_ADMIN']:
    raise SystemExit('signed capability boundary is invalid')
if manifest.get('privacy_boundary') != 'tcp_udp_ipv4_ipv6_headers_and_aggregate_counters_only_no_payload':
    raise SystemExit('signed privacy boundary is invalid')
if set(manifest.get('files', {})) != expected:
    raise SystemExit('signed file allowlist is invalid')
if not re.fullmatch(r'sha256:[0-9a-f]{64}', manifest.get('plan_hash', '')):
    raise SystemExit('signed plan hash is invalid')
for name, expected_hash in manifest['files'].items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected_hash:
        raise SystemExit(f'signed file hash mismatch: {name}')
PY
  local plan_output=''
  plan_output=$(CHALLENGER_SIEM_AGENT_CONFIG="$config" "$bundle/Challenger.Siem.LinuxAgent" --kernel-network-plan)
  python3 - "$bundle/kernel-network-manifest.json" "$config" "$plan_output" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding='utf-8'))
config = json.load(open(sys.argv[2], encoding='utf-8'))
plan = json.loads(sys.argv[3])
kernel = (config.get('Agent') or {}).get('KernelNetworkTelemetry') or {}
approved = kernel.get('ApprovedPlanHash', kernel.get('approvedPlanHash', ''))
approved_helper = kernel.get('ApprovedHelperSha256', kernel.get('approvedHelperSha256', ''))
approved_signer = kernel.get('ApprovedSignerPublicKeySha256', kernel.get('approvedSignerPublicKeySha256', ''))
enabled = kernel.get('Enabled', kernel.get('enabled', False))
if enabled is not True:
    raise SystemExit('Agent:KernelNetworkTelemetry:Enabled must be true')
if approved != plan.get('plan_hash') or approved != manifest.get('plan_hash'):
    raise SystemExit('configuration, candidate agent, and signed bundle plan hashes do not match')
if approved_helper != 'sha256:' + manifest['files']['Challenger.Siem.EbpfHelper']:
    raise SystemExit('configuration does not approve the signed helper hash')
if approved_signer != 'sha256:' + manifest['signer_public_key_sha256']:
    raise SystemExit('configuration does not approve the signed signer fingerprint')
if plan.get('helper_sha256') != approved_helper or plan.get('signer_public_key_sha256') != approved_signer:
    raise SystemExit('candidate plan does not bind the approved helper and signer hashes')
if plan.get('approval_hash_matches') is not True:
    raise SystemExit('candidate agent rejected the configured kernel network plan approval')
PY
  [[ -r /sys/kernel/btf/vmlinux && -d /sys/fs/cgroup ]] || { echo 'Kernel BTF and cgroup v2 root are required.' >&2; return 1; }
  stat -fc %T /sys/fs/cgroup | grep -qx cgroup2fs || { echo 'The host cgroup root is not cgroup v2.' >&2; return 1; }
  local libbpf_listing='' ldconfig_command=''
  ldconfig_command=$(command -v ldconfig 2>/dev/null || true)
  [[ -n $ldconfig_command ]] || [[ ! -x /sbin/ldconfig ]] || ldconfig_command=/sbin/ldconfig
  [[ -n $ldconfig_command ]] || { echo 'The fixed helper requires ldconfig for libbpf verification.' >&2; return 1; }
  libbpf_listing=$($ldconfig_command -p 2>/dev/null || true)
  grep -q 'libbpf\.so\.1' <<<"$libbpf_listing" || { echo 'The fixed helper requires libbpf.so.1.' >&2; return 1; }
}

print_plan(){
  preflight
  echo 'Challenger SIEM kernel network telemetry plan'
  python3 - "$bundle/kernel-network-manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding='utf-8'))
print('approved signer public-key SHA-256: sha256:' + manifest['signer_public_key_sha256'])
print('approved fixed helper SHA-256: sha256:' + manifest['files']['Challenger.Siem.EbpfHelper'])
print('approved deterministic plan: ' + manifest['plan_hash'])
PY
  echo 'identity: create or validate locked non-login challenger-siem-ebpf user and group; retain it on rollback'
  echo 'capabilities: helper receives exactly CAP_BPF CAP_PERFMON CAP_NET_ADMIN; the main agent receives no new capability'
  echo 'kernel attachments: fixed embedded cgroup v2 socket/bind/connect/sendmsg/recvmsg, sock-ops, accepted/closed socket-state raw tracepoint, and ingress/egress programs at /sys/fs/cgroup; additive BPF links with no replacement and no bpffs pins'
  echo 'telemetry: 10-second bounded drains aggregate TCP/UDP IPv4/IPv6 headers into started, 60-second active, and closed/inactive records with tuple, direction, PID/UID, TCP flags, packet and SKB-byte interval counters only; no payload, DNS, TLS, process environment, memory, or file content'
  echo "files: $helper_binary, $helper_service, $helper_socket, $agent_dropin, $trusted_key"
  echo 'service impact: daemon-reload and socket activation are staged; the agent is not restarted by this command'
  echo 'rollback: stop/disable helper socket and service to detach links, remove only fixed helper files/drop-in, daemon-reload, preserve agent queue/config/state and helper identity'
}

ensure_identity(){
  [[ $root == / ]] || { echo 'Alternate-root activation requires the helper identity to be prepared externally.' >&2; return 1; }
  if ! getent group challenger-siem-ebpf >/dev/null; then groupadd --system challenger-siem-ebpf; fi
  if ! getent passwd challenger-siem-ebpf >/dev/null; then
    local shell=/usr/sbin/nologin
    [[ -x $shell ]] || shell=/sbin/nologin
    useradd --system --gid challenger-siem-ebpf --home-dir /nonexistent --shell "$shell" challenger-siem-ebpf
  fi
  usermod --lock challenger-siem-ebpf
  local entry='' uid='' shell=''
  entry=$(getent passwd challenger-siem-ebpf)
  uid=$(id -u challenger-siem-ebpf)
  shell=${entry##*:}
  [[ $uid =~ ^[1-9][0-9]*$ && $shell == */nologin ]] || { echo 'Helper identity is not a locked non-root non-login account.' >&2; return 1; }
}

validate_candidate_agent_install(){
  require_file "$agent_binary" $((80 * 1024 * 1024)) 'Installed candidate agent binary'
  require_file "$agent_service" $((256 * 1024)) 'Installed candidate agent service'
  cmp -s "$bundle/Challenger.Siem.LinuxAgent" "$agent_binary" || { echo 'Installed agent binary does not match the signed candidate bundle.' >&2; return 1; }
  cmp -s "$bundle/challenger-siem-agent.service" "$agent_service" || { echo 'Installed agent service does not match the signed candidate bundle.' >&2; return 1; }
}

enable_source(){
  preflight
  validate_candidate_agent_install
  if [[ $root == / ]]; then ensure_identity; elif ! $no_service; then echo 'Alternate-root activation requires --no-service.' >&2; return 1; fi
  [[ ! -L $runtime_dir && ( ! -e $runtime_dir || -d $runtime_dir ) ]] || { echo 'Helper runtime path must be a directory and not a symlink.' >&2; return 1; }
  mkdir -p -m 0755 "$opt" "$unit_dir" "$agent_dropin_dir" "$trusted_key_dir"
  command install -d -m 0755 "$runtime_dir"
  command install -m 0755 "$bundle/Challenger.Siem.EbpfHelper" "$helper_binary"
  command install -m 0644 "$bundle/challenger-siem-ebpf-helper.service" "$helper_service"
  command install -m 0644 "$bundle/challenger-siem-ebpf-helper.socket" "$helper_socket"
  command install -m 0644 "$bundle/challenger-siem-agent-kernel-network.conf" "$agent_dropin"
  command install -m 0644 "$public_key" "$trusted_key"
  if [[ $root == / ]]; then chown root:root "$helper_binary" "$helper_service" "$helper_socket" "$agent_dropin" "$trusted_key" "$runtime_dir"; fi
  if ! $no_service && [[ $root == / ]]; then
    systemctl daemon-reload
    systemctl enable --now challenger-siem-ebpf-helper.socket
  fi
  echo 'Kernel network helper, socket, and agent ordering drop-in staged; the agent was not restarted.'
}

validate_source(){
  preflight
  validate_candidate_agent_install
  cmp -s "$bundle/Challenger.Siem.EbpfHelper" "$helper_binary"
  cmp -s "$bundle/challenger-siem-ebpf-helper.service" "$helper_service"
  cmp -s "$bundle/challenger-siem-ebpf-helper.socket" "$helper_socket"
  cmp -s "$bundle/challenger-siem-agent-kernel-network.conf" "$agent_dropin"
  cmp -s "$public_key" "$trusted_key"
  [[ -d $runtime_dir && ! -L $runtime_dir && $(stat -c %a "$runtime_dir") == 755 ]] || { echo 'Helper runtime directory mode is not the fixed 0755 boundary.' >&2; return 1; }
  if $no_service || [[ $root != / ]]; then echo 'Kernel network files and signature validated; runtime validation skipped.'; return 0; fi
  systemctl is-active --quiet challenger-siem-ebpf-helper.socket
  local bounding='' ambient=''
  bounding=$(systemctl show challenger-siem-ebpf-helper.service -p CapabilityBoundingSet --value)
  ambient=$(systemctl show challenger-siem-ebpf-helper.service -p AmbientCapabilities --value)
  python3 - "$bounding" "$ambient" <<'PY'
import sys
expected = {'cap_bpf', 'cap_perfmon', 'cap_net_admin'}
for label, value in [('bounding', sys.argv[1]), ('ambient', sys.argv[2])]:
    if set(value.split()) != expected:
        raise SystemExit(f'{label} capability set is not the exact approved three-capability set')
PY
  if systemctl is-active --quiet challenger-siem-ebpf-helper.service; then
    local pid='' effective=''
    pid=$(systemctl show challenger-siem-ebpf-helper.service -p MainPID --value)
    effective=$(awk '/^CapEff:/ {print $2; exit}' "/proc/$pid/status")
    python3 - "$effective" <<'PY'
import sys
value = int(sys.argv[1], 16)
expected = (1 << 39) | (1 << 38) | (1 << 12)
if value != expected:
    raise SystemExit('running helper effective capability set is not exactly CAP_BPF,CAP_PERFMON,CAP_NET_ADMIN')
PY
  fi
  if [[ -d /sys/fs/bpf ]]; then
    [[ -z $(find /sys/fs/bpf -maxdepth 2 -iname '*challenger*' -print -quit 2>/dev/null) ]] || { echo 'Unexpected Challenger SIEM bpffs pin detected.' >&2; return 1; }
  fi
  echo 'Kernel network signature, files, socket, and exact capability boundary validated.'
}

disable_source(){
  [[ $root != / || $EUID -eq 0 ]] || { echo 'Administrative execution is required.' >&2; exit 1; }
  if ! $no_service && [[ $root == / ]]; then
    systemctl disable --now challenger-siem-ebpf-helper.socket 2>/dev/null || true
    systemctl stop challenger-siem-ebpf-helper.service 2>/dev/null || true
  fi
  rm -f -- "$agent_dropin" "$helper_socket" "$helper_service" "$helper_binary" "$trusted_key"
  rmdir -- "$agent_dropin_dir" 2>/dev/null || true
  rmdir -- "$runtime_dir" 2>/dev/null || true
  if ! $no_service && [[ $root == / ]]; then systemctl daemon-reload; fi
  echo 'Kernel network helper disabled and fixed files removed; links detach on helper stop. Agent queue/config/state and helper identity were preserved.'
}

case "$command_name" in
  plan) print_plan ;;
  enable) enable_source ;;
  validate) validate_source ;;
  disable) disable_source ;;
esac
