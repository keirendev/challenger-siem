#!/usr/bin/env bash
set -euo pipefail

mode=${1:-plan}
shift || true
root=/
payload=
config=
no_service=false

while (($#)); do
  case "$1" in
    --root) root=$2; shift 2 ;;
    --payload) payload=$2; shift 2 ;;
    --config) config=$2; shift 2 ;;
    --no-service-control) no_service=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$mode" in
  plan|install|upgrade|validate|uninstall) ;;
  *) echo "Usage: $0 plan|install|upgrade|validate|uninstall" >&2; exit 2 ;;
esac

p(){ [[ $root == / ]] && printf '%s' "$1" || printf '%s%s' "${root%/}" "$1"; }
opt=$(p /opt/challenger-siem-agent)
etc=$(p /etc/challenger-siem-agent)
state=$(p /var/lib/challenger-siem-agent)
unit=$(p /etc/systemd/system/challenger-siem-agent.service)

preflight(){
  local mutation=${1:-mutation}
  [[ $(uname -s) == Linux ]] || { echo 'Unsupported platform: Linux is required.' >&2; return 1; }
  case $(uname -m) in x86_64|aarch64) ;; *) echo 'Unsupported architecture.' >&2; return 1 ;; esac
  [[ $root != / || -d /run/systemd/system ]] || { echo 'Unsupported init: systemd is required.' >&2; return 1; }
  [[ $mutation == plan || $root != / || $EUID -eq 0 ]] || { echo 'Administrative execution is required for mutation.' >&2; return 1; }
}

probe(){
  local path=$1 kind=$2 cap=$3
  if [[ -L $path ]]; then
    echo "symlink_rejected"
  elif [[ $kind == dir ]]; then
    [[ -d $path ]] && echo "present" || echo "missing"
  elif [[ -f $path ]]; then
    if [[ $cap -gt 0 && $(stat -c %s "$path" 2>/dev/null || echo 0) -gt $cap ]]; then
      echo "file_too_large"
    elif [[ -r $path ]]; then
      echo "present"
    else
      echo "permission_denied"
    fi
  else
    echo "missing"
  fi
}

self_integrity_config_path(){
  if [[ -n $config && -r $config ]]; then
    printf '%s' "$config"
  elif [[ -r $etc/agentsettings.json ]]; then
    printf '%s' "$etc/agentsettings.json"
  else
    return 1
  fi
}

self_integrity_plan_hash(){
  local cfg=${1:-}
  python3 - "$cfg" <<'PY'
import hashlib, json, sys
cfg_path = sys.argv[1]
self_integrity = {}
if cfg_path:
    with open(cfg_path, 'r', encoding='utf-8') as handle:
        data = json.load(handle)
    self_integrity = (data.get('Agent') or {}).get('SelfIntegrity') or {}

def get(name, default):
    return self_integrity.get(name, self_integrity.get(name[0].lower() + name[1:], default))
interval = int(get('IntervalSeconds', 3600))
timeout = int(get('ScanTimeoutSeconds', 30))
queue_pause = int(get('QueuePauseDepth', 100000))
max_events = int(get('MaxEventsPerScan', 20))
allowlist = [
    ('agent_binary', '/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent', 'HashedFile', 64 * 1024 * 1024, 'False'),
    ('systemd_unit', '/etc/systemd/system/challenger-siem-agent.service', 'HashedFile', 256 * 1024, 'False'),
    ('agent_config', '/etc/challenger-siem-agent/agentsettings.json', 'MetadataFile', 256 * 1024, 'True'),
    ('config_directory', '/etc/challenger-siem-agent/', 'Directory', 0, 'False'),
    ('state_directory', '/var/lib/challenger-siem-agent/', 'Directory', 0, 'False'),
]
canonical = '\n'.join([
    'linux-agent-self-integrity-snapshot-v1',
    f'interval={interval}',
    f'timeout={timeout}',
    f'queue_pause={queue_pause}',
    f'max_events={max_events}',
    ';'.join(','.join(map(str, entry)) for entry in allowlist),
])
print('sha256:' + hashlib.sha256(canonical.encode('utf-8')).hexdigest())
PY
}

plan(){
  echo 'Challenger SIEM Linux Agent plan (read-only)'
  echo "binary: $opt"
  echo "configuration (0600): $etc/agentsettings.json"
  echo "private state/queue (0700): $state"
  echo "unit: $unit"
  echo 'identity: challenger-siem (locked, no login); capabilities: none'
  echo 'host policy changes: none (audit/firewall/authentication/kernel/security policy untouched)'
  echo 'linux L3 self-integrity snapshot: disabled by default; requires Agent:SelfIntegrity:Enabled=true and matching ApprovedPlanHash'
  echo 'self-integrity supported platform/filesystem: Linux x86_64/aarch64 with ordinary POSIX stat/open on local filesystems; no audit/eBPF/fanotify/inotify/IMA/packages/kernel objects'
  local cfg=''
  if cfg=$(self_integrity_config_path); then
    echo "self-integrity approval plan hash: $(self_integrity_plan_hash "$cfg")"
    echo "self-integrity approval config: $cfg"
  else
    echo "self-integrity approval plan hash: $(self_integrity_plan_hash '') (default self-integrity options; rerun with --config or installed config for approval)"
  fi
  echo "self-integrity allowlist: $opt/Challenger.Siem.LinuxAgent (regular metadata+sha256 <=64MiB) [$(probe "$opt/Challenger.Siem.LinuxAgent" file $((64*1024*1024)))]"
  echo "self-integrity allowlist: $unit (regular metadata+sha256 <=256KiB) [$(probe "$unit" file $((256*1024)))]"
  echo "self-integrity allowlist: $etc/agentsettings.json (metadata only; credential-bearing, no hash/content) [$(probe "$etc/agentsettings.json" file 0)]"
  echo "self-integrity allowlist: $etc/ (directory metadata only; no recursion) [$(probe "$etc" dir 0)]"
  echo "self-integrity allowlist: $state/ (directory metadata only; no recursion) [$(probe "$state" dir 0)]"
  echo 'self-integrity privacy/resource impact: metadata plus two bounded streaming SHA-256 digests; no file contents, secret values, arbitrary paths, or recursive scans; minimum 5 minute cadence and 30 second deadline'
  echo 'self-integrity sequencing/loss/pressure: sequence checkpoints, queue-before-checkpoint, ack-before-delete; added/changed/deleted/unreadable/gap/drop/sample states; pause L3 before L1/L2 under queue pressure'
  echo 'self-integrity rollback: disable the source and remove only /var/lib/challenger-siem-agent/self-integrity-state.json; monitored files and host policy remain untouched'
}

validate(){
  preflight
  [[ -x $opt/Challenger.Siem.LinuxAgent ]] || { echo 'agent binary missing' >&2; return 1; }
  [[ -f $etc/agentsettings.json && $(stat -c %a "$etc/agentsettings.json") == 600 ]] || { echo 'configuration missing or not mode 0600' >&2; return 1; }
  [[ -f $unit ]] || { echo 'unit missing' >&2; return 1; }
  grep -q '^User=challenger-siem$' "$unit"
  ! grep -Eq 'Token|Password|ApiToken|EnrollmentToken' "$unit"
  echo 'validation passed'
}

install(){
  preflight
  [[ -n $payload && -x $payload/Challenger.Siem.LinuxAgent ]] || { echo 'A published executable payload is required.' >&2; return 1; }
  [[ -n $config && -f $config ]] || { echo 'A configuration file is required.' >&2; return 1; }
  [[ $root != / || $(stat -c %a "$config") == 600 ]] || { echo 'Configuration input must be mode 0600.' >&2; return 1; }
  [[ $root != / || $(id -u challenger-siem 2>/dev/null || true) ]] || { echo 'Dedicated challenger-siem identity must exist; create it explicitly before install.' >&2; return 1; }
  mkdir -p -m 0755 "$opt" "$(dirname "$unit")"
  mkdir -p -m 0700 "$etc" "$state"
  command install -m 0755 "$payload/Challenger.Siem.LinuxAgent" "$opt/Challenger.Siem.LinuxAgent"
  command install -m 0600 "$config" "$etc/agentsettings.json"
  command install -m 0644 "$(dirname "$0")/../packaging/linux/challenger-siem-agent.service" "$unit"
  if [[ $root == / ]]; then
    chown -R root:root "$opt"
    chown -R challenger-siem:challenger-siem "$etc" "$state"
  fi
  if ! $no_service && [[ $root == / ]]; then
    systemctl daemon-reload
    systemctl enable --now challenger-siem-agent.service
  fi
  validate
}

uninstall(){
  preflight
  if ! $no_service && [[ $root == / ]]; then
    systemctl disable --now challenger-siem-agent.service || true
  fi
  rm -f "$unit"
  rm -rf "$opt" "$etc" "$state"
  if ! $no_service && [[ $root == / ]]; then
    systemctl daemon-reload
  fi
  echo 'project-owned files removed; service identity retained'
}

case "$mode" in
  plan) preflight plan; plan ;;
  install|upgrade) install ;;
  validate) validate ;;
  uninstall) uninstall ;;
esac
