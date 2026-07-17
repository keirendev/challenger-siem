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

validate_service_identity(){
  local require_locked_password=${1:-false}
  local account='' account_uid='' shell='' primary_group='' shadow_entry='' password_field=''
  command -v getent >/dev/null 2>&1 || {
    echo 'Dedicated identity validation requires getent.' >&2
    return 1
  }
  account=$(getent passwd challenger-siem 2>/dev/null || true)
  [[ -n $account ]] || {
    echo 'Dedicated challenger-siem identity is missing.' >&2
    return 1
  }
  account_uid=$(id -u challenger-siem 2>/dev/null || true)
  [[ $account_uid =~ ^[0-9]+$ && $account_uid -ne 0 ]] || {
    echo 'Dedicated challenger-siem identity must be non-root.' >&2
    return 1
  }
  shell=${account##*:}
  case "$shell" in
    /usr/sbin/nologin|/sbin/nologin|/bin/false) ;;
    *) echo 'Dedicated challenger-siem identity must use a non-login shell.' >&2; return 1 ;;
  esac
  primary_group=$(id -gn challenger-siem 2>/dev/null || true)
  [[ $primary_group == challenger-siem ]] && getent group challenger-siem >/dev/null 2>&1 || {
    echo 'Dedicated challenger-siem primary group is missing or mismatched.' >&2
    return 1
  }
  if $require_locked_password; then
    [[ $EUID -eq 0 ]] || {
      echo 'Root is required to verify that the challenger-siem password is locked.' >&2
      return 1
    }
    shadow_entry=$(getent shadow challenger-siem 2>/dev/null || true)
    password_field=${shadow_entry#*:}
    password_field=${password_field%%:*}
    [[ -n $shadow_entry && ( $password_field == '!'* || $password_field == '*'* ) ]] || {
      echo 'Dedicated challenger-siem identity must have a locked, non-reusable password.' >&2
      return 1
    }
  fi
}

require_regular_bounded_file(){
  local path=$1 maximum_bytes=$2 label=$3 size=''
  [[ -f $path && ! -L $path && -r $path ]] || {
    echo "$label must be a readable regular non-symlink file." >&2
    return 1
  }
  size=$(stat -c %s "$path" 2>/dev/null || true)
  [[ $size =~ ^[0-9]+$ && $size -le $maximum_bytes ]] || {
    echo "$label exceeds its fixed size bound or could not be inspected." >&2
    return 1
  }
}

require_safe_product_target(){
  local path=$1 kind=$2
  [[ ! -L $path ]] || {
    echo "Product target is a symlink and was rejected: $path" >&2
    return 1
  }
  if [[ -e $path ]]; then
    if [[ $kind == dir && ! -d $path ]] || [[ $kind == file && ! -f $path ]]; then
      echo "Product target has an unexpected file type: $path" >&2
      return 1
    fi
  fi
}

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

passive_telemetry_plan(){
  local cfg=${1:-}
  python3 - "$cfg" <<'PY'
import hashlib, json, os, sys

cfg_path = sys.argv[1]
passive = {}
journal = {}
queue = {}

for environment_name in os.environ:
    normalized_name = environment_name.upper().replace('__', ':')
    if (normalized_name.startswith('CHALLENGER_SIEM_AGENT_AGENT:PASSIVETELEMETRY:')
            or normalized_name in {
                'CHALLENGER_SIEM_AGENT_AGENT:JOURNAL:QUEUEPAUSEDEPTH',
                'CHALLENGER_SIEM_AGENT_AGENT:JOURNAL:MAXRECORDSPERPOLL',
                'CHALLENGER_SIEM_AGENT_AGENT:JOURNAL:MAXINPUTRECORDBYTES',
                'CHALLENGER_SIEM_AGENT_AGENT:JOURNAL:INCLUDEACCESSIBLEUSERJOURNALS',
                'CHALLENGER_SIEM_AGENT_AGENT:QUEUE:MAXSIZEMB',
                'CHALLENGER_SIEM_AGENT_AGENT:QUEUE:WARNINGSIZEPERCENT',
            }):
        raise SystemExit(
            'passive telemetry plan: configuration environment overrides are present; '
            'use the published agent --passive-telemetry-plan output as authoritative'
        )

def lookup(block, name, default):
    for key, value in block.items():
        if key.casefold() == name.casefold():
            return value
    return default

if cfg_path:
    with open(cfg_path, 'r', encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit('agent configuration must be a JSON object')
    agent = lookup(data, 'Agent', {}) or {}
    if not isinstance(agent, dict):
        raise SystemExit('Agent must be a JSON object')
    passive = lookup(agent, 'PassiveTelemetry', {}) or {}
    journal = lookup(agent, 'Journal', {}) or {}
    queue = lookup(agent, 'Queue', {}) or {}
    if not isinstance(passive, dict) or not isinstance(journal, dict) or not isinstance(queue, dict):
        raise SystemExit('PassiveTelemetry, Journal, and Queue must be JSON objects')

def get(block, name, default):
    return lookup(block, name, default)

def integer(block, name, default):
    value = get(block, name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise SystemExit(f'{name} must be a JSON integer')
    return value

def boolean(block, name, default):
    value = get(block, name, default)
    if not isinstance(value, bool):
        raise SystemExit(f'{name} must be a JSON boolean')
    return value

journal_scope = (
    'all_accessible_local'
    if boolean(journal, 'IncludeAccessibleUserJournals', False)
    else 'system_only'
)

values = {
    'startup_delay': integer(passive, 'StartupDelaySeconds', 30),
    'process_interval': integer(passive, 'ProcessPollIntervalSeconds', 15),
    'network_interval': integer(passive, 'NetworkPollIntervalSeconds', 15),
    'metrics_interval': integer(passive, 'HostMetricsIntervalSeconds', 60),
    'scan_timeout': integer(passive, 'ScanTimeoutSeconds', 5),
    'queue_pause': integer(passive, 'QueuePauseDepth', 50000),
    'queue_max_size_mb': integer(queue, 'MaxSizeMb', 512),
    'queue_warning_size_percent': integer(queue, 'WarningSizePercent', 80),
    'journal_queue_pause': integer(journal, 'QueuePauseDepth', 100000),
    'journal_max_records_per_poll': integer(journal, 'MaxRecordsPerPoll', 500),
    'journal_max_input_record_bytes': integer(journal, 'MaxInputRecordBytes', 131072),
    'journal_scope': journal_scope,
    'max_processes': integer(passive, 'MaxProcessesPerScan', 4096),
    'max_sockets': integer(passive, 'MaxSocketsPerScan', 8192),
    'max_events': integer(passive, 'MaxEventsPerScan', 500),
    'process_read_bytes': integer(passive, 'MaxProcessReadBytesPerScan', 16 * 1024 * 1024),
    'network_read_bytes': integer(passive, 'MaxNetworkReadBytesPerScan', 4 * 1024 * 1024),
    'command_line_bytes': integer(passive, 'MaxCommandLineBytes', 4096),
    'raw_event_bytes': integer(passive, 'MaxRawEventBytes', 16 * 1024),
}
cleanup = get(passive, 'CleanupStateOnDisable', False)
if not isinstance(cleanup, bool):
    raise SystemExit('CleanupStateOnDisable must be a JSON boolean')
state_path = get(passive, 'StatePath', '/var/lib/challenger-siem-agent/passive-telemetry-state.json')
if not isinstance(state_path, str):
    raise SystemExit('StatePath must be a JSON string')
if state_path != '/var/lib/challenger-siem-agent/passive-telemetry-state.json':
    raise SystemExit('passive telemetry StatePath must remain the fixed product-owned state file')
queue_max_send_attempts = integer(queue, 'MaxSendAttempts', 10)
queue_max_backoff_seconds = integer(queue, 'MaxBackoffSeconds', 300)
checks = (
    (0 <= values['startup_delay'] <= 300, 'StartupDelaySeconds must be between 0 and 300'),
    (5 <= values['process_interval'] <= 300, 'ProcessPollIntervalSeconds must be between 5 and 300'),
    (5 <= values['network_interval'] <= 300, 'NetworkPollIntervalSeconds must be between 5 and 300'),
    (10 <= values['metrics_interval'] <= 3600, 'HostMetricsIntervalSeconds must be between 10 and 3600'),
    (1 <= values['scan_timeout'] <= 30, 'ScanTimeoutSeconds must be between 1 and 30'),
    (2 * values['scan_timeout'] <= values['process_interval'], 'process interval must be at least twice the scan timeout'),
    (2 * values['scan_timeout'] <= values['network_interval'], 'network interval must be at least twice the scan timeout'),
    (values['scan_timeout'] < values['metrics_interval'], 'metrics interval must exceed the scan timeout'),
    (100 <= values['queue_pause'] <= 1_000_000, 'passive QueuePauseDepth must be between 100 and 1000000'),
    (1 <= values['queue_max_size_mb'] <= 1_048_576, 'queue MaxSizeMb must be between 1 and 1048576'),
    (1 <= queue_max_send_attempts <= 1_000, 'queue MaxSendAttempts must be between 1 and 1000'),
    (1 <= queue_max_backoff_seconds <= 86_400, 'queue MaxBackoffSeconds must be between 1 and 86400'),
    (1 <= values['queue_warning_size_percent'] <= 95, 'queue WarningSizePercent must be between 1 and 95'),
    (100 <= values['journal_queue_pause'] <= 1_000_000, 'journal QueuePauseDepth must be between 100 and 1000000'),
    (1 <= values['journal_max_records_per_poll'] <= 5000, 'journal MaxRecordsPerPoll must be between 1 and 5000'),
    (4096 <= values['journal_max_input_record_bytes'] <= 262144, 'journal MaxInputRecordBytes must be between 4096 and 262144'),
    (1 <= values['max_processes'] <= 4096, 'MaxProcessesPerScan must be between 1 and 4096'),
    (1 <= values['max_sockets'] <= 8192, 'MaxSocketsPerScan must be between 1 and 8192'),
    (1 <= values['max_events'] <= 5000, 'MaxEventsPerScan must be between 1 and 5000'),
    (values['max_events'] <= values['queue_pause'], 'MaxEventsPerScan must not exceed passive QueuePauseDepth'),
    (values['queue_pause'] <= values['journal_queue_pause'], 'passive QueuePauseDepth must not exceed journal QueuePauseDepth'),
    (1024 * 1024 <= values['process_read_bytes'] <= 64 * 1024 * 1024, 'MaxProcessReadBytesPerScan is outside the supported range'),
    (256 * 1024 <= values['network_read_bytes'] <= 16 * 1024 * 1024, 'MaxNetworkReadBytesPerScan is outside the supported range'),
    (256 <= values['command_line_bytes'] <= 4096, 'MaxCommandLineBytes must be between 256 and 4096'),
    (4096 <= values['raw_event_bytes'] <= 32 * 1024, 'MaxRawEventBytes must be between 4096 and 32768'),
)
for valid, message in checks:
    if not valid:
        raise SystemExit(f'invalid passive telemetry plan: {message}')

maximum_queue_bytes = values['queue_max_size_mb'] * 1024 * 1024
soft_queue_limit = maximum_queue_bytes * values['queue_warning_size_percent'] // 100
journal_bytes_per_record = (values['journal_max_input_record_bytes'] + 32 * 1024) * 2
journal_reserve = values['journal_max_records_per_poll'] * journal_bytes_per_record
journal_headroom_limit = max(0, maximum_queue_bytes - min(maximum_queue_bytes, journal_reserve))
passive_byte_limit = min(soft_queue_limit, journal_headroom_limit)
passive_bytes_per_event = (
    values['raw_event_bytes'] + values['command_line_bytes'] * 3 + 32 * 1024
) * 2
maximum_passive_batch_bytes = values['max_events'] * passive_bytes_per_event
if maximum_passive_batch_bytes > passive_byte_limit:
    raise SystemExit(
        'invalid passive telemetry plan: estimated maximum passive batch exceeds '
        'the empty-queue soft byte limit after one journal-poll reserve'
    )

canonical = '\n'.join([
    'linux-passive-snapshot-v1',
    *(f'{name}={value}' for name, value in values.items()),
    'partial_baseline_miss_limit=12',
    f'cleanup_on_disable={cleanup}',
    f'state_path={state_path}',
    'process=/proc/self/mountinfo,/proc/sys/kernel/random/boot_id,/proc/<numeric-pid>/{stat,status,loginuid,cgroup,cmdline,exe}',
    'network=/proc/sys/kernel/random/boot_id,/proc/net/{tcp,tcp6,udp,udp6}',
    'metrics=/proc/sys/kernel/random/boot_id,/proc/{stat,meminfo,loadavg,uptime,diskstats,net/dev,pressure/cpu,pressure/memory,pressure/io}',
    'exclusions=environ,fd,cwd,root,maps,mem,stack,syscall,packet_payload,dns_payload,unix_socket_path',
])
plan_hash = 'sha256:' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()
print(f'passive telemetry approval plan hash: {plan_hash}')
print(
    'passive telemetry schedule/limits: '
    f"startup={values['startup_delay']}s; process={values['process_interval']}s; "
    f"network={values['network_interval']}s; metrics={values['metrics_interval']}s; "
    f"deadline={values['scan_timeout']}s; queue_pause={values['queue_pause']}; "
    f"processes={values['max_processes']}; sockets={values['max_sockets']}; "
    f"events_per_scan={values['max_events']}; process_read_bytes={values['process_read_bytes']}; "
    f"network_read_bytes={values['network_read_bytes']}; command_line_bytes={values['command_line_bytes']}; "
    f"raw_event_bytes={values['raw_event_bytes']}"
)
print(f'passive telemetry cleanup/state: cleanup_on_disable={cleanup}; state={state_path}')
print(
    'journal scope: '
    f'{journal_scope}; system journal visibility remains independently required; '
    'scope changes preserve the durable cursor and do not backfill older records'
)
print(
    'journal scope privacy: '
    + ('all local journals already readable by the service identity may include high-sensitivity user-service text, command lines, paths, and identities; bounded redaction cannot guarantee arbitrary messages are secret-free'
       if journal_scope == 'all_accessible_local'
       else 'system journal only; user journals remain excluded')
)
print(
    'passive telemetry priority relation: '
    f'passive_queue_pause={values["queue_pause"]}; '
    f'journal_queue_pause={values["journal_queue_pause"]}; '
    f'queue_max_size_mb={values["queue_max_size_mb"]}; '
    f'queue_warning_size_percent={values["queue_warning_size_percent"]}; '
    f'journal_poll_reserve_bytes={journal_reserve}; '
    f'maximum_passive_batch_bytes={maximum_passive_batch_bytes}'
)
PY
}

l4_telemetry_binary(){
  if [[ -x $opt/Challenger.Siem.LinuxAgent ]]; then
    printf '%s' "$opt/Challenger.Siem.LinuxAgent"
  elif [[ -n $payload && -x $payload/Challenger.Siem.LinuxAgent ]]; then
    printf '%s' "$payload/Challenger.Siem.LinuxAgent"
  else
    return 1
  fi
}

l4_telemetry_plan(){
  local cfg=$1 binary=''
  if [[ $root != / ]]; then
    echo 'L4 telemetry preflight: skipped for an alternate --root because posture must be observed on the real target host as the service identity'
    return 0
  fi
  if ! binary=$(l4_telemetry_binary); then
    echo 'L4 telemetry preflight: published or installed agent binary unavailable; install with L4 disabled, then rerun this read-only plan on the target host'
    return 0
  fi
  if [[ $(stat -c %a "$cfg" 2>/dev/null || true) != 600 ]]; then
    echo 'L4 telemetry preflight: configuration must be a private mode-0600 file before host posture is observed'
    return 0
  fi
  if ! python3 - <<'PY'
import os

bound = (
    'AGENT:L4TELEMETRY:',
    'AGENT:JOURNAL:ENABLED',
    'AGENT:JOURNAL:TARGETCOVERAGELEVEL',
    'AGENT:JOURNAL:DECLAREDROLES',
    'AGENT:JOURNAL:INCLUDEACCESSIBLEUSERJOURNALS',
    'AGENT:JOURNAL:QUEUEPAUSEDEPTH',
    'AGENT:PASSIVETELEMETRY:ENABLED',
    'AGENT:PASSIVETELEMETRY:QUEUEPAUSEDEPTH',
    'AGENT:QUEUE:MAXSIZEMB',
    'AGENT:QUEUE:WARNINGSIZEPERCENT',
)
for name in os.environ:
    if not name.upper().startswith('CHALLENGER_SIEM_AGENT_'):
        continue
    normalized = name[len('CHALLENGER_SIEM_AGENT_'):].upper().replace('__', ':')
    if any(normalized == item or normalized.startswith(item) for item in bound):
        raise SystemExit(1)
PY
  then
    echo 'L4 telemetry preflight: configuration environment overrides are present; remove them and use the protected JSON file as the approval source'
    return 0
  fi

  echo 'L4 telemetry preflight: bounded non-policy-mutating observation follows; the single-file runtime may populate only its private product-owned bundle cache'
  if [[ ! -d $state ]]; then
    echo 'L4 telemetry preflight: private agent state directory is absent; install with L4 disabled, then rerun the plan as the steady-state identity'
    return 0
  fi
  if [[ $EUID -eq 0 ]]; then
    if ! validate_service_identity true; then
      echo 'L4 telemetry preflight: dedicated challenger-siem identity is absent or is not a locked no-login account with its matching primary group; correct the separately reviewed prerequisite, then rerun the plan'
      return 0
    fi
    if ! command -v runuser >/dev/null 2>&1; then
      echo 'L4 telemetry preflight: runuser is unavailable; invoke the published agent --l4-telemetry-plan as challenger-siem with only CHALLENGER_SIEM_AGENT_CONFIG set'
      return 0
    fi
    if ! runuser -u challenger-siem -- test -w "$state"; then
      echo 'L4 telemetry preflight: private agent state directory is not writable by challenger-siem; validate installed ownership before preflight'
      return 0
    fi
    (
      cd "$state"
      runuser -u challenger-siem -- env -i \
        PATH=/usr/bin:/bin \
        CHALLENGER_SIEM_AGENT_CONFIG="$cfg" \
        DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/challenger-siem-agent/.dotnet-bundle \
        "$binary" --l4-telemetry-plan
    )
    return
  fi
  if [[ $(id -un) != challenger-siem ]]; then
    echo 'L4 telemetry preflight: not executed because the current identity differs from the installed service identity; rerun as root or challenger-siem'
    return 0
  fi
  if [[ ! -w $state ]]; then
    echo 'L4 telemetry preflight: private agent state directory is not writable by the service identity; validate the installed ownership before preflight'
    return 0
  fi
  (
    cd "$state"
    env -i \
      PATH=/usr/bin:/bin \
      CHALLENGER_SIEM_AGENT_CONFIG="$cfg" \
      DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/challenger-siem-agent/.dotnet-bundle \
      "$binary" --l4-telemetry-plan
  )
}

plan(){
  command -v python3 >/dev/null 2>&1 || {
    echo 'Lifecycle planning requires Python 3 for local JSON parsing and deterministic approval-hash calculation.' >&2
    return 1
  }
  local requested_config=''
  if [[ -n $config ]]; then
    requested_config=$config
  elif [[ -e $etc/agentsettings.json || -L $etc/agentsettings.json ]]; then
    requested_config=$etc/agentsettings.json
  fi
  if [[ -n $requested_config ]]; then
    require_regular_bounded_file "$requested_config" $((256 * 1024)) 'Planning configuration'
    [[ $root != / || $(stat -c %a "$requested_config") == 600 ]] || {
      echo 'Planning configuration must be mode 0600 on the real target.' >&2
      return 1
    }
  fi
  echo 'Challenger SIEM Linux Agent plan (read-only)'
  echo "binary: $opt"
  echo "configuration (0600): $etc/agentsettings.json"
  echo "private state/queue (0700): $state"
  echo "unit: $unit"
  echo 'identity requirement: pre-existing challenger-siem account with matching primary group, locked password, and non-login shell; capabilities: none'
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
  echo 'linux L3 passive procfs snapshots: disabled by default; requires Agent:PassiveTelemetry:Enabled=true and its separate matching ApprovedPlanHash'
  if [[ -n $cfg ]]; then
    passive_telemetry_plan "$cfg"
    echo "passive telemetry approval config: $cfg"
  else
    passive_telemetry_plan ''
    echo 'passive telemetry approval config: default options (rerun with --config or installed config for approval)'
  fi
  echo 'passive telemetry fixed inputs: procfs mount-visibility evidence plus process identity/security metadata from /proc/<pid>; TCP/UDP tuples from /proc/net; aggregate CPU/memory/load/disk/network/PSI metrics from fixed procfs files'
  echo 'passive telemetry exclusions: process environment/memory/maps/fd targets/cwd/root/syscalls, file contents, Unix-socket paths, packet/DNS payloads, audit, eBPF, shell history, screenshots, and keystrokes'
  echo 'passive telemetry semantics: polling-honest observed/changed/disappeared snapshots and coalesced metrics; no exact exec/exit/bind/connect claim and no process-to-socket attribution'
  echo 'passive telemetry sequencing/loss/pressure: durable sequence reservation before queue insertion, baseline/checkpoint commit after queue insertion, committed-row ack-before-delete, interrupted-row accepted replay with explicit non-reused recovery gaps, and passive pause before the journal threshold'
  echo 'passive telemetry rollback: disable the pack; optional cleanup removes only /var/lib/challenger-siem-agent/passive-telemetry-state.json and never processes, sockets, policy, the shared queue, or server data'
  echo 'linux L4 posture/SLO/role telemetry: disabled by default; requires target L4, a reviewed supported role declaration, enabled prerequisite packs, and exact separate plan plus posture-baseline approvals'
  echo 'L4 fixed posture inputs: bounded sanitized linux_agent_integrity, linux_firewall, linux_mandatory_access_control, linux_secure_boot, and linux_ssh inventory snapshots; raw values are not emitted by the L4 pack'
  echo 'L4 rolling guardrail: bounded process CPU/RSS/write-rate measurements with queue context; online health does not replace the private VM benchmark and soak'
  echo 'L4 role inputs: fixed systemd journal identifier/unit matches for declared web, database, DNS, file-server, container-host, and identity-server roles; no application files, message mining, new reader, or producer changes'
  echo 'L4 approval order: generate candidate baseline while disabled, copy only its reviewed hash, regenerate the now baseline-bound plan hash, then enable with both exact values'
  echo 'L4 sequencing/loss/pressure: sequence reservation before queue insertion, acknowledgement before deletion, bounded state-only pressure accounting, and L4 yielding before passive L3 and journal collection'
  echo 'L4 rollback: disable the pack; optional cleanup removes only /var/lib/challenger-siem-agent/l4-telemetry-state.json and never changes host posture, journal policy, the shared queue, credentials, or server evidence'
  if [[ -n $cfg ]]; then
    l4_telemetry_plan "$cfg"
    echo "L4 telemetry approval config: $cfg"
  else
    echo 'L4 telemetry preflight: configuration unavailable; rerun with --config or the installed private configuration after installing the agent with L4 disabled'
  fi
}

validate(){
  # Validation is read-only. Do not require administrative execution merely to
  # inspect product-owned paths that the caller can already traverse.
  preflight plan
  require_regular_bounded_file "$opt/Challenger.Siem.LinuxAgent" $((64 * 1024 * 1024)) 'Installed agent binary'
  [[ -x $opt/Challenger.Siem.LinuxAgent ]] || { echo 'agent binary is not executable' >&2; return 1; }
  require_regular_bounded_file "$etc/agentsettings.json" $((256 * 1024)) 'Installed configuration'
  [[ $(stat -c %a "$etc/agentsettings.json") == 600 ]] || { echo 'configuration is not mode 0600' >&2; return 1; }
  require_regular_bounded_file "$unit" $((256 * 1024)) 'Installed systemd unit'
  grep -q '^User=challenger-siem$' "$unit"
  ! grep -Eq 'Token|Password|ApiToken|EnrollmentToken' "$unit"
  if [[ $root == / ]]; then
    validate_service_identity "$([[ $EUID -eq 0 ]] && echo true || echo false)"
  fi
  echo 'validation passed'
}

install(){
  preflight
  [[ -n $payload ]] || { echo 'A published executable payload is required.' >&2; return 1; }
  require_regular_bounded_file "$payload/Challenger.Siem.LinuxAgent" $((64 * 1024 * 1024)) 'Published agent payload'
  [[ -x $payload/Challenger.Siem.LinuxAgent ]] || { echo 'Published agent payload is not executable.' >&2; return 1; }
  [[ -n $config ]] || { echo 'A configuration file is required.' >&2; return 1; }
  require_regular_bounded_file "$config" $((256 * 1024)) 'Configuration input'
  local unit_template="$(dirname "$0")/../packaging/linux/challenger-siem-agent.service"
  if [[ ! -f $unit_template ]]; then
    unit_template="$payload/challenger-siem-agent.service"
  fi
  require_regular_bounded_file "$unit_template" $((256 * 1024)) 'Packaged systemd unit'
  [[ $root != / || $(stat -c %a "$config") == 600 ]] || { echo 'Configuration input must be mode 0600.' >&2; return 1; }
  if [[ $root == / ]]; then
    validate_service_identity true || {
      echo 'Create or correct the locked no-login challenger-siem identity through a separately reviewed prerequisite before install.' >&2
      return 1
    }
  fi
  require_safe_product_target "$opt" dir
  require_safe_product_target "$etc" dir
  require_safe_product_target "$state" dir
  require_safe_product_target "$unit" file
  mkdir -p -m 0755 "$opt" "$(dirname "$unit")"
  mkdir -p -m 0700 "$etc" "$state"
  command install -m 0755 "$payload/Challenger.Siem.LinuxAgent" "$opt/Challenger.Siem.LinuxAgent"
  if [[ -e $etc/agentsettings.json && $config -ef $etc/agentsettings.json ]]; then
    echo 'configuration input is the installed protected configuration; preserving it in place'
  else
    command install -m 0600 "$config" "$etc/agentsettings.json"
  fi
  command install -m 0644 "$unit_template" "$unit"
  if [[ $root == / ]]; then
    chown -R root:root "$opt"
    chown -R challenger-siem:challenger-siem "$etc" "$state"
  fi
  if ! $no_service && [[ $root == / ]]; then
    systemctl daemon-reload
    if [[ $mode == install ]]; then
      systemctl enable --now challenger-siem-agent.service
    else
      systemctl enable challenger-siem-agent.service
      echo 'upgrade staged without starting or restarting the service; obtain approval, then restart separately to activate the new binary/configuration'
    fi
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
