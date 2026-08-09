#!/usr/bin/env bash
set -euo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-}
agent_binary=${2:-}
signing_key=${3:-}
public_key=${4:-}
plan_hash=${5:-}
fixed_helper=${CHALLENGER_SIEM_FIXED_HELPER_BINARY:-}
if [[ -z $output || -z $agent_binary || -z $signing_key || -z $public_key || -z $plan_hash ]]; then
  echo 'Usage: build-kernel-network-bundle.sh OUTPUT AGENT_BINARY ED25519_PRIVATE_KEY ED25519_PUBLIC_KEY PLAN_HASH' >&2
  exit 2
fi
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'The initial kernel network helper supports Linux x86_64 only.' >&2; exit 1; }
[[ $plan_hash =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'PLAN_HASH must be a lowercase sha256 plan identifier.' >&2; exit 2; }
for path in "$agent_binary" "$signing_key" "$public_key"; do
  [[ -f $path && ! -L $path ]] || { echo 'Every bundle input must be a regular non-symlink file.' >&2; exit 1; }
done
if [[ -n $fixed_helper ]]; then
  [[ -f $fixed_helper && ! -L $fixed_helper ]] || { echo 'The fixed helper override must be a regular non-symlink file.' >&2; exit 1; }
fi
output_abs=$(realpath -m -- "$output")
if [[ $output_abs == "$root_dir"/* ]]; then
  case "$output_abs" in "$root_dir/dist/"*|"$root_dir/.local/"*) ;; *) echo 'Repository-local bundle output must be under ignored dist/ or .local/.' >&2; exit 1 ;; esac
  git -C "$root_dir" check-ignore -q -- "$output_abs/" || { echo 'Repository-local bundle output must be gitignored.' >&2; exit 1; }
fi
[[ ! -e $output || -d $output ]] || { echo 'Output exists and is not a directory.' >&2; exit 1; }
[[ ! -d $output || -z $(find "$output" -mindepth 1 -maxdepth 1 -print -quit) ]] || { echo 'Output directory must be empty.' >&2; exit 1; }
mkdir -p -m 0700 "$output"
build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT
if [[ -z $fixed_helper ]]; then
  make -C "$root_dir/agent/KernelNetwork/Native" BUILD_DIR="$build_dir"
  fixed_helper=$build_dir/challenger-siem-ebpf-helper
fi
command install -m 0755 "$agent_binary" "$output/Challenger.Siem.LinuxAgent"
command install -m 0755 "$fixed_helper" "$output/Challenger.Siem.EbpfHelper"
command install -m 0644 "$root_dir/packaging/linux/challenger-siem-agent.service" "$output/challenger-siem-agent.service"
command install -m 0644 "$root_dir/packaging/linux/challenger-siem-agent-kernel-network.conf" "$output/challenger-siem-agent-kernel-network.conf"
command install -m 0644 "$root_dir/packaging/linux/challenger-siem-ebpf-helper.service" "$output/challenger-siem-ebpf-helper.service"
command install -m 0644 "$root_dir/packaging/linux/challenger-siem-ebpf-helper.socket" "$output/challenger-siem-ebpf-helper.socket"
fingerprint=$(openssl pkey -pubin -in "$public_key" -outform DER | sha256sum | awk '{print $1}')
python3 - "$output" "$plan_hash" "$fingerprint" <<'PY'
import hashlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1])
files = [
    'Challenger.Siem.LinuxAgent',
    'Challenger.Siem.EbpfHelper',
    'challenger-siem-agent.service',
    'challenger-siem-agent-kernel-network.conf',
    'challenger-siem-ebpf-helper.service',
    'challenger-siem-ebpf-helper.socket',
]
manifest = {
    'schema_version': 1,
    'bundle_type': 'challenger-siem-kernel-network-linux-x64',
    'plan_hash': sys.argv[2],
    'signer_public_key_sha256': sys.argv[3],
    'helper_version': 'challenger-siem-ebpf-helper-v2',
    'collector_version': 'linux-network-flow-summary-v3',
    'privacy_boundary': 'tcp_udp_ipv4_ipv6_headers_and_aggregate_counters_only_no_payload',
    'required_capabilities': ['CAP_BPF', 'CAP_PERFMON', 'CAP_NET_ADMIN'],
    'files': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files},
}
(root / 'kernel-network-manifest.json').write_text(
    json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
openssl pkeyutl -sign -rawin -inkey "$signing_key" \
  -in "$output/kernel-network-manifest.json" -out "$output/kernel-network-manifest.sig"
chmod 0600 "$output/kernel-network-manifest.json" "$output/kernel-network-manifest.sig"
echo "Signed kernel network bundle created at $output"
echo "Signer public-key SHA-256: $fingerprint"
echo "Bound plan: $plan_hash"
