#!/usr/bin/env bash
set -euo pipefail
umask 077

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT

publish=$work/publish
config=$work/agentsettings.json
private_key=$work/signing-private.pem
public_key=$work/signing-public.pem
bundle=$work/bundle
fixed_helper_bundle=$work/fixed-helper-bundle
mismatched_bundle=$work/mismatched-bundle
target=$work/target

"$repository/scripts/publish-linux-agent.sh" linux-x64 "$publish" >/dev/null
make -C "$repository/agent/KernelNetwork/Native" clean all >/dev/null
openssl genpkey -algorithm ED25519 -out "$private_key" >/dev/null 2>&1
openssl pkey -in "$private_key" -pubout -out "$public_key" >/dev/null 2>&1
helper_hash="sha256:$(sha256sum "$repository/agent/KernelNetwork/Native/build/challenger-siem-ebpf-helper" | awk '{print $1}')"
signer_hash="sha256:$(openssl pkey -pubin -in "$public_key" -outform DER | sha256sum | awk '{print $1}')"
command install -m 0600 "$repository/examples/synthetic-linux-agent-config.json" "$config"
python3 - "$config" "$helper_hash" "$signer_hash" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding='utf-8'))
value['Agent']['KernelNetworkTelemetry']['Enabled'] = True
value['Agent']['KernelNetworkTelemetry']['ApprovedPlanHash'] = ''
value['Agent']['KernelNetworkTelemetry']['ApprovedHelperSha256'] = sys.argv[2]
value['Agent']['KernelNetworkTelemetry']['ApprovedSignerPublicKeySha256'] = sys.argv[3]
path.write_text(json.dumps(value, separators=(',', ':')) + '\n', encoding='utf-8')
PY

plan=$(CHALLENGER_SIEM_AGENT_CONFIG="$config" "$publish/Challenger.Siem.LinuxAgent" --kernel-network-plan)
plan_hash=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["plan_hash"])' <<<"$plan")
python3 - "$config" "$plan_hash" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding='utf-8'))
value['Agent']['KernelNetworkTelemetry']['ApprovedPlanHash'] = sys.argv[2]
path.write_text(json.dumps(value, separators=(',', ':')) + '\n', encoding='utf-8')
PY

"$repository/scripts/build-kernel-network-bundle.sh" \
  "$bundle" "$publish/Challenger.Siem.LinuxAgent" "$private_key" "$public_key" "$plan_hash" >/dev/null
CHALLENGER_SIEM_FIXED_HELPER_BINARY="$bundle/Challenger.Siem.EbpfHelper" \
  "$repository/scripts/build-kernel-network-bundle.sh" \
  "$fixed_helper_bundle" "$publish/Challenger.Siem.LinuxAgent" "$private_key" "$public_key" "$plan_hash" >/dev/null
cmp -s "$bundle/Challenger.Siem.EbpfHelper" "$fixed_helper_bundle/Challenger.Siem.EbpfHelper"

command install -d -m 0755 "$target/opt/challenger-siem-agent" "$target/etc/systemd/system"
command install -m 0755 "$bundle/Challenger.Siem.LinuxAgent" "$target/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent"
command install -m 0644 "$bundle/challenger-siem-agent.service" "$target/etc/systemd/system/challenger-siem-agent.service"

common=(--bundle "$bundle" --config "$config" --public-key "$public_key" --root "$target" --no-service)
fixed_helper_common=(--bundle "$fixed_helper_bundle" --config "$config" --public-key "$public_key" --root "$target" --no-service)
cp -a -- "$bundle" "$mismatched_bundle"
python3 - "$mismatched_bundle/kernel-network-manifest.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding='utf-8'))
value['collector_version'] = 'linux-network-flow-summary-v1'
path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
openssl pkeyutl -sign -rawin -inkey "$private_key" \
  -in "$mismatched_bundle/kernel-network-manifest.json" \
  -out "$mismatched_bundle/kernel-network-manifest.sig"
mismatched_common=(--bundle "$mismatched_bundle" --config "$config" --public-key "$public_key" --root "$target" --no-service)
if "$repository/scripts/kernel-network.sh" plan "${mismatched_common[@]}" >/dev/null 2>&1; then
  echo 'Signed manifest with a mismatched collector version unexpectedly validated.' >&2
  exit 1
fi
"$repository/scripts/kernel-network.sh" plan "${common[@]}" >/dev/null
"$repository/scripts/kernel-network.sh" plan "${fixed_helper_common[@]}" >/dev/null
"$repository/scripts/kernel-network.sh" enable "${common[@]}" >/dev/null
"$repository/scripts/kernel-network.sh" validate "${common[@]}" >/dev/null

[[ -x $target/opt/challenger-siem-agent/Challenger.Siem.EbpfHelper ]]
[[ -f $target/etc/systemd/system/challenger-siem-ebpf-helper.service ]]
[[ -f $target/etc/systemd/system/challenger-siem-ebpf-helper.socket ]]
[[ -f $target/etc/systemd/system/challenger-siem-agent.service.d/40-kernel-network.conf ]]
[[ -f $target/etc/challenger-siem-agent/kernel-network-signing-key.pem ]]

python3 - "$bundle/Challenger.Siem.EbpfHelper" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(path.read_bytes() + b'\x00')
PY
if "$repository/scripts/kernel-network.sh" validate "${common[@]}" >/dev/null 2>&1; then
  echo 'Tampered signed bundle unexpectedly validated.' >&2
  exit 1
fi

"$repository/scripts/kernel-network.sh" disable --root "$target" --no-service >/dev/null
[[ -x $target/opt/challenger-siem-agent/Challenger.Siem.LinuxAgent ]]
[[ -f $target/etc/systemd/system/challenger-siem-agent.service ]]
[[ ! -e $target/opt/challenger-siem-agent/Challenger.Siem.EbpfHelper ]]
[[ ! -e $target/etc/systemd/system/challenger-siem-ebpf-helper.service ]]
[[ ! -e $target/etc/systemd/system/challenger-siem-ebpf-helper.socket ]]

echo 'kernel network signed lifecycle validation passed'
