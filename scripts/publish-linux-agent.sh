#!/usr/bin/env bash
set -euo pipefail
umask 077

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root_dir"

runtime=${1:-linux-x64}
case "$runtime" in
  linux-x64|linux-arm64) ;;
  *)
    echo 'Usage: ./scripts/publish-linux-agent.sh [linux-x64|linux-arm64] [output-directory]' >&2
    exit 2
    ;;
esac

output_dir=${2:-dist/linux-agent-$runtime}
binary=$output_dir/Challenger.Siem.LinuxAgent
if [[ -L $output_dir ]]; then
  echo 'Linux publish output must not be a symlink.' >&2
  exit 1
fi
output_abs=$(realpath -m -- "$output_dir")

if [[ $output_abs == "$root_dir" || $output_abs == "$root_dir"/* ]]; then
  case "$output_abs" in
    "$root_dir/dist/"*|"$root_dir/.local/"*) ;;
    *) echo 'Repository-local publish output must be below the private dist/ or .local/ tree.' >&2; exit 1 ;;
  esac
  if ! git check-ignore -q -- "$output_abs/"; then
    echo 'Repository-local publish output must be gitignored.' >&2
    exit 1
  fi
fi
if [[ -e $output_dir && ! -d $output_dir ]]; then
  echo 'Linux publish output exists and is not a directory.' >&2
  exit 1
fi
if [[ -d $output_dir && -n $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo 'Linux publish output must be empty to prevent stale or credential-bearing files entering the bundle.' >&2
  exit 1
fi
mkdir -p -m 0700 "$output_dir"
chmod 0700 "$output_dir"

dotnet publish agent/LinuxAgent/LinuxAgent.csproj \
  -c Release \
  -r "$runtime" \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true \
  -p:DebugType=None \
  -o "$output_dir"

[[ -f $binary ]] || {
  echo 'Linux publish did not produce the installer-required Challenger.Siem.LinuxAgent executable.' >&2
  exit 1
}
chmod 0755 "$binary"
command install -m 0755 scripts/linux-agent.sh "$output_dir/linux-agent.sh"
command install -m 0644 packaging/linux/challenger-siem-agent.service "$output_dir/challenger-siem-agent.service"
command install -m 0644 examples/synthetic-linux-agent-config.json "$output_dir/agentsettings.synthetic.example.json"

entry_count=0
while IFS= read -r -d '' entry; do
  entry_count=$((entry_count + 1))
  [[ -f $entry && ! -L $entry ]] || {
    echo 'Published Linux bundle contains a non-regular or linked top-level entry.' >&2
    exit 1
  }
  case $(basename "$entry") in
    Challenger.Siem.LinuxAgent|linux-agent.sh|challenger-siem-agent.service|agentsettings.synthetic.example.json) ;;
    *) echo 'Published Linux bundle contains an unexpected top-level file.' >&2; exit 1 ;;
  esac
done < <(find "$output_dir" -mindepth 1 -maxdepth 1 -print0)
[[ $entry_count -eq 4 ]] || {
  echo 'Published Linux bundle does not contain the exact four-file payload allowlist.' >&2
  exit 1
}

size=$(stat -c %s "$binary")
maximum_size=$((64 * 1024 * 1024))
if ((size > maximum_size)); then
  echo 'Published Linux agent exceeds the fixed 64 MiB self-integrity and installer safety cap.' >&2
  exit 1
fi

echo "Published standalone $runtime Linux agent:"
echo "  $binary"
echo "Size: $size bytes"
echo "SHA256: $(sha256sum "$binary" | awk '{print $1}')"
echo 'Bundle contents include the lifecycle helper, systemd unit, and a placeholder-only synthetic configuration reference.'
echo 'Keep this generated payload and every real agent configuration outside Git; run the bundled linux-agent.sh plan before deployment.'
