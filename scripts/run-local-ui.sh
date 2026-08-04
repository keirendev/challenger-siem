#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

required=(
  ConnectionStrings__SiemDatabase
  Auth__EnrollmentToken
  Auth__ServiceToken
  TrafficMap__Enabled
  TrafficMap__PublicBaseUrl
  TrafficMap__Origin__Label
  TrafficMap__Origin__Latitude
  TrafficMap__Origin__Longitude
  TrafficMap__Geolocation__CachePath
)

missing=()
for name in "${required[@]}"; do
  if [[ -z ${!name:-} ]]; then missing+=("$name"); fi
done
if ((${#missing[@]})); then
  printf 'Missing required local UI environment keys:\n' >&2
  printf ' - %s\n' "${missing[@]}" >&2
  printf 'Load an ignored local environment file before running this script.\n' >&2
  exit 1
fi
if [[ ${TrafficMap__Enabled,,} != true ]]; then
  printf 'TrafficMap__Enabled must be true for the local UI.\n' >&2
  exit 1
fi

traffic_map_port=${SIEM_TRAFFIC_MAP_PORT:-55444}
if [[ ! $traffic_map_port =~ ^[0-9]+$ ]] || ((traffic_map_port < 49152 || traffic_map_port > 65535)); then
  printf 'SIEM_TRAFFIC_MAP_PORT must be a high local port from 49152 through 65535.\n' >&2
  exit 1
fi
expected_public_base_url="http://127.0.0.1:$traffic_map_port"
if [[ $TrafficMap__PublicBaseUrl != "$expected_public_base_url" ]]; then
  printf 'TrafficMap__PublicBaseUrl must exactly match %s for this loopback launcher.\n' "$expected_public_base_url" >&2
  exit 1
fi

if [[ ${TrafficMap__ReadOnlyDatabase:-false} == true ]]; then
  "$repository/scripts/validate-traffic-map-database.sh"
else
  "$repository/scripts/validate-schema.sh"
fi
"$repository/scripts/build-ui.sh"
export ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Development}"
exec dotnet run --project "$repository/server/Siem.Api" --no-launch-profile --urls "$expected_public_base_url"
