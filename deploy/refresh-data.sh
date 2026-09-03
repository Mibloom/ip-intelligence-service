#!/bin/bash
set -euo pipefail

project_dir="${IP_INTELLIGENCE_DIR:-/opt/ip-intelligence-service}"
credentials_file="${MAXMIND_ENV_FILE:-/etc/ip-intelligence/maxmind.env}"
mode="${1:-all}"

exec 9>/run/lock/ip-intelligence-data-update.lock
if ! flock -n 9; then
  echo "Another IP intelligence data update is already running; skipping."
  exit 0
fi

cd "$project_dir"

update_cloud() {
  ./scripts/update-cloud-ranges.sh
}

update_threat() {
  ./scripts/update-threat-ranges.sh
}

update_dbip() {
  ./scripts/update-dbip.sh
}

update_maxmind() {
  if [[ ! -r "$credentials_file" ]]; then
    echo "MaxMind credentials are not configured; skipping GeoLite2 update."
    return
  fi
  set -a
  source "$credentials_file"
  set +a
  ./scripts/update-maxmind.sh
  unset MAXMIND_ACCOUNT_ID MAXMIND_LICENSE_KEY
}

case "$mode" in
  cloud)
    update_cloud
    ;;
  threat)
    update_threat
    ;;
  dbip)
    update_dbip
    ;;
  maxmind)
    update_maxmind
    ;;
  all)
    update_cloud
    update_threat
    update_dbip
    update_maxmind
    ;;
  *)
    echo "Usage: $0 {cloud|threat|dbip|maxmind|all}" >&2
    exit 2
    ;;
esac

docker compose restart ip-intelligence

for _ in {1..15}; do
  if curl --fail --silent http://127.0.0.1:18080/ready >/dev/null; then
    echo "IP intelligence data update completed; service is ready."
    exit 0
  fi
  sleep 2
done

echo "IP intelligence did not become ready after the data update." >&2
exit 1
