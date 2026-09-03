#!/bin/sh
set -eu

: "${MAXMIND_ACCOUNT_ID:?MAXMIND_ACCOUNT_ID is required}"
: "${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY is required}"

destination="${1:-data/geoip}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

mkdir -p "$destination"

download() {
  edition="$1"
  output="$2"
  archive="$tmp_dir/$edition.tar.gz"
  unpacked="$tmp_dir/$output"
  url="https://download.maxmind.com/geoip/databases/$edition/download?suffix=tar.gz"

  printf 'Downloading %s\n' "$edition"
  curl --fail --location --retry 3 --silent --show-error \
    --user "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" \
    --output "$archive" "$url"
  gzip -t "$archive"
  member="$(tar -tzf "$archive" | awk '/\.mmdb$/ { member = $0 } END { print member }')"
  test -n "$member"
  tar -xOzf "$archive" "$member" > "$unpacked"
  test -s "$unpacked"
  chmod 0644 "$unpacked"
  mv "$unpacked" "$destination/$output"
}

download GeoLite2-Country maxmind-country.mmdb
download GeoLite2-ASN maxmind-asn.mmdb

printf 'MaxMind GeoLite2 databases installed in %s\n' "$destination"
