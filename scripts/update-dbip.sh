#!/bin/sh
set -eu

release="${DBIP_RELEASE:-$(date -u +%Y-%m)}"
destination="${1:-data/geoip}"
base_url="https://download.db-ip.com/free"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

mkdir -p "$destination"

download() {
  database="$1"
  output="$2"
  archive="$tmp_dir/$database.mmdb.gz"
  unpacked="$tmp_dir/$database.mmdb"
  url="$base_url/dbip-$database-lite-$release.mmdb.gz"

  printf 'Downloading %s\n' "$url"
  curl --fail --location --retry 3 --silent --show-error --output "$archive" "$url"
  gzip -t "$archive"
  gzip -dc "$archive" > "$unpacked"
  test -s "$unpacked"
  chmod 0644 "$unpacked"
  mv "$unpacked" "$destination/$output"
}

download country country.mmdb
download asn asn.mmdb

printf 'DB-IP Lite %s databases installed in %s\n' "$release" "$destination"
