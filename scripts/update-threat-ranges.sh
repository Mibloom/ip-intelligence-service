#!/bin/sh
set -eu

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output="${1:-$root_dir/data/rules/threat.json}"

if command -v go >/dev/null 2>&1; then
  cd "$root_dir"
  exec go run ./cmd/update-threat-ranges -output "$output"
fi

exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$root_dir:/src" \
  --workdir /src \
  golang:1.23-alpine \
  go run ./cmd/update-threat-ranges -output "$output"
