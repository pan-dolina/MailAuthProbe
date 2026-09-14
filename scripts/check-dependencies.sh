#!/usr/bin/env bash
# Verifies module checksums and that the release binary links only modules
# listed in .github/allowed-modules.txt. Adding a dependency therefore
# requires an explicit, reviewed change to that file.
set -euo pipefail

cd "$(dirname "$0")/.."

go mod verify

allowed=".github/allowed-modules.txt"
actual="$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' ./cmd/mailauthprobe | sort -u)"
expected="$(grep -v '^#' "$allowed" | sed '/^$/d' | sort -u)"

if [ "$actual" != "$expected" ]; then
  echo "Modules linked into mailauthprobe differ from $allowed:" >&2
  diff <(echo "$expected") <(echo "$actual") >&2 || true
  exit 1
fi
echo "dependencies OK:"
echo "$actual" | sed 's/^/  /'
