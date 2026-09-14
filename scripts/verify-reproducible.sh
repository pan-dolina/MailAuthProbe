#!/usr/bin/env bash
# Builds the release twice in separate directories and compares checksums.
set -euo pipefail

cd "$(dirname "$0")/.."
a="$(mktemp -d)"
b="$(mktemp -d)"
modcache="$(mktemp -d)"
cleanup() {
  # Module cache files are read-only.
  chmod -R u+w "$modcache" 2>/dev/null || true
  rm -rf "$a" "$b" "$modcache"
}
trap cleanup EXIT

DIST="$a" scripts/build-release.sh >/dev/null
# A different module cache and build cache must not change the output.
GOMODCACHE="$modcache" GOCACHE="$modcache/build" GOFLAGS=-modcacherw DIST="$b" scripts/build-release.sh >/dev/null

if ! diff "$a/SHA256SUMS" "$b/SHA256SUMS"; then
  echo "release build is not reproducible" >&2
  exit 1
fi
echo "reproducible:"
cat "$a/SHA256SUMS"
