#!/usr/bin/env bash
# Builds release archives for all supported platforms into dist/.
#
# The build is reproducible: given the same commit and Go toolchain, the
# archives and SHA256SUMS are byte-for-byte identical. Inputs that would
# otherwise vary (paths, build IDs, timestamps) are fixed:
#   - go build -trimpath, -buildid= and CGO_ENABLED=0
#   - version metadata taken from git (tag, commit, commit date)
#   - archive entries timestamped with the commit time (SOURCE_DATE_EPOCH)
#
# Environment:
#   VERSION  release version (default: exact git tag, else v0.0.0-<commit>)
#   DIST     output directory (default: dist)
set -euo pipefail

cd "$(dirname "$0")/.."

DIST="${DIST:-dist}"
COMMIT="$(git rev-parse HEAD)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
DATE="$(git log -1 --format=%cI)"
VERSION="${VERSION:-$(git describe --tags --exact-match 2>/dev/null || echo "v0.0.0-${COMMIT:0:12}")}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "warning: working tree has uncommitted changes; the build is not reproducible from the commit" >&2
fi

pkg="github.com/marcindolinski/mailauthprobe/internal/version"
ldflags="-s -w -buildid= -X ${pkg}.Version=${VERSION} -X ${pkg}.Commit=${COMMIT} -X ${pkg}.Date=${DATE}"

rm -rf "$DIST"
mkdir -p "$DIST"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

go build -o "$work/archive" ./internal/tools/archive

for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="mailauthprobe_${VERSION#v}_${goos}_${goarch}"
  exe="mailauthprobe"
  [ "$goos" = "windows" ] && exe="mailauthprobe.exe"

  echo "building $name"
  mkdir -p "$work/$name"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$work/$name/$exe" ./cmd/mailauthprobe

  ext="tar.gz"
  [ "$goos" = "windows" ] && ext="zip"
  "$work/archive" -o "$DIST/$name.$ext" -mtime "$SOURCE_DATE_EPOCH" -exec "$exe" \
    "$exe=$work/$name/$exe" "LICENSE=LICENSE" "README.md=README.md"
done

(
  cd "$DIST"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- *.tar.gz *.zip | LC_ALL=C sort -k2 > SHA256SUMS
  else
    shasum -a 256 -- *.tar.gz *.zip | LC_ALL=C sort -k2 > SHA256SUMS
  fi
)
echo "wrote $DIST/SHA256SUMS"
cat "$DIST/SHA256SUMS"
