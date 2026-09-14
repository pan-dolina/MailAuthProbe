#!/usr/bin/env bash
# Generates SPDX and CycloneDX SBOMs.
#
#   scripts/sbom.sh <output-dir> [binary...]
#
# Without binaries, SBOMs describe the Go module (go.mod/go.sum). With
# binaries, one pair of SBOMs is written per binary, based on the build
# information embedded by the Go toolchain.
set -euo pipefail

out="${1:?usage: scripts/sbom.sh <output-dir> [binary...]}"
shift
mkdir -p "$out"

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required (https://github.com/anchore/syft)" >&2
  exit 1
fi

export SYFT_CHECK_FOR_APP_UPDATE=false

if [ "$#" -eq 0 ]; then
  out="$(cd "$out" && pwd)"
  cd "$(dirname "$0")/.."
  syft scan dir:. --source-name mailauthprobe --source-version "${VERSION:-unknown}" \
    --override-default-catalogers go-module-file-cataloger --select-catalogers -file \
    -o "spdx-json=$out/mailauthprobe.spdx.json" \
    -o "cyclonedx-json=$out/mailauthprobe.cdx.json"
  exit 0
fi

out="$(cd "$out" && pwd)"
for bin in "$@"; do
  file="$(basename "$bin")"
  name="${SBOM_NAME:-${file%.exe}}"
  # Scan from the binary's directory so that no local paths end up in the
  # SBOM.
  (cd "$(dirname "$bin")" && syft scan "file:$file" --source-name "$name" --select-catalogers -file \
    -o "spdx-json=$out/$name.spdx.json" \
    -o "cyclonedx-json=$out/$name.cdx.json")
done
