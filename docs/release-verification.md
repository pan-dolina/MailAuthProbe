# Verifying a release

Every release publishes, for each platform archive:

| File | Purpose |
|------|---------|
| `mailauthprobe_<version>_<os>_<arch>.tar.gz` / `.zip` | The binary with LICENSE and README. |
| `*.sigstore.json` | Sigstore bundle: keyless signature, Fulcio certificate and Rekor transparency log entry. |
| `SHA256SUMS` and `SHA256SUMS.sigstore.json` | Checksums of all archives and their signature. |
| `mailauthprobe_<version>_<os>_<arch>.spdx.json` / `.cdx.json` | SBOM of the binary (SPDX 2.3 and CycloneDX). |
| `mailauthprobe.spdx.json` / `mailauthprobe.cdx.json` | SBOM of the Go module. |

GitHub build provenance attestations (SLSA provenance, signed through
Sigstore) are stored for every archive.

Releases are signed without long-lived keys: the release workflow obtains a
short-lived certificate from Sigstore Fulcio using the GitHub Actions OIDC
identity of `.github/workflows/release.yml` for the release tag.

The examples use `v0.1.0` and `linux_amd64`; substitute your version and
platform.

## 1. Check the checksum

```sh
sha256sum --ignore-missing -c SHA256SUMS
# macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
```

## 2. Verify the signature with cosign

Requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.x or newer.

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/marcindolinski/mailauthprobe/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

A valid `SHA256SUMS` signature together with step 1 authenticates every
archive. Individual archives can be verified the same way with their own
`.sigstore.json` bundle.

## 3. Verify build provenance

Requires the [GitHub CLI](https://cli.github.com/).

```sh
gh attestation verify mailauthprobe_0.1.0_linux_amd64.tar.gz \
  --repo marcindolinski/mailauthprobe \
  --signer-workflow marcindolinski/mailauthprobe/.github/workflows/release.yml
```

This confirms that the archive was built by the release workflow from this
repository, and shows the commit it was built from.

## 4. Reproduce the build (optional)

Release builds are reproducible. With the Go version recorded in the release
notes or reported by `mailauthprobe version`:

```sh
git clone https://github.com/marcindolinski/mailauthprobe
cd mailauthprobe
git checkout v0.1.0
VERSION=v0.1.0 scripts/build-release.sh
diff dist/SHA256SUMS /path/to/downloaded/SHA256SUMS
```

The archives must be byte-for-byte identical. A different Go toolchain
version produces different binaries.

## 5. Inspect the SBOM and embedded build information

```sh
go version -m mailauthprobe
```

prints the module versions compiled into the binary; they match the SBOM.
