# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/). Finding IDs and the
JSON `schema_version` are part of the public interface.

## [Unreleased]

## [0.1.0] - 2026-09-14

First public release.

### Added

- `domain` command: MX, SPF (with dependency tree and lookup counting), DKIM
  key records for given selectors, DMARC, MTA-STS and TLS-RPT assessment.
- `message` and `headers` commands: RFC 5322 and MIME parsing with resource
  limits, Received chain modelling with stated and inferred values,
  cryptographic DKIM verification (rsa-sha256, ed25519-sha256), SPF and DMARC
  evaluation, Authentication-Results comparison and conflict detection, ARC
  structure checks.
- Human-readable terminal output and versioned JSON output
  (`schema_version: "1"`), stable finding IDs, `--fail-on` threshold and
  documented exit codes.
- Shell completion for bash, zsh and fish.
- Reproducible release archives for Linux, macOS and Windows with SHA256SUMS,
  SPDX and CycloneDX SBOMs, Sigstore keyless signatures and build provenance.
