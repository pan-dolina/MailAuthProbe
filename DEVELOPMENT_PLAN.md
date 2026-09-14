# Development plan

This plan tracks the work towards releases. It is updated as the
implementation progresses; the development journal in
[docs/development.md](docs/development.md) records what actually happened.

## Milestone 1 – foundations

- [x] Go module, license, repository hygiene
- [x] Threat model and architecture
- [x] CLI skeleton with version information and shell completion
- [x] Finding model, severities and stable ID catalog
- [x] DNS resolver abstraction (timeouts, response size limit, query budget)
- [x] Deterministic DNS test infrastructure (in-memory zone, local server)

## Milestone 2 – domain assessment

- [x] MX discovery and validation (null MX, CNAME targets, address records)
- [x] SPF parser (RFC 7208 ABNF, macros)
- [x] SPF evaluator (lookup and void-lookup limits, loops, dependency tree)
- [x] DMARC record parsing, policy discovery and validation
- [x] DKIM key record parsing (`--dkim-selector`)
- [x] MTA-STS record and policy fetch
- [x] TLS-RPT record

## Milestone 3 – message analysis

- [x] RFC 5322 header and MIME structure parser with hostile-input limits
- [x] DKIM cryptographic verification (simple/relaxed, rsa-sha256, ed25519-sha256)
- [x] Received chain model (stated vs inferred data)
- [x] Authentication-Results and Received-SPF parsing
- [x] SPF verification in message context (`--source-ip`, `--helo`, `--mail-from`)
- [x] Independent DMARC evaluation and comparison with Authentication-Results

## Milestone 4 – output and quality

- [x] Human-readable terminal report
- [x] Versioned JSON report
- [x] Golden output and CLI functional tests
- [x] Fuzz targets for all hostile parsers
- [x] Benchmarks for parsers and evaluators

## Milestone 5 – release engineering

- [x] Cross-platform CI
- [x] Static analysis and vulnerability scanning
- [x] SBOM generation and dependency verification
- [x] Reproducible cross-platform release builds
- [x] Keyless signing (Sigstore) and build provenance
- [x] Release artifact smoke tests
- [x] Documentation: standards coverage, limitations, release verification
- [x] v0.1.0

## After v0.1.0

- [ ] ARC signature verification (RFC 8617)
- [ ] Optional DNSSEC-validating resolver mode (AD bit checks)
- [ ] DANE/TLSA checks for MX hosts (RFC 7672)
- [ ] BIMI record validation
- [ ] SARIF output for code-scanning integrations
- [ ] Longer continuous fuzzing (OSS-Fuzz or scheduled workflow)
