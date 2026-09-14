# Development plan

This plan tracks the work towards the first public release. It is updated as
the implementation progresses; the development journal in
[docs/development.md](docs/development.md) records what actually happened.

## Milestone 1 – foundations

- [ ] Go module, license, repository hygiene
- [ ] Threat model and architecture
- [ ] CLI skeleton with version information and shell completion
- [ ] Finding model, severities and stable ID catalog
- [ ] DNS resolver abstraction (timeouts, response size limit, query budget)
- [ ] Deterministic DNS test infrastructure (in-memory zone, local server)

## Milestone 2 – domain assessment

- [ ] MX discovery and validation (null MX, CNAME targets, address records)
- [ ] SPF parser (RFC 7208 ABNF, macros)
- [ ] SPF evaluator (lookup and void-lookup limits, loops, dependency tree)
- [ ] DMARC record parsing, policy discovery and validation
- [ ] DKIM key record parsing (`--dkim-selector`)
- [ ] MTA-STS record and policy fetch
- [ ] TLS-RPT record

## Milestone 3 – message analysis

- [ ] RFC 5322 header and MIME structure parser with hostile-input limits
- [ ] DKIM cryptographic verification (simple/relaxed, rsa-sha256, ed25519-sha256)
- [ ] Received chain model (stated vs inferred data)
- [ ] Authentication-Results and Received-SPF parsing
- [ ] SPF verification in message context (`--source-ip`, `--helo`, `--mail-from`)
- [ ] Independent DMARC evaluation and comparison with Authentication-Results

## Milestone 4 – output and quality

- [ ] Human-readable terminal report
- [ ] Versioned JSON report
- [ ] Golden output and CLI functional tests
- [ ] Fuzz targets for all hostile parsers
- [ ] Benchmarks for parsers and evaluators

## Milestone 5 – release engineering

- [ ] Cross-platform CI
- [ ] Static analysis and vulnerability scanning
- [ ] SBOM generation and dependency verification
- [ ] Reproducible cross-platform release builds
- [ ] Keyless signing (Sigstore) and build provenance
- [ ] Release artifact smoke tests
- [ ] Documentation: standards coverage, limitations, release verification
- [ ] v0.1.0
