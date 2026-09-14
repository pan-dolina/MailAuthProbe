# Development journal

A running record of problems, decisions and changes made while building
MailAuthProbe. Newest entries at the bottom of each section.

## Setup

- Toolchain: Go 1.27 locally; `go.mod` declares `go 1.26.0` so the previous
  stable release can still build the project.
- Module path: `github.com/pan-dolina/mailauthprobe`.

## Dependency decisions

- **github.com/spf13/cobra** (+ spf13/pflag). Considered the standard library
  `flag` package with hand-written completion scripts. Cobra provides POSIX
  flags, nested subcommands and maintained bash/zsh/fish completion generators;
  writing and testing three completion scripts by hand is more code to audit
  than the dependency itself. Cobra has no transitive runtime dependencies
  beyond pflag (mousetrap is Windows-only).
- **golang.org/x/net** for `dns/dnsmessage` (stub resolver and test DNS
  server) and, later, `publicsuffix` (DMARC organizational domain). Chosen
  over `miekg/dns` to keep the graph to one module; see ADR 0001.

## Design decisions

- Exit codes are defined once in `internal/cli/exitcode.go` and printed in
  `--help`. Cobra's own flag and argument errors are mapped to exit code 2 by
  treating every untyped error as a usage error; every error created by our
  commands carries an explicit code.
- The DNS client ignores UDP datagrams whose ID or question does not match
  instead of failing the query. A mismatching datagram is more likely a late
  answer to an earlier attempt (or spoofing) than a server bug, and failing
  would turn a harmless race into a `temperror`.
- Resolver wrappers are composed as `Cache(Budget(Client))`: cached answers do
  not consume budget, so repeated checks of the same record are free.
- SPF has two evaluation modes. `Checker.CheckHost` is a faithful
  `check_host()` for one client IP and stops at the first match.
  `Analyzer.Analyze` walks the whole include/redirect tree to compute the
  worst-case lookup count a receiver may need; terms after `all` and a
  redirect next to `all` are not counted because receivers never evaluate
  them. Terms whose domain depends on sender or client macros are counted but
  not followed.
- Include loops are detected explicitly (domain already on the evaluation
  stack) instead of relying on the lookup limit, so the report can show the
  actual cycle. Including the same domain twice on different branches is
  legal and is not reported as a loop.
- DKIM verification is implemented on the standard library rather than
  using go-msgauth (ADR 0003). To check it independently, a throw-away
  program outside the module signed messages with each implementation and
  verified them with the other: 4 canonicalization modes x RSA/Ed25519 x 4
  body shapes, in both directions, 64 combinations, all passing. go-msgauth
  v0.7.0 was used for this check only.
- Exchange Online writes Authentication-Results without an authserv-id and
  with bare properties (`action=none`, `compauth=pass reason=100`). The first
  parser rejected such headers as invalid RFC 8601, which would have hidden
  the most common source of conflicting results. They are now accepted with
  an empty authserv-id.
- The message parser keeps each header field's raw bytes (`Header.Raw`)
  next to the unfolded value. DKIM canonicalization must operate on the bytes
  that were signed; reconstructing them from parsed values loses folding and
  whitespace.
- A line in the header section that is neither a field nor a continuation is
  treated as the start of the body, matching what Postfix and Exim do. The
  alternative (skipping the line) would let an attacker hide header fields
  from MailAuthProbe that receivers never saw.
- Message size and header section limits are hard errors (exit code 3);
  MIME depth and part limits are defects. Authentication does not depend on
  MIME structure, so a message with 10 000 parts can still be verified.
- Running the new fixtures through the CLI showed that a message without a
  Return-Path fed the HELO SPF result into DMARC. RFC 7489 uses the HELO
  identity only for a null reverse-path; with an unknown MAIL FROM the SPF
  input to DMARC is now "not evaluated".
- Domain checks run concurrently. The first cache implementation stored an
  answer only after the lookup returned, so two checks asking for the same
  name at the same time (for example `mx.Assess` and an SPF `mx` mechanism)
  both hit the network and the `dns_queries` count in the JSON report varied
  between runs. The cache now shares in-flight lookups.
- Owner names in answers are compared case-insensitively: servers and
  forwarders using 0x20 case randomisation return names in mixed case.
- DKIM selectors for domain audits (after 0.1.0). Selectors cannot be
  enumerated, but most hosted services tell customers to publish fixed names
  (`google`, `selector1`/`selector2`, `s1`/`s2`, ...). `internal/mailprovider`
  maps MX suffixes and exact SPF include targets to those documented names.
  Rejected: a generic dictionary of common selectors, which is brute-forcing
  under another name and produces results that depend on luck. SPF includes
  are only followed inside the audited domain, so a provider's own includes
  (SendGrid including another service) do not add providers. Amazon SES MX
  endpoints are not matched because `amazonaws.com` also covers arbitrary EC2
  hosts. A missing key under a guessed selector is not a finding by itself;
  it is mentioned in MAIL-DKIM-001/016 because the domain may use custom
  selectors. Explicit `--dkim-selector` values disable guessing.

## Problems and fixes

- SPF static analysis: the first version bounded hostile dependency trees by
  counting analysed *records*. `TestAnalyzeBoundsHostileTrees` (a tree where
  every record includes ten others, most of them non-existent) still issued
  614 DNS queries, because failed include targets were not counted. The bound
  now counts every include/redirect target fetched.
- Received parsing: TLS detection took the first word of the `with` clause
  via `strings.Fields(protocol + " ")[0]`, which panics for headers without a
  `with` clause (local delivery: `by host id X; date`). Found by the first
  table test with a Postfix local-delivery header. Also, Exim writes
  `with esmtps (TLS1.3) tls <cipher>`, so the protocol is now the words before
  the first comment in the clause.
- ARC summary: a message whose ARC headers all carried invalid instance
  numbers produced an empty set list, and the summary indexed the last set
  unconditionally (index out of range). Caught by the "bad instance" table
  case before the code was ever run on real input.

## Static analysis

- First staticcheck run (v0.8.1): one finding, an unused `knownTags` map left
  over from an earlier DMARC parser draft. Removed.
- First gosec run (v2.29.0): six findings, all in test infrastructure or
  developer tools: unchecked `Close` errors in the test DNS server, two
  integer conversions (a byte built from a bounds-checked escape value, and
  the DNS ID split into bytes, now written with `binary.BigEndian`) and a
  file read from a flag in `fixturegen`. Fixed or annotated with `#nosec`
  and a reason.
- govulncheck and OSV-Scanner report no known vulnerabilities in the module
  graph (cobra, pflag, golang.org/x/net).
- `scripts/check-dependencies.sh` fails when the set of third-party modules
  linked into the binary changes without a matching edit to
  `.github/allowed-modules.txt` (currently cobra, pflag and golang.org/x/net;
  mousetrap is only linked on Windows builds and appears in module SBOMs).
- SBOMs are generated with Syft in SPDX 2.3 and CycloneDX JSON. The first
  attempt at a source SBOM embedded the absolute checkout path through
  Syft's file cataloger; the script now scans the module from the repository
  root with file cataloging disabled.
- CI runs the tools with `go run module@version`; versions are pinned and
  module checksums are verified against sum.golang.org.

## Release engineering

- Release archives are produced by `scripts/build-release.sh` rather than a
  release framework: the whole pipeline is ~100 lines of shell plus a small
  Go program for deterministic tar.gz/zip creation, and it can be run and
  checked locally.
- Reproducibility: `-trimpath`, `-buildid=`, `CGO_ENABLED=0`, version,
  commit and date injected from git (commit date, not build time), and
  archive entries with fixed owner, mode and `SOURCE_DATE_EPOCH` mtime.
  The first version used `-buildvcs=false`; the supply-chain review showed
  that with `-trimpath` this leaves the main module version as `(devel)` in
  the build information, so SBOMs of the binaries had no product version.
  Release builds now use `-buildvcs=true` and pin the toolchain from the
  `toolchain` line in go.mod, `GOENV=off`, `GOAMD64=v1`, `GOARM64=v8.0` and
  an empty `GOEXPERIMENT`.
- `scripts/verify-reproducible.sh` builds twice, the second time with an empty
  module and build cache, and compares SHA256SUMS. First local run (Go
  1.27.1, darwin/arm64 host, all five targets): identical checksums.
- First smoke run against a release archive failed twice for real reasons:
  `build-release.sh` aborted when a target subset produced no `.zip` (the
  checksum glob did not match), and `MAILAUTHPROBE_BIN` was resolved relative
  to the test package directory instead of the repository root. Both fixed;
  smoke tests pass for darwin/arm64 natively and darwin/amd64 under Rosetta.

## Performance

Benchmarks: `go test -run '^$' -bench . -benchmem ./internal/...`.
Baseline on 2026-09-14 (Go 1.27.1, Apple M-series, 10 cores):

| Benchmark | Time/op | Allocs/op | Notes |
|-----------|--------:|----------:|-------|
| mailparser ParseFixture (1.9 KB, 3 DKIM signatures) | 4.6 µs | 45 | 409 MB/s |
| mailparser ParseLargeMultipart (200 parts, 600 KB) | 468 µs | 4050 | 1.3 GB/s |
| dkim VerifyFixture (3 signatures, RSA + Ed25519) | 62 µs | 214 → 202 | includes zone lookups |
| dkim CanonicalBodyRelaxed (1 MiB) | 1.8 ms | 16650 → 5 | 571 MB/s |
| spf Parse | 1.2 µs | 25 | |
| spf CheckHost (include chain, in-memory zone) | 3.1 µs | 78 | |
| received Parse (Postfix header with TLS comment) | 4.0 µs | 125 | |
| dmarc Parse | 1.3 µs | 16 | |
| dmarc OrganizationalDomain | 125 ns | 1 | |

The first run showed one allocation per line in body canonicalization: the
CRLF terminator was converted from a string literal on every call through
an `io.Writer`. A shared slice removed 16 645 allocations per MiB; throughput
was unchanged because hashing dominates. Parsing and verification are far
below DNS latency, so no further optimisation is planned.

## Fuzzing

Native Go fuzzing (`go test -fuzz`), targets listed in `.github/workflows/ci.yml`.
CI runs each target for 45 seconds on every push; longer campaigns are run
locally before releases.

### Campaign 1 – 2026-09-14, Go 1.27.1, Apple M-series, 60 s per target

| Target | Executions | New corpus entries | Result |
|--------|-----------:|-------------------:|--------|
| mailparser/FuzzParseHeaders | 23.4 M | 221 | pass |
| mailparser/FuzzParseMIME | 16.6 M | 520 | pass |
| received/FuzzParseReceived | 12.2 M | 620 | pass |
| spf/FuzzParseSPF | 19.8 M | 370 | pass |
| spf/FuzzCheckHost | 16.3 M | 639 | pass |
| dmarc/FuzzParseDMARC | 11.9 M | 399 | pass |
| dmarc/FuzzAlignment | 5.2 M | 363 | pass |
| dkim/FuzzParseKeyRecord | 14.1 M | 380 | pass |
| dkim/FuzzParseSignature | 13.2 M | 329 | pass |
| dkim/FuzzVerifyMessage | 11.0 M | 300 | pass |
| dkim/FuzzCanonicalization | 14.6 M | 165 | pass |
| authres/FuzzParseAuthenticationResults | – | – | **failure after 0.4 s** |
| authres/FuzzParseReceivedSPF | 23.6 M | 407 | pass |
| mtasts/FuzzParsePolicy | 6.5 M | 262 | pass |

No panics were found. One invariant violation:

- `authres.Parse("0=\"\"")` returned a result with an empty result keyword.
  Method and result were checked for emptiness *before* removing quotes, so
  `spf=""` produced `Result{Method: "spf", Result: ""}`. Downstream, an empty
  claimed result is silently skipped by the comparison, which would hide a
  malformed header instead of reporting it. Method and result are now
  validated as RFC 8601 keywords after unquoting. The failing input is kept
  as a regression seed in
  `internal/authres/testdata/fuzz/FuzzParseAuthenticationResults/`; a
  further 60 s run (21.6 M executions) passed.

Before the campaign, the seed corpus alone caught an incorrect property in
`FuzzParseHeaders`: raw header bytes were expected to be a prefix of the
input, which is false when a continuation line precedes the first field (the
line is skipped). The property was corrected to "raw bytes appear in order
within the header section".

## Pre-release review

Before tagging v0.1.0 the code was reviewed separately from four
perspectives. Findings that were fixed:

**Go maintainer**
- Hostile input reached the terminal unescaped (also found by the AppSec
  review); the text renderer now escapes control characters, C1 controls,
  invalid UTF-8 and bidi overrides, enforced by a distinct `styled` type.
- Golden tests embedded OS-specific path separators and would fail on
  Windows.
- Concurrent domain checks raced for the shared query budget, making reports
  non-deterministic once the budget was hit, and a panic in a check goroutine
  bypassed the CLI's recover. Checks now run sequentially; budget rejections
  are cached and summarised in one finding.
- A data race on the MTA-STS certificate captured in a TLS callback.
- The Windows fallback resolver reported existing names without records as
  NXDOMAIN.
- `--timeout` did not apply to a stalled standard input; Ctrl-C was reported
  as a deadline; a second Ctrl-C was swallowed.
- A local DNS temperror was reported as disagreement with
  Authentication-Results; MTA-STS DNS failures did not map to exit code 4.

**Mail security (RFC semantics)**
- A forged `Received-SPF` header could supply the SMTP client address and
  turn a spoofed message into SPF and DMARC pass. The client address now
  comes only from the Received chain or `--source-ip`.
- DMARC concluded `fail` (with the reject disposition) when SPF was not
  evaluated or DKIM could only be checked without the body. Such cases are
  now `indeterminate`; aligned temperrors give `temperror`.
- `a/0` and `mx//0` were not reported as authorizing the whole Internet;
  `/` as a macro delimiter broke `a`/`mx` parsing; `c`, `r`, `t` macros were
  accepted in the `exp=` domain-spec.
- An invalid DMARC `sp` fell back to `p` instead of invalidating the record;
  external report authorization accepted `v=DMARC1x` and skipped https URIs.
- Authentication-Results DKIM matching accepted `header.b` prefixes shorter
  than 8 characters.

**Application security**
- SPF macro expansion with a 400 KB envelope sender from headers allocated
  3.8 GiB; expansions are now bounded to 4096 octets and inferred inputs are
  length-checked (measured after the fix: 3 MiB).
- A sender's SPF policy could exhaust the scan's DNS budget with `%{p}`
  macros and downgrade the victim domain's DMARC result to temperror. SPF now
  has its own budget, `%{p}` is resolved once per domain, and only
  identifiers that could align affect the DMARC decision.
- Nested MIME copied a 49 MiB body at every level (2.2 GiB allocated); copies
  are now bounded to twice the body size (223 MiB peak measured).
- A hostile SPF tree produced 512 071 findings; repeated findings are capped
  per rule (46 findings after the fix).
- NAT64, 6to4, Teredo and IPv4-compatible addresses bypassed the MTA-STS
  private-address check; DNS responses with a mismatching question and an
  error code, or truncated over TCP, were accepted; RSA DKIM keys had no
  upper size bound; DNS error messages revealed the internal resolver.

**Supply chain**
- Release binaries would have been built with Go 1.26.0 (20 reachable
  standard library vulnerabilities according to govulncheck) because go.mod
  had no `toolchain` line; the vulnerability job scanned a different
  toolchain. go.mod now names the release toolchain, and release binaries are
  scanned with `govulncheck -mode=binary`.
- Releases can only be published from commits on main, through a `release`
  environment; SBOMs are signed; cosign is pinned; darwin/amd64 is smoke
  tested; the reproducibility check compares against the artifacts being
  published; build environment variables that change binaries are pinned.

Not changed, by decision: `pct` sampling is not simulated (the requested
disposition is reported), and MTA-STS policies with `max_age` above the RFC
maximum are rejected rather than capped.
