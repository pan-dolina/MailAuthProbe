# Development journal

A running record of problems, decisions and changes made while building
MailAuthProbe. Newest entries at the bottom of each section.

## Setup

- Toolchain: Go 1.27 locally; `go.mod` declares `go 1.26.0` so the previous
  stable release can still build the project.
- Module path: `github.com/marcindolinski/mailauthprobe`.

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

## Fuzzing

_No fuzzing campaigns yet._
