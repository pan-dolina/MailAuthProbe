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

## Fuzzing

_No fuzzing campaigns yet._
