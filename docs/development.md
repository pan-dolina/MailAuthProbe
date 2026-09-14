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
- Owner names in answers are compared case-insensitively: servers and
  forwarders using 0x20 case randomisation return names in mixed case.

## Problems and fixes

_None yet._

## Fuzzing

_No fuzzing campaigns yet._
