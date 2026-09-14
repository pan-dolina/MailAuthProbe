# ADR 0001: Resolver abstraction

- Status: Accepted

## Context

Every check in MailAuthProbe depends on DNS, and the mail authentication RFCs
attach different meanings to different DNS outcomes:

- SPF (RFC 7208) counts "void lookups" (NXDOMAIN or no answers), turns
  temporary failures into `temperror` and missing include targets into
  `permerror`.
- DMARC (RFC 7489) falls back to the organizational domain only when no
  record exists, not when the lookup failed.
- MX validation must know whether a target is a CNAME.

The standard library's `net.Resolver` does not reliably distinguish NXDOMAIN
from NODATA, cannot report whether a response was truncated or oversized,
cannot be pointed at an arbitrary server without replacing its dialer, and
its behaviour differs between the pure-Go and cgo implementations. Tests
must also run without the public Internet.

## Decision

1. Protocol code depends only on the small `dnsresolver.Resolver` interface
   (TXT, MX, A, AAAA, CNAME, PTR). NODATA is an empty result with a nil error;
   all failures are `*dnsresolver.Error` values with a `Kind`.
2. The default implementation is a stub resolver (`Client`) built on
   `golang.org/x/net/dns/dnsmessage`. It sends recursive queries over UDP with
   EDNS(0) (1232 byte payload), falls back to TCP on truncation, verifies the
   response ID and question, ignores unrelated datagrams, enforces a maximum
   response size and per-attempt timeouts, and follows CNAME chains inside
   the answer section.
3. Servers come from `--resolver` or `/etc/resolv.conf`. Where no resolver
   configuration file exists (Windows) `StdResolver` adapts `net.Resolver`
   with documented loss of precision.
4. Cross-cutting policies are wrappers: `Budget` (per-scan query budget) and
   `Cache` (per-scan memoisation, never caching temporary failures). The
   analyzer composes `Cache(Budget(Client))`.
5. Tests use an in-memory zone implementing the same interface, and a local
   UDP/TCP server built on the same message library for end-to-end tests.

We considered `github.com/miekg/dns`. It is excellent but pulls in several
`golang.org/x` modules and offers far more than a stub resolver needs.
`dnsmessage` is maintained by the Go team, is already required for the public
suffix list (`golang.org/x/net/publicsuffix`), and keeps the dependency graph
to a single module.

## Consequences

- We own a few hundred lines of transport code (ID matching, TCP framing,
  truncation), covered by unit tests against local sockets.
- DNSSEC validation is out of scope; users who need it point `--resolver` at
  a validating resolver.
- Protocol packages are trivially testable with deterministic zones.
