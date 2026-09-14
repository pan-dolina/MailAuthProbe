# Security model

This document describes what MailAuthProbe trusts, what it does not, and which
controls protect the machine running it.

## Assets

- The host running MailAuthProbe (analyst workstation, CI runner, SOC worker).
- The confidentiality of analysed messages.
- The integrity of the verdicts MailAuthProbe reports.

## Trust boundaries

| Input | Trust | Notes |
|-------|-------|-------|
| Message files / stdin | **Untrusted** | Arbitrary bytes, possibly crafted to exhaust resources or confuse parsers. |
| Header values, including `Authentication-Results`, `Received`, `Received-SPF` | **Untrusted** | Any header above the first trusted hop may be forged by the sender. |
| DNS responses | **Untrusted** | Can be malformed, oversized, slow or deliberately recursive (SPF include chains). DNSSEC is not validated. |
| MTA-STS policy over HTTPS | Authenticated by WebPKI | Only fetched from `mta-sts.<domain>`; redirects are refused. |
| Command-line flags | Trusted | Supplied by the operator. |

## Threats and controls

### Resource exhaustion from messages

A message may be huge, contain millions of headers, deeply nested MIME parts or
an unbounded number of DKIM signatures.

Controls: hard limits on message size, header section size, number of header
fields, MIME nesting depth, number of MIME parts, bytes copied out of nested
MIME parts, number of DKIM signatures evaluated, DKIM key size and number of
`Received` headers processed. The message size limit is enforced while
reading, so at most 50 MiB are buffered; the other limits are checked on that
bounded buffer. The terminal renderer escapes control characters in all data
taken from messages, DNS and HTTP, so crafted content cannot inject terminal
escape sequences.

### Resource exhaustion from DNS

SPF records can reference each other recursively and a malicious zone can make
a naïve evaluator issue unbounded queries.

Controls: RFC 7208 lookup limit (10 DNS-querying terms), void lookup limit (2),
MX/PTR address limits, explicit include/redirect loop detection, a bound on
macro expansion, a separate query budget for SPF inside the per-scan DNS query
budget (so that a sender's SPF policy cannot starve DMARC and DKIM lookups for
the From domain), maximum DNS response size, per-query timeouts and a global
scan deadline.

### Parser confusion and crashes

Malformed input must never crash the tool or produce a misleading verdict.

Controls: parsers return errors rather than panicking, all parsers are covered
by fuzz targets, and ambiguous data (for example a `Received` header whose
`from` clause can be read two ways) is reported as *inferred* rather than
*stated*.

### Active content

Controls: MailAuthProbe never decodes attachments to disk, never renders HTML,
never follows links contained in a message and never executes embedded
content. MIME is parsed only to the extent needed to describe its structure.

### Forged authentication headers

`Authentication-Results` and `Received-SPF` headers can be injected by a
sender. MailAuthProbe recomputes SPF, DKIM and DMARC and reports
disagreements, including conflicting results issued under the same
`authserv-id`. The SMTP client address used for SPF is never taken from
`Received-SPF`; such a header is used for HELO and MAIL FROM only when its
`client-ip` matches the address from the Received chain or `--source-ip`.
When inputs are missing, DMARC is reported as `indeterminate` rather than
`fail`.

### Network side effects

A scan of a domain issues DNS queries to the configured resolver and a single
HTTPS request to `https://mta-sts.<domain>/.well-known/mta-sts.txt`. The
request is refused when the host resolves only to private, loopback,
link-local or other non-routable addresses, including IPv4 addresses embedded
in NAT64, 6to4, Teredo and IPv4-compatible IPv6 addresses. Analysing
a message issues DNS queries for DKIM keys, SPF and DMARC records of domains
named in the message. Operators analysing sensitive messages should be aware
that these lookups are observable by the domain owners' DNS servers.

## Out of scope

- DNSSEC validation (use a validating resolver via `--resolver`).
- ARC cryptographic verification (ARC headers are parsed and summarised).
- SMTP-level probing of MX hosts, STARTTLS certificate checks and DANE.
