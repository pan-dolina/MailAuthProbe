# Standards coverage and limitations

This document lists the specifications MailAuthProbe implements, how
ambiguous points are interpreted, and what is out of scope.

## MX (RFC 5321, RFC 7505, RFC 2181)

- MX targets are resolved for A and AAAA records; targets that are CNAMEs,
  IP literals, invalid host names, unresolvable or non-routable are reported.
- A domain without MX records but with address records is reported as using
  an implicit MX. Null MX (`0 .`) is recognised, including invalid
  combinations with other MX records.
- "Unreachable" means unreachable according to DNS: MailAuthProbe does not
  open SMTP connections.
- Documentation address ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24, 2001:db8::/32) are treated as public so that examples
  behave like real deployments.

## SPF (RFC 7208)

- Complete record syntax, including macros, dual CIDR lengths and unknown
  modifiers. Any syntax error yields `permerror`, as required by section 4.6.
- Macro expansions longer than 4096 octets are treated as invalid domains,
  and the `c`, `r` and `t` macro letters are accepted only in explanation
  text, not in the `exp=` domain-spec.
- `check_host()` implements all mechanisms (`all`, `include`, `a`, `mx`,
  `ptr`, `ip4`, `ip6`, `exists`), the `redirect` and `exp` modifiers, and all
  macro letters. IPv4-mapped IPv6 clients are evaluated as IPv4.
- Limits: 10 DNS-querying terms, 2 void lookups, 10 MX names for `mx`,
  10 PTR names for `ptr`. Include and redirect loops are detected explicitly.
- Domain audits compute the worst-case lookup count across the whole
  include/redirect tree. Terms after `all` and a `redirect` next to `all` are
  not counted, because receivers never evaluate them. Terms whose target
  depends on sender or client macros are counted once and not followed.
- Record selection requires `v=spf1` followed by a space or the end of the
  record; the obsolete SPF RR type (99) is not queried.
- Domain specs must match the `domain-end` production, so single-label
  targets such as `include:localhost` are syntax errors.

## DKIM (RFC 6376, RFC 8301, RFC 8463)

- Signature and key record tag lists, simple and relaxed canonicalization,
  `l=`, `i=`, `t=`, `x=`, `q=`, key flags `t=y` and `t=s`, service types and
  hash restrictions.
- Algorithms: `rsa-sha256` and `ed25519-sha256`. `rsa-sha1` signatures are
  verified but reported as `permerror`, and RSA keys shorter than 1024 bits
  are rejected (RFC 8301).
- Keys are accepted as SubjectPublicKeyInfo and, with a finding, as bare
  PKCS #1 RSAPublicKey.
- Messages stored with LF line endings are normalised to CRLF before
  canonicalization, since the signer saw CRLF on the wire.
- At most 10 signatures per message are verified. RSA keys larger than
  8192 bits are rejected to bound verification cost.
- Result names follow RFC 8601: `pass`, `fail` (signature or body hash
  mismatch), `neutral` (header signature valid, body unavailable),
  `permerror`, `temperror`.

## DMARC (RFC 7489)

- Record parsing with defaults, duplicate and unknown tag detection, report
  URI validation and external report destination authorization
  (section 7.1). The DMARCbis tags `np`, `psd` and `t` are recognised and
  validated but not applied.
- Policy discovery falls back to the organizational domain determined with
  the Public Suffix List shipped in `golang.org/x/net/publicsuffix`
  (including its private section). The list is a snapshot from the module
  version in use.
- Messages must have exactly one From header with one mailbox; otherwise the
  result is `permerror`.
- The SPF identity used for alignment is MAIL FROM, or HELO only for a null
  reverse-path. `pct` is reported but not sampled: the disposition shows the
  requested policy.
- A message is reported as DMARC `fail` only when every identifier that could
  align produced a definite result. If there is no aligned pass but SPF could
  not be evaluated, or an aligned DKIM signature could only be partially
  verified (headers without body), the result is `indeterminate` (not an
  RFC 7489 result); aligned SPF or DKIM `temperror` gives `temperror`.
- An invalid `sp` tag is handled like an invalid `p` tag (RFC 7489
  section 6.6.3): the record is ignored, or treated as `p=none` when it lists
  a valid `rua`. External report destinations are checked for `mailto:` and
  `https:` URIs.

## MTA-STS (RFC 8461) and TLS-RPT (RFC 8460)

- `_mta-sts` TXT record, HTTPS policy fetch with WebPKI certificate
  validation, no redirects, a 64 KiB size limit and `text/plain` check;
  policy syntax, mode, `max_age` and coverage of every MX host by the `mx`
  patterns.
- The policy host is resolved through the scan's resolver. Connections to
  private, loopback and other non-routable addresses are refused.
- `_smtp._tls` TXT record with `mailto:` and `https:` report URIs.
- MTA-STS policy caching semantics (`id` changes, `max_age` expiry) are not
  simulated; each scan fetches the current policy.

## Message analysis (RFC 5322, RFC 2045/2046, RFC 5321 section 4.4, RFC 8601, RFC 8617)

- Header fields are kept with their exact bytes. A line that is neither a
  field nor a continuation ends the header section, as in common MTAs.
- MIME structure is parsed without decoding content; malformed structure is
  reported as defects.
- Received headers are parsed for the common formats of Postfix, Sendmail,
  Exim, qmail, Microsoft Exchange and Gmail. Every extracted value is marked
  `stated` (explicit in the header) or `inferred` (dependent on a
  convention, such as the word after `from` being the HELO name).
- The SMTP client used for SPF is inferred from the most recent Received
  header with a public client address. `Received-SPF` never supplies the
  client address; it supplies HELO and MAIL FROM only when its `client-ip`
  matches. The receiving organization's trust boundary is unknown, so these
  values are always marked as inferred.
- Authentication-Results (RFC 8601) are parsed, including the Exchange Online
  variant without an authserv-id. Conflicts between headers from the same
  authserv-id and disagreement with MailAuthProbe's own results are reported.
- ARC header sets are checked structurally (instances, completeness, `cv`
  values). ARC signatures are **not** verified.

## Out of scope

- DNSSEC validation. Point `--resolver` at a validating resolver if needed.
- DANE for SMTP (RFC 7672) and STARTTLS certificate checks on MX hosts.
- SMTP connections of any kind.
- BIMI.
- Brute-forcing DKIM selectors.
- Processing DMARC aggregate or failure reports.
