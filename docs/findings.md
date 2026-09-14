# Finding catalog

Finding IDs are stable across releases. This file is generated from
`internal/findings/catalog.go` by `go test ./internal/findings -update`.

Severity is the default; context may raise or lower it for a specific
finding.

## mx

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-MX-001` | medium | hardening | No MX records; mail relies on implicit MX |
| `MAIL-MX-002` | low | hardening | Domain publishes neither MX nor address records |
| `MAIL-MX-003` | high | informational | Domain does not exist |
| `MAIL-MX-004` | info | informational | Null MX published; domain does not accept mail |
| `MAIL-MX-005` | high | standard-violation | Null MX combined with other MX records |
| `MAIL-MX-006` | low | standard-violation | Null MX uses a non-zero preference |
| `MAIL-MX-007` | low | hardening | Duplicate MX host |
| `MAIL-MX-008` | high | standard-violation | MX target is an IP address |
| `MAIL-MX-009` | medium | standard-violation | MX target is a CNAME alias |
| `MAIL-MX-010` | medium | standard-violation | MX host has no address records |
| `MAIL-MX-011` | high | standard-violation | MX host resolves to a non-routable address |
| `MAIL-MX-012` | medium | informational | MX host lookup failed |
| `MAIL-MX-013` | info | hardening | MX hosts are reachable over IPv4 only |
| `MAIL-MX-014` | info | hardening | Single MX host |
| `MAIL-MX-015` | pass | informational | MX records are valid |
| `MAIL-MX-016` | high | standard-violation | MX target is not a valid host name |
| `MAIL-MX-017` | info | informational | Too many MX hosts to check |

## spf

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-SPF-001` | medium | security-weakness | No SPF record |
| `MAIL-SPF-002` | high | standard-violation | Multiple SPF records |
| `MAIL-SPF-003` | high | standard-violation | SPF syntax error |
| `MAIL-SPF-004` | high | standard-violation | SPF include or redirect loop |
| `MAIL-SPF-005` | high | standard-violation | SPF exceeds the 10 DNS lookup limit |
| `MAIL-SPF-006` | medium | standard-violation | SPF exceeds the void lookup limit |
| `MAIL-SPF-007` | critical | security-weakness | SPF authorizes every host (+all) |
| `MAIL-SPF-008` | medium | security-weakness | SPF ends with ?all (neutral) |
| `MAIL-SPF-009` | low | hardening | SPF ends with ~all (softfail) |
| `MAIL-SPF-010` | medium | security-weakness | SPF has no all mechanism or redirect |
| `MAIL-SPF-011` | medium | security-weakness | SPF authorizes a very large address range |
| `MAIL-SPF-012` | low | hardening | SPF uses the deprecated ptr mechanism |
| `MAIL-SPF-013` | high | standard-violation | SPF include or redirect target has no SPF record |
| `MAIL-SPF-014` | medium | informational | SPF lookup failed temporarily |
| `MAIL-SPF-015` | low | hardening | SPF terms after all are never evaluated |
| `MAIL-SPF-016` | low | hardening | SPF redirect is ignored because the record contains all |
| `MAIL-SPF-017` | low | hardening | SPF is close to the 10 DNS lookup limit |
| `MAIL-SPF-018` | low | hardening | SPF uses the discouraged p macro |
| `MAIL-SPF-019` | info | informational | SPF publishes an explanation (exp) |
| `MAIL-SPF-020` | info | informational | SPF contains an unknown modifier |
| `MAIL-SPF-021` | high | standard-violation | SPF mx mechanism references more than 10 MX records |
| `MAIL-SPF-022` | pass | informational | SPF record is valid |
| `MAIL-SPF-023` | info | informational | SPF term depends on message data and cannot be followed statically |
| `MAIL-SPF-024` | low | hardening | SPF record is longer than 450 octets |
| `MAIL-SPF-025` | low | hardening | SPF mechanism references a name without records |
| `MAIL-SPF-030` | pass | informational | SPF pass |
| `MAIL-SPF-031` | high | security-weakness | SPF fail: sending host is not authorized |
| `MAIL-SPF-032` | medium | security-weakness | SPF softfail: sending host is probably not authorized |
| `MAIL-SPF-033` | low | informational | SPF neutral or none: sender not verified |
| `MAIL-SPF-034` | medium | standard-violation | SPF evaluation error |
| `MAIL-SPF-035` | info | informational | SPF inputs inferred from message headers |
| `MAIL-SPF-036` | info | informational | SPF not evaluated |

## dkim

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-DKIM-001` | info | informational | DKIM audit incomplete: no selector specified |
| `MAIL-DKIM-002` | high | standard-violation | DKIM key record not found |
| `MAIL-DKIM-003` | high | standard-violation | DKIM key record is invalid |
| `MAIL-DKIM-004` | medium | informational | DKIM key is revoked |
| `MAIL-DKIM-005` | high | security-weakness | DKIM RSA key shorter than 1024 bits |
| `MAIL-DKIM-006` | medium | hardening | DKIM RSA key shorter than 2048 bits |
| `MAIL-DKIM-007` | low | hardening | DKIM RSA key longer than 4096 bits |
| `MAIL-DKIM-008` | high | standard-violation | DKIM key restricts hashes to SHA-1 |
| `MAIL-DKIM-009` | low | hardening | DKIM key is in testing mode (t=y) |
| `MAIL-DKIM-010` | high | standard-violation | DKIM key is not usable for e-mail |
| `MAIL-DKIM-011` | info | informational | DKIM key uses Ed25519 |
| `MAIL-DKIM-012` | pass | informational | DKIM key record is valid |
| `MAIL-DKIM-013` | medium | standard-violation | Multiple TXT records at a DKIM selector |
| `MAIL-DKIM-014` | info | informational | DKIM key record contains an unknown tag |
| `MAIL-DKIM-015` | low | hardening | DKIM RSA key is not in SubjectPublicKeyInfo format |

## dmarc

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-DMARC-001` | high | security-weakness | No DMARC record |
| `MAIL-DMARC-002` | high | standard-violation | Multiple DMARC records |
| `MAIL-DMARC-003` | high | standard-violation | Invalid DMARC record |
| `MAIL-DMARC-004` | medium | security-weakness | DMARC policy is p=none (monitoring only) |
| `MAIL-DMARC-005` | low | hardening | DMARC policy is p=quarantine |
| `MAIL-DMARC-006` | medium | security-weakness | DMARC policy applies to only part of the mail (pct < 100) |
| `MAIL-DMARC-007` | medium | security-weakness | DMARC subdomain policy is weaker than the domain policy |
| `MAIL-DMARC-008` | low | hardening | DMARC aggregate reports are not requested |
| `MAIL-DMARC-009` | info | informational | DMARC failure reports (ruf) requested |
| `MAIL-DMARC-010` | medium | standard-violation | DMARC tag has an invalid value |
| `MAIL-DMARC-011` | medium | standard-violation | DMARC tag appears more than once |
| `MAIL-DMARC-012` | info | informational | DMARC record contains an unknown tag |
| `MAIL-DMARC-013` | medium | standard-violation | DMARC report URI is invalid |
| `MAIL-DMARC-014` | medium | standard-violation | External DMARC report destination is not authorized |
| `MAIL-DMARC-015` | info | informational | DMARC policy inherited from the organizational domain |
| `MAIL-DMARC-016` | info | informational | DMARC requires strict identifier alignment |
| `MAIL-DMARC-017` | pass | informational | DMARC policy is enforced |
| `MAIL-DMARC-018` | info | informational | DMARC fo tag has no effect without ruf |
| `MAIL-DMARC-030` | pass | informational | DMARC pass |
| `MAIL-DMARC-031` | high | security-weakness | DMARC fail |
| `MAIL-DMARC-032` | medium | security-weakness | No usable DMARC policy for the From domain |
| `MAIL-DMARC-033` | high | standard-violation | From header unusable for DMARC |
| `MAIL-DMARC-034` | medium | informational | DMARC temperror |
| `MAIL-DMARC-035` | medium | informational | Strict alignment prevented a DMARC pass |
| `MAIL-DMARC-036` | info | informational | SPF passed but is not aligned with From |
| `MAIL-DMARC-037` | info | informational | DKIM passed but is not aligned with From |

## mta-sts

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-MTASTS-001` | low | hardening | MTA-STS not deployed |
| `MAIL-MTASTS-002` | high | standard-violation | Invalid MTA-STS TXT record |
| `MAIL-MTASTS-003` | high | standard-violation | MTA-STS policy cannot be fetched |
| `MAIL-MTASTS-004` | high | standard-violation | MTA-STS policy host certificate is invalid |
| `MAIL-MTASTS-005` | high | standard-violation | MTA-STS policy URL redirects |
| `MAIL-MTASTS-006` | medium | standard-violation | MTA-STS policy is not served as text/plain |
| `MAIL-MTASTS-007` | high | standard-violation | MTA-STS policy is invalid |
| `MAIL-MTASTS-008` | low | hardening | MTA-STS policy in testing mode |
| `MAIL-MTASTS-009` | medium | security-weakness | MTA-STS policy mode is none |
| `MAIL-MTASTS-010` | low | hardening | MTA-STS max_age shorter than one day |
| `MAIL-MTASTS-011` | high | standard-violation | MX hosts not covered by the MTA-STS policy |
| `MAIL-MTASTS-012` | low | informational | MTA-STS policy host certificate expires soon |
| `MAIL-MTASTS-013` | medium | standard-violation | MTA-STS policy published without a TXT record |
| `MAIL-MTASTS-014` | pass | informational | MTA-STS is enforced |
| `MAIL-MTASTS-015` | info | informational | MTA-STS policy uses LF line endings |
| `MAIL-MTASTS-016` | medium | standard-violation | MTA-STS policy is too large |

## received

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-RCVD-001` | low | informational | No Received headers |
| `MAIL-RCVD-002` | low | standard-violation | Received header could not be parsed |
| `MAIL-RCVD-003` | low | informational | Received timestamps go backwards |
| `MAIL-RCVD-004` | medium | informational | Too many Received headers |
| `MAIL-RCVD-005` | info | hardening | Hop transmitted without TLS |
| `MAIL-RCVD-006` | low | standard-violation | Received header has no date |
| `MAIL-RCVD-007` | info | informational | Long delay between hops |

## authentication-results

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-AR-001` | high | security-weakness | Conflicting Authentication-Results from the same server |
| `MAIL-AR-002` | medium | informational | Authentication-Results disagree with independent verification |
| `MAIL-AR-003` | pass | informational | Authentication-Results agree with independent verification |
| `MAIL-AR-004` | low | standard-violation | Authentication-Results header cannot be parsed |
| `MAIL-AR-005` | info | informational | No Authentication-Results headers |

## dns

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-DNS-001` | high | informational | DNS lookup failed |
| `MAIL-DNS-002` | medium | informational | DNS query budget exhausted |
