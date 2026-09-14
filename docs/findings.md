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

## dns

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-DNS-001` | high | informational | DNS lookup failed |
| `MAIL-DNS-002` | medium | informational | DNS query budget exhausted |
