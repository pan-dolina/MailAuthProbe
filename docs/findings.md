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

## dns

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-DNS-001` | high | informational | DNS lookup failed |
| `MAIL-DNS-002` | medium | informational | DNS query budget exhausted |
