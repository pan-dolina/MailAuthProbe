# Finding catalog

Finding IDs are stable across releases. This file is generated from
`internal/findings/catalog.go` by `go test ./internal/findings -update`.

Severity is the default; context may raise or lower it for a specific
finding.

## dns

| ID | Default severity | Category | Title |
|----|------------------|----------|-------|
| `MAIL-DNS-001` | high | informational | DNS lookup failed |
| `MAIL-DNS-002` | medium | informational | DNS query budget exhausted |
