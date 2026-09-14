# ADR 0004: Resource limits for hostile input

- Status: Accepted

## Context

MailAuthProbe is pointed at messages that may have been crafted by an
attacker (phishing samples, spam traps, abuse reports) and at DNS zones
controlled by the sender. Both can be used to exhaust memory or CPU, or to
make the tool issue an unbounded number of network requests from an
analyst's machine or a CI runner.

## Decision

Every stage that consumes untrusted data has an explicit, documented limit.
Limits are grouped by what exceeding them means.

**Hard limits** abort processing of the input with exit code 3, because
continuing would require unbounded resources or would analyse only an
arbitrary prefix of the message:

| Limit | Default | Where |
|-------|---------|-------|
| Message size | 50 MiB | `mailparser.Limits.MaxMessageBytes`, enforced by `io.LimitReader` while reading |
| Header section size | 512 KiB | `mailparser.Limits.MaxHeaderBytes` |
| Header field count | 1000 | `mailparser.Limits.MaxHeaders` |

**Soft limits** stop a sub-analysis and are reported as a defect or finding;
the rest of the report remains valid:

| Limit | Default | Where |
|-------|---------|-------|
| MIME nesting depth | 20 | `mailparser.Limits.MaxMIMEDepth` |
| MIME parts | 500 | `mailparser.Limits.MaxMIMEParts` |
| DKIM signatures verified | 10 | `dkim.MaxSignatures` |
| DKIM RSA key size | 8192 bits | `dkim.MaxRSAKeyBits` (larger keys are rejected) |
| Bytes copied out of nested MIME parts | 2 × body + 1 MiB | `mailparser` MIME walker |
| Received headers analysed | 100 | `received.MaxHops` |
| SPF DNS-querying terms | 10 | `spf.Limits.MaxLookups` (RFC 7208) |
| SPF void lookups | 2 | `spf.Limits.MaxVoidLookups` (RFC 7208) |
| SPF MX/PTR names | 10 | `spf.Limits` (RFC 7208) |
| SPF include/redirect nesting | 16 | `spf.Limits.MaxDepth` |
| SPF records fetched during static analysis | 64 | `spf.maxAnalysisNodes` |
| SPF macro expansion | 4096 octets | `spf.maxExpansion` (longer expansions are invalid) |
| DNS queries for SPF per message or domain scan | 120 | `analyzer.spfQueryBudget`, inside the scan budget |
| Repeated findings per rule in one SPF tree | 20 | `spf.maxFindingsPerRule` |
| MX hosts resolved | 32 | `mx.MaxHosts` |
| DNS queries per scan | 250 | query budget (`dnsresolver.Budget`) |
| DNS response size | 32 KiB | `dnsresolver.Client.MaxResponseSize` |
| DNS query timeout | 5 s per attempt, 2 attempts per configured server | `dnsresolver.Client` |
| Scan deadline | 30 s | `--timeout`; also applies to reading standard input |
| MTA-STS policy size | 64 KiB | `mtasts` |
| HTTP redirects | 0 | `mtasts` (RFC 8461 forbids following redirects) |

The MIME parser records structure only: part bodies are measured but never
decoded, stored or interpreted.

## Consequences

- Legitimate but unusually large messages (for example with big attachments)
  may exceed the message size limit. The limit is a constant chosen well
  above typical provider limits (25–35 MiB).
- The limits make worst-case resource use predictable, which is a
  precondition for running MailAuthProbe on untrusted input in automation.
- Fuzz targets exercise the parsers with the default limits so that limit
  handling itself is covered.
