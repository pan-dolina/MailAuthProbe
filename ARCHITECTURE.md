# Architecture

MailAuthProbe is a single static Go binary. The code is organised so that
networking, parsing, validation, findings and rendering are separate layers
that can be tested in isolation.

```
cmd/mailauthprobe          main(): exit code handling only
internal/
  cli/                     cobra commands, flags, exit codes
  analyzer/                orchestration: domain, message and header assessments
  dnsresolver/             Resolver interface, UDP/TCP client, budget, cache
    dnstest/               in-memory zone + local DNS server for tests
  mx/                      MX discovery and validation
  spf/                     SPF parser, macro expansion, evaluator, static analysis
  dkim/                    DKIM key records, signatures, canonicalization, verification
  dmarc/                   DMARC records, policy discovery, alignment, evaluation
  mtasts/                  MTA-STS TXT record and HTTPS policy
  tlsrpt/                  TLS-RPT record
  mailparser/              RFC 5322 header section and MIME structure, with limits
  received/                Received header parsing and hop chain modelling
  authres/                 Authentication-Results and Received-SPF parsing
  findings/                Finding model, severities and the stable ID catalog
  report/                  report model, text and JSON renderers
  version/                 build metadata
test/
  functional/              runs the compiled CLI against fixtures
  smoke/                   runs a release binary
testdata/                  message fixtures, DNS zones, golden output
docs/                      standards notes, security model, ADRs
```

## Data flow

```
                +-------------------+
  flags ------> |       cli         | ---- exit code
                +---------+---------+
                          |
                +---------v---------+        +----------------+
                |     analyzer      | -----> |    report      | --> text / JSON
                +---------+---------+        +----------------+
                          |
     +----------+---------+---------+----------+-----------+
     |          |         |         |          |           |
    mx        spf       dkim      dmarc     mtasts      tlsrpt      (validation)
     |          |         |         |          |           |
     +----------+----+----+---------+----------+-----------+
                     |                         |
             +-------v-------+          +------v------+
             |  dnsresolver  |          |  net/http   |               (networking)
             +---------------+          +-------------+

  message bytes --> mailparser --> received / authres / dkim.Signature   (parsing)
```

Protocol packages never print anything and never import `report` or `cli`.
They return typed results plus `[]findings.Finding`. The analyzer assembles
those into a `report.Report`, and renderers turn the report into bytes.

## Key abstractions

- **`dnsresolver.Resolver`** – the only way protocol code talks to DNS. It
  distinguishes NXDOMAIN, "no data", temporary failures and malformed
  responses, which SPF and DMARC semantics depend on. Wrappers add a query
  budget and caching. See [ADR 0001](docs/adr/0001-resolver-abstraction.md).
- **`findings.Finding`** – every observation, including passes, is a finding
  with a stable ID from a central catalog. See
  [ADR 0002](docs/adr/0002-finding-model.md).
- **`mailparser.Message`** – keeps the exact bytes of every header field so
  DKIM can canonicalise what was actually signed.
- **`report.Report`** – the JSON contract (`schema_version: "1"`). See
  [ADR 0005](docs/adr/0005-json-schema.md).

## Error handling

Protocol problems in the scanned data (a broken SPF record, an invalid
signature) are *findings*, not Go errors. Go errors are reserved for
conditions that prevent a scan from producing a trustworthy answer: invalid
arguments, unreadable input, input exceeding limits and DNS infrastructure
failures. The CLI maps them to exit codes (see README).

## Testing strategy

- Table-driven unit tests per package, using `dnstest.Zone` as an in-memory
  resolver.
- Functional tests build the CLI and run it against `testdata/messages` with
  a `dnstest.Server` listening on localhost.
- Fuzz targets for every parser that consumes untrusted bytes.
- Smoke tests exercise release binaries produced by the release build.

No test requires access to the public Internet.
