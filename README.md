# MailAuthProbe

MailAuthProbe is a local command-line tool for auditing e-mail authentication
and transport-security configuration, and for analysing real messages.

It answers two questions:

1. **Is this domain's mail configuration sound?** MX, SPF, DKIM, DMARC,
   MTA-STS and TLS-RPT records are fetched and validated against the
   relevant RFCs.
2. **What really happened to this message?** SPF, DKIM and DMARC are
   evaluated independently of the receiving server, and the result is
   compared with the `Authentication-Results` headers the message carries.

Results are produced for humans (terminal output) and for machines (versioned
JSON with stable finding IDs and exit codes suitable for CI and SOC pipelines).

## Goals

- Independent, standards-based evaluation. MailAuthProbe does not trust
  `Authentication-Results` headers; it recomputes the verdicts.
- Actionable output. Every finding carries a stable ID, a severity, evidence
  and a recommendation.
- Safe by default. Messages are treated as hostile input; no attachment is
  executed, no HTML is rendered, no link from a message is ever fetched.
- Predictable in automation. Deterministic output where possible, documented
  exit codes, no hidden network access beyond DNS and the MTA-STS policy fetch.

## Non-goals

- Acting as an MTA, spam filter or DMARC report processor.
- Guessing DKIM selectors by brute force.
- Opening SMTP connections to mail servers.

## Status

Under active development. See [ARCHITECTURE.md](ARCHITECTURE.md) and
[docs/security-model.md](docs/security-model.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
