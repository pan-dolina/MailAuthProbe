# Security policy

## Supported versions

Security fixes are released for the latest minor version. Before 1.0,
only the most recent release is supported.

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/pan-dolina/MailAuthProbe/security/advisories/new)
("Report a vulnerability" on the Security tab).

Include, where possible:

- the affected version (`mailauthprobe version`) and platform;
- a description of the impact;
- a minimal input that reproduces the problem (a message, a DNS zone in the
  `testdata/dns/zone.txt` format, or a record);
- whether the issue is already public.

You can expect an acknowledgement within five working days and an initial
assessment within ten. Fixes are coordinated with the reporter; credit is
given in the release notes unless you prefer otherwise.

## Scope

In scope:

- crashes, hangs or unbounded resource use caused by messages, DNS responses
  or MTA-STS policies;
- incorrect verdicts that would make a forged message look authenticated
  (for example a DKIM or DMARC `pass` that should not be one);
- network requests MailAuthProbe should not make, such as following links
  from messages or connecting to internal addresses;
- weaknesses in the release, signing or build process.

Out of scope:

- findings about third-party domains reported by MailAuthProbe itself;
- the absence of features documented as out of scope in
  [docs/standards.md](docs/standards.md) (DNSSEC validation, ARC signature
  verification, DANE);
- DNS lookups for domains named in an analysed message, which are inherent
  to verification and documented in the [security model](docs/security-model.md).

## Verifying releases

Release artifacts are signed with Sigstore and carry build provenance. See
[docs/release-verification.md](docs/release-verification.md).
