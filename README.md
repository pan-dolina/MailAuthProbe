# MailAuthProbe

MailAuthProbe is a local command-line tool for auditing e-mail authentication
and transport security, and for analysing real messages.

- **Domain audit** – MX, SPF, DKIM, DMARC, MTA-STS and TLS-RPT records are
  fetched and validated against their RFCs, including the SPF dependency tree
  and the 10-lookup limit.
- **Message analysis** – DKIM signatures are verified cryptographically, SPF
  and DMARC are evaluated independently of the receiving server, the Received
  chain is modelled hop by hop, and the verdicts are compared with the
  `Authentication-Results` headers the message carries.
- **Built for automation** – versioned JSON output, stable finding IDs,
  documented exit codes and a `--fail-on` threshold for CI and SOC pipelines.

```
$ mailauthprobe message suspicious.eml

Verdicts
  SPF:               pass (evil.example) inputs inferred
  DKIM:              pass (1 of 1 signatures valid)
  DMARC:             fail (test.example, policy reject)
...
Findings
  HIGH     MAIL-DMARC-031  DMARC fail
           DMARC fail for test.example: neither SPF nor DKIM produced an aligned pass. The domain
           requests p=reject.
```

## Installation

Download an archive for your platform from the
[releases page](https://github.com/marcindolinski/mailauthprobe/releases),
verify it (see [release verification](docs/release-verification.md)) and put
the `mailauthprobe` binary on your `PATH`. Release binaries are available for
Linux (amd64, arm64), macOS (amd64, arm64) and Windows (amd64).

To build from source (Go 1.26 or newer):

```sh
go install github.com/marcindolinski/mailauthprobe/cmd/mailauthprobe@latest
```

## Usage

### Audit a domain

```sh
mailauthprobe domain example.com
mailauthprobe domain example.com --dkim-selector selector1 --dkim-selector selector2
mailauthprobe domain example.com --json --fail-on high
```

DKIM selectors cannot be discovered from DNS, and MailAuthProbe does not
guess them. Without `--dkim-selector` the report says that DKIM keys were not
audited. Analysing a signed message from the domain reveals its selectors.

### Analyse a message

```sh
mailauthprobe message email.eml
cat email.eml | mailauthprobe message -
mailauthprobe headers headers.txt
```

`headers` accepts only the header section (for example headers copied from a
mail client); DKIM header signatures are verified but body hashes are not.

SPF needs the SMTP client IP, HELO name and envelope sender. When they are
not given, MailAuthProbe infers them from `Received-SPF`, `Received` and
`Return-Path` headers and marks them as inferred. Supply the values from your
MTA logs for an authoritative result:

```sh
mailauthprobe message email.eml --source-ip 192.0.2.10 --helo mail.example.com --mail-from bounce@example.com
```

### Shell completion

```sh
mailauthprobe completion bash > /etc/bash_completion.d/mailauthprobe
mailauthprobe completion zsh  > "${fpath[1]}/_mailauthprobe"
mailauthprobe completion fish > ~/.config/fish/completions/mailauthprobe.fish
```

### Global flags

| Flag | Description |
|------|-------------|
| `--json` | Write the versioned JSON report instead of text. |
| `--quiet`, `-q` | Write nothing to standard output; rely on the exit code. |
| `--verbose`, `-v` | Show passing checks, all evidence, references and SPF traces. |
| `--no-color` | Disable colours. `NO_COLOR` is honoured; colour is off when output is not a terminal and on Windows. |
| `--fail-on <severity>` | Exit with status 1 if any finding is at least `info`, `low`, `medium`, `high` or `critical`. Default `none`. |
| `--timeout <duration>` | Deadline for the whole scan, including reading standard input (default `30s`). Each DNS attempt is limited to 5 s, with two attempts per configured server. |
| `--resolver <ip[:port]>` | DNS resolver to use. Default: servers from `/etc/resolv.conf`, or the OS resolver on Windows (which cannot tell a non-existent name from a name without records; use `--resolver` for precise results). |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no finding reached the `--fail-on` threshold. |
| 1 | At least one finding reached the `--fail-on` threshold. |
| 2 | Invalid arguments or flags. |
| 3 | The input could not be read or parsed, or exceeded a safety limit. |
| 4 | DNS or network failures made the result unreliable. |
| 5 | Internal error. |

When several apply, the most specific code wins: 5, then 3, then 4, then 1.
With `--json`, a report is written for codes 0, 1 and 4, and for code 3 when
the input could be opened but not parsed (for example when it exceeds a
limit). Files that cannot be opened produce only an error message.

## Output

Every observation is a *finding* with a stable ID such as `MAIL-SPF-005`, a
severity (`critical`, `high`, `medium`, `low`, `info`, `pass`), a category
(`standard-violation`, `security-weakness`, `hardening`, `informational`),
a description, evidence, a recommendation and references. The full list is in
[docs/findings.md](docs/findings.md). IDs never change meaning between
releases.

The JSON report carries `"schema_version": "1"` and is described by
[docs/schema/report-v1.schema.json](docs/schema/report-v1.schema.json).
Output is deterministic for identical input and DNS data.

## Security

Messages are treated as hostile input. MailAuthProbe enforces limits on
message size, header size and count, MIME depth and part count, DKIM
signatures, DNS queries and response sizes; it never extracts or executes
attachments, renders HTML or follows links from a message. The MTA-STS
policy fetch refuses redirects and private or loopback addresses. See the
[security model](docs/security-model.md) and [SECURITY.md](SECURITY.md).

Analysing a message issues DNS queries for the domains it names. The owners
of those domains can observe the lookups.

## Standards and limitations

See [docs/standards.md](docs/standards.md) for the RFCs implemented, the
interpretation choices made, and what MailAuthProbe deliberately does not do
(DNSSEC validation, ARC signature verification, SMTP probing, DANE).

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Standards coverage and limitations](docs/standards.md)
- [Security model](docs/security-model.md)
- [Release verification](docs/release-verification.md)
- [Architecture decision records](docs/adr/)
- [Development journal](docs/development.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
