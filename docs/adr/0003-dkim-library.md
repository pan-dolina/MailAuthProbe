# ADR 0003: DKIM implementation

- Status: Accepted

## Context

MailAuthProbe must verify DKIM signatures and, unlike a mail filter, explain
*why* a signature fails: whether the body hash or the header signature is
wrong, whether the key is missing, revoked, too short or of the wrong type,
whether `l=` leaves the body open to appended content, and which header
fields were covered. It also has to verify header signatures when only the
header section of a message is available.

The main Go library is `github.com/emersion/go-msgauth/dkim`. It is well
maintained and correct, but it streams the message through an `io.Reader`,
reports failures as error strings, and has no notion of a header-only
verification. It also pulls in `golang.org/x/crypto`.

## Decision

Implement DKIM verification in `internal/dkim` on top of the standard
library (`crypto/rsa`, `crypto/ed25519`, `crypto/sha256`, `crypto/sha1`):

- signature and key record tag-list parsing (RFC 6376 section 3.2);
- simple and relaxed canonicalization for headers and bodies, operating on
  the raw header bytes preserved by `mailparser`;
- header selection from the bottom of the header section, including
  "oversigned" names without a matching field;
- `rsa-sha256` and `ed25519-sha256` (RFC 8463); `rsa-sha1` is verified but
  reported as `permerror` and RSA keys below 1024 bits are rejected
  (RFC 8301);
- structured results with a failure category (`body-hash-mismatch`,
  `signature-mismatch`, `key-revoked`, ...), per-message key caching and a
  limit of 10 signatures per message.

Correctness is checked by a cross-validation run against go-msgauth: messages
signed by the MailAuthProbe test signer are verified by go-msgauth and vice
versa, for all four canonicalization combinations, RSA and Ed25519, and body
edge cases (empty body, missing final CRLF, trailing whitespace-only lines).
go-msgauth is used only for that check and is not a dependency of the
module.

## Consequences

- About 600 lines of security-sensitive code to maintain, covered by table
  tests, fuzzing of the parsers and committed fixtures.
- Constant-time comparison is used for body hashes; signature verification
  relies on the standard library.
- The test-only signer (`internal/dkim/dkimtest`) shares canonicalization
  code with the verifier. It is therefore not an independent oracle, which is
  why the cross-validation against a second implementation matters.
