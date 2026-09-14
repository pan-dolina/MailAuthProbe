# Test keys

These keys exist only to sign the message fixtures in `testdata/messages`.
They are public, are not used anywhere else, and must never be used to sign
real mail.

- `test-rsa2048.pem` – RSA 2048-bit key for selector `s2026`.
- The Ed25519 key for selector `ed2026` is derived from a fixed seed in
  `internal/tools/fixturegen`.
