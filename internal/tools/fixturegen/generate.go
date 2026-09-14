package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pan-dolina/mailauthprobe/internal/dkim/dkimtest"
)

// File is a generated fixture.
type File struct {
	Path string
	Data []byte
}

// Fixed values shared by fixtures.
const (
	signTime    = 1789380000 // 2026-09-14T10:00:00Z
	dateHeader  = "Mon, 14 Sep 2026 10:00:00 +0000"
	goodIP      = "192.0.2.10"
	attackerIP  = "203.0.113.66"
	receiver    = "mx.receiver.example"
	rsaSelector = "s2026"
	edSelector  = "ed2026"
)

type keys struct {
	rsa *rsa.PrivateKey
	ed  ed25519.PrivateKey
}

func loadKeys(root string) (*keys, error) {
	data, err := os.ReadFile(filepath.Join(root, "testdata", "keys", "test-rsa2048.pem")) // #nosec G304 -- developer tool reading the repository
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("test-rsa2048.pem: no PEM block")
	}
	var k *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		k = parsed
	} else {
		anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("test-rsa2048.pem: %w", err)
		}
		var ok bool
		if k, ok = anyKey.(*rsa.PrivateKey); !ok {
			return nil, errors.New("test-rsa2048.pem: not an RSA key")
		}
	}
	seed := []byte("mailauthprobe-ed25519-test-seed!") // 32 bytes
	return &keys{rsa: k, ed: ed25519.NewKeyFromSeed(seed)}, nil
}

// message builds a CRLF message from header lines and body lines.
func message(headers []string, body ...string) string {
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.Join(body, "\r\n") + "\r\n"
}

func received(fromHost, ip, id string) string {
	return fmt.Sprintf("Received: from %s (%s [%s])\r\n\tby %s (Postfix) with ESMTPS id %s\r\n\tfor <bob@receiver.example>; %s", fromHost, fromHost, ip, receiver, id, dateHeader)
}

func signWith(msg string, signer crypto.Signer, domain, selector string, mutate ...func(*dkimtest.Options)) (string, error) {
	opts := dkimtest.Options{
		Domain:    domain,
		Selector:  selector,
		Signer:    signer,
		Headers:   []string{"From", "To", "Subject", "Date", "Message-ID"},
		Timestamp: signTime,
	}
	for _, m := range mutate {
		m(&opts)
	}
	out, err := dkimtest.Sign([]byte(msg), opts)
	return string(out), err
}

// prepend adds trace headers above a signed message, as a receiving MTA
// would.
func prepend(msg string, headers ...string) string {
	return strings.Join(headers, "\r\n") + "\r\n" + msg
}

// Generate returns all fixtures.
func Generate(root string) ([]File, error) {
	k, err := loadKeys(root)
	if err != nil {
		return nil, err
	}
	var files []File
	add := func(path, data string) { files = append(files, File{Path: path, Data: []byte(data)}) }

	rsaRecord, err := dkimtest.PublicKeyRecord(k.rsa)
	if err != nil {
		return nil, err
	}
	edRecord, err := dkimtest.PublicKeyRecord(k.ed)
	if err != nil {
		return nil, err
	}
	add("testdata/dns/zone.txt", zone(rsaRecord, edRecord))

	base := func(from, subject, msgid string) []string {
		return []string{
			"From: " + from,
			"To: Bob <bob@receiver.example>",
			"Subject: " + subject,
			"Date: " + dateHeader,
			"Message-ID: <" + msgid + ">",
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=utf-8",
		}
	}
	body := []string{"Hello Bob,", "", "the quarterly report is ready.", "", "-- ", "Alice"}

	// 1. Valid message: DKIM, SPF and DMARC pass with relaxed alignment.
	valid, err := signWith(message(base("Alice <alice@test.example>", "Quarterly report", "valid-1@test.example"), body...), k.rsa, "test.example", rsaSelector)
	if err != nil {
		return nil, err
	}
	add("testdata/messages/valid.eml", prepend(valid,
		"Return-Path: <bounces@test.example>",
		"Authentication-Results: "+receiver+";\r\n\tdkim=pass header.d=test.example header.s="+rsaSelector+";\r\n\tspf=pass smtp.mailfrom=bounces@test.example;\r\n\tdmarc=pass header.from=test.example",
		received("mail.test.example", goodIP, "4A1B2C3D4E")))

	// 2. Signature mismatch: a signed header was changed after signing.
	tampered := strings.Replace(valid, "Subject: Quarterly report", "Subject: Urgent: update your payment details", 1)
	add("testdata/messages/dkim-signature-mismatch.eml", prepend(tampered,
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "5B2C3D4E5F")))

	// 3. Body hash mismatch: the body was changed after signing.
	bodyTampered := strings.Replace(valid, "the quarterly report is ready.", "the quarterly report is ready: http://phish.invalid/login", 1)
	add("testdata/messages/dkim-body-hash-mismatch.eml", prepend(bodyTampered,
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "6C3D4E5F6A")))

	// 4. Multiple signatures: author domain (RSA and Ed25519) and an ESP
	// whose key is not published.
	multi, err := signWith(message(base("Alice <alice@test.example>", "Newsletter", "multi-1@test.example"), body...), k.rsa, "test.example", rsaSelector)
	if err != nil {
		return nil, err
	}
	if multi, err = signWith(multi, k.ed, "test.example", edSelector); err != nil {
		return nil, err
	}
	if multi, err = signWith(multi, k.rsa, "esp.example", "mailer", func(o *dkimtest.Options) { o.Canon = "simple/simple" }); err != nil {
		return nil, err
	}
	add("testdata/messages/dkim-multiple.eml", prepend(multi,
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "7D4E5F6A7B")))

	// 5. SPF pass: unsigned, sent from an authorized address.
	add("testdata/messages/spf-pass.eml", prepend(message(base("Alice <alice@test.example>", "SPF only", "spfpass-1@test.example"), body...),
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "9F6A7B8C9D")))

	// 6. SPF fail: unsigned, sent from an address outside the SPF record.
	add("testdata/messages/spf-fail.eml", prepend(message(base("Alice <alice@test.example>", "Password reset", "spffail-1@test.example"), body...),
		"Return-Path: <bounces@test.example>",
		received("unknown.invalid", attackerIP, "AA7B8C9DAE")))

	// 7. SPF lookup limit: the envelope domain's policy needs 11 lookups.
	add("testdata/messages/spf-lookup-limit.eml", prepend(message(base("Newsletter <news@lookups.example>", "Monthly news", "lookups-1@lookups.example"), body...),
		"Return-Path: <bounce@lookups.example>",
		received("mail.lookups.example", goodIP, "BB8C9DAEBF")))

	// 8. SPF recursion loop.
	add("testdata/messages/spf-loop.eml", prepend(message(base("Loop <a@loop.example>", "Loop", "loop-1@loop.example"), body...),
		"Return-Path: <bounce@loop.example>",
		received("mail.loop.example", goodIP, "CC9DAEBFC0")))

	// 9. DMARC reject: test.example spoofed by evil.example, which signs and
	// passes SPF for its own domain only.
	spoof, err := signWith(message(base("IT Support <support@test.example>", "Your mailbox is full", "spoof-1@evil.example"), body...), k.rsa, "evil.example", "s1")
	if err != nil {
		return nil, err
	}
	add("testdata/messages/dmarc-reject.eml", prepend(spoof,
		"Return-Path: <bounce@evil.example>",
		received("mail.evil.example", attackerIP, "DDAEBFC0D1")))

	// 10. DMARC none: none.example publishes p=none; the message fails.
	add("testdata/messages/dmarc-none.eml", prepend(message(base("Billing <billing@none.example>", "Invoice overdue", "none-1@evil.example"), body...),
		"Return-Path: <bounce@evil.example>",
		received("mail.evil.example", attackerIP, "EEBFC0D1E2")))

	// 11. Strict alignment fail: signed and sent by a subdomain of
	// strict.example, which requires adkim=s and aspf=s.
	strict, err := signWith(message(base("Alerts <alerts@strict.example>", "Alert", "strict-1@strict.example"), body...), k.rsa, "mail.strict.example", rsaSelector)
	if err != nil {
		return nil, err
	}
	add("testdata/messages/dmarc-strict-alignment-fail.eml", prepend(strict,
		"Return-Path: <bounce@mail.strict.example>",
		received("mail.strict.example", goodIP, "FFC0D1E2F3")))

	// 12. Relaxed alignment pass: same setup under relaxed.example.
	relaxed, err := signWith(message(base("Alerts <alerts@relaxed.example>", "Alert", "relaxed-1@relaxed.example"), body...), k.rsa, "mail.relaxed.example", rsaSelector)
	if err != nil {
		return nil, err
	}
	add("testdata/messages/dmarc-relaxed-alignment-pass.eml", prepend(relaxed,
		"Return-Path: <bounce@mail.relaxed.example>",
		received("mail.relaxed.example", attackerIP, "10D1E2F304")))

	// 13. Malformed MIME: missing boundary on a nested multipart, an unknown
	// transfer encoding and an unterminated outer multipart.
	add("testdata/messages/malformed.eml", prepend(strings.Join([]string{
		"From: Alice <alice@test.example>",
		"To: bob@receiver.example",
		"Subject: Malformed MIME",
		"Date: " + dateHeader,
		"Message-ID: <malformed-1@test.example>",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="outer"`,
		"",
		"--outer",
		"Content-Type: multipart/alternative",
		"",
		"no boundary parameter above",
		"--outer",
		"Content-Type: application/octet-stream; name=\"payload.js\"",
		"Content-Transfer-Encoding: x-custom",
		"Content-Disposition: attachment; filename=\"payload.js\"",
		"",
		"ZXZhbCgp",
		"",
	}, "\r\n"), received("mail.test.example", goodIP, "21E2F30415")))

	// 14. Malformed headers: continuation before the first field, whitespace
	// before a colon, a duplicated From and a line that is not a header.
	add("testdata/messages/malformed-headers.eml", strings.Join([]string{
		" orphan continuation line",
		"Received: from mail.test.example (mail.test.example [" + goodIP + "]) by " + receiver + " with ESMTPS id 32F3041526; " + dateHeader,
		"From: Alice <alice@test.example>",
		"From: Security Team <security@bank.example>",
		"Subject : Account verification",
		"Date: " + dateHeader,
		"This line is not a header: but looks like one",
		"Message-ID: <hidden@test.example>",
		"",
		"body",
		"",
	}, "\r\n"))

	// 15. Conflicting Authentication-Results: two headers from the same
	// authserv-id disagree, and the top one claims a DKIM pass for a
	// signature that does not verify.
	add("testdata/messages/conflicting-auth-results.eml", prepend(tampered,
		"Authentication-Results: "+receiver+"; dkim=pass header.d=test.example header.s="+rsaSelector+"; spf=pass smtp.mailfrom=bounces@test.example; dmarc=pass header.from=test.example",
		"Authentication-Results: "+receiver+"; dkim=fail header.d=test.example header.s="+rsaSelector+"; spf=pass smtp.mailfrom=bounces@test.example; dmarc=fail header.from=test.example",
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "43041526A7")))

	// 17. Oversized headers: a header section larger than the 512 KiB limit.
	var big strings.Builder
	for i := 0; big.Len() < 600<<10; i++ {
		fmt.Fprintf(&big, "X-Padding-%05d: %s\r\n", i, strings.Repeat("A", 900))
	}
	add("testdata/messages/oversized-headers.eml", big.String()+message(base("Alice <alice@test.example>", "Big", "big-1@test.example"), "x"))

	// Header section only, as copied from a mail client.
	add("testdata/messages/headers.txt", strings.SplitN(prepend(valid,
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "4A1B2C3D4E")), "\r\n\r\n", 2)[0]+"\r\n")

	// 16. Message without DKIM.
	add("testdata/messages/no-dkim.eml", prepend(message(base("Alice <alice@test.example>", "Unsigned", "nodkim-1@test.example"), body...),
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "8E5F6A7B8C")))

	return files, nil
}

func zone(rsaRecord, edRecord string) string {
	var lookups strings.Builder
	var includes []string
	for i := 1; i <= 11; i++ {
		fmt.Fprintf(&lookups, "inc%d.lookups.example.            TXT   \"v=spf1 ip4:198.51.100.%d -all\"\n", i, i)
		includes = append(includes, fmt.Sprintf("include:inc%d.lookups.example", i))
	}
	return `; DNS zone for MailAuthProbe fixtures and functional tests.
; Generated by internal/tools/fixturegen; do not edit by hand.
;
; Addresses: 192.0.2.10 is the legitimate sender, 203.0.113.66 the attacker.

; test.example: well-configured domain
test.example.                    MX    10 mx1.test.example.
test.example.                    MX    20 mx2.test.example.
mx1.test.example.                A     192.0.2.25
mx1.test.example.                AAAA  2001:db8::25
mx2.test.example.                A     192.0.2.26
mx2.test.example.                AAAA  2001:db8::26
mail.test.example.               A     192.0.2.10
test.example.                    TXT   "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/48 -all"
_dmarc.test.example.             TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@test.example"
` + rsaSelector + `._domainkey.test.example.   TXT   "` + rsaRecord + `"
` + edSelector + `._domainkey.test.example.  TXT   "` + edRecord + `"

; evil.example: attacker-controlled domain with valid SPF and DKIM
evil.example.                    TXT   "v=spf1 ip4:203.0.113.0/24 -all"
s1._domainkey.evil.example.      TXT   "` + rsaRecord + `"

; none.example: DMARC monitoring only
none.example.                    TXT   "v=spf1 ip4:192.0.2.0/24 ~all"
_dmarc.none.example.             TXT   "v=DMARC1; p=none; rua=mailto:dmarc@none.example"

; strict.example: strict alignment, mail sent from a subdomain
_dmarc.strict.example.           TXT   "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc@strict.example"
strict.example.                  TXT   "v=spf1 -all"
mail.strict.example.             TXT   "v=spf1 ip4:192.0.2.0/24 -all"
` + rsaSelector + `._domainkey.mail.strict.example. TXT "` + rsaRecord + `"

; relaxed.example: relaxed alignment, mail sent from a subdomain
_dmarc.relaxed.example.          TXT   "v=DMARC1; p=quarantine; rua=mailto:dmarc@relaxed.example"
mail.relaxed.example.            TXT   "v=spf1 ip4:192.0.2.0/24 -all"
` + rsaSelector + `._domainkey.mail.relaxed.example. TXT "` + rsaRecord + `"

; lookups.example: SPF needs 11 DNS lookups
lookups.example.                 TXT   "v=spf1 ` + strings.Join(includes, " ") + ` ip4:192.0.2.0/24 -all"
_dmarc.lookups.example.          TXT   "v=DMARC1; p=reject"
` + lookups.String() + `
; loop.example: include loop
loop.example.                    TXT   "v=spf1 include:a.loop.example -all"
a.loop.example.                  TXT   "v=spf1 include:loop.example -all"
_dmarc.loop.example.             TXT   "v=DMARC1; p=quarantine"

; broken.example and garbled.example: DNS failures
broken.example.                  TIMEOUT
_dmarc.broken.example.           TIMEOUT
garbled.example.                 MALFORMED
_dmarc.garbled.example.          MALFORMED
`
}
