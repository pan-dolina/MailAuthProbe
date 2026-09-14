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

	"github.com/marcindolinski/mailauthprobe/internal/dkim/dkimtest"
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
	data, err := os.ReadFile(filepath.Join(root, "testdata", "keys", "test-rsa2048.pem"))
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

	// 16. Message without DKIM.
	add("testdata/messages/no-dkim.eml", prepend(message(base("Alice <alice@test.example>", "Unsigned", "nodkim-1@test.example"), body...),
		"Return-Path: <bounces@test.example>",
		received("mail.test.example", goodIP, "8E5F6A7B8C")))

	return files, nil
}

func zone(rsaRecord, edRecord string) string {
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
`
}
