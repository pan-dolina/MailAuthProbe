package dkim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
)

func FuzzParseKeyRecord(f *testing.F) {
	for _, s := range []string{
		"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
		"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
		"v=DKIM1; p=",
		"v=DKIM1; h=sha1:sha256; s=email:*; t=y:s; n=note; p=AAAA",
		"k=rsa; v=DKIM1",
		";;;=;",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		k, err := ParseKeyRecord(record)
		if err != nil {
			return
		}
		if !k.Revoked && k.PublicKey == nil {
			t.Fatal("non-revoked key without public key")
		}
		_ = KeyFindings("fuzz._domainkey.example.com", k)
	})
}

func FuzzParseSignature(f *testing.F) {
	f.Add("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1; t=1; x=2; l=10; i=a@sub.example.com; q=dns/txt; h=From:To; bh=AAAA; b=AAAA")
	f.Add("v=1; a=ed25519-sha256; d=example.com; s=s; h=from; bh=; b=")
	f.Fuzz(func(t *testing.T, value string) {
		sig, err := ParseSignature(mailparser.Header{Name: "DKIM-Signature", Value: value, Raw: []byte("DKIM-Signature: " + value + "\r\n")})
		if err != nil {
			return
		}
		if sig.Domain == "" || sig.Selector == "" || len(sig.SignedHeaders) == 0 {
			t.Fatalf("incomplete signature accepted: %+v", sig)
		}
		_ = stripSignatureValue(sig.Header.Raw)
	})
}

// FuzzVerifyMessage runs full verification on arbitrary messages against
// the fixture zone.
func FuzzVerifyMessage(f *testing.F) {
	zoneText, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dns", "zone.txt"))
	if err != nil {
		f.Fatal(err)
	}
	zone := dnstest.MustParseZone(string(zoneText))
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "messages", "*.eml"))
	for _, name := range files {
		if data, err := os.ReadFile(name); err == nil && len(data) < 64<<10 {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := mailparser.ParseBytes(data, mailparser.Options{Limits: mailparser.Limits{MaxMessageBytes: 1 << 20}})
		if err != nil {
			return
		}
		vs := VerifyMessage(context.Background(), zone, msg, VerifyOptions{Now: time.Unix(1789380000, 0)})
		if len(vs) > MaxSignatures {
			t.Fatalf("%d verifications exceed the limit", len(vs))
		}
		for _, v := range vs {
			if v.Result == ResultPass && (v.SignatureOK == nil || !*v.SignatureOK || v.BodyHashOK == nil || !*v.BodyHashOK) {
				t.Fatalf("pass without successful checks: %+v", v)
			}
		}
	})
}

func FuzzCanonicalization(f *testing.F) {
	f.Add([]byte("Subject:  a \r\n\tb \r\n"), []byte(" line \t\r\n\r\n\r\n"))
	f.Add([]byte(":\n"), []byte("\n\r\r\n"))
	f.Fuzz(func(t *testing.T, header, body []byte) {
		for _, alg := range []string{CanonSimple, CanonRelaxed} {
			_ = canonHeader(header, alg)
			var full, limited countingWriter
			n := CanonicalBody(&full, body, alg, -1)
			if int64(full.n) != n {
				t.Fatalf("%s: reported length %d, wrote %d", alg, n, full.n)
			}
			CanonicalBody(&limited, body, alg, n/2)
			if limited.n != n/2 {
				t.Fatalf("%s: limit %d wrote %d", alg, n/2, limited.n)
			}
		}
	})
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
