package dkim_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pan-dolina/mailauthprobe/internal/dkim"
	"github.com/pan-dolina/mailauthprobe/internal/dkim/dkimtest"
	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/pan-dolina/mailauthprobe/internal/mailparser"
)

var (
	keysOnce sync.Once
	rsaKey   *rsa.PrivateKey
	rsaOther *rsa.PrivateKey
	edKey    ed25519.PrivateKey
)

func keys(t *testing.T) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if rsaOther, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		edKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	})
}

const baseMessage = "From: Alice <alice@example.com>\r\n" +
	"To: bob@example.net\r\n" +
	"Subject: Quarterly  report\r\n" +
	"\tcontinued\r\n" +
	"Date: Mon, 14 Sep 2026 10:00:00 +0000\r\n" +
	"Message-ID: <1@example.com>\r\n" +
	"\r\n" +
	"Hello Bob,  \r\n" +
	"\r\n" +
	"the numbers are attached.\r\n" +
	"\r\n" +
	"\r\n"

func zoneFor(t *testing.T, extra string) *dnstest.Zone {
	t.Helper()
	keys(t)
	rsaRec, _ := dkimtest.PublicKeyRecord(rsaKey)
	edRec, _ := dkimtest.PublicKeyRecord(edKey)
	return dnstest.MustParseZone(`
s1._domainkey.example.com.   TXT "` + rsaRec + `"
ed._domainkey.example.com.   TXT "` + edRec + `"
revoked._domainkey.example.com. TXT "v=DKIM1; p="
sha1only._domainkey.example.com. TXT "v=DKIM1; h=sha1; ` + strings.TrimPrefix(rsaRec, "v=DKIM1; ") + `"
strict._domainkey.example.com. TXT "v=DKIM1; t=s; ` + strings.TrimPrefix(rsaRec, "v=DKIM1; ") + `"
flaky._domainkey.example.com. SERVFAIL
` + extra)
}

func sign(t *testing.T, msg string, opts dkimtest.Options) []byte {
	t.Helper()
	keys(t)
	if opts.Domain == "" {
		opts.Domain = "example.com"
	}
	if opts.Selector == "" {
		opts.Selector = "s1"
	}
	if opts.Signer == nil {
		opts.Signer = rsaKey
	}
	out, err := dkimtest.Sign([]byte(msg), opts)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func verify(t *testing.T, zone *dnstest.Zone, raw []byte, headersOnly bool) []dkim.Verification {
	t.Helper()
	msg, err := mailparser.ParseBytes(raw, mailparser.Options{HeadersOnly: headersOnly})
	if err != nil {
		t.Fatal(err)
	}
	return dkim.VerifyMessage(context.Background(), zone, msg, dkim.VerifyOptions{Now: time.Unix(1789380000, 0)})
}

func TestVerify(t *testing.T) {
	keys(t)
	tests := []struct {
		name    string
		raw     func(t *testing.T) []byte
		result  dkim.Result
		failure string
	}{
		{"relaxed/relaxed", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{}) }, dkim.ResultPass, ""},
		{"simple/simple", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Canon: "simple/simple"}) }, dkim.ResultPass, ""},
		{"relaxed/simple", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Canon: "relaxed/simple"}) }, dkim.ResultPass, ""},
		{"simple (body default)", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Canon: "simple"}) }, dkim.ResultPass, ""},
		{"ed25519", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{Signer: edKey, Selector: "ed"})
		}, dkim.ResultPass, ""},
		{"with auid subdomain", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{AUID: "alice@mail.example.com"})
		}, dkim.ResultPass, ""},
		{"relaxed tolerates whitespace changes", func(t *testing.T) []byte {
			raw := sign(t, baseMessage, dkimtest.Options{})
			raw = bytes.Replace(raw, []byte("Subject: Quarterly  report"), []byte("subject:   Quarterly report "), 1)
			return bytes.Replace(raw, []byte("Hello Bob,  \r\n"), []byte("Hello   Bob,\r\n"), 1)
		}, dkim.ResultPass, ""},
		{"relaxed tolerates trailing blank lines", func(t *testing.T) []byte {
			return append(sign(t, baseMessage, dkimtest.Options{}), "\r\n\r\n"...)
		}, dkim.ResultPass, ""},
		{"LF line endings on disk", func(t *testing.T) []byte {
			return bytes.ReplaceAll(sign(t, baseMessage, dkimtest.Options{Canon: "simple/simple"}), []byte("\r\n"), []byte("\n"))
		}, dkim.ResultPass, ""},
		{"simple detects header whitespace change", func(t *testing.T) []byte {
			raw := sign(t, baseMessage, dkimtest.Options{Canon: "simple/simple"})
			return bytes.Replace(raw, []byte("Subject: Quarterly  report"), []byte("Subject: Quarterly report"), 1)
		}, dkim.ResultFail, dkim.FailSignature},
		{"simple detects body whitespace change", func(t *testing.T) []byte {
			raw := sign(t, baseMessage, dkimtest.Options{Canon: "simple/simple"})
			return bytes.Replace(raw, []byte("Hello Bob,  "), []byte("Hello Bob,"), 1)
		}, dkim.ResultFail, dkim.FailBodyHash},
		{"body modified", func(t *testing.T) []byte {
			return bytes.Replace(sign(t, baseMessage, dkimtest.Options{}), []byte("numbers"), []byte("NUMBERS"), 1)
		}, dkim.ResultFail, dkim.FailBodyHash},
		{"signed header modified", func(t *testing.T) []byte {
			return bytes.Replace(sign(t, baseMessage, dkimtest.Options{}), []byte("alice@example.com"), []byte("mallory@example.com"), 1)
		}, dkim.ResultFail, dkim.FailSignature},
		{"unsigned header added is fine", func(t *testing.T) []byte {
			return append([]byte("X-Spam-Score: 0\r\n"), sign(t, baseMessage, dkimtest.Options{})...)
		}, dkim.ResultPass, ""},
		{"second From added below breaks signature", func(t *testing.T) []byte {
			raw := sign(t, baseMessage, dkimtest.Options{})
			return bytes.Replace(raw, []byte("\r\n\r\nHello"), []byte("\r\nFrom: mallory@evil.example\r\n\r\nHello"), 1)
		}, dkim.ResultFail, dkim.FailSignature},
		{"oversigned From prevents added From", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{Headers: []string{"From", "From", "Subject", "Date"}})
		}, dkim.ResultPass, ""},
		{"wrong key published", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{Signer: rsaOther})
		}, dkim.ResultFail, dkim.FailSignature},
		{"body length allows appended content", func(t *testing.T) []byte {
			raw := sign(t, baseMessage, dkimtest.Options{BodyLength: -1, BodyLengthSet: true})
			return append(raw, "Appended by an attacker.\r\n"...)
		}, dkim.ResultPass, ""},
		{"body length longer than body", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{BodyLength: 100000, BodyLengthSet: true})
		}, dkim.ResultFail, dkim.FailBodyHash},
		{"rsa-sha1", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Hash: "sha1"}) }, dkim.ResultPermError, dkim.FailInsecureAlgorithm},
		{"key requires sha1 only", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Selector: "sha1only"}) }, dkim.ResultPermError, dkim.FailKeyUnsuitable},
		{"strict identity", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{Selector: "strict", AUID: "a@sub.example.com"})
		}, dkim.ResultPermError, dkim.FailKeyUnsuitable},
		{"expired", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{Timestamp: 1700000000, Expire: 1700086400})
		}, dkim.ResultPermError, dkim.FailExpired},
		{"key not found", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Selector: "missing"}) }, dkim.ResultPermError, dkim.FailKeyNotFound},
		{"key revoked", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Selector: "revoked"}) }, dkim.ResultPermError, dkim.FailKeyRevoked},
		{"key type mismatch", func(t *testing.T) []byte {
			return sign(t, baseMessage, dkimtest.Options{Signer: edKey, Selector: "s1"})
		}, dkim.ResultPermError, dkim.FailKeyUnsuitable},
		{"dns failure", func(t *testing.T) []byte { return sign(t, baseMessage, dkimtest.Options{Selector: "flaky"}) }, dkim.ResultTempError, dkim.FailDNS},
		{"syntax error", func(t *testing.T) []byte {
			return []byte("DKIM-Signature: v=1; a=rsa-sha256; d=example.com\r\n" + baseMessage)
		}, dkim.ResultPermError, dkim.FailSyntax},
	}
	zone := zoneFor(t, "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := verify(t, zone, tt.raw(t), false)
			if len(vs) != 1 {
				t.Fatalf("got %d verifications", len(vs))
			}
			v := vs[0]
			if v.Result != tt.result || v.Failure != tt.failure {
				t.Errorf("result = %s/%s (%s), want %s/%s", v.Result, v.Failure, v.Reason, tt.result, tt.failure)
			}
		})
	}
}

func TestVerifyHeadersOnly(t *testing.T) {
	zone := zoneFor(t, "")
	raw := sign(t, baseMessage, dkimtest.Options{})
	vs := verify(t, zone, bytes.Replace(raw, []byte("numbers"), []byte("NUMBERS"), 1), true)
	if vs[0].Result != dkim.ResultNeutral || vs[0].BodyHashOK != nil || vs[0].SignatureOK == nil || !*vs[0].SignatureOK {
		t.Errorf("headers-only = %+v", vs[0])
	}
}

func TestVerifyMultipleSignatures(t *testing.T) {
	zone := zoneFor(t, "")
	raw := sign(t, baseMessage, dkimtest.Options{})                                          // author domain
	raw = sign(t, string(raw), dkimtest.Options{Signer: edKey, Selector: "ed"})              // ed25519 by same domain
	raw = sign(t, string(raw), dkimtest.Options{Selector: "missing", Domain: "esp.example"}) // third party, no key
	vs := verify(t, zone, raw, false)
	if len(vs) != 3 {
		t.Fatalf("got %d", len(vs))
	}
	got := []dkim.Result{vs[0].Result, vs[1].Result, vs[2].Result}
	want := []dkim.Result{dkim.ResultPermError, dkim.ResultPass, dkim.ResultPass}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("signature %d (%s) = %s: %s", i+1, vs[i].Domain, got[i], vs[i].Reason)
		}
	}
	if vs[0].Index != 1 || vs[2].Index != 3 {
		t.Error("indexes not set")
	}
}

func TestVerifyLimitsSignatureCount(t *testing.T) {
	zone := zoneFor(t, "")
	raw := []byte(baseMessage)
	for range dkim.MaxSignatures + 5 {
		raw = sign(t, string(raw), dkimtest.Options{})
	}
	vs := verify(t, zone, raw, false)
	if len(vs) != dkim.MaxSignatures {
		t.Errorf("verified %d signatures", len(vs))
	}
	if q := len(zone.Queries()); q != 1 {
		t.Errorf("key fetched %d times, want 1 (cached per message)", q)
	}
}
