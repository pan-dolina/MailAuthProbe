package dkim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
	"github.com/pan-dolina/mailauthprobe/internal/findings"
)

// Keys generated with openssl for sizes the Go runtime refuses to generate.
const (
	rsa512SPKI  = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMoAfp4pgsGmNq2MjkywdiLsG6bdr+hn7a7kwlsnEZ3oplkeOtjyFBtmNE9R8Y58g8i/WkXCYLaQCieP1/rgfi0CAwEAAQ=="
	rsa512PKCS1 = "MEgCQQDKAH6eKYLBpjatjI5MsHYi7Bum3a/oZ+2u5MJbJxGd6KZZHjrY8hQbZjRPUfGOfIPIv1pFwmC2kAonj9f64H4tAgMBAAE="
	rsa5120SPKI = "MIICojANBgkqhkiG9w0BAQEFAAOCAo8AMIICigKCAoEA1lXuzojcFaUKhhlownc1yfImMHWAb53V0qlpDtqEj5MR2rKhkk1gx4sPBcLWJMZRF7No58HeYGdKyAeBq2GkGUvYLSqRfuvKq/N6uOOYT1NpqQmu3XK6HJFNbEGZeECL5MzDqdj2xnryMTYvjkrXvmH1biocWdabKvo3ewDYVh5ihEs6dPiaBrSSnZvNwoftvc+5tbpxfUbn7kpva7Y3WgSg+QK3Mc/muPhm/Avpob08JLoCp+Q3fNhFDofM2EqrKZ4X61zhMARW2eu3xt5Uujl/r9tE+OW+Z8ysOvC2mgPFqJjuRZrdY+Vx1vPTlHi1nrc1OOG/cAYTBOltIZ8jYjRknMW+7OqqojAteqLvhl5lJnEp2sqHBw95O/9MLPA1fSNz8lFVwqhvmb76A8mngdo1uFvoGU5qSioXhcCqaPg1IcgsUocnvLbmtwT59dWCfAmVsE3pP0wQ85GEZ3G5E9TeBBseg6ehZcw3sefms3dD+m6OTmUg0CckvYZLXjgdRpFdEztmhKPKJmgt9Q2s0Us3clqALsZWTNnUR8rtQ96sm231wMa4sOgzgrMO2/F0AmaJbbh0Z5z5aLNFxLy8i36bBJTWVzteT25sTJ3kJeKtInuR3DJu2YVb6ZjIQVjBdffawogvvAbtersDt4mieJU+l0XZjAH2LFV0ZQsixy2y/j6lrE0LTiTD52gvFeisqBeC6NBkcrj8GyvgGqNpX5ML6SKwQAECLcZKHAJwPe8PyAX+fSWK8MVfeVeuDZk5KMCQiubL7Z5N8niOrKkn+nn3f/83mW8087GNMxn3KesDdDu5xdkiINkvjwoqcdm5Xsw6wQrl92EpPheP5S1shwIDAQAB"
)

var (
	keyOnce    sync.Once
	rsa1024    string
	rsa2048    string
	ed25519Pub string
)

func testKeys(t *testing.T) {
	t.Helper()
	keyOnce.Do(func() {
		for _, bits := range []int{1024, 2048} {
			k, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				panic(err)
			}
			der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if bits == 1024 {
				rsa1024 = base64.StdEncoding.EncodeToString(der)
			} else {
				rsa2048 = base64.StdEncoding.EncodeToString(der)
			}
		}
		pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		ed25519Pub = base64.StdEncoding.EncodeToString(pub)
	})
}

func TestParseTagList(t *testing.T) {
	tags, err := parseTagList(" v = DKIM1 ;k=rsa;\r\n\tp=ab cd ; ")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 3 || tags[0] != (tag{"v", "DKIM1"}) || tags[2] != (tag{"p", "ab cd"}) {
		t.Errorf("tags = %+v", tags)
	}
	for _, bad := range []string{"v=DKIM1; v=DKIM1", "novalue", "1a=b", "a-b=c", "=x"} {
		if _, err := parseTagList(bad); err == nil {
			t.Errorf("parseTagList(%q) succeeded", bad)
		}
	}
}

func TestParseKeyRecord(t *testing.T) {
	testKeys(t)
	tests := []struct {
		name    string
		txt     string
		check   func(*testing.T, *KeyRecord)
		wantErr string
	}{
		{name: "rsa 2048", txt: "v=DKIM1; k=rsa; p=" + rsa2048, check: func(t *testing.T, k *KeyRecord) {
			if k.KeyBits != 2048 || k.KeyType != "rsa" || k.Revoked || !k.AllowsEmail() || !k.AllowsHash("sha256") {
				t.Errorf("%+v", k)
			}
		}},
		{name: "defaults without v and k", txt: "p=" + rsa1024, check: func(t *testing.T, k *KeyRecord) {
			if k.KeyBits != 1024 || k.KeyType != "rsa" || k.Version != "" {
				t.Errorf("%+v", k)
			}
		}},
		{name: "base64 with folding whitespace", txt: "v=DKIM1; p=" + rsa2048[:40] + " \r\n\t" + rsa2048[40:], check: func(t *testing.T, k *KeyRecord) {
			if k.KeyBits != 2048 {
				t.Errorf("bits = %d", k.KeyBits)
			}
		}},
		{name: "pkcs1", txt: "v=DKIM1; p=" + rsa512PKCS1, check: func(t *testing.T, k *KeyRecord) {
			if !k.PKCS1 || k.KeyBits != 512 {
				t.Errorf("%+v", k)
			}
		}},
		{name: "ed25519", txt: "v=DKIM1; k=ed25519; p=" + ed25519Pub, check: func(t *testing.T, k *KeyRecord) {
			if k.KeyType != "ed25519" || k.KeyBits != 256 {
				t.Errorf("%+v", k)
			}
		}},
		{name: "revoked", txt: "v=DKIM1; p=", check: func(t *testing.T, k *KeyRecord) {
			if !k.Revoked {
				t.Error("not revoked")
			}
		}},
		{name: "flags services hashes notes", txt: "v=DKIM1; h=sha1:SHA256; s=email:*; t=y:s; n=rotated 2026; x=1; p=" + rsa1024, check: func(t *testing.T, k *KeyRecord) {
			if !k.Testing() || !k.StrictIdentity() || !k.AllowsHash("sha1") || !slices.Equal(k.Services, []string{"email", "*"}) ||
				k.Notes != "rotated 2026" || !slices.Equal(k.UnknownTags, []string{"x"}) {
				t.Errorf("%+v", k)
			}
		}},
		{name: "v not first", txt: "k=rsa; v=DKIM1; p=" + rsa1024, wantErr: "must be the first tag"},
		{name: "wrong version", txt: "v=DKIM2; p=" + rsa1024, wantErr: "unsupported version"},
		{name: "missing p", txt: "v=DKIM1; k=rsa", wantErr: "p is missing"},
		{name: "bad base64", txt: "v=DKIM1; p=!!!notbase64", wantErr: "not valid base64"},
		{name: "not a key", txt: "v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte("hello world")), wantErr: "not a valid RSA public key"},
		{name: "ed25519 wrong length", txt: "v=DKIM1; k=ed25519; p=" + rsa1024, wantErr: "must be 32 bytes"},
		{name: "rsa key declared as ed25519 size mismatch", txt: "v=DKIM1; k=rsa; p=" + ed25519Pub, wantErr: "not a valid RSA public key"},
		{name: "unknown key type", txt: "v=DKIM1; k=dsa; p=" + rsa1024, wantErr: "unsupported key type"},
		{name: "duplicate tag", txt: "v=DKIM1; p=" + rsa1024 + "; p=" + rsa1024, wantErr: "duplicate tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseKeyRecord(tt.txt)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, k)
		})
	}
}

func TestAssessSelectors(t *testing.T) {
	testKeys(t)
	zone := dnstest.MustParseZone(`
good._domainkey.example.com.     TXT "v=DKIM1; k=rsa; p=` + rsa2048 + `"
weak._domainkey.example.com.     TXT "v=DKIM1; k=rsa; p=` + rsa1024 + `"
tiny._domainkey.example.com.     TXT "v=DKIM1; k=rsa; p=` + rsa512SPKI + `"
huge._domainkey.example.com.     TXT "v=DKIM1; k=rsa; p=` + rsa5120SPKI + `"
pkcs1._domainkey.example.com.    TXT "v=DKIM1; p=` + rsa512PKCS1 + `"
ed._domainkey.example.com.       TXT "v=DKIM1; k=ed25519; p=` + ed25519Pub + `"
revoked._domainkey.example.com.  TXT "v=DKIM1; p="
test._domainkey.example.com.     TXT "v=DKIM1; t=y; p=` + rsa2048 + `"
sha1._domainkey.example.com.     TXT "v=DKIM1; h=sha1; p=` + rsa2048 + `"
web._domainkey.example.com.      TXT "v=DKIM1; s=tlsrpt; p=` + rsa2048 + `"
broken._domainkey.example.com.   TXT "v=DKIM1; p=AAAA"
dup._domainkey.example.com.      TXT "v=DKIM1; p=` + rsa2048 + `"
dup._domainkey.example.com.      TXT "v=DKIM1; p=` + rsa1024 + `"
extra._domainkey.example.com.    TXT "v=DKIM1; foo=bar; p=` + rsa2048 + `"
flaky._domainkey.example.com.    SERVFAIL
`)
	tests := []struct {
		selector string
		want     []string
		wantErr  bool
	}{
		{"good", []string{"MAIL-DKIM-012"}, false},
		{"GOOD", []string{"MAIL-DKIM-012"}, false},
		{"weak", []string{"MAIL-DKIM-006"}, false},
		{"tiny", []string{"MAIL-DKIM-005"}, false},
		{"huge", []string{"MAIL-DKIM-007"}, false},
		{"pkcs1", []string{"MAIL-DKIM-005", "MAIL-DKIM-015"}, false},
		{"ed", []string{"MAIL-DKIM-011", "MAIL-DKIM-012"}, false},
		{"revoked", []string{"MAIL-DKIM-004"}, false},
		{"test", []string{"MAIL-DKIM-009"}, false},
		{"sha1", []string{"MAIL-DKIM-008"}, false},
		{"web", []string{"MAIL-DKIM-010"}, false},
		{"broken", []string{"MAIL-DKIM-003"}, false},
		{"dup", []string{"MAIL-DKIM-013"}, false},
		{"extra", []string{"MAIL-DKIM-012", "MAIL-DKIM-014"}, false},
		{"missing", []string{"MAIL-DKIM-002"}, false},
		{"bad selector", []string{"MAIL-DKIM-002"}, false},
		{"flaky", []string{"MAIL-DNS-001"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			a, err := Assess(context.Background(), zone, "example.com", []string{tt.selector}, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			var got []string
			for _, f := range a.Findings {
				got = append(got, f.ID)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
				for _, f := range a.Findings {
					t.Logf("  %s: %s", f.ID, f.Description)
				}
			}
		})
	}
}

func TestAssessWithoutSelector(t *testing.T) {
	a, err := Assess(context.Background(), dnstest.NewZone(), "example.com", nil, nil)
	if err != nil || len(a.Findings) != 1 || a.Findings[0].ID != findings.DKIMNoSelector.ID {
		t.Fatalf("findings = %+v, err = %v", a.Findings, err)
	}
}

func TestAssessDeduplicatesSelectors(t *testing.T) {
	zone := dnstest.MustParseZone("s._domainkey.example.com. TXT \"v=DKIM1; p=\"")
	a, _ := Assess(context.Background(), zone, "example.com", []string{"s", " S ", ""}, nil)
	if len(a.Selectors) != 1 || len(zone.Queries()) != 1 {
		t.Errorf("selectors = %d, queries = %d", len(a.Selectors), len(zone.Queries()))
	}
}

func TestParseKeyRecordRejectsHugeRSAKeys(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), MaxRSAKeyBits+100)
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseKeyRecord("v=DKIM1; p=" + base64.StdEncoding.EncodeToString(der))
	if err == nil || !strings.Contains(err.Error(), "exceeds the supported maximum") {
		t.Errorf("err = %v", err)
	}
}
