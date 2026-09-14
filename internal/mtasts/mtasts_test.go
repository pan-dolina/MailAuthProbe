package mtasts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

func TestParseRecord(t *testing.T) {
	r, err := ParseRecord("v=STSv1; id=20260914T010101; ext=1;")
	if err != nil || r.ID != "20260914T010101" || r.Extensions["ext"] != "1" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{
		"v=STSv2; id=1",
		"id=1; v=STSv1",
		"v=STSv1;",
		"v=STSv1; id=",
		"v=STSv1; id=has-dash",
		"v=STSv1; id=" + strings.Repeat("a", 33),
		"v=STSv1; id=1; id=2",
		"v=STSv1; garbage",
	} {
		if _, err := ParseRecord(bad); err == nil {
			t.Errorf("ParseRecord(%q) succeeded", bad)
		}
	}
}

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy("version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.mail.example.com.\r\nmax_age: 604800\r\nfuture: yes\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeEnforce || p.MaxAge != 604800 || !slices.Equal(p.MX, []string{"mx1.example.com", "*.mail.example.com"}) ||
		p.LFOnly || !slices.Equal(p.UnknownKeys, []string{"future"}) {
		t.Errorf("%+v", p)
	}
	if p, _ := ParsePolicy("version: STSv1\nmode: none\nmax_age: 0\n"); p == nil || !p.LFOnly {
		t.Errorf("LF policy = %+v", p)
	}
	for _, bad := range []string{
		"mode: enforce\nmx: a.example.com\nmax_age: 1",
		"version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 1",
		"version: STSv1\nmode: strict\nmx: a.example.com\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmx: a.example.com",
		"version: STSv1\nmode: enforce\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 31557601",
		"version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: -1",
		"version: STSv1\nmode: enforce\nmode: testing\nmx: a.example.com\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmx: *.*.example.com\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmx: localhost\nmax_age: 1",
		"version STSv1",
	} {
		if _, err := ParsePolicy(bad); err == nil {
			t.Errorf("ParsePolicy(%q) succeeded", bad)
		}
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"mx.example.com", "mx.example.com", true},
		{"mx.example.com", "MX.Example.com.", true},
		{"mx.example.com", "mx2.example.com", false},
		{"*.example.com", "mx.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", ".example.com", false},
	}
	for _, tt := range tests {
		if got := Matches(tt.pattern, tt.host); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v", tt.pattern, tt.host, got)
		}
	}
}

// testPKI creates a CA and a server certificate for the given names.
func testPKI(t *testing.T, names []string, notAfter time.Time) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MailAuthProbe Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

type server struct {
	status      int
	contentType string
	body        string
	location    string
}

func startPolicyServer(t *testing.T, names []string, notAfter time.Time, s server) (*HTTPFetcher, string) {
	t.Helper()
	pool, cert := testPKI(t, names, notAfter)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		if s.location != "" {
			w.Header().Set("Location", s.location)
		}
		if s.contentType != "" {
			w.Header().Set("Content-Type", s.contentType)
		}
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return &HTTPFetcher{RootCAs: pool, Port: port, AllowNonPublic: true, Timeout: 2 * time.Second}, port
}

const goodPolicy = "version: STSv1\r\nmode: enforce\r\nmx: mx1.example.test\r\nmx: *.backup.example.test\r\nmax_age: 1209600\r\n"

func TestAssess(t *testing.T) {
	baseZone := `
_mta-sts.example.test.  TXT "v=STSv1; id=20260914;"
mta-sts.example.test.   A   127.0.0.1
`
	valid := time.Now().Add(90 * 24 * time.Hour)
	mx := []string{"mx1.example.test", "mx9.backup.example.test"}
	tests := []struct {
		name     string
		zone     string
		certFor  []string
		notAfter time.Time
		srv      server
		mx       []string
		noServer bool
		want     []string
	}{
		{name: "enforced", zone: baseZone, srv: server{200, "text/plain; charset=utf-8", goodPolicy, ""}, mx: mx, want: []string{"MAIL-MTASTS-014"}},
		{name: "not deployed", zone: `example.test. TXT "v=spf1 -all"`, noServer: true, want: []string{"MAIL-MTASTS-001"}},
		{name: "policy without record", zone: `mta-sts.example.test. A 127.0.0.1`, srv: server{200, "text/plain", goodPolicy, ""}, want: []string{"MAIL-MTASTS-013"}},
		{name: "multiple records", zone: baseZone + `_mta-sts.example.test. TXT "v=STSv1; id=2;"`, noServer: true, want: []string{"MAIL-MTASTS-002"}},
		{name: "invalid record", zone: `_mta-sts.example.test. TXT "v=STSv1; id=bad-id;"`, noServer: true, want: []string{"MAIL-MTASTS-002"}},
		{name: "404", zone: baseZone, srv: server{404, "text/plain", "", ""}, want: []string{"MAIL-MTASTS-003"}},
		{name: "host does not resolve", zone: `_mta-sts.example.test. TXT "v=STSv1; id=1;"`, noServer: true, want: []string{"MAIL-MTASTS-003"}},
		{name: "redirect", zone: baseZone, srv: server{301, "", "", "https://www.example.test/mta-sts.txt"}, want: []string{"MAIL-MTASTS-005"}},
		{name: "wrong certificate name", zone: baseZone, certFor: []string{"www.example.test"}, srv: server{200, "text/plain", goodPolicy, ""}, want: []string{"MAIL-MTASTS-004"}},
		{name: "expired certificate", zone: baseZone, notAfter: time.Now().Add(-time.Minute), srv: server{200, "text/plain", goodPolicy, ""}, want: []string{"MAIL-MTASTS-004"}},
		{name: "certificate expiring", zone: baseZone, notAfter: time.Now().Add(5 * 24 * time.Hour), srv: server{200, "text/plain", goodPolicy, ""}, mx: mx, want: []string{"MAIL-MTASTS-012"}},
		{name: "wrong content type and LF", zone: baseZone, srv: server{200, "text/html", strings.ReplaceAll(goodPolicy, "\r\n", "\n"), ""}, mx: mx, want: []string{"MAIL-MTASTS-006", "MAIL-MTASTS-015"}},
		{name: "invalid policy", zone: baseZone, srv: server{200, "text/plain", "version: STSv1\r\nmode: enforce\r\n", ""}, want: []string{"MAIL-MTASTS-007"}},
		{name: "too large", zone: baseZone, srv: server{200, "text/plain", strings.Repeat("x", MaxPolicySize+10), ""}, want: []string{"MAIL-MTASTS-016"}},
		{name: "testing short max_age uncovered mx", zone: baseZone,
			srv: server{200, "text/plain", "version: STSv1\r\nmode: testing\r\nmx: mx1.example.test\r\nmax_age: 3600\r\n", ""}, mx: mx,
			want: []string{"MAIL-MTASTS-008", "MAIL-MTASTS-010", "MAIL-MTASTS-011"}},
		{name: "mode none", zone: baseZone, srv: server{200, "text/plain", "version: STSv1\r\nmode: none\r\nmax_age: 0\r\n", ""}, mx: mx, want: []string{"MAIL-MTASTS-009"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := dnstest.MustParseZone(tt.zone)
			var fetcher *HTTPFetcher
			if tt.noServer {
				fetcher = &HTTPFetcher{AllowNonPublic: true, Port: "1", Timeout: time.Second}
			} else {
				names := tt.certFor
				if names == nil {
					names = []string{"mta-sts.example.test"}
				}
				notAfter := tt.notAfter
				if notAfter.IsZero() {
					notAfter = valid
				}
				fetcher, _ = startPolicyServer(t, names, notAfter, tt.srv)
			}
			fetcher.Resolver = zone
			a, err := Assess(context.Background(), "example.test", Options{Resolver: zone, Fetcher: fetcher, MXHosts: tt.mx})
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, f := range a.Findings {
				ids = append(ids, f.ID)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tt.want) {
				t.Errorf("findings = %v, want %v", ids, tt.want)
				for _, f := range a.Findings {
					t.Logf("  %s: %s", f.ID, f.Description)
				}
			}
		})
	}
}

func TestFetchRefusesNonPublicAddresses(t *testing.T) {
	zone := dnstest.MustParseZone("mta-sts.example.test. A 127.0.0.1\nmta-sts.example.test. AAAA fd00::1")
	f := &HTTPFetcher{Resolver: zone, Timeout: time.Second}
	_, err := f.Fetch(context.Background(), "example.test")
	fe, ok := err.(*FetchError)
	if !ok || fe.Kind != FetchForbiddenAddress {
		t.Fatalf("err = %v", err)
	}
}
