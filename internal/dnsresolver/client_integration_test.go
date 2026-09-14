package dnsresolver_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver"
	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

func startServer(t *testing.T, zoneText string) (*dnsresolver.Client, *dnstest.Zone) {
	t.Helper()
	zone := dnstest.MustParseZone(zoneText)
	srv, err := dnstest.NewServer(zone)
	if err != nil {
		t.Skip("cannot start local DNS server:", err)
	}
	t.Cleanup(func() { srv.Close() })
	return &dnsresolver.Client{Servers: []string{srv.Addr()}, Timeout: 200 * time.Millisecond, Attempts: 1}, zone
}

func TestClientAgainstLocalServer(t *testing.T) {
	longSPF := "v=spf1 " + strings.Repeat("ip4:192.0.2.1 ", 150) + "-all"
	client, _ := startServer(t, `
example.test.       TXT   "v=spf1 -all"
example.test.       MX    10 mx.example.test.
mx.example.test.    A     192.0.2.25
mx.example.test.    AAAA  2001:db8::25
alias.example.test. CNAME mx.example.test.
big.example.test.   TXT   "`+longSPF+`"
trunc.example.test. TXT   "forced tcp"
trunc.example.test. TRUNCATE
servfail.example.test. SERVFAIL
refused.example.test.  REFUSED
malformed.example.test. MALFORMED
timeout.example.test.  TIMEOUT
192.0.2.25          PTR   mx.example.test.
`)
	ctx := context.Background()

	t.Run("TXT", func(t *testing.T) {
		got, err := client.LookupTXT(ctx, "example.test")
		if err != nil || !slices.Equal(got, []string{"v=spf1 -all"}) {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("TXT over TCP after size truncation", func(t *testing.T) {
		got, err := client.LookupTXT(ctx, "big.example.test")
		if err != nil || len(got) != 1 || got[0] != longSPF {
			t.Fatalf("got %d records, err %v", len(got), err)
		}
	})
	t.Run("forced truncation", func(t *testing.T) {
		got, err := client.LookupTXT(ctx, "trunc.example.test")
		if err != nil || !slices.Equal(got, []string{"forced tcp"}) {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("MX", func(t *testing.T) {
		got, err := client.LookupMX(ctx, "example.test")
		if err != nil || len(got) != 1 || got[0] != (dnsresolver.MX{Host: "mx.example.test", Preference: 10}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("A and AAAA via CNAME", func(t *testing.T) {
		a, err := client.LookupA(ctx, "alias.example.test")
		if err != nil || len(a) != 1 || a[0] != netip.MustParseAddr("192.0.2.25") {
			t.Fatalf("A = %v, %v", a, err)
		}
		aaaa, err := client.LookupAAAA(ctx, "alias.example.test")
		if err != nil || len(aaaa) != 1 || aaaa[0] != netip.MustParseAddr("2001:db8::25") {
			t.Fatalf("AAAA = %v, %v", aaaa, err)
		}
		cname, err := client.LookupCNAME(ctx, "alias.example.test")
		if err != nil || cname != "mx.example.test" {
			t.Fatalf("CNAME = %q, %v", cname, err)
		}
	})
	t.Run("PTR", func(t *testing.T) {
		got, err := client.LookupPTR(ctx, netip.MustParseAddr("192.0.2.25"))
		if err != nil || !slices.Equal(got, []string{"mx.example.test"}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("NODATA", func(t *testing.T) {
		got, err := client.LookupAAAA(ctx, "example.test")
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	errTests := []struct {
		name string
		kind dnsresolver.Kind
	}{
		{"missing.example.test", dnsresolver.KindNXDomain},
		{"servfail.example.test", dnsresolver.KindTemporary},
		{"refused.example.test", dnsresolver.KindRefused},
		{"malformed.example.test", dnsresolver.KindMalformed},
		{"timeout.example.test", dnsresolver.KindTemporary},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.LookupTXT(ctx, tt.name)
			if got := dnsresolver.KindOf(err); got != tt.kind {
				t.Fatalf("kind = %v, want %v (err %v)", got, tt.kind, err)
			}
		})
	}
}

func TestClientFailsOverToSecondServer(t *testing.T) {
	good, _ := startServer(t, `example.test. TXT "ok"`)
	bad, _ := startServer(t, `example.test. SERVFAIL`)
	c := &dnsresolver.Client{Servers: []string{bad.Servers[0], good.Servers[0]}, Timeout: 200 * time.Millisecond, Attempts: 1}
	got, err := c.LookupTXT(context.Background(), "example.test")
	if err != nil || !slices.Equal(got, []string{"ok"}) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestClientHonoursContextCancellation(t *testing.T) {
	client, _ := startServer(t, `example.test. TIMEOUT`)
	client.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.LookupTXT(ctx, "example.test")
	if !dnsresolver.IsTemporary(err) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("cancellation took %v", time.Since(start))
	}
}
