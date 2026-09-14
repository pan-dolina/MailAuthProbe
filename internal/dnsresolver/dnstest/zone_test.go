package dnstest

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver"
)

const testZone = `
; test zone
example.test.        MX    10 mx1.example.test.
example.test.        MX    20 mx2.example.test
example.test.        TXT   "v=spf1 " "ip4:192.0.2.0/24 -all"
example.test.        TXT   unquoted text here
mx1.example.test.    A     192.0.2.10
mx1.example.test.    AAAA  2001:db8::10
mx2.example.test.    CNAME mx1.example.test.
s1._domainkey.example.test. TXT "v=DKIM1; p="
192.0.2.10           PTR   mx1.example.test.
escaped.example.test. TXT "a\"b\\c\059"
slow.example.test.   TIMEOUT
flaky.example.test.  SERVFAIL TXT
flaky.example.test.  A     192.0.2.99
null.example.test.   MX    0 .
`

func TestParseZoneErrors(t *testing.T) {
	tests := []string{
		"example.test A",
		"example.test A 2001:db8::1",
		"example.test AAAA 192.0.2.1",
		"example.test MX ten mx.example.test",
		"example.test MX 10",
		"example.test CNAME",
		`example.test TXT "unterminated`,
		`example.test TXT "a" b`,
		"example.test SRV 0 0 25 mx.example.test",
		"lonely",
	}
	for _, line := range tests {
		if _, err := ParseZone(line); err == nil {
			t.Errorf("ParseZone(%q) succeeded, want error", line)
		}
	}
}

func TestZoneLookups(t *testing.T) {
	ctx := context.Background()
	z := MustParseZone(testZone)

	txt, err := z.LookupTXT(ctx, "EXAMPLE.test")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"v=spf1 ip4:192.0.2.0/24 -all", "unquoted text here"}; !slices.Equal(txt, want) {
		t.Errorf("TXT = %q, want %q", txt, want)
	}
	if txt, _ := z.LookupTXT(ctx, "escaped.example.test"); len(txt) != 1 || txt[0] != `a"b\c;` {
		t.Errorf("escaped TXT = %q", txt)
	}

	mx, err := z.LookupMX(ctx, "example.test")
	if err != nil || len(mx) != 2 || mx[1].Host != "mx2.example.test" || mx[1].Preference != 20 {
		t.Errorf("MX = %v, %v", mx, err)
	}
	if mx, _ := z.LookupMX(ctx, "null.example.test"); len(mx) != 1 || mx[0].Host != "." {
		t.Errorf("null MX = %v", mx)
	}

	// CNAME is followed for address lookups.
	a, err := z.LookupA(ctx, "mx2.example.test")
	if err != nil || len(a) != 1 || a[0] != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("A via CNAME = %v, %v", a, err)
	}
	cname, err := z.LookupCNAME(ctx, "mx2.example.test")
	if err != nil || cname != "mx1.example.test" {
		t.Errorf("CNAME = %q, %v", cname, err)
	}
	if cname, err := z.LookupCNAME(ctx, "mx1.example.test"); cname != "" || err != nil {
		t.Errorf("CNAME of non-alias = %q, %v", cname, err)
	}

	ptr, err := z.LookupPTR(ctx, netip.MustParseAddr("192.0.2.10"))
	if err != nil || !slices.Equal(ptr, []string{"mx1.example.test"}) {
		t.Errorf("PTR = %v, %v", ptr, err)
	}

	// NODATA: name exists, no records of the type.
	if aaaa, err := z.LookupAAAA(ctx, "example.test"); err != nil || len(aaaa) != 0 {
		t.Errorf("NODATA AAAA = %v, %v", aaaa, err)
	}
	// Empty non-terminal is NODATA, not NXDOMAIN.
	if txt, err := z.LookupTXT(ctx, "_domainkey.example.test"); err != nil || len(txt) != 0 {
		t.Errorf("empty non-terminal = %v, %v", txt, err)
	}
	if _, err := z.LookupTXT(ctx, "missing.example.test"); !dnsresolver.IsNXDomain(err) {
		t.Errorf("missing name err = %v", err)
	}
}

func TestZoneBehaviors(t *testing.T) {
	ctx := context.Background()
	z := MustParseZone(testZone)
	if _, err := z.LookupTXT(ctx, "slow.example.test"); dnsresolver.KindOf(err) != dnsresolver.KindTemporary {
		t.Errorf("TIMEOUT err = %v", err)
	}
	if _, err := z.LookupTXT(ctx, "flaky.example.test"); dnsresolver.KindOf(err) != dnsresolver.KindTemporary {
		t.Errorf("SERVFAIL TXT err = %v", err)
	}
	if a, err := z.LookupA(ctx, "flaky.example.test"); err != nil || len(a) != 1 {
		t.Errorf("type-scoped behaviour leaked to A: %v, %v", a, err)
	}
}

func TestZoneQueryLog(t *testing.T) {
	ctx := context.Background()
	z := MustParseZone(testZone)
	_, _ = z.LookupTXT(ctx, "Example.Test")
	_, _ = z.LookupA(ctx, "mx2.example.test")
	want := []string{"TXT example.test.", "A mx2.example.test."}
	if got := z.Queries(); !slices.Equal(got, want) {
		t.Errorf("queries = %v, want %v", got, want)
	}
	z.ResetQueries()
	if len(z.Queries()) != 0 {
		t.Error("ResetQueries did not clear the log")
	}
}

func TestSplitTXT(t *testing.T) {
	long := strings.Repeat("x", 600)
	parts := splitTXT(long)
	if len(parts) != 3 || len(parts[0]) != 255 || strings.Join(parts, "") != long {
		t.Errorf("splitTXT produced %d parts", len(parts))
	}
	if got := splitTXT(""); len(got) != 1 || got[0] != "" {
		t.Errorf("splitTXT(\"\") = %q", got)
	}
}
