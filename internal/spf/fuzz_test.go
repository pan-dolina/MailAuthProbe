package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
)

var spfSeeds = []string{
	"v=spf1 -all",
	"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx include:_spf.example.com ~all",
	"v=spf1 a:mail.example.com/24//64 mx:example.com/28 ptr:example.com exists:%{ir}.%{l1r-}.%{d2} redirect=_spf.example.com",
	"v=spf1 exp=explain.%{d} ?all foo=%{s}",
	"v=spf1 include:%{d} -all",
	"v=spf1 %{",
	"v=spf1 a:%{d9999999999r.-+,/_=}.example.com",
	"v=spf1 ip4:1.2.3.4/0 ip6:::/0 +all",
}

func FuzzParseSPF(f *testing.F) {
	for _, s := range spfSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		rec, err := Parse(record)
		if err != nil {
			if IsSPF(record) && rec == nil {
				t.Fatal("syntax error without partial record")
			}
			return
		}
		mc := &macroContext{ip: netip.MustParseAddr("2001:db8::1"), sender: "a.b@c.example", domain: "c.example", helo: "h.example"}
		for _, term := range rec.Terms {
			if term.Name == "" {
				t.Fatalf("term %q has no name", term.Raw)
			}
			if d := term.expandDomain(mc); len(d) > 253 {
				t.Fatalf("expanded domain longer than 253 octets: %d", len(d))
			}
		}
	})
}

// FuzzCheckHost evaluates arbitrary records, including self-references, to
// check that evaluation terminates within its limits.
func FuzzCheckHost(f *testing.F) {
	for _, s := range spfSeeds {
		f.Add(s, "192.0.2.1")
	}
	f.Fuzz(func(t *testing.T, record, ip string) {
		addr, err := netip.ParseAddr(ip)
		if err != nil || strings.ContainsAny(record, "\"\\\n\r") {
			return
		}
		zone := dnstest.NewZone()
		for _, line := range []string{
			`fuzz.example. TXT "` + record + `"`,
			`_spf.example.com. TXT "` + record + `"`,
			`example.com. TXT "` + record + `"`,
			"example.com. MX 10 mail.example.com.",
			"mail.example.com. A 192.0.2.1",
		} {
			if zone.AddLine(line) != nil {
				return
			}
		}
		c := &Checker{Resolver: zone}
		ev := c.CheckHost(context.Background(), Request{IP: addr, Sender: "user@fuzz.example", HELO: "fuzz.example"})
		if ev.Result == "" {
			t.Fatal("empty result")
		}
		if q := len(zone.Queries()); q > 500 {
			t.Fatalf("evaluation issued %d DNS queries", q)
		}
		a := &Analyzer{Resolver: zone}
		if _, err := a.Analyze(context.Background(), "fuzz.example"); err != nil {
			t.Fatalf("analysis returned infrastructure error with an in-memory zone: %v", err)
		}
	})
}
