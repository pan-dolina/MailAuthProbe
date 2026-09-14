package spf

import (
	"context"
	"net/netip"
	"testing"

	"github.com/pan-dolina/mailauthprobe/internal/dnsresolver/dnstest"
)

func BenchmarkParse(b *testing.B) {
	const record = "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a:mail.example.com/24//64 mx include:_spf.example.com exists:%{ir}.%{l1r-}._spf.%{d} ~all"
	for b.Loop() {
		if _, err := Parse(record); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckHost(b *testing.B) {
	zone := dnstest.MustParseZone(evalZone)
	c := &Checker{Resolver: zone}
	req := Request{IP: netip.MustParseAddr("203.0.113.5"), Sender: "user@example.test"}
	for b.Loop() {
		if ev := c.CheckHost(context.Background(), req); ev.Result != ResultPass {
			b.Fatal(ev.Result)
		}
	}
}
