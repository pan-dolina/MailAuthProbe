package received

import (
	"strings"
	"testing"
)

func FuzzParseReceived(f *testing.F) {
	for _, s := range []string{
		"from mail.sender.example (mail.sender.example [198.51.100.7]) (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)) by mx.receiver.example (Postfix) with ESMTPS id 4F1A2B3C4D for <bob@receiver.example>; Mon, 14 Sep 2026 10:11:12 +0200 (CEST)",
		"from rdns.sender.example ([192.0.2.44] helo=claimed.example) by mx.exim.example with esmtps (TLS1.3) tls TLS_AES_128_GCM_SHA256 id 1rABCD; Mon, 14 Sep 2026 12:00:00 +0000",
		"from AM9PR01MB1234.eurprd01.prod.exchangelabs.com (2603:10a6:20b:4c9::19) by DB9PR01MB5678.eurprd01.prod.exchangelabs.com with HTTPS; Mon, 14 Sep 2026 09:10:11 +0000",
		"by local id 1; Mon, 14 Sep 2026 10:00:00 +0000",
		"from ((((((( by ; ;",
		`from "quoted by" by x; x`,
		"from [IPv6:::1] (helo=[) by \\ with (",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		h := Parse(value)
		if h.Raw != value {
			t.Fatal("Raw does not preserve the input")
		}
		if _, ok := h.Addr(); ok && h.IP.Source != Stated {
			t.Fatalf("parsed IP with provenance %q", h.IP.Source)
		}
		for _, f := range []*Field{h.FromHost, h.HELO, h.ReverseDNS, h.IP, h.By} {
			if f != nil && f.Source != Stated && f.Source != Inferred {
				t.Fatalf("invalid provenance %q", f.Source)
			}
		}
		c := Build(strings.Split(value, "\n"))
		_, _ = c.InferSource()
	})
}
