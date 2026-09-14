package received

import (
	"testing"
	"time"
)

func field(f *Field) string {
	if f == nil {
		return "-"
	}
	return f.Value + "/" + f.Source
}

func TestParseRealWorldFormats(t *testing.T) {
	tests := []struct {
		name                          string
		value                         string
		from, helo, rdns, ip, by      string
		protocol, id, forAddr         string
		tlsUsed                       bool
		tlsSource, tlsVersion, cipher string
		date                          string
	}{
		{
			name:  "postfix with TLS",
			value: "from mail.sender.example (mail.sender.example [198.51.100.7]) (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (2048 bits)) (No client certificate requested) by mx.receiver.example (Postfix) with ESMTPS id 4F1A2B3C4D for <bob@receiver.example>; Mon, 14 Sep 2026 10:11:12 +0200 (CEST)",
			from:  "mail.sender.example/stated", helo: "mail.sender.example/inferred", rdns: "mail.sender.example/inferred",
			ip: "198.51.100.7/stated", by: "mx.receiver.example/stated", protocol: "ESMTPS", id: "4F1A2B3C4D", forAddr: "bob@receiver.example",
			tlsUsed: true, tlsSource: Stated, tlsVersion: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", date: "2026-09-14T08:11:12Z",
		},
		{
			name:  "postfix unknown reverse DNS",
			value: "from helo.example (unknown [203.0.113.9]) by mx.receiver.example (Postfix) with ESMTP id AAA; Mon, 14 Sep 2026 08:00:00 +0000",
			from:  "helo.example/stated", helo: "helo.example/inferred", rdns: "-", ip: "203.0.113.9/stated", by: "mx.receiver.example/stated",
			protocol: "ESMTP", id: "AAA", tlsUsed: false, tlsSource: Inferred, date: "2026-09-14T08:00:00Z",
		},
		{
			name:  "gmail",
			value: "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id a640c23a62f3a-abc123 for <user@gmail.com> (Google Transport Security); Mon, 14 Sep 2026 01:02:03 -0700 (PDT)",
			from:  "mail-sor-f41.google.com/stated", helo: "mail-sor-f41.google.com/inferred", rdns: "mail-sor-f41.google.com/inferred",
			ip: "209.85.220.41/stated", by: "mx.google.com/stated", protocol: "SMTPS", id: "a640c23a62f3a-abc123", forAddr: "user@gmail.com",
			tlsUsed: true, tlsSource: Inferred, date: "2026-09-14T08:02:03Z",
		},
		{
			name:  "exim with explicit helo",
			value: "from rdns.sender.example ([192.0.2.44] helo=claimed.example) by mx.exim.example with esmtps (TLS1.3) tls TLS_AES_128_GCM_SHA256 (Exim 4.97) (envelope-from <a@sender.example>) id 1rABCD-000123-XY for b@exim.example; Mon, 14 Sep 2026 12:00:00 +0000",
			from:  "rdns.sender.example/stated", helo: "claimed.example/stated", rdns: "rdns.sender.example/inferred", ip: "192.0.2.44/stated",
			by: "mx.exim.example/stated", protocol: "esmtps", id: "1rABCD-000123-XY", forAddr: "b@exim.example",
			tlsUsed: true, tlsSource: Stated, tlsVersion: "TLS1.3", date: "2026-09-14T12:00:00Z",
		},
		{
			name:  "exim address literal",
			value: "from [192.0.2.50] (helo=laptop) by smtp.example.org with esmtpsa id 1rXYZ; Mon, 14 Sep 2026 12:00:00 +0000",
			from:  "-", helo: "laptop/stated", rdns: "-", ip: "192.0.2.50/stated", by: "smtp.example.org/stated", protocol: "esmtpsa", id: "1rXYZ",
			tlsUsed: true, tlsSource: Inferred, date: "2026-09-14T12:00:00Z",
		},
		{
			name:  "microsoft exchange online",
			value: "from AM9PR01MB1234.eurprd01.prod.exchangelabs.com (2603:10a6:20b:4c9::19) by DB9PR01MB5678.eurprd01.prod.exchangelabs.com with HTTPS; Mon, 14 Sep 2026 09:10:11 +0000",
			from:  "am9pr01mb1234.eurprd01.prod.exchangelabs.com/stated", helo: "am9pr01mb1234.eurprd01.prod.exchangelabs.com/inferred", rdns: "-",
			ip: "2603:10a6:20b:4c9::19/stated", by: "db9pr01mb5678.eurprd01.prod.exchangelabs.com/stated", protocol: "HTTPS", date: "2026-09-14T09:10:11Z",
		},
		{
			name:  "microsoft smtp server tls comment",
			value: "from EUR05-AM6-obe.outbound.protection.outlook.com (40.107.22.100) by mx.example.net (10.0.0.5) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.4; Mon, 14 Sep 2026 09:10:12 +0000",
			from:  "eur05-am6-obe.outbound.protection.outlook.com/stated", helo: "eur05-am6-obe.outbound.protection.outlook.com/inferred", rdns: "-",
			ip: "40.107.22.100/stated", by: "mx.example.net/stated", protocol: "Microsoft SMTP Server", id: "15.2.1544.4",
			tlsUsed: true, tlsSource: Stated, tlsVersion: "TLS1_2", cipher: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", date: "2026-09-14T09:10:12Z",
		},
		{
			name:  "qmail helo comment",
			value: "from unknown (HELO mail.qmail.example) (198.51.100.99) by mx.example.com with SMTP; 14 Sep 2026 10:00:00 -0000",
			from:  "unknown/stated", helo: "mail.qmail.example/stated", rdns: "unknown/inferred", ip: "198.51.100.99/stated", by: "mx.example.com/stated",
			protocol: "SMTP", tlsUsed: false, tlsSource: Inferred, date: "2026-09-14T10:00:00Z",
		},
		{
			name:  "local delivery without from",
			value: "by mailstore.example.com (Postfix, from userid 1001) id 9C1D2E3F; Mon, 14 Sep 2026 10:00:01 +0000",
			from:  "-", helo: "-", rdns: "-", ip: "-", by: "mailstore.example.com/stated", id: "9C1D2E3F", date: "2026-09-14T10:00:01Z",
		},
		{
			name:  "ipv6 literal",
			value: "from mail.v6.example (mail.v6.example [IPv6:2001:db8::25]) by mx.example.com (Postfix) with ESMTPS id X; Mon, 14 Sep 2026 10:00:00 +0000",
			from:  "mail.v6.example/stated", helo: "mail.v6.example/inferred", rdns: "mail.v6.example/inferred", ip: "2001:db8::25/stated",
			by: "mx.example.com/stated", protocol: "ESMTPS", id: "X", tlsUsed: true, tlsSource: Inferred, date: "2026-09-14T10:00:00Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Parse(tt.value)
			check := func(what, got, want string) {
				t.Helper()
				if want != "" && got != want {
					t.Errorf("%s = %q, want %q", what, got, want)
				}
			}
			check("from", field(h.FromHost), tt.from)
			check("helo", field(h.HELO), tt.helo)
			check("rdns", field(h.ReverseDNS), tt.rdns)
			check("ip", field(h.IP), tt.ip)
			check("by", field(h.By), tt.by)
			check("protocol", h.Protocol, tt.protocol)
			check("id", h.ID, tt.id)
			check("for", h.For, tt.forAddr)
			if h.Timestamp == nil || h.Timestamp.UTC().Format(time.RFC3339) != tt.date {
				t.Errorf("timestamp = %v, want %s", h.Timestamp, tt.date)
			}
			if tt.tlsSource == "" {
				if h.TLS != nil && tt.protocol != "HTTPS" {
					t.Errorf("tls = %+v, want nil", h.TLS)
				}
			} else if h.TLS == nil || h.TLS.Used != tt.tlsUsed || h.TLS.Source != tt.tlsSource ||
				h.TLS.Version != tt.tlsVersion || h.TLS.Cipher != tt.cipher {
				t.Errorf("tls = %+v", h.TLS)
			}
			if len(h.Problems) != 0 {
				t.Errorf("problems = %v", h.Problems)
			}
		})
	}
}

func TestBuildChain(t *testing.T) {
	headers := []string{ // header order: most recent first
		"by mailstore.example.com (Postfix) id Z; Mon, 14 Sep 2026 10:00:05 +0000",
		"from mail.sender.example (mail.sender.example [198.51.100.7]) by mx.example.com (Postfix) with ESMTPS id Y; Mon, 14 Sep 2026 10:00:03 +0000",
		"from laptop (10.1.2.3) by mail.sender.example with ESMTPSA id X; Mon, 14 Sep 2026 10:00:00 +0000",
	}
	c := Build(headers)
	if len(c.Hops) != 3 || c.Hops[0].ID != "X" || c.Hops[2].ID != "Z" || c.Hops[0].Index != 1 {
		t.Fatalf("hops = %+v", c.Hops)
	}
	if c.Hops[0].Delay != nil || c.Hops[1].Delay == nil || *c.Hops[1].Delay != 3*time.Second {
		t.Errorf("delays: %v %v", c.Hops[0].Delay, c.Hops[1].Delay)
	}
	if len(c.Findings) != 0 {
		t.Errorf("findings = %+v", c.Findings)
	}
	src, ok := c.InferSource()
	if !ok || src.IP != "198.51.100.7" || src.HELO != "mail.sender.example" || src.HopIndex != 2 {
		t.Errorf("source = %+v", src)
	}
}
