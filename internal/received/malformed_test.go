package received

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestParseMalformed(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		problems []string // substrings expected in Hop.Problems, in order
	}{
		{"empty", "", []string{"missing date", "no recognisable clauses"}},
		{"only date", "; Mon, 14 Sep 2026 10:00:00 +0000", []string{"no recognisable clauses"}},
		{"garbage", "hello world", []string{"missing date", "text before the first clause", "missing by clause"}},
		{"bad date", "from a.example by b.example; yesterday at noon", []string{"unparseable date"}},
		{"missing by", "from a.example (a.example [192.0.2.1]); Mon, 14 Sep 2026 10:00:00 +0000", []string{"missing by clause"}},
		{"empty from", "from (comment only) by b.example; Mon, 14 Sep 2026 10:00:00 +0000", []string{"empty from clause"}},
		{"unbalanced comment", "from a.example (a.example [192.0.2.1] by b.example; Mon, 14 Sep 2026 10:00:00 +0000", []string{"missing by clause"}},
		{"unterminated quote", `from "a.example by b.example; Mon, 14 Sep 2026 10:00:00 +0000`, []string{"missing by clause"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Parse(tt.value)
			want := tt.problems
			if len(h.Problems) < len(want) {
				t.Fatalf("problems = %q, want %q", h.Problems, want)
			}
			for i, w := range want {
				if !strings.Contains(h.Problems[i], w) {
					t.Errorf("problem %d = %q, want %q", i, h.Problems[i], w)
				}
			}
		})
	}
}

func TestParseAmbiguous(t *testing.T) {
	t.Run("bracketed IP in from word and comment disagree", func(t *testing.T) {
		// The literal after "from" is what the client announced; the IP in
		// the comment would be the connecting address. The first address
		// seen wins and is stated.
		h := Parse("from [10.0.0.1] (evil.example [203.0.113.66]) by mx.example.com with ESMTP; Mon, 14 Sep 2026 10:00:00 +0000")
		if field(h.IP) != "10.0.0.1/stated" || field(h.HELO) != "[10.0.0.1]/inferred" {
			t.Errorf("ip = %s, helo = %s", field(h.IP), field(h.HELO))
		}
	})
	t.Run("keyword used as host name", func(t *testing.T) {
		// "from by by mx" cannot be disambiguated; the parser must still
		// produce a hop with a by clause and without panicking.
		h := Parse("from by by mx.example.com with SMTP; Mon, 14 Sep 2026 10:00:00 +0000")
		if h.By == nil {
			t.Errorf("hop = %+v", h)
		}
	})
	t.Run("duplicate clauses keep the first", func(t *testing.T) {
		h := Parse("from a.example by first.example by second.example id 1 id 2; Mon, 14 Sep 2026 10:00:00 +0000")
		if h.By.Value != "first.example" || h.ID != "1" {
			t.Errorf("by = %s, id = %s", field(h.By), h.ID)
		}
	})
	t.Run("invalid address literal is ignored", func(t *testing.T) {
		h := Parse("from a.example (a.example [999.1.1.1]) by mx.example.com; Mon, 14 Sep 2026 10:00:00 +0000")
		if h.IP != nil {
			t.Errorf("ip = %s", field(h.IP))
		}
	})
	t.Run("nested comments", func(t *testing.T) {
		h := Parse("from a.example (a.example [192.0.2.1] (nested (deeper))) by mx.example.com (Postfix (x)) with ESMTP id Q; Mon, 14 Sep 2026 10:00:00 +0000")
		if field(h.IP) != "192.0.2.1/stated" || h.ID != "Q" || h.Protocol != "ESMTP" {
			t.Errorf("hop = %+v", h)
		}
	})
	t.Run("semicolon inside comment before date", func(t *testing.T) {
		h := Parse("from a.example (x; y [192.0.2.1]) by mx.example.com; Mon, 14 Sep 2026 10:00:00 +0000")
		if h.Timestamp == nil || h.By == nil {
			t.Errorf("hop = %+v", h)
		}
	})
}

func TestChainFindings(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    []string
	}{
		{"no headers", nil, []string{"MAIL-RCVD-001"}},
		{"unparseable", []string{"garbage; Mon, 14 Sep 2026 10:00:00 +0000"}, []string{"MAIL-RCVD-002", "MAIL-RCVD-002"}},
		{"no date", []string{"from a.example by b.example with ESMTPS"}, []string{"MAIL-RCVD-006"}},
		{"time travel", []string{
			"from b.example by c.example with ESMTPS; Mon, 14 Sep 2026 09:00:00 +0000",
			"from a.example by b.example with ESMTPS; Mon, 14 Sep 2026 10:00:00 +0000",
		}, []string{"MAIL-RCVD-003"}},
		{"small skew tolerated", []string{
			"from b.example by c.example with ESMTPS; Mon, 14 Sep 2026 09:58:00 +0000",
			"from a.example by b.example with ESMTPS; Mon, 14 Sep 2026 10:00:00 +0000",
		}, nil},
		{"long delay", []string{
			"from b.example by c.example with ESMTPS; Mon, 14 Sep 2026 13:00:00 +0000",
			"from a.example by b.example with ESMTPS; Mon, 14 Sep 2026 10:00:00 +0000",
		}, []string{"MAIL-RCVD-007"}},
		{"plaintext hop", []string{"from a.example (a.example [192.0.2.1]) by b.example with ESMTP; Mon, 14 Sep 2026 10:00:00 +0000"}, []string{"MAIL-RCVD-005"}},
		{"plaintext loopback hop is fine", []string{"from localhost (localhost [127.0.0.1]) by b.example with ESMTP; Mon, 14 Sep 2026 10:00:00 +0000"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Build(tt.headers)
			var got []string
			for _, f := range c.Findings {
				got = append(got, f.ID)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChainTruncation(t *testing.T) {
	headers := make([]string, MaxHops+50)
	for i := range headers {
		headers[i] = fmt.Sprintf("from h%d.example by h%d.example with ESMTPS; Mon, 14 Sep 2026 10:00:00 +0000", i+1, i)
	}
	c := Build(headers)
	if !c.Truncated || len(c.Hops) != MaxHops || c.Findings[0].ID != "MAIL-RCVD-004" {
		t.Errorf("truncated = %v, hops = %d", c.Truncated, len(c.Hops))
	}
	// The most recent headers are kept.
	if c.Hops[len(c.Hops)-1].By.Value != "h0.example" {
		t.Errorf("last hop = %s", field(c.Hops[len(c.Hops)-1].By))
	}
}

func TestInferSourceSkipsPrivateHops(t *testing.T) {
	c := Build([]string{
		"from internal (internal [10.0.0.5]) by store.example with LMTP; Mon, 14 Sep 2026 10:00:02 +0000",
		"from gw (gw [192.168.1.1]) by internal with ESMTP; Mon, 14 Sep 2026 10:00:01 +0000",
		"from [2001:db8::99] (helo=client.example) by gw with ESMTPS; Mon, 14 Sep 2026 10:00:00 +0000",
	})
	src, ok := c.InferSource()
	if !ok || src.IP != "2001:db8::99" || src.HELO != "client.example" || src.HopIndex != 1 {
		t.Errorf("source = %+v", src)
	}
	if _, ok := Build([]string{"by local id 1; Mon, 14 Sep 2026 10:00:00 +0000"}).InferSource(); ok {
		t.Error("inferred a source without any client address")
	}
}
