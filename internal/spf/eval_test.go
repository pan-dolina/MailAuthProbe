package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/marcindolinski/mailauthprobe/internal/dnsresolver/dnstest"
)

func TestMacroExpansionRFCExamples(t *testing.T) {
	// RFC 7208 section 7.4.
	mc := &macroContext{
		ip:     netip.MustParseAddr("192.0.2.3"),
		sender: "strong-bad@email.example.com",
		domain: "email.example.com",
		helo:   "mx.example.org",
		now:    time.Unix(1700000000, 0),
	}
	tests := []struct{ in, want string }{
		{"%{s}", "strong-bad@email.example.com"},
		{"%{o}", "email.example.com"},
		{"%{d}", "email.example.com"},
		{"%{d4}", "email.example.com"},
		{"%{d3}", "email.example.com"},
		{"%{d2}", "example.com"},
		{"%{d1}", "com"},
		{"%{dr}", "com.example.email"},
		{"%{d2r}", "example.email"},
		{"%{l}", "strong-bad"},
		{"%{l-}", "strong.bad"},
		{"%{lr}", "strong-bad"},
		{"%{lr-}", "bad.strong"},
		{"%{l1r-}", "strong"},
		{"%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"},
		{"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
		{"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
		{"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com"},
		{"%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"},
		{"%{h}", "mx.example.org"},
		{"%{c}", "192.0.2.3"},
		{"%{t}", "1700000000"},
		{"%{r}", "unknown"},
		{"%{p}", "unknown"},
		{"%%%_%-", "% %20"},
		{"%{S}", "strong-bad%40email.example.com"},
	}
	for _, tt := range tests {
		m, err := parseMacroString(tt.in, true)
		if err != nil {
			t.Errorf("parse %q: %v", tt.in, err)
			continue
		}
		if got := m.expand(mc); got != tt.want {
			t.Errorf("expand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	mc.ip = netip.MustParseAddr("2001:db8::cb01")
	m, _ := parseMacroString("%{ir}.%{v}._spf.%{d2}", false)
	want := "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
	if got := m.expand(mc); got != want {
		t.Errorf("IPv6 expansion = %q", got)
	}
}

func TestTruncateDomain(t *testing.T) {
	long := strings.Repeat("abcdefghij.", 30) + "example.com"
	got := truncateDomain(long)
	if len(got) > 253 || !strings.HasSuffix(got, ".example.com") || strings.HasPrefix(got, ".") {
		t.Errorf("truncateDomain produced %d octets: %q", len(got), got)
	}
	if got := truncateDomain("example.com."); got != "example.com" {
		t.Errorf("got %q", got)
	}
}

const evalZone = `
example.test.           TXT  "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a:mail.example.test mx include:_spf.partner.test -all"
example.test.           MX   10 mx.example.test.
mx.example.test.        A    198.51.100.25
mx.example.test.        AAAA 2001:db8:ffff::25
mail.example.test.      A    198.51.100.10
_spf.partner.test.      TXT  "v=spf1 ip4:203.0.113.0/28 ~all"

soft.test.              TXT  "v=spf1 ~all"
neutral.test.           TXT  "v=spf1 ?all"
open.test.              TXT  "v=spf1 +all"
noall.test.             TXT  "v=spf1 ip4:192.0.2.1"
none.test.              TXT  "google-site-verification=abc"
multi.test.             TXT  "v=spf1 -all"
multi.test.             TXT  "v=spf1 +all"
syntax.test.            TXT  "v=spf1 ip4:300.1.1.1 -all"
redirect.test.          TXT  "v=spf1 redirect=example.test"
redirect-none.test.     TXT  "v=spf1 redirect=none.test"
redirect-ignored.test.  TXT  "v=spf1 -all redirect=open.test"
include-none.test.      TXT  "v=spf1 include:none.test -all"
include-fail.test.      TXT  "v=spf1 include:multi.test -all"
cidr.test.              TXT  "v=spf1 a:hosts.cidr.test/24//64 -all"
hosts.cidr.test.        A    192.0.2.200
hosts.cidr.test.        AAAA 2001:db8:1:2::1
exists.test.            TXT  "v=spf1 exists:%{ir}.allow.exists.test -all"
1.2.0.192.allow.exists.test. A 127.0.0.2
ptr.test.               TXT  "v=spf1 ptr -all"
mail.ptr.test.          A    192.0.2.99
192.0.2.99              PTR  mail.ptr.test.
192.0.2.98              PTR  mail.ptr.test.
temp.test.              TXT  "v=spf1 include:flaky.test -all"
flaky.test.             SERVFAIL
tempa.test.             TXT  "v=spf1 a:flaky.test -all"
exp.test.               TXT  "v=spf1 -all exp=why.exp.test"
why.exp.test.           TXT  "%{i} is not allowed to send for %{d}"
helo.test.              TXT  "v=spf1 a -all"
helo.test.              A    192.0.2.55
`

func TestCheckHost(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		sender  string
		helo    string
		want    Result
		matched string
		reason  string
	}{
		{"ip4 match", "192.0.2.10", "user@example.test", "", ResultPass, "ip4:192.0.2.0/24", ""},
		{"ip6 match", "2001:db8::1", "user@example.test", "", ResultPass, "ip6:2001:db8::/32", ""},
		{"ipv4-mapped ipv6 treated as ipv4", "::ffff:192.0.2.10", "user@example.test", "", ResultPass, "ip4:192.0.2.0/24", ""},
		{"a with domain", "198.51.100.10", "user@example.test", "", ResultPass, "a:mail.example.test", ""},
		{"mx ipv4", "198.51.100.25", "user@example.test", "", ResultPass, "mx", ""},
		{"mx ipv6", "2001:db8:ffff::25", "user@example.test", "", ResultPass, "ip6:2001:db8::/32", ""},
		{"include pass", "203.0.113.5", "user@example.test", "", ResultPass, "include:_spf.partner.test", ""},
		{"include softfail does not match", "203.0.113.200", "user@example.test", "", ResultFail, "-all", ""},
		{"softfail", "192.0.2.1", "a@soft.test", "", ResultSoftFail, "~all", ""},
		{"neutral", "192.0.2.1", "a@neutral.test", "", ResultNeutral, "?all", ""},
		{"plus all", "10.9.8.7", "a@open.test", "", ResultPass, "+all", ""},
		{"no match default neutral", "192.0.2.2", "a@noall.test", "", ResultNeutral, "", "default result is neutral"},
		{"no record", "192.0.2.1", "a@none.test", "", ResultNone, "", "no SPF record"},
		{"nxdomain", "192.0.2.1", "a@missing.test", "", ResultNone, "", ""},
		{"single label domain", "192.0.2.1", "a@localhost", "", ResultNone, "", "multi-label"},
		{"multiple records", "192.0.2.1", "a@multi.test", "", ResultPermError, "", "2 SPF records"},
		{"syntax error", "192.0.2.1", "a@syntax.test", "", ResultPermError, "", "syntax error"},
		{"redirect", "192.0.2.10", "a@redirect.test", "", ResultPass, "", "redirect to example.test"},
		{"redirect to no record", "192.0.2.10", "a@redirect-none.test", "", ResultPermError, "", "has no SPF record"},
		{"redirect ignored when all matches", "192.0.2.10", "a@redirect-ignored.test", "", ResultFail, "-all", ""},
		{"include of domain without record", "192.0.2.10", "a@include-none.test", "", ResultPermError, "", "has no SPF record"},
		{"include of permerror", "192.0.2.10", "a@include-fail.test", "", ResultPermError, "", "2 SPF records"},
		{"dual cidr ipv4", "192.0.2.17", "a@cidr.test", "", ResultPass, "a:hosts.cidr.test/24//64", ""},
		{"dual cidr ipv6", "2001:db8:1:2::ffff", "a@cidr.test", "", ResultPass, "a:hosts.cidr.test/24//64", ""},
		{"dual cidr outside", "2001:db8:1:3::1", "a@cidr.test", "", ResultFail, "-all", ""},
		{"exists with macro", "192.0.2.1", "a@exists.test", "", ResultPass, "exists:%{ir}.allow.exists.test", ""},
		{"exists no record", "192.0.2.2", "a@exists.test", "", ResultFail, "-all", ""},
		{"ptr validated", "192.0.2.99", "a@ptr.test", "", ResultPass, "ptr", ""},
		{"ptr not validated", "192.0.2.98", "a@ptr.test", "", ResultFail, "-all", ""},
		{"temperror in include", "192.0.2.1", "a@temp.test", "", ResultTempError, "", "failed"},
		{"temperror in a", "192.0.2.1", "a@tempa.test", "", ResultTempError, "", "failed"},
		{"helo identity", "192.0.2.55", "", "helo.test", ResultPass, "a", ""},
		{"null sender local part", "192.0.2.10", "@example.test", "", ResultPass, "ip4:192.0.2.0/24", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := dnstest.MustParseZone(evalZone)
			c := &Checker{Resolver: zone}
			ev := c.CheckHost(context.Background(), Request{IP: netip.MustParseAddr(tt.ip), Sender: tt.sender, HELO: tt.helo})
			if ev.Result != tt.want {
				t.Fatalf("result = %s, want %s (reason: %s)\ntrace: %+v", ev.Result, tt.want, ev.Reason, ev.Trace)
			}
			if tt.matched != "" && ev.MatchedTerm != tt.matched {
				t.Errorf("matched = %q, want %q", ev.MatchedTerm, tt.matched)
			}
			if tt.reason != "" && !strings.Contains(ev.Reason, tt.reason) {
				t.Errorf("reason %q does not contain %q", ev.Reason, tt.reason)
			}
		})
	}
}

func TestCheckHostExplanation(t *testing.T) {
	zone := dnstest.MustParseZone(evalZone)
	c := &Checker{Resolver: zone}
	ev := c.CheckHost(context.Background(), Request{IP: netip.MustParseAddr("192.0.2.1"), Sender: "a@exp.test"})
	if ev.Result != ResultFail || ev.Explanation != "192.0.2.1 is not allowed to send for exp.test" {
		t.Errorf("result %s, explanation %q", ev.Result, ev.Explanation)
	}
}

func TestMacroExpansionIsBounded(t *testing.T) {
	m, err := parseMacroString(strings.Repeat("%{s}", 2000)+".example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	mc := &macroContext{sender: strings.Repeat("a", 64) + "@" + strings.Repeat("b", 180) + ".example", domain: "example.com"}
	if got := m.expand(mc); got != "" {
		t.Errorf("oversized expansion returned %d bytes", len(got))
	}
	zone := dnstest.MustParseZone(`big.test. TXT "v=spf1 exists:` + strings.Repeat("%{l}", 1500) + `.x.test -all"`)
	c := &Checker{Resolver: zone}
	ev := c.CheckHost(context.Background(), Request{IP: netip.MustParseAddr("192.0.2.1"), Sender: strings.Repeat("a", 64) + "@big.test"})
	if ev.Result != ResultFail {
		t.Errorf("result = %s (%s)", ev.Result, ev.Reason)
	}
}
